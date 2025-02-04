#ifndef __FCSM_H__
#define __FCSM_H__

#include <queue>

#include "aznfsc.h"

// Forward declarations.
struct nfs_inode;
struct nfs_client;
struct rpc_task;

namespace aznfsc {

/**
 * This is the flush-commit state machine responsible for ensuring cached file
 * data is properly synced with the backend blob, with the following goals:
 * - Keep dirty/uncommitted data in check as per configured limits.
 *   This is to make sure we flush dirty data and commit uncommitted data at
 *   appropriate time so that it doesn't grow beyond configured limits and also
 *   flushing and committing at regular intervals results in better utilization
 *   of storage bandwidth. There are two sub goals when honoring local limits
 *   for unstable writes:
 *   - Flush in units of full block size.
 *   - Flush multiple blocks in parallel to maximize storage throughput.
 *   - Spread out storage IOs uniformly for better throughput.
 * - Keep global memory pressure in check as per configured limits.
 *   Note that global memory pressure can force premature flush (resulting in
 *   smaller blocks) and premature commit (resulting in more PBL calls), but
 *   when in high memory pressure we have no option.
 *
 * This follows a declarative model where caller calls ensure_flush() and
 * ensure_commit() for telling the state machine to flush and commit at the
 * next opportune time. These two are the state machine event handlers called
 * by the fuse threads executing application writes. The other two event
 * handlers are called by libnfs threads when flush or commit completes, those
 * are:
 * - on_flush_complete()
 * - on_commit_complete()
 *
 * The state machine starts in idle state till one of the ensure handlers is
 * called. If the ensure handler finds out that it has to flush or commit and
 * the state machine is not running, it kicks off the state machine by sending
 * a flush/write or commit RPC request. Any other fuse thread which comes in
 * the meantime and has to flush or commit finds out that the state machine
 * is already running, so it just queues a flush/commit job (fctgt) expressing
 * the flush/commit goal. When the ongoing flush or commit completes the
 * callback (libnfs thread) checks the queue and finds out that more flush
 * and/or commit needs to be done so it issues the required flush/commit
 * request, keeping the state machine moving, till the flush/commit callback
 * finds no fctgt queued and then the state machine goes back to idle state,
 * to be kicked again when new ensure calls are made.
 *
 * Note: fcsm doesn't introduce new locks, various members of fcsm are
 *       protected by flush_lock.
 */
#define FCSM_MAGIC *((const uint32_t *)"FCSM")

class fcsm
{
public:
    const uint32_t magic = FCSM_MAGIC;

    /**
     * Initialize fcsm.
     * nfs_client is for convenience, nfs_inode identifies the target file.
     */
    fcsm(struct nfs_client *_client,
         struct nfs_inode *_inode);

    /**
     * Ensure 'flush_bytes' additional bytes are flushed from the cache, above
     * and beyond what's already flushed or flushing now. flush_bytes==0 implies
     * flush all dirty bytes.
     * If the state machine is currently not running, it'll kick off the state
     * machine by calling sync_membufs(), else it'll add a new flush target to
     * ftgtq, which will be run by on_flush_complete() when the ongoing flush
     * completes. If task is non-null it is the frontend write task which
     * initiated this flush and in that case a blocking target will be added
     * which means the specified task will block till the requested target
     * completes, else a non-blocking target will be added which just requests
     * the specific amount of bytes to be flushed w/o having the application
     * wait.
     *
     * ensure_flush() provides the following guarantees:
     * - Additional flush_bytes bytes will be flushed. This is beyond what's
     *   already flushed or scheduled for flush.
     * - On completion of that flush, task will be completed.
     *   If after grabbing flush_lock it figures out that the requested flush
     *   target is already met, it completes the task rightaway.
     *
     * write_off and write_len describe the current application write call.
     * write_len is needed for completing the write rightaway for non-blocking
     * cases, where 'task' is null.
     *
     * LOCKS: flush_lock.
     */
    void ensure_flush(uint64_t flush_bytes,
                      uint64_t write_off,
                      uint64_t write_len,
                      struct rpc_task *task = nullptr);

    /**
     * Ensure 'commit_bytes' additional bytes are committed from the cache,
     * above and beyond what's already committed or committing now.
     * If 'task' is null it'll add a non-blocking commit target to ctgtq, else
     * it'll add a blocking commit target for completing task when given commit
     * goal is met.
     */
    void ensure_commit(uint64_t commit_bytes,
                       struct rpc_task *task = nullptr);

    /**
     * Callbacks to be called when flush/commit successfully complete.
     * These will update flushed_seq_num/committed_seq_num and run flush/commit
     * targets from ftgtq/ctgtq as appropriate.
     */
    void on_flush_complete(uint64_t flush_bytes);
    void on_commit_complete();

    /**
     * Is the state machine currently running, i.e. it has sent (one or more)
     * flush requests or a commit request and is waiting for it to complete.
     * At any point only one flush (executed as one or more parallel write
     * calls for different blocks) or commit can be running. Once the currently
     * running flush/commit completes it checks ftgtq/ctgtq to see if it needs
     * to perform more flush/commit, if yes the state machine continues to run,
     * till it has no more targets to execute, at which point the state machine
     * is no more actively running. It's said to be "idling" and needs to be
     * "kicked" again if a new flush/commit is to be executed.
     * The stats machine starts in idle state.
     */
    bool is_running() const
    {
        return running;
    }

    /**
     * Mark the state machine as "running".
     * This will be done by the fuse thread that calls one of the ensure methods
     * and finds the state machine as idling. It kicks off the state machine by
     * triggering the flush/commit and calls mark_running() to mark the state
     * machine as running.
     * clear_running() will be called by a libnfs callback thread that calls one
     * of the on_flush_complete()/on_commit_complete() callbacks and finds out
     * that there are no more flush/commit targets.
     */
    void mark_running();
    void clear_running();

    /**
     * Call when more writes are dispatched, or prepared to be dispatched.
     * This MUST be called before the write callback can be called.
     */
    void add_flushing(uint64_t bytes);

    struct nfs_inode *get_inode() const
    {
        return inode;
    }

    void fc_cb_enter()
    {
        ++in_fc_callback;
    }

    void fc_cb_exit()
    {
        assert(fc_cb_running());
        --in_fc_callback;
    }

    uint64_t fc_cb_count() const
    {
        return in_fc_callback;
    }

    bool fc_cb_running() const
    {
        return (fc_cb_count() > 0);
    }

private:
    /*
     * The singleton nfs_client, for convenience.
     */
    struct nfs_client *const client;

    /*
     * File inode for which we are tracking flush/commit.
     */
    struct nfs_inode *const inode;

    /**
     * Flush/commit target.
     * One such target is added to fcsm::ctgtq/ctgtq by ensure_flush() or
     * ensure_commit() to request the flush/commit state machine to perform a
     * specific flush/commit operation when flushed_seq_num/committed_seq_num
     * match the target values. This also has an implied meaning that the
     * requestor wants appropriate flush/commit to be performed (by fcsm) to
     * reach those flush/commit goals. Note that this follows a declarative
     * syntax where fctgt specifies what flushed_seq_num/committed_seq_num it
     * wants to reach and then the state machine issues the appropriate
     * flush/commit requests to reach that goal.
     * If task is non-null it is the requestor frontend write task that wants
     * to be completed when the flush/commit seq goal is met. Such targets are
     * called blocking targets as they cause the requesting task to block till
     * the flush/commit goal is met. Non-blocking targets have task==nullptr.
     * Blocking targets are added to slow down the writer application while
     * non-blocking targets are added to "initiate" flush/commit while the
     * task would not wait for it to complete, more of a background activity
     * vs the inline nature of blocking targets.
     */
    struct fctgt
    {
        fctgt(struct fcsm *fcsm,
              uint64_t _flush_seq,
              uint64_t _commit_seq,
              struct rpc_task *_task = nullptr);

        /*
         * Flush and commit targets (in terms of flushed_seq_num/committed_seq_num)
         * that this target wants to reach.
         */
        const uint64_t flush_seq = 0;
        const uint64_t commit_seq = 0;

        /*
         * If non-null this is the frontend write task that must be completed
         * once the above target is reached.
         */
        struct rpc_task *const task = nullptr;

        /*
         * Pointer to the containing fcsm.
         */
        struct fcsm *const fcsm = nullptr;
#if 0
        /*
         * Has the required flush/commit task started?
         * Once triggered, then it just waits for the flush/commit callback
         * and once completed, if task is non-null, it'll complete the task.
         */
        bool triggered = false;
#endif
    };

    /*
     * Queue of flush targets for the state machine.
     * These indicate how much needs to be flushed and what task to complete
     * when the requested flush target is met.
     */
    std::queue<struct fctgt> ftgtq;

    /*
     * Queue of commit targets for the state machine.
     * These indicate how much needs to be committed and what task to complete
     * when the requested commit target is met.
     */
    std::queue<struct fctgt> ctgtq;

    /*
     * Continually increasing seq number of the last byte successfully flushed
     * and committed. Flush-commit targets (fctgt) are expressed in terms of
     * these.
     * Note that these are *not* offsets in the file but these are cumulative
     * values for total bytes flushed/committed till now since the file was
     * opened. In case of overwrite same byte(s) may be repeatedly flushed
     * and/or committed so these can grow higher than AZNFSC_MAX_FILE_SIZE.
     */
    std::atomic<uint64_t> flushed_seq_num = 0;
    std::atomic<uint64_t> flushing_seq_num = 0;
    std::atomic<uint64_t> committed_seq_num = 0;
    std::atomic<uint64_t> committing_seq_num = 0;
    std::atomic<uint64_t> in_fc_callback = 0;

    /*
     * The state machine starts in an idle state.
     */
    std::atomic<bool> running = false;
};

struct FC_CB_TRACKER
{
    explicit FC_CB_TRACKER(struct nfs_inode *_inode);
    ~FC_CB_TRACKER();

    private:
    struct nfs_inode *const inode;
};

}
#endif /* __FCSM_H__ */
