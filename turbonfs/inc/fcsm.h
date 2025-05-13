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
     * Ensure *all* dirty bytes are flushed or scheduled for flushing (if flush
     * or commit is already ongoing).
     * If the state machine is currently not running, it'll kick off the state
     * machine by calling sync_membufs(), else it'll add a new flush target to
     * ftgtq, which will be run by on_flush_complete() when the ongoing flush
     * completes. If task is non-null it is the frontend write task which
     * initiated this flush and in that case a blocking target will be added
     * which means the specified task will block till the requested target
     * completes, else a non-blocking target will be added which just requests
     * dirty bytes to be flushed w/o having the application wait.
     *
     * ensure_flush() provides the following guarantees:
     * - For stable write, it'll flush *all* cached dirty bytes starting from
     *   the lowest offset. More dirty data can be added, but that may not
     *   necessarily be flushed, only what is returned by
     *   get_dirty_nonflushing_bcs_range() at the time of the call.
     * - For unstable write, it'll flush contiguous cached dirty bytes starting
     *   from the lowest offset. If caller wants to flush *all* then they need
     *   to pass 'flush_full_unstable'. If all dirty data is not contiguous,
     *   then it'll involve switch to stable write.
     * - On completion of that flush:
     *   - If 'task' is non-null, it will be completed.
     *   - If 'done' is non-null, it will be set to true to signal completion.
     *     Caller must wait for that in a loop.
     *   Only one of 'task' and 'done' can be non-null.
     *
     * write_off and write_len describe the current application write call.
     * They are needed for logging when task is nullptr.
     *
     * Caller MUST hold the flush_lock.
     */
    void ensure_flush(uint64_t write_off,
                      uint64_t write_len,
                      struct rpc_task *task = nullptr,
                      std::atomic<bool> *done = nullptr,
                      bool flush_full_unstable = false);

    /**
     * Ensure all or some commit-pending bytes are committed or scheduled for
     * commit (if a flush or commit is already ongoing). If not already flushed
     * data will be flushed before committing. Caller can pass 'commit_full' as
     * true to convey flush/commit *all dirty data*, else ensure_commit() will
     * decide how much to flush/commit based on heurustics and configuration.
     * If 'task' is null it'll add a non-blocking commit target to ctgtq, else
     * it'll add a blocking commit target for completing task when given commit
     * goal is met. The goal is decided by ensure_commit() based on configured
     * limits or if 'commit_full' is true it means caller wants entire dirty
     * data to be flushed and committed.
     *
     * Caller MUST hold the flush_lock.
     *
     * See ensure_flush() for more details.
     */
    void ensure_commit(uint64_t write_off,
                       uint64_t write_len,
                       struct rpc_task *task = nullptr,
                       std::atomic<bool> *done = nullptr,
                       bool commit_full = false);

    /**
     * Callbacks to be called when flush/commit successfully complete.
     * These will update flushed_seq_num/committed_seq_num and run flush/commit
     * targets from ftgtq/ctgtq as appropriate.
     */
    void on_flush_complete(uint64_t flush_bytes);
    void on_commit_complete(uint64_t commit_bytes);

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
     * Nudge the flush-commit state machine.
     * After the fuse thread copies the application data into the cache, it
     * must call this to let FCSM know that some more dirty data has been
     * added. It checks the dirty data against the configured limits and
     * decides which of the following action to take:
     * - Do nothing, as dirty data is still within limits.
     * - Start flushing.
     * - Start committing.
     * - Flush/commit while blocking the task till flush/commit completes.
     */
    void run(struct rpc_task *task,
             uint64_t extent_left,
             uint64_t extent_right);

    /**
     * Call when more writes are dispatched, or prepared to be dispatched.
     * These must correspond to membufs which are dirty and not already
     * flushing.
     * This MUST be called before the write_iov_callback() can be called, i.e.,
     * before the actual write call is issued.
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

    /**
     * Call when more commit are dispatched, or prepared to be dispatched.
     * These must correspond to membufs which are already flushed, i.e., they
     * must not be dirty or flushing and must be commit pending.
     * This MUST be called before the commit_callback can be called, i.e.,
     * before the actual commit call is issued.
     */
    void add_committing(uint64_t bytes);

    /**
     * ctgtq_cleanup() is called when we switch to stable writes.
     * It clears up all the queued commit targets as stable writes will not
     * cause a commit and those targets would never normally complete.
     */
    void ctgtq_cleanup();
    void ftgtq_cleanup();

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
              struct rpc_task *_task = nullptr,
              std::atomic<bool> *_done = nullptr,
              bool _commit_full = false);

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
         * If non-null, it's initial value must be false, and will be set to
         * true when the target completes. Caller will typically wait for it
         * to become true, in a loop.
         */
        std::atomic<bool> *done = nullptr;

        /*
         * Pointer to the containing fcsm.
         */
        struct fcsm *const fcsm = nullptr;

        /*
         * commit *all* dirty data. This means for unstable writes, if all
         * dirty data is not contiguous then we will switch to stable write.
         * This is true only when ensure_commit() is called from
         * flush_cache_and_wait().
         */
        bool commit_full = false;
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
     * these. These are actually numerically one more than the last
     * flushing/commiting and flushed/committed byte's seq number, e.g., if the
     * last byte flushed was byte #1 (0 and 1 are flushed), then flushed_seq_num
     * would be 2.
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
