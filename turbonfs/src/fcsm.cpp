#include "fcsm.h"
#include "rpc_task.h"
#include "nfs_inode.h"

namespace aznfsc {

/**
 * This is called from alloc_fcsm() with exclusive lock on ilock_1.
 */
fcsm::fcsm(struct nfs_client *_client,
           struct nfs_inode *_inode) :
    client(_client),
    inode(_inode)
{
    assert(client->magic == NFS_CLIENT_MAGIC);
    assert(inode->magic == NFS_INODE_MAGIC);

    // We should be called only for open regular files.
    assert(inode->is_regfile());
    assert(inode->has_filecache());

    AZLogDebug("[{}] [FCSM] created", inode->get_fuse_ino());
}

fcsm::fctgt::fctgt(struct fcsm *fcsm,
                   uint64_t _flush_seq,
                   uint64_t _commit_seq,
                   struct rpc_task *_task) :
    flush_seq(_flush_seq),
    commit_seq(_commit_seq),
    task(_task),
    fcsm(fcsm)
{
    assert(fcsm->magic == FCSM_MAGIC);
    // At least one of flush/commit goals must be set.
    assert((flush_seq != 0) || (commit_seq != 0));

#ifdef NDEBUG
    if (task) {
        // Only frontend write tasks must be specified.
        assert(task->magic == RPC_TASK_MAGIC);
        assert(task->get_op_type() == FUSE_WRITE);
        assert(task->rpc_api->write_task.is_fe());
        assert(task->rpc_api->write_task.get_size() > 0);
    }
#endif

    AZLogDebug("[{}] [FCSM] {} fctgt queued (F: {}, C: {}, T: {})",
               fcsm->get_inode()->get_fuse_ino(),
               task ? "Blocking" : "Non-blocking",
               flush_seq,
               commit_seq,
               fmt::ptr(task));
}

FC_CB_TRACKER::FC_CB_TRACKER(struct nfs_inode *_inode) :
    inode(_inode)
{
    assert(inode->magic == NFS_INODE_MAGIC);
    assert(inode->has_fcsm());

    inode->get_fcsm()->fc_cb_enter();
}

FC_CB_TRACKER::~FC_CB_TRACKER()
{
    inode->get_fcsm()->fc_cb_exit();
}

void fcsm::mark_running()
{
    assert(inode->is_flushing);
    running = true;
}

void fcsm::clear_running()
{
    assert(inode->is_flushing);
    // Must be running.
    assert(running);
    running = false;
}

void fcsm::add_flushing(uint64_t bytes)
{
    assert(inode->is_flushing);
    assert(flushed_seq_num <= flushing_seq_num);
    flushing_seq_num += bytes;
}

void fcsm::ensure_flush(uint64_t flush_bytes,
                        uint64_t write_off,
                        uint64_t write_len,
                        struct rpc_task *task)
{
    AZLogDebug("[{}] [FCSM] ensure_flush<{}>({}), write req [{}, {}), task: {}",
               inode->get_fuse_ino(),
               task ? "blocking" : "non-blocking",
               flush_bytes,
               write_off, write_off + write_len,
               fmt::ptr(task));

    /*
     * TODO: Do we have a usecase for caller specifying how many bytes to
     *       flush.
     */
    assert(flush_bytes == 0);

    // flushed_seq_num can never be more than flushing_seq_num.
    assert(flushed_seq_num <= flushing_seq_num);

#ifdef NDEBUG
    if (task) {
        // task provided must be a frontend write task.
        assert(task->magic == RPC_TASK_MAGIC);
        assert(task->get_op_type() == FUSE_WRITE);
        assert(task->rpc_api->write_task.is_fe());
        assert(task->rpc_api->write_task.get_size() > 0);

        // write_len and write_off must match that of the task.
        assert(task->rpc_api->write_task.get_size() == write_len);
        assert(task->rpc_api->write_task.get_offset() == write_off);
    }
#endif

    /*
     * Grab flush_lock to atomically get list of dirty chunks, which are not
     * already being flushed. This also protects us racing with a truncate
     * call and growing the file size after truncate shrinks the file.
     */
    inode->flush_lock();

    /*
     * What will be the flushed_seq_num value after all current dirty bytes are
     * flushed? That becomes our target flushed_seq_num.
     */
    const uint64_t bytes_to_flush =
        inode->get_filecache()->get_bytes_to_flush();
    const uint64_t target_flushed_seq_num = flushing_seq_num + bytes_to_flush;

    /*
     * If the state machine is already running, we just need to add an
     * appropriate flush target and return. When the ongoing operation
     * completes, this flush would be dispatched.
     */
    if (is_running()) {
#ifdef NDEBUG
        /*
         * Make sure flush targets are always added in an increasing flush_seq.
         */
        if (!ftgtq.empty()) {
            assert(ftgtq.front().flush_seq <= target_flushed_seq_num);
            assert(ftgtq.front().commit_seq == 0);
        }
#endif
        ftgtq.emplace(this,
                      target_flushed_seq_num /* target flush_seq */,
                      0 /* commit_seq */,
                      task);
        inode->flush_unlock();
        return;
    }

    /*
     * FCSM not running.
     */
    uint64_t bytes;
    std::vector<bytes_chunk> bc_vec =
        inode->get_filecache()->get_dirty_nonflushing_bcs_range(0, UINT64_MAX,
                                                                &bytes);
    assert(bc_vec.empty() == (bytes == 0));

    /*
     * FCSM not running and nothing to flush, complete the task and return.
     * Note that moe dirty data can be added after we get the list of dirty
     * and non-flushing bcs above, but they can be flushed at a later point.
     */
    if (bytes == 0) {
        inode->flush_unlock();

        if (task) {
            AZLogDebug("[{}] [FCSM] not running and nothing to flush, "
                       "completing fuse write [{}, {}) rightaway",
                       inode->get_fuse_ino(), write_off, write_off+write_len);
            task->reply_write(write_len);
        }
        return;
    }

    /*
     * Kickstart the state machine.
     * Since we pass the 3rd arg to sync_membufs, it tells sync_membufs()
     * to call the fuse callback after all the issued backend writes
     * complete. This will be done asynchronously while the sync_membufs()
     * call will return after issuing the writes.
     *
     * Note: sync_membufs() can free this rpc_task if all issued backend
     *       writes complete before sync_membufs() can return.
     *       DO NOT access rpc_task after sync_membufs() call.
     */
    AZLogDebug("[{}] [FCSM] kicking, flushing_seq_num now: {}",
               inode->get_fuse_ino(),
               flushing_seq_num.load());

    // sync_membufs() will update flushing_seq_num() and mark fcsm running.
    inode->sync_membufs(bc_vec, false /* is_flush */, task);

    assert(is_running());
    assert(flushing_seq_num >= bytes);

    inode->flush_unlock();
}

/**
 * TODO: We MUST ensure that on_flush_complete() doesn't block else it'll
 *       block a libnfs thread which may stall further request processing
 *       which may cause deadlock.
 *       We call sync_membufs() which can block in alloc_rpc_task() if tasks
 *       are exhausted. No new tasks can complete if libnfs threads are
 *       blocked.
 */
void fcsm::on_flush_complete(uint64_t flush_bytes)
{
    // Must be called only for success.
    assert(inode->get_write_error() == 0);
    assert(flush_bytes > 0);
    // Must be called from flush/write callback.
    assert(fc_cb_running());

    // Flush callback can only be called if FCSM is running.
    assert(is_running());

    // Update flushed_seq_num to account for the newly flushed bytes.
    flushed_seq_num += flush_bytes;

    // flushed_seq_num can never go more than flushing_seq_num.
    assert(flushed_seq_num <= flushing_seq_num);

    AZLogDebug("[{}] [FCSM] on_flush_complete({}), flushed_seq_num now: {}, "
               "flushing_in_progress: {}",
               inode->get_fuse_ino(),
               flush_bytes,
               flushed_seq_num.load(),
               inode->get_filecache()->is_flushing_in_progress());

    /*
     * If this is not the last completing flush (of the multiple parallel
     * flushes that sync_membufs() may start), don't do anything.
     * Only the last completing flush checks flush targets, as we cannot
     * start a new flush or commit till the current flush completes fully.
     */
    if (inode->get_filecache()->is_flushing_in_progress()) {
        return;
    }

    inode->flush_lock();

    /*
     * Multiple libnfs (callback) threads can find is_flushing_in_progress()
     * return false. The first one to get the flush_lock, gets to run the
     * queued flush targets which includes completing the waiting tasks and/or
     * trigger pending flush/commit.
     */
    if (inode->get_filecache()->is_flushing_in_progress()) {
        inode->flush_unlock();
        return;
    }

    /*
     * Go over all queued flush targets to see if any can be completed after
     * the latest flush completed.
     */
    while (!ftgtq.empty()) {
        struct fctgt& tgt = ftgtq.front();

        assert(tgt.fcsm == this);

        /*
         * ftgtq has flush targets in increasing order of flushed_seq_num, so
         * as soon as we find one that's greater than flushed_seq_num, we can
         * safely skip the rest.
         */
        if (tgt.flush_seq > flushed_seq_num) {
            break;
        }

        if (tgt.task) {
            assert(tgt.task->magic == RPC_TASK_MAGIC);
            assert(tgt.task->get_op_type() == FUSE_WRITE);
            assert(tgt.task->rpc_api->write_task.is_fe());
            assert(tgt.task->rpc_api->write_task.get_size() > 0);

            AZLogDebug("[{}] [FCSM] completing blocking flush target: {}, "
                       "flushed_seq_num: {}, write task: [{}, {})",
                       inode->get_fuse_ino(),
                       tgt.flush_seq,
                       flushed_seq_num.load(),
                       tgt.task->rpc_api->write_task.get_offset(),
                       tgt.task->rpc_api->write_task.get_offset() +
                       tgt.task->rpc_api->write_task.get_size());

            tgt.task->reply_write(
                    tgt.task->rpc_api->write_task.get_size());
        } else {
            AZLogDebug("[{}] [FCSM] completing non-blocking flush target: {}, "
                       "flushed_seq_num: {}",
                       inode->get_fuse_ino(),
                       tgt.flush_seq,
                       flushed_seq_num.load());
        }

        // Flush target accomplished, remove from queue.
        ftgtq.pop();
    }

    /*
     * See if we have more flush targets and check if the next flush target
     * has its flush issued. If yes, then we need to wait for this flush to
     * complete and we will take stock of flush targets when that completes.
     */
    if (!ftgtq.empty() && (ftgtq.front().flush_seq > flushing_seq_num)) {
        uint64_t bytes;
        std::vector<bytes_chunk> bc_vec =
            inode->get_filecache()->get_dirty_nonflushing_bcs_range(
                    0, UINT64_MAX, &bytes);

        /*
         * Since we have a flush target asking more data to be flushed, we must
         * have the corresponding bcs in the file cache.
         */
        assert(!bc_vec.empty());
        assert(bytes > 0);

        // flushed_seq_num can never be more than flushing_seq_num.
        assert(flushed_seq_num <= flushing_seq_num);

        AZLogDebug("[{}] [FCSM] continuing, flushing_seq_num now: {}, "
                   "flushed_seq_num: {}",
                   inode->get_fuse_ino(),
                   flushing_seq_num.load(),
                   flushed_seq_num.load());

        // sync_membufs() will update flushing_seq_num() and mark fcsm running.
        inode->sync_membufs(bc_vec, false /* is_flush */);
        assert(flushing_seq_num >= bytes);
    } else if (ftgtq.empty()) {
        AZLogDebug("[{}] [FCSM] idling, flushing_seq_num now: {}, "
                   "flushed_seq_num: {}",
                   inode->get_fuse_ino(),
                   flushing_seq_num.load(),
                   flushed_seq_num.load());

        // FCSM should not idle when there's any ongoing flush.
        assert(flushing_seq_num == flushed_seq_num);

        /*
         * No more flush targets, pause the state machine.
         * TODO: We need to clear running when flush fails.
         */
        clear_running();
    }

    inode->flush_unlock();
}

}
