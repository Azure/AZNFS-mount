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

#ifndef NDEBUG
    if (task) {
        // Only frontend write tasks must be specified.
        assert(task->magic == RPC_TASK_MAGIC);
        assert(task->get_op_type() == FUSE_WRITE);
        assert(task->rpc_api->write_task.is_fe());
        assert(task->rpc_api->write_task.get_size() > 0);
    }
#endif

    AZLogInfo("[{}] [FCSM] {} fctgt queued (F: {}, C: {}, T: {})",
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

void fcsm::run(struct rpc_task *task,
               uint64_t extent_left,
               uint64_t extent_right)
{
#ifdef NDEBUG
    assert(task->magic == RPC_TASK_MAGIC);
    assert(task->get_op_type() == FUSE_WRITE);
    assert(task->rpc_api->write_task.is_fe());
    assert(task->rpc_api->write_task.get_size() > 0);
#endif

    const size_t length = task->rpc_api->write_task.get_size();
    const off_t offset = task->rpc_api->write_task.get_offset();
    const bool sparse_write = false;
    const fuse_ino_t ino = task->rpc_api->write_task.get_ino();

    /*
     * We have successfully copied the user data into the cache.
     * We can have the following cases (in decreasing order of criticality):
     * 1. Cache has dirty+uncommitted data beyond the "inline write threshold",
     *    ref do_inline_write().
     *    In this case we begin flush of the dirty data and/or commit of the
     *    uncommitted data.
     *    This is a memory pressure situation and hence we do not complete the
     *    application write till all the above backend writes complete.
     *    This will happen when application is writing faster than our backend
     *    write throughput, eventually dirty data will grow beyond the "inline
     *    write threshold" and then we have to slow down the writers by delaying
     *    completion.
     * 2. Cache has uncommitted data beyond the "commit threshold", ref
     *    commit_required().
     *    In this case we free up space in the cache by committing data.
     *    We just initiate a commit while the current write request is
     *    completed. Note that we want to delay commits so that we can reduce
     *    the commit calls (commit more data per call) as commit calls sort
     *    of serialize the writes as we cannot send any other write to the
     *    server while commit is on.
     * 3. Cache has enough dirty data that we can flush.
     *    For sequential writes, this means the new write caused a contiguous
     *    extent to be greater than max_dirty_extent_bytes(), aka MDEB, while
     *    for non-seq writes it would mean that the total dirty data grew beyond
     *    MDEB.
     *    In this case we begin flush of this contiguous extent (in multiple
     *    parallel wsize sized blocks) since there's no benefit in waiting more
     *    as the data is sufficient for the server scheduler to effectively
     *    write, in optimal sized blocks.
     *    We complete the application write rightaway without waiting for the
     *    flush to complete as we are not under memory pressure.
     *
     * Other than this we have a special case of "write beyond eof" (termed
     * sparse write). In sparse write case also we perform "inline write" of
     * all the dirty data. This is needed for correct read behaviour. Imagine
     * a reader reading from the sparse part of the file which is not yet in
     * the bytes_chunk_cache. This read will be issued to the server and since
     * server doesn't know the updated file size (as the write may still be
     * sitting in our bytes_chunk_cache) it will return eof. This is not correct
     * as such reads issued after successful write, are valid and should return
     * 0 bytes for the sparse range.
     */

    /*
     * If the extent size exceeds the max allowed dirty size as returned by
     * max_dirty_extent_bytes(), then it's time to flush the extent.
     * Note that this will cause sequential writes to be flushed at just the
     * right intervals to optimize fewer write calls and also allowing the
     * server scheduler to merge better.
     * See bytes_to_flush for how random writes are flushed.
     *
     * Note: max_dirty_extent is static as it doesn't change after it's
     *       queried for the first time.
     */
    static const uint64_t max_dirty_extent =
        inode->get_filecache()->max_dirty_extent_bytes();
    assert(max_dirty_extent > 0);

    /*
     * Check what kind of limit we have hit.
     */
    const bool need_inline_write =
        (sparse_write || inode->get_filecache()->do_inline_write());
    const bool need_commit =
        inode->get_filecache()->commit_required();
    const bool need_flush =
        ((extent_right - extent_left) >= max_dirty_extent) ||
        inode->get_filecache()->flush_required();

    AZLogDebug("[{}] handle write (sparse={}, need_inline_write={}, "
               "need_commit={}, need_flush={}, extent=[{}, {}))",
               inode->get_fuse_ino(), sparse_write, need_inline_write,
               need_commit, need_flush, extent_left, extent_right);

    /*
     * Nothing to do, we can complete the application write rightaway.
     * This should be the happy path!
     */
    if (!need_inline_write && !need_commit && !need_flush) {
        task->reply_write(length);
        return;
    }

    /*
     * Do we need to perform "inline write"?
     * Inline write implies, we flush all the dirty data and wait for all the
     * corresponding backend writes to complete.
     */
    if (need_inline_write) {
        INC_GBL_STATS(inline_writes, 1);

        AZLogDebug("[{}] Inline write (sparse={}), {} bytes, extent @ [{}, {})",
                   ino, sparse_write, (extent_right - extent_left),
                   extent_left, extent_right);

        /*
         * ensure_flush() will arrange to flush all the dirty data and complete
         * the write task when the flush completes.
         */
        inode->flush_lock();
        if (inode->is_stable_write()) {
            inode->get_fcsm()->ensure_flush(offset, length, task);
        } else {
            inode->get_fcsm()->ensure_commit(task);
        }
        inode->flush_unlock();

        // Free up the fuse thread without completing the application write.
        return;
    }

    // Case 2: Commit
    /*
     * We don't need to do inline writes. See if we need to commit the
     * uncommitted data to the backend. We just need to stat the commit
     * and not hold the current write task till the commit completes.
     */
    if (need_commit) {
        inode->flush_lock();
        if (inode->is_commit_in_progress()) {
            AZLogDebug("[{}] Commit already in progress, skipping commit",
                       ino);
        } else {
            AZLogDebug("[{}] Committing {} bytes", ino,
                       inode->get_filecache()->max_commit_bytes());
            inode->get_fcsm()->ensure_commit(nullptr);
        }
        inode->flush_unlock();

        assert(!need_inline_write);
    }

    /*
     * Ok, we don't need to do inline writes. See if we have enough dirty
     * data and we need to start async flush.
     */

    // Case 3: Flush
    if ((extent_right - extent_left) < max_dirty_extent) {
        /*
         * This is the case of non-sequential writes causing enough dirty
         * data to be accumulated, need to flush all of that.
         */
        extent_left = 0;
        extent_right = UINT64_MAX;
    }

    /*
     * Queue a non-blocking flush target for flushing all the dirty data.
     */
    inode->flush_lock();
    inode->get_fcsm()->ensure_flush(offset, length, nullptr);
    inode->flush_unlock();

    /*
     * Complete the write request without waiting for the backend flush to
     * complete.
     */
    task->reply_write(length);
}

void fcsm::ctgtq_cleanup()
{
    assert(inode->is_flushing);
    assert(inode->is_stable_write());

    AZLogDebug("[FCSM][{}] ctgtq_cleanup()", inode->get_fuse_ino());
    while (!ctgtq.empty()) {
        struct fctgt &ctgt = ctgtq.front();
        assert(ctgt.fcsm == this);

        struct rpc_task *task = ctgt.task;
        if (task) {
        #ifdef NDEBUG
            // Complete the commit task as we switch to stable writes.
            assert(task->magic == RPC_TASK_MAGIC);
            assert(task->get_op_type() == FUSE_WRITE);
            assert(task->rpc_api->write_task.is_fe());
            assert(task->rpc_api->write_task.get_size() > 0);
        #endif
            task->reply_write(task->rpc_api->write_task.get_size());
        }

        AZLogInfo("[FCSM][{}] ctgtq_cleanup(): completed task: {} commit_seq: {}",
                  inode->get_fuse_ino(),
                  fmt::ptr(task),
                  ctgt.commit_seq);
        ctgtq.pop();
    }

    assert(ctgtq.empty());
}

void fcsm::ensure_commit(struct rpc_task *task)
{
    uint64_t commit_bytes = 0;

    assert(inode->is_flushing == true);
    AZLogDebug("[{}] [FCSM] ensure_commit<{}> task: {}",
               inode->get_fuse_ino(),
               task ? "blocking" : "non-blocking",
               fmt::ptr(task));

    assert(!inode->is_stable_write());

    // committed_seq_num can never be more than committing_seq_num.
    assert(committed_seq_num <= committing_seq_num);

#ifdef NDEBUG
    if (task) {
        // task provided must be a frontend write task.
        assert(task->magic == RPC_TASK_MAGIC);
        assert(task->get_op_type() == FUSE_WRITE);
        assert(task->rpc_api->write_task.is_fe());
        assert(task->rpc_api->write_task.get_size() > 0);
    }
#endif

    /*
     * What will be the committed_seq_num value after commit_bytes are committed?
     */
    if (inode->get_filecache()->get_bytes_to_commit() == 0) {
        int64_t bytes = inode->get_filecache()->get_bytes_to_flush() -
                          inode->get_filecache()->max_dirty_extent_bytes();
        commit_bytes = std::max(bytes, (int64_t) 0);
    } else {
        commit_bytes = inode->get_filecache()->get_bytes_to_commit();
    }

    if (commit_bytes == 0) {
        AZLogDebug("COMMIT BYTES ZERO");
    }

    const uint64_t target_committed_seq_num = committed_seq_num + commit_bytes;

    /*
     * If the state machine is already running, we just need to add an
     * appropriate commit target and return. When the ongoing operation
     * completes, this commit would be dispatched.
     */
    if (is_running()) {
#ifdef NDEBUG
        /*
         * Make sure commit targets are always added in an increasing commit_seq.
         */
        if (!ctgtq.empty()) {
            assert(ctgtq.front().commit_seq <= target_committed_seq_num);
            assert(ctgtq.front().flush_seq == 0);
        }
#endif
        ctgtq.emplace(this,
                      0 /* target flush_seq */,
                      target_committed_seq_num /* target commit_seq */,
                      task);
        assert(is_running());
        assert(inode->is_flushing);
        assert(!inode->is_stable_write());
        return;
    }

    /*
     * FCSM not running.
     * Flushed_seq_num tells us how much data is already flushed, If it's less
     * than the target_committed_seq_num, we need to schedule a flush to catch up
     * with the target_committed_seq_num.
     */
    if (flushed_seq_num < target_committed_seq_num) {
        AZLogDebug("[{}] [FCSM] not running, schedule a new flush to catch up, "
                   "flushed_seq_num: {}, target_committed_seq_num: {}",
                   inode->get_fuse_ino(),
                   flushed_seq_num.load(),
                   target_committed_seq_num);

        ensure_flush(0, 0, nullptr);
        assert(is_running());
        assert(flushing_seq_num >= target_committed_seq_num);

        if (!inode->is_stable_write()) {
            /**
             * Enqueue a commit target to be triggered once the flush completes.
             */
            ctgtq.emplace(this,
                          0 /* target flush_seq */,
                          target_committed_seq_num /* target commit_seq */,
                          task);
        } else {
            task->reply_write(task->rpc_api->write_task.get_size());
        }

        return;
    } else {
        AZLogDebug("[{}] [FCSM] not running, schedule a new commit,"
                   " flushed_seq_num: {}, "
                   "target_committed_seq_num: {}",
                   inode->get_fuse_ino(),
                   flushed_seq_num.load(),
                   target_committed_seq_num);

        uint64_t bytes;
        std::vector<bytes_chunk> bc_vec =
            inode->get_filecache()->get_commit_pending_bcs(&bytes);
        assert(bc_vec.empty() == (bytes == 0));

       /*
        * FCSM not running and nothing to commit, complete the task and return.
        * It may happen due writes are changed to stable write.
        */
        if (bytes == 0) {
            assert(inode->is_stable_write() || commit_bytes == 0);
            if (task) {
                AZLogDebug("[{}] [FCSM] not running and nothing to commit, "
                           "completing fuse write rightaway",
                           inode->get_fuse_ino());
                task->reply_write(task->rpc_api->write_task.get_size());
            }
            return;
        }

        inode->commit_membufs(bc_vec);
        assert(is_running());
        assert(committing_seq_num >= commit_bytes);
    }
}

/**
 * Must be called with flush_lock() held.
 */
void fcsm::ensure_flush(uint64_t write_off,
                        uint64_t write_len,
                        struct rpc_task *task)
{
    uint64_t flush_bytes = 0;

    assert(inode->is_flushing == true);
    AZLogDebug("[{}] [FCSM] ensure_flush<{}>({}), write req [{}, {}], task: {}",
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

#ifndef NDEBUG
    if (task) {
        // task provided must be a frontend write task.
        assert(task->magic == RPC_TASK_MAGIC);
        if (task->get_op_type() == FUSE_WRITE) {
            assert(task->rpc_api->write_task.is_fe());
            assert(task->rpc_api->write_task.get_size() > 0);
            // write_len and write_off must match that of the task.
            assert(task->rpc_api->write_task.get_size() == write_len);
            assert((uint64_t) task->rpc_api->write_task.get_offset() ==
                                                                 write_off);
        } else {
            assert(0);
        }
    }
#endif

    /*
     * What will be the flushed_seq_num value after all current dirty bytes are
     * flushed? That becomes our target flushed_seq_num.
     */
    const uint64_t bytes_to_flush =
        inode->get_filecache()->get_bytes_to_flush();
    const uint64_t last_flush_seq =
                !ftgtq.empty() ? ftgtq.front().flush_seq : 0;
    const uint64_t target_flushed_seq_num =
             std::max((flushing_seq_num + bytes_to_flush), last_flush_seq);

    /*
     * If the state machine is already running, we just need to add an
     * appropriate flush target and return. When the ongoing operation
     * completes, this flush would be dispatched.
     */
    if (is_running()) {
#ifndef NDEBUG
        /*
         * Make sure flush targets are always added in an increasing flush_seq.
         */
        if (!ftgtq.empty()) {
            assert(ftgtq.front().flush_seq <= target_flushed_seq_num);
            assert(ftgtq.front().commit_seq == 0);
        }
#endif
#ifdef ENABLE_PARANOID
        /*
         * Since we are adding a flush target make sure we have that much dirty
         * data in the chunkmap.
         */
        {
            uint64_t bytes;
            std::vector<bytes_chunk> bc_vec =
                inode->get_filecache()->get_dirty_nonflushing_bcs_range(
                        0, UINT64_MAX, &bytes);
            assert(bc_vec.empty() == (bytes == 0));
            assert(bytes >= bytes_to_flush);

            for (auto& bc : bc_vec) {
                bc.get_membuf()->clear_inuse();
            }
        }
#endif
        if (task == nullptr &&
             (target_flushed_seq_num == last_flush_seq)) {
            assert(is_running());
            return;
        }

        ftgtq.emplace(this,
                      target_flushed_seq_num /* target flush_seq */,
                      0 /* commit_seq */,
                      task);
        assert(is_running());
        return;
    }

    /*
     * FCSM not running.
     */
    uint64_t bytes;
    std::vector<bytes_chunk> bc_vec;

    if (inode->is_stable_write()) {
        bc_vec = inode->get_filecache()->get_dirty_nonflushing_bcs_range(
                                                    0, UINT64_MAX, &bytes);
    } else {
        bc_vec = inode->get_filecache()->get_contiguous_dirty_bcs(&bytes);
    }
    assert(bc_vec.empty() == (bytes == 0));
    assert(bytes > 0);

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

#ifndef NDEBUG
    const uint64_t flushing_seq_num_before = flushing_seq_num;
#endif
    assert(flushed_seq_num <= flushing_seq_num);

    // sync_membufs() will update flushing_seq_num() and mark fcsm running.
    inode->sync_membufs(bc_vec, false /* is_flush */, task);

    assert(is_running());
    assert(flushing_seq_num == (flushing_seq_num_before + bytes));
    assert(flushed_seq_num <= flushing_seq_num);
}

/**
 * TODO: We MUST ensure that on_commit_complete() doesn't block else it'll
 *       block a libnfs thread which may stall further request processing
 *       which may cause deadlock.
 */
void fcsm::on_commit_complete(uint64_t commit_bytes)
{
    // Must be called only for success.
    assert(commit_bytes > 0);
    assert(!inode->get_filecache()->is_flushing_in_progress());

    // Commit callback can only be called if FCSM is running.
    assert(is_running());

    // Update committed_seq_num to account for the commit_bytes.
    committed_seq_num += commit_bytes;

    // committed_seq_num can never go more than committing_seq_num.
    assert(committed_seq_num == committing_seq_num);

    AZLogDebug("[{}] [FCSM] on_commit_complete, committed_seq_num now: {}, "
               "committing_seq_num: {}",
               inode->get_fuse_ino(),
               committed_seq_num.load(),
               committing_seq_num.load());

    inode->flush_lock();

    /*
     * Go over all queued commit targets to see if any can be completed after
     * the latest commit completed.
     */
    while (!ctgtq.empty()) {
        struct fctgt& tgt = ctgtq.front();

        assert(tgt.fcsm == this);

        /*
         * ftgtq has commit targets in increasing order of committed_seq_num, so
         * as soon as we find one that's greater than committed_seq_num, we can
         * safely skip the rest.
         */
        if (tgt.commit_seq > committed_seq_num) {
            break;
        }

        if (tgt.task) {
            assert(tgt.task->magic == RPC_TASK_MAGIC);
            if (tgt.task->get_op_type() == FUSE_WRITE) {
                assert(tgt.task->rpc_api->write_task.is_fe());
                assert(tgt.task->rpc_api->write_task.get_size() > 0);

                AZLogInfo("[{}] [FCSM] completing blocking commit target: {}, "
                           "committed_seq_num: {}, write task: [{}, {})",
                           inode->get_fuse_ino(),
                           tgt.commit_seq,
                           committed_seq_num.load(),
                           tgt.task->rpc_api->write_task.get_offset(),
                           tgt.task->rpc_api->write_task.get_offset() +
                           tgt.task->rpc_api->write_task.get_size());

                tgt.task->reply_write(
                        tgt.task->rpc_api->write_task.get_size());
            } else {
                assert(0);
            }
        } else {
            AZLogDebug("[{}] [FCSM] completing non-blocking flush target: {}, "
                       "flushed_seq_num: {}",
                       inode->get_fuse_ino(),
                       tgt.flush_seq,
                       flushed_seq_num.load());
        }

        // Flush target accomplished, remove from queue.
        ctgtq.pop();
    }

    assert(!inode->get_filecache()->is_flushing_in_progress());
    assert(!inode->is_commit_in_progress());
    assert(committed_seq_num == committing_seq_num);
    assert(flushed_seq_num == committed_seq_num);
    assert(!inode->is_stable_write() || ctgtq.empty());

    /*
     * See if we have more commit targets and issue flush for the same.
     */
    if (!ftgtq.empty() || !ctgtq.empty()) {
        assert(ftgtq.empty() || ftgtq.front().flush_seq > flushed_seq_num);
        assert(ctgtq.empty() || ctgtq.front().commit_seq > committed_seq_num);
       /*
        * See if we have more flush targets and issue them.
        */
        uint64_t bytes;
        std::vector<bytes_chunk> bc_vec;
        if (inode->is_stable_write()) {
            bc_vec =
                inode->get_filecache()->get_dirty_nonflushing_bcs_range(
                                                        0, UINT64_MAX, &bytes);
        } else {
            bc_vec =
                inode->get_filecache()->get_contiguous_dirty_bcs(&bytes);
        }

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
    } else {
        AZLogDebug("[{}] [FCSM] idling, flushed_seq_num now: {}, "
                   "committed_seq_num: {}",
                   inode->get_fuse_ino(),
                   flushed_seq_num.load(),
                   committed_seq_num.load());

        // FCSM should not idle when there's any ongoing flush.
        assert(flushing_seq_num == flushed_seq_num);
        assert(committed_seq_num == committing_seq_num);
        assert(flushed_seq_num == committed_seq_num);

        /*
         * It may happen flush initiated from flush_cache_and_wait(), so
         * we should not clear the running flag.
         */
        if(!inode->get_filecache()->is_flushing_in_progress()) {
            assert(ctgtq.empty() && ftgtq.empty());
            clear_running();
        }
    }

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
    // assert(is_running());

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
    if (inode->get_filecache()->is_flushing_in_progress() ||
        !is_running() ||
        inode->is_commit_in_progress()) {
        AZLogDebug("[{}] [FCSM] not running, flushing_seq_num now: {}, "
                   "flushed_seq_num: {}",
                   inode->get_fuse_ino(),
                   flushing_seq_num.load(),
                   flushed_seq_num.load());
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
            if (tgt.task->get_op_type() == FUSE_WRITE) {
                assert(tgt.task->rpc_api->write_task.is_fe());
                assert(tgt.task->rpc_api->write_task.get_size() > 0);

                AZLogInfo("[{}] [FCSM] completing blocking flush target: {}, "
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
                assert(0);
            }
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
     * Check if there commit target to be triggered.
     * If we flushed, we should trigger commit so that memory is released.
     */
    if (!ctgtq.empty() && (ctgtq.front().commit_seq < flushed_seq_num)) {
        assert(!inode->is_stable_write());

        uint64_t bytes;
        std::vector<bytes_chunk> bc_vec =
            inode->get_filecache()->get_commit_pending_bcs(&bytes);
        assert(bc_vec.empty() == (bytes == 0));

        /*
         * Since we have a commit target asking more data to be committed, we
         * must have the corresponding bcs in the file cache.
         */
        assert(!bc_vec.empty());
        assert(bytes > 0);

        // commit_membufs() will update committing_seq_num() and mark fcsm running.
        inode->commit_membufs(bc_vec);
        assert(committing_seq_num >= bytes);
    } else if ((!ftgtq.empty() && (ftgtq.front().flush_seq > flushed_seq_num)) ||
               (!ctgtq.empty() && (ctgtq.front().commit_seq > committed_seq_num))) {
       /*
        * See if we have more flush targets and check if the next flush target
        * has its flush issued. If yes, then we need to wait for this flush to
        * complete and we will take stock of flush targets when that completes.
        */
        uint64_t bytes;
        std::vector<bytes_chunk> bc_vec;
        if (inode->is_stable_write()) {
            bc_vec = inode->get_filecache()->get_dirty_nonflushing_bcs_range(
                                                                    0, UINT64_MAX,
                                                                    &bytes);
        } else {
            bc_vec = inode->get_filecache()->get_contiguous_dirty_bcs(&bytes);
        }

        /*
         * Since we have a flush target asking more data to be flushed, we must
         * have the corresponding bcs in the file cache.
         */
        assert(!bc_vec.empty());

        if (inode->is_stable_write()) {
            // We should have all the dirty data in the chunkmap.
            assert(bytes >= (ftgtq.front().flush_seq - flushed_seq_num));
        } else {
            assert(bytes > 0);
        }

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
    } else if (ftgtq.empty() && ctgtq.empty()) {
        AZLogDebug("[{}] [FCSM] idling, flushing_seq_num now: {}, "
                   "flushed_seq_num: {}",
                   inode->get_fuse_ino(),
                   flushing_seq_num.load(),
                   flushed_seq_num.load());

        // FCSM should not idle when there's any ongoing flush.
        assert(flushing_seq_num >= flushed_seq_num);

        /*
         * If commit is in progress, then we should not clear
         * the running flag. Most likely it's issued from flush_cache_and_wait().
         */
        if (!inode->is_commit_in_progress()) {
            assert(ftgtq.empty() || ctgtq.empty());
            clear_running();
        }
    } else {
        assert(0);
        AZLogDebug("SHould not reach here");
    }

    inode->flush_unlock();
}

}
