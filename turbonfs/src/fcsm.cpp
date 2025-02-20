#include "fcsm.h"
#include "rpc_task.h"
#include "nfs_inode.h"

namespace aznfsc {
/* static */ std::atomic<double> fcsm::fc_scale_factor = 1.0;

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
                   struct rpc_task *_task,
                   std::atomic<bool> *_done) :
    flush_seq(_flush_seq),
    commit_seq(_commit_seq),
    task(_task),
    done(_done),
    fcsm(fcsm)
{
    assert(fcsm->magic == FCSM_MAGIC);
    // At least one of flush/commit goals must be set.
    assert((flush_seq != 0) || (commit_seq != 0));

    // If conditional variable, it's initial value should be false.
    assert(!done || (*done == false));

    if (task) {
        // Only frontend write tasks must be specified.
        assert(task->magic == RPC_TASK_MAGIC);
        assert(task->get_op_type() == FUSE_WRITE);
        assert(task->rpc_api->write_task.is_fe());
        assert(task->rpc_api->write_task.get_size() > 0);
    }

    AZLogDebug("[{}] [FCSM] {} fctgt queued (F: {}, C: {}, T: {}, D: {})",
               fcsm->get_inode()->get_fuse_ino(),
               task ? "Blocking" : "Non-blocking",
               flush_seq,
               commit_seq,
               fmt::ptr(task),
               fmt::ptr(done));
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
    assert(committed_seq_num <= committing_seq_num);
    assert(committing_seq_num <= flushed_seq_num);

    flushing_seq_num += bytes;
}

void fcsm::add_committing(uint64_t bytes)
{
    assert(inode->is_flushing);
    // Must be called only for unstable writes.
    assert(!inode->is_stable_write());
    assert(committed_seq_num <= committing_seq_num);

    committing_seq_num += bytes;

    // We can only commit a byte that's flushed.
    assert(flushed_seq_num <= flushing_seq_num);
    assert(committing_seq_num <= flushed_seq_num);
}

/* static */
void fcsm::update_fc_scale_factor()
{
    // Maximum cache size allowed in bytes.
    static const uint64_t max_cache =
        (aznfsc_cfg.cache.data.user.max_size_mb * 1024 * 1024ULL);
    assert(max_cache != 0);
    const uint64_t curr_cache = bytes_chunk_cache::bytes_allocated_g;
    const double percent_cache = (curr_cache * 100.0) / max_cache;
    double scale = 1.0;

    if (percent_cache > 95) {
        /*
         * Every file has fundamental right to 100MB of cache space.
         * If we reduce it further we will end up in sub-optimal writes
         * to the server.
         */
        scale = 1.0/10;
    } else if (percent_cache > 90) {
        // 200MB
        scale = 2.0/10;
    } else if (percent_cache > 80) {
        // 300MB
        scale = 3.0/10;
    } else if (percent_cache > 70) {
        // 500MB
        scale = 5.0/10;
    } else if (percent_cache > 60) {
        // 800MB
        scale = 8.0/10;
    }

    if (fc_scale_factor != scale) {
        static uint64_t last_log_usec;
        const uint64_t now = get_current_usecs();
        // Don't log more frequently than 5 secs.
        if ((now - last_log_usec) > (5 * 1000 * 1000)) {
            AZLogInfo("[FC] Scale factor updated ({} -> {})",
                      fc_scale_factor.load(), scale);
            last_log_usec = now;
        }
        fc_scale_factor = scale;
    }
}

void fcsm::run(struct rpc_task *task,
               uint64_t extent_left,
               uint64_t extent_right)
{
    assert(task->magic == RPC_TASK_MAGIC);
    assert(task->get_op_type() == FUSE_WRITE);
    assert(task->rpc_api->write_task.is_fe());
    assert(task->rpc_api->write_task.get_size() > 0);
    assert(extent_right > extent_left);

    const size_t length = task->rpc_api->write_task.get_size();
    const off_t offset = task->rpc_api->write_task.get_offset();
    const bool sparse_write = false;
    const fuse_ino_t ino = task->rpc_api->write_task.get_ino();

    /*
     * fcsm::run() is called after fuse thread successfully copies user data
     * into the cache. We can have the following cases (in decreasing order of
     * criticality):
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
        !need_inline_write &&
        inode->get_filecache()->commit_required();
    const bool need_flush =
        !need_inline_write &&
        inode->get_filecache()->flush_required(extent_right - extent_left);

    AZLogDebug("[{}] fcsm::run() (sparse={}, need_inline_write={}, "
               "need_commit={}, need_flush={}, extent=[{}, {}))",
               inode->get_fuse_ino(), sparse_write, need_inline_write,
               need_commit, need_flush, extent_left, extent_right);

    /*
     * Nothing to do, we can complete the application write rightaway.
     * This should be the happy path!
     */
    if (!need_inline_write && !need_commit && !need_flush) {
        INC_GBL_STATS(writes_np, 1);
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
         * Queue a blocking flush/commit target, which will complete the fuse
         * write after flush/commit completes.
         * In case of stable writes we queue a flush target while in case of
         * unstable writes we queue a commit target. Commit target implicitly
         * performs flush before the commit.
         */
        inode->flush_lock();
        if (inode->is_stable_write()) {
            inode->get_fcsm()->ensure_flush(offset, length, task);
        } else {
            inode->get_fcsm()->ensure_commit(offset, length, task);
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
        assert(!inode->is_stable_write());

        inode->flush_lock();
        /*
         * Commit will only start after all ongoing flush complete and no new
         * flush can start (as we have the flush_lock). This means no new
         * commit-pending data can be added and hence the current inprogress
         * commit will finish committing all commit-pending bytes.
         */
        if (inode->is_commit_in_progress()) {
            assert(!inode->get_filecache()->is_flushing_in_progress());

            AZLogDebug("[{}] Commit already in progress, skipping commit",
                       ino);
        } else {
            AZLogDebug("[{}] Committing {} bytes", ino,
                       inode->get_filecache()->max_commit_bytes());
            inode->get_fcsm()->ensure_commit(offset, length, nullptr);
        }
        inode->flush_unlock();
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
     * Queue a non-blocking flush target for flushing *all* the dirty data.
     */
    if (need_flush) {
        inode->flush_lock();
        inode->get_fcsm()->ensure_flush(offset, length, nullptr);
        inode->flush_unlock();
    }

    /*
     * Complete the write request without waiting for the backend flush/commit
     * to complete. For need_inline_write we should not complete the task now.
     */
    assert(!need_inline_write);
    task->reply_write(length);
}

void fcsm::ctgtq_cleanup()
{
    assert(inode->is_flushing);
    // Must be called after switching the inode to stable write.
    assert(inode->is_stable_write());

    AZLogDebug("[FCSM][{}] ctgtq_cleanup()", inode->get_fuse_ino());

    while (!ctgtq.empty()) {
        struct fctgt &ctgt = ctgtq.front();
        assert(ctgt.fcsm == this);

        struct rpc_task *task = ctgt.task;
        if (task) {
            // task and done are exclusive.
            assert(!ctgt.done);
            /*
             * ctgtq_cleanup() is called when we have decided to swith to
             * stable writes. Since commit is never called for stable writes,
             * these tasks waiting for commit must be completed now.
             */
            assert(task->magic == RPC_TASK_MAGIC);
            assert(task->get_op_type() == FUSE_WRITE);
            assert(task->rpc_api->write_task.is_fe());
            assert(task->rpc_api->write_task.get_size() > 0);

            AZLogInfo("[{}] [FCSM] ctgtq_cleanup: purging blocking commit "
                       "target: {}, write task: [{}, {})",
                       inode->get_fuse_ino(),
                       ctgt.commit_seq,
                       task->rpc_api->write_task.get_offset(),
                       task->rpc_api->write_task.get_offset() +
                       task->rpc_api->write_task.get_size());

            task->reply_write(task->rpc_api->write_task.get_size());
        } else if (ctgt.done) {
            AZLogInfo("[{}] [FCSM] ctgtq_cleanup: purging blocking commit "
                       "target: {}",
                       inode->get_fuse_ino(),
                       ctgt.commit_seq);

            assert(*ctgt.done == false);
            *ctgt.done = true;
        }

        ctgtq.pop();
    }

    assert(ctgtq.empty());
}

void fcsm::ftgtq_cleanup()
{
    assert(inode->is_flushing);
    // TODO: Verify this.
    assert(inode->is_stable_write());

    AZLogDebug("[FCSM][{}] ftgtq_cleanup()", inode->get_fuse_ino());

    while (!ftgtq.empty()) {
        struct fctgt &ftgt = ftgtq.front();
        assert(ftgt.fcsm == this);

        struct rpc_task *task = ftgt.task;
        if (task) {
            // task and done are exclusive.
            assert(!ftgt.done);
            /*
             * ftgtq_cleanup() is called when file is truncated and we have
             * flushed all existing dirty bytes. No more flush callback would
             * be called so we have to complete all the flush targets now.
             */
            assert(task->magic == RPC_TASK_MAGIC);
            assert(task->get_op_type() == FUSE_WRITE);
            assert(task->rpc_api->write_task.is_fe());
            assert(task->rpc_api->write_task.get_size() > 0);

            AZLogInfo("[{}] [FCSM] ftgtq_cleanup: purging blocking flush "
                       "target: {}, write task: [{}, {})",
                       inode->get_fuse_ino(),
                       ftgt.commit_seq,
                       task->rpc_api->write_task.get_offset(),
                       task->rpc_api->write_task.get_offset() +
                       task->rpc_api->write_task.get_size());

            task->reply_write(task->rpc_api->write_task.get_size());
        } else if (ftgt.done) {
            AZLogInfo("[{}] [FCSM] ftgtq_cleanup: purging blocking flush "
                       "target: {}",
                       inode->get_fuse_ino(),
                       ftgt.commit_seq);

            assert(*ftgt.done == false);
            *ftgt.done = true;
        }

        ftgtq.pop();
    }

    assert(ftgtq.empty());
}

void fcsm::ensure_commit(uint64_t write_off,
                         uint64_t write_len,
                         struct rpc_task *task,
                         std::atomic<bool> *done,
                         bool commit_full)
{
    assert(inode->is_flushing);
    assert(!inode->is_stable_write());

    /*
     * Caller passes commit_full when they want all dirty data to be flushed
     * and committed (o/w ensure_commit() can choose how much to flush/commit
     * based on configured limits). In such case it will pass a pointer to an
     * atomic bool 'done' which we should set to true once the flush/commit is
     * done. Only one of task and done can be passed.
     */
    assert(!commit_full || (task == nullptr));
    assert(!commit_full || (done != nullptr));
    assert((!!task + !!done) < 2);
    assert(!done || (*done == false));

    /*
     * If any of the flush/commit targets are waiting completion, state machine
     * must be running.
     */
    assert(is_running() || (ctgtq.empty() && ftgtq.empty()));
    assert(is_running() || (flushed_seq_num == flushing_seq_num));
    assert(is_running() || (committed_seq_num == committing_seq_num));

    AZLogDebug("[{}] [FCSM] ensure_commit<{}>"" write req [{}, {}], task: {}, "
               "done: {}",
               inode->get_fuse_ino(),
               task ? "blocking" : "non-blocking",
               commit_full ? " FULL" : "",
               write_off, write_off + write_len,
               fmt::ptr(task),
               fmt::ptr(done));

    // committed_seq_num can never be more than committing_seq_num.
    assert(committed_seq_num <= committing_seq_num);

    // we can only commit bytes which are flushed.
    assert(committing_seq_num <= flushed_seq_num);

    if (task) {
        // task provided must be a frontend write task.
        assert(task->magic == RPC_TASK_MAGIC);
        assert(task->get_op_type() == FUSE_WRITE);
        assert(task->rpc_api->write_task.is_fe());
        assert(task->rpc_api->write_task.get_size() > 0);
    }

    /*
     * Find how many bytes we would like to commit.
     * If there are some commit-pending bytes we commit all of those, else
     * we set a commit target large enough to flush+commit all leaving
     * one full sized dirty extent.
     */
    uint64_t commit_bytes =
        inode->get_filecache()->get_bytes_to_commit();

    /*
     * Only known caller to pass commit_full as true is flush_cache_and_wait().
     * It will first drain all commit_pending data by making a call to
     * wait_for_ongoing_flush() before calling us, so we should not have any
     * commit_pending data. Now we need to flush *all* dirty bytes and commit
     * them and let the caller know once flush+commit is done.
     */
    if (commit_full) {
        assert(done && !*done);
        assert(commit_bytes == 0);
        commit_bytes = inode->get_filecache()->get_bytes_to_flush();
    } else if (commit_bytes == 0) {
        /*
         * TODO: Make sure this doesn't result in small-blocks being written.
         */
        const int64_t bytes =
            (inode->get_filecache()->get_bytes_to_flush() -
             inode->get_filecache()->max_dirty_extent_bytes());

        commit_bytes = std::max(bytes, (int64_t) 0);
    }

    /*
     * No new bytes to commit, complete the task if it was a blocking call.
     */
    if (commit_bytes == 0) {
        AZLogDebug("COMMIT BYTES ZERO");
        if (task) {
            assert(!done);
            task->reply_write(task->rpc_api->write_task.get_size());
        } else if (done) {
            assert(*done == false);
            *done = true;
        }
        return;
    }

    /*
     * What will be the committed_seq_num value after commit_bytes are committed?
     * Since commit_pending_bytes can reduce as another thread could be parallely
     * running commit completion, so we may set target_commited_seq_num lower than
     * the last queued commit_seq, so take the max.
     */
    const uint64_t last_commit_seq =
                !ctgtq.empty() ? ctgtq.front().commit_seq : 0;
    const uint64_t target_committed_seq_num =
             std::max((committed_seq_num + commit_bytes), last_commit_seq);

    /*
     * If the state machine is already running, we just need to add an
     * appropriate commit target and return. When the ongoing operation
     * completes, this commit would be dispatched.
     */
    if (is_running()) {
#ifndef NDEBUG
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
                      task,
                      done);
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
                   "flushed_seq_num: {}, target_committed_seq_num: {}, "
                   "stable: {}",
                   inode->get_fuse_ino(),
                   flushed_seq_num.load(),
                   target_committed_seq_num,
                   inode->is_stable_write());

        /*
         * ensure_flush()->sync_membufs() below may convert this inode to stable
         * writes. In that case we should let caller know of completion once all
         * dirty data is flushed, else we want to let caller know once all data
         * is flushed and committed.
         */
        ensure_flush(task ? task->rpc_api->write_task.get_offset() : 0,
                     task ? task->rpc_api->write_task.get_size() : 0);

        /*
         * ensure_flush() flushes *all* dirty data, so it must have scheduled
         * flushing till target_committed_seq_num.
         */
        assert(flushing_seq_num >= target_committed_seq_num);

        if (!inode->is_stable_write()) {
            /**
             * Enqueue a commit target to be triggered once the flush completes.
             */
            ctgtq.emplace(this,
                          0 /* target flush_seq */,
                          target_committed_seq_num /* target commit_seq */,
                          task,
                          done);
        } else {
            /*
             * Caller wanted to wait till commit completes, but now the inode
             * has been converted to stable writes, there won't be any commits,
             * complete the task.
             */
            if (task) {
                assert(!commit_full);
                assert(!done);
                task->reply_write(task->rpc_api->write_task.get_size());
            } else if (done) {
                assert(commit_full);
                assert(*done == false);

                ensure_flush(0, 0, nullptr, done);
            }
        }

        return;
    } else {
        /*
         * No new data to flush for the current commit goal, just add a commit.
         * target and we are done.
         * Since FCSM is not running and we discovered that we have one or more
         * bytes to be committed, get_commit_pending_bcs() MUST return those.
         */
        AZLogDebug("[{}] [FCSM] not running, schedule a new commit, "
                   "flushed_seq_num: {}, "
                   "target_committed_seq_num: {}",
                   inode->get_fuse_ino(),
                   flushed_seq_num.load(),
                   target_committed_seq_num);

        uint64_t bytes;
        std::vector<bytes_chunk> bc_vec =
            inode->get_filecache()->get_commit_pending_bcs(&bytes);
        assert(!bc_vec.empty());
        assert(bytes > 0);

        // With FCSM not running, these should be same.
        assert(committing_seq_num == committed_seq_num);
        [[maybe_unused]]
        const uint64_t prev_committing_seq_num = committing_seq_num;
        inode->commit_membufs(bc_vec);
        assert(is_running());

        assert(committing_seq_num == (prev_committing_seq_num + bytes));
        assert(committing_seq_num > committed_seq_num);

        /*
         * Enqueue a commit target for caller to be notified when all data
         * till target_committed_seq_num is flushed+committed. In case
         * commit_full is true, above commit_membufs() may not be sufficient
         * to commit all that data, but FCSM will ensure that all the requested
         * data is flushed and committed.
         */
        ctgtq.emplace(this,
                      0 /* target flush_seq */,
                      target_committed_seq_num /* target commit_seq */,
                      task,
                      done);
    }
}

/**
 * Must be called with flush_lock() held.
 */
void fcsm::ensure_flush(uint64_t write_off,
                        uint64_t write_len,
                        struct rpc_task *task,
                        std::atomic<bool> *done)
{
    assert(inode->is_flushing);
    /*
     * Only one of task and done can be passed.
     */
    assert((!!task + !!done) < 2);
    assert(!done || (*done == false));

    /*
     * If any of the flush/commit targets are waiting completion, state machine
     * must be running.
     */
    assert(is_running() || (ctgtq.empty() && ftgtq.empty()));
    assert(is_running() || (flushed_seq_num == flushing_seq_num));
    assert(is_running() || (committed_seq_num == committing_seq_num));

    AZLogDebug("[{}] [FCSM] ensure_flush<{}> write req [{}, {}], task: {}, "
               "done: {}",
               inode->get_fuse_ino(),
               task ? "blocking" : "non-blocking",
               write_off, write_off + write_len,
               fmt::ptr(task),
               fmt::ptr(done));

    // flushed_seq_num can never be more than flushing_seq_num.
    assert(flushed_seq_num <= flushing_seq_num);

    if (task) {
        // task provided must be a frontend write task.
        assert(task->magic == RPC_TASK_MAGIC);
        assert(task->get_op_type() == FUSE_WRITE);
        assert(task->rpc_api->write_task.is_fe());
        assert(task->rpc_api->write_task.get_size() > 0);
        // write_len and write_off must match that of the task.
        assert(task->rpc_api->write_task.get_size() == write_len);
        assert(task->rpc_api->write_task.get_offset() == (off_t) write_off);
    }

    /*
     * What will be the flushed_seq_num value after *all* current dirty bytes
     * are flushed? That becomes our target flushed_seq_num.
     * Since bytes_chunk_cache::{bytes_dirty,bytes_flushing} are not updated
     * inside flush_lock, we can have race conditions where later values of
     * target_flushed_seq_num may be less than what we have already queued in
     * the latest flush target. In such case, just wait for the larger value.
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

        /*
         * If no new flush target and caller doesn't need to be notified,
         * don't add a dup target. The already queued target will ensure
         * the requested flush is done.
         */
        if (!task && !done &&
            (target_flushed_seq_num == last_flush_seq)) {
            return;
        }

        ftgtq.emplace(this,
                      target_flushed_seq_num /* target flush_seq */,
                      0 /* commit_seq */,
                      task,
                      done);
        return;
    }

    /*
     * FCSM not running.
     */
    assert(flushed_seq_num == flushing_seq_num);
    assert(target_flushed_seq_num >= flushing_seq_num);

    // No new data to flush.
    if (target_flushed_seq_num == flushed_seq_num) {
        if (task) {
            assert(!done);
            task->reply_write(task->rpc_api->write_task.get_size());
        } else if (done) {
            assert(*done == false);
            *done = true;
        }
        return;
    }

    uint64_t bytes;
    std::vector<bytes_chunk> bc_vec;

    if (inode->is_stable_write()) {
        bc_vec = inode->get_filecache()->get_dirty_nonflushing_bcs_range(
                                                    0, UINT64_MAX, &bytes);
        /*
         * Dirty flushable data can increase after get_bytes_to_flush() call
         * above as more dirty data can be added, while no dirty data can
         * become flushing as we have the flush_lock.
         */
        assert(bytes >= bytes_to_flush);
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
    AZLogDebug("[{}] [FCSM] kicking, flushing_seq_num now: {} "
               "flushed_seq_num: {}",
               inode->get_fuse_ino(),
               flushing_seq_num.load(),
               flushed_seq_num.load());

    [[maybe_unused]]
    const uint64_t flushing_seq_num_before = flushing_seq_num;
    assert(flushed_seq_num <= flushing_seq_num);

    /*
     * sync_membufs() will update flushing_seq_num and mark fcsm running.
     * Task is not passed to sync_membufs, but enqueued to ftgtq.
     */
    inode->sync_membufs(bc_vec, false /* is_flush */, nullptr);

    assert(is_running());
    assert(flushing_seq_num == (flushing_seq_num_before + bytes));
    assert(flushed_seq_num <= flushing_seq_num);

    /*
     * Enqueue a flush target for caller to be notified when all data
     * till target_flushed_seq_num is flushed.
     */
    ftgtq.emplace(this,
                 target_flushed_seq_num /* target flush_seq */,
                 0 /* commit_seq */,
                 task,
                 done);
}

/**
 * TODO: We MUST ensure that on_commit_complete() doesn't block else it'll
 *       block a libnfs thread which may stall further request processing
 *       which may cause deadlock.
 */
void fcsm::on_commit_complete(uint64_t commit_bytes)
{
    // Commit must be called only for unstable writes.
    assert(!inode->is_stable_write());

    // Must be called only for success.
    assert(inode->get_write_error() == 0);
    assert(commit_bytes > 0);

    // Must be called from flush/write callback.
    assert(fc_cb_running());

    // Commit callback can only be called if FCSM is running.
    assert(is_running());

    /*
     * Commit callback can be called only when commit is in progress, clear
     * it now. Must do it before grabbing the flush_lock, note that
     * wait_for_ongoing_commit() is waiting for commit-in-progress to be
     * cleared, with flush_lock held.
     */
    assert(inode->is_commit_in_progress());
    inode->clear_commit_in_progress();

    // If commit is running, flush cannot be running.
    assert(!inode->get_filecache()->is_flushing_in_progress());

    // commit_pending_bytes must be 0 here.
    assert(inode->get_filecache()->get_bytes_to_commit() == 0);

    // a byte can only be committed after it's flushed successfully.
    assert(committing_seq_num <= flushed_seq_num);
    assert(committing_seq_num <= flushing_seq_num);

    // Update committed_seq_num to account for the commit_bytes.
    committed_seq_num += commit_bytes;

    /*
     * When a commit completes it commits everything that has been flushed
     * till now also whatever has been scheduled for commit.
     */
    assert(flushed_seq_num == committed_seq_num);
    assert(committed_seq_num == committing_seq_num);

    AZLogDebug("[{}] [FCSM] on_commit_complete({}), Fd: {}, Fing: {}, "
               "Cd: {}, Cing: {}, Fq: {}, Cq: {}, bytes_flushing: {}",
               inode->get_fuse_ino(),
               commit_bytes,
               flushed_seq_num.load(),
               flushing_seq_num.load(),
               committed_seq_num.load(),
               committing_seq_num.load(),
               ftgtq.size(),
               ctgtq.size(),
               inode->get_filecache()->bytes_flushing.load());

    inode->flush_lock();

    /*
     * This can only come here with stable write true when
     * switch_to_stable_write() was waiting for ongoing commits to complete
     * and it went ahead and set inode stable write after we cleared the
     * commit_in_progress above.
     */
    assert(!inode->is_stable_write() || ctgtq.empty());

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
            // Only one of task or done can be present.
            assert(!tgt.done);
            assert(tgt.task->magic == RPC_TASK_MAGIC);
            assert(tgt.task->get_op_type() == FUSE_WRITE);
            assert(tgt.task->rpc_api->write_task.is_fe());
            assert(tgt.task->rpc_api->write_task.get_size() > 0);

            AZLogDebug("[{}] [FCSM] completing blocking commit target: {}, "
                       "committed_seq_num: {}, write task: [{}, {})",
                       inode->get_fuse_ino(),
                       tgt.commit_seq,
                       committed_seq_num.load(),
                       tgt.task->rpc_api->write_task.get_offset(),
                       tgt.task->rpc_api->write_task.get_offset() +
                       tgt.task->rpc_api->write_task.get_size());

            tgt.task->reply_write(
                    tgt.task->rpc_api->write_task.get_size());
        } else if (tgt.done) {
            AZLogDebug("[{}] [FCSM] completing blocking commit target: {}, "
                       "committed_seq_num: {}",
                       inode->get_fuse_ino(),
                       tgt.commit_seq,
                       committed_seq_num.load());

            assert(*tgt.done == false);
            *tgt.done = true;
        } else {
            AZLogDebug("[{}] [FCSM] completing non-blocking commit target: {}, "
                       "committed_seq_num: {}",
                       inode->get_fuse_ino(),
                       tgt.commit_seq,
                       committed_seq_num.load());
        }

        // Commit target accomplished, remove from queue.
        ctgtq.pop();
    }

    /*
     * See if we have more commit targets and issue flush for the same.
     */
    if (!ftgtq.empty() || !ctgtq.empty()) {
        /*
         * If we have any commit target here it must have commit_seq greater
         * than committed_seq_num, else it would have been completed by the
         * above loop.
         * If we have any flush target it must have flush_seq greater than
         * flushed_seq_num. This is because commit would have started after
         * the flush and we would have completed all eligible flush targets.
         */
        assert(ftgtq.empty() || ftgtq.front().flush_seq > flushed_seq_num);
        assert(ctgtq.empty() || ctgtq.front().commit_seq > committed_seq_num);

        uint64_t bytes;
        std::vector<bytes_chunk> bc_vec;

        /*
         * This means we are here after switch_to_stable_write() switched to
         * stable, we need to handle that.
         */
        if (inode->is_stable_write()) {
            assert(ctgtq.empty());
            bc_vec =
                inode->get_filecache()->get_dirty_nonflushing_bcs_range(
                                                        0, UINT64_MAX, &bytes);
            // Here bc_vec can be empty, sync_membufs() can handle that.
        } else {
            bc_vec =
                inode->get_filecache()->get_contiguous_dirty_bcs(&bytes);
            /*
             * Since we have a flush target asking more data to be flushed, we
             * must have the corresponding bcs in the file cache.
             *
             * Note: We cannot have this assert for the stable write case, as
             *       sync_membufs() that called switch_to_stable_write(), might
             *       have consumed all these bcs and marked them flushing. When
             *       we come here we won't find any dirty-and-not-flushing bcs.
             */
            assert(!bc_vec.empty());
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
        [[maybe_unused]]
        const uint64_t prev_flushing_seq_num = flushing_seq_num;
        inode->sync_membufs(bc_vec, false /* is_flush */);
        assert(flushing_seq_num == (prev_flushing_seq_num + bytes));
    } else {
        AZLogDebug("[{}] [FCSM] idling, flushed_seq_num now: {}, "
                   "committed_seq_num: {}",
                   inode->get_fuse_ino(),
                   flushed_seq_num.load(),
                   committed_seq_num.load());

        // FCSM should not idle when there's any ongoing flush or commit.
        assert(flushing_seq_num == flushed_seq_num);
        assert(committing_seq_num == committed_seq_num);
        assert(flushed_seq_num == committed_seq_num);

        assert(!inode->get_filecache()->is_flushing_in_progress());
        assert(!inode->is_commit_in_progress());

        clear_running();
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

    // See below why we cannot assert this.
#if 0
    // Flush callback can only be called if FCSM is running.
    assert(is_running);
#endif

    /*
     * Commit will only be run after current flush completes.
     * Since we are inside flush completion callback, commit cannot be
     * running yet.
     */
    assert(!inode->is_commit_in_progress());

    // a byte can only be committed after it's flushed successfully.
    assert(committing_seq_num <= flushed_seq_num);
    assert(committed_seq_num <= committing_seq_num);
    assert(committing_seq_num <= flushing_seq_num);

    // Update flushed_seq_num to account for the newly flushed bytes.
    flushed_seq_num += flush_bytes;

    // flushed_seq_num can never go more than flushing_seq_num.
    assert(flushed_seq_num <= flushing_seq_num);

    AZLogDebug("[{}] [FCSM] on_flush_complete({}), Fd: {}, Fing: {}, "
               "Cd: {}, Cing: {}, Fq: {}, Cq: {}, bytes_flushing: {}",
               inode->get_fuse_ino(),
               flush_bytes,
               flushed_seq_num.load(),
               flushing_seq_num.load(),
               committed_seq_num.load(),
               committing_seq_num.load(),
               ftgtq.size(),
               ctgtq.size(),
               inode->get_filecache()->bytes_flushing.load());

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
     * trigger pending flush/commit. Other flush callback threads which get
     * the lock after the first one, should simply return. They check for
     * one of the following conditions to avoid duplicating work:
     * 1. The first one didn't find anything to do, so it stopped the FSCM.
     * 2. The first one triggered a flush target.
     * 3. The first one triggered a commit target.
     */
    if (inode->get_filecache()->is_flushing_in_progress() ||
        inode->is_commit_in_progress() ||
        !is_running()) {
        assert(is_running() || ftgtq.empty());
        inode->flush_unlock();
        return;
    }

    /*
     * Entire flush is done and no new flush can start, so flushed_seq_num must
     * match flushing_seq_num.
     */
    assert(flushed_seq_num == flushing_seq_num);

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
            // Only one of task or done can be present.
            assert(!tgt.done);
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
        } else if (tgt.done) {
            AZLogDebug("[{}] [FCSM] completing blocking flush target: {}, "
                       "flushed_seq_num: {}",
                       inode->get_fuse_ino(),
                       tgt.flush_seq,
                       flushed_seq_num.load());

            assert(*tgt.done == false);
            *tgt.done = true;
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
     * We just completed a flush. See if we have some commit targets that we
     * should trigger now. A commit target can only be triggered if we have
     * flushed all bytes till the commit target.
     * We check commit target before any other flush targets as committing
     * helps us free memory.
     */
    if (!ctgtq.empty() && (flushed_seq_num >= ctgtq.front().commit_seq)) {
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

        /*
         * commit_membufs() must increase committing_seq_num exactly by bytes,
         * as all the bcs in bc_vec should be committed.
         */
        [[maybe_unused]]
        const uint64_t prev_committing_seq_num = committing_seq_num;
        inode->commit_membufs(bc_vec);
        assert(committing_seq_num == (prev_committing_seq_num + bytes));

    } else if ((!ftgtq.empty() && (ftgtq.front().flush_seq > flushing_seq_num)) ||
               (!ctgtq.empty() && (ctgtq.front().commit_seq > flushing_seq_num))) {
       /*
        * Nothing to commit, or what we want to commit has not yet flushed
        * successfully. Do we want to flush more? We check two things:
        * 1. Is there an explicit flush target which has not yet started
        *    flushing?
        * 2. Is there an commit target which implies flushing?
        *
        * If the next flush or commit target has its flush issued, then we
        * just have to wait for that flush to complete and then we will decide
        * the next action, else issue it now.
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
        // We should flush all the dirty data in the chunkmap.
        [[maybe_unused]]
        const uint64_t next_goal =
            std::max((ftgtq.empty() ? 0 : ftgtq.front().flush_seq),
                     (ctgtq.empty() ? 0 : ctgtq.front().commit_seq));
        assert(bytes >= (next_goal - flushing_seq_num));

        // flushed_seq_num can never be more than flushing_seq_num.
        assert(flushed_seq_num <= flushing_seq_num);

        AZLogDebug("[{}] [FCSM] continuing, flushing_seq_num now: {}, "
                   "flushed_seq_num: {}, bc_vec.size(): {}, FQ: {}, CQ: {}",
                   inode->get_fuse_ino(),
                   flushing_seq_num.load(),
                   flushed_seq_num.load(),
                   bc_vec.size(),
                   ftgtq.size(), ctgtq.size());

        // sync_membufs() will update flushing_seq_num.
        [[maybe_unused]]
        const uint64_t prev_flushing_seq_num = flushing_seq_num;
        inode->sync_membufs(bc_vec, false /* is_flush */);
        assert(flushing_seq_num == (prev_flushing_seq_num + bytes));
    } else if (ftgtq.empty() && ctgtq.empty()) {
        /*
         * No flush to issue, if we don't have any to wait for, then we can
         * stop the state machine.
         */
        AZLogDebug("[{}] [FCSM] idling, flushing_seq_num now: {}, "
                   "flushed_seq_num: {}",
                   inode->get_fuse_ino(),
                   flushing_seq_num.load(),
                   flushed_seq_num.load());

        // FCSM should not idle when there's any ongoing flush.
        assert(flushing_seq_num >= flushed_seq_num);

        /*
         * TODO: Modify flush_cache_and_wait() to also use the FCSM for
         *       performing the flush. Then we have any flush or commit
         *       only peformed by the state machine.
         */
        assert(!inode->get_filecache()->is_flushing_in_progress());
        assert(!inode->is_commit_in_progress());

        clear_running();
    } else {
        AZLogCrit("Should not reach here");
        assert(0);
    }

    inode->flush_unlock();
}

}
