#include "aznfsc.h"
#include "nfs_client.h"
#include "nfs_internal.h"
#include "rpc_task.h"
#include "rpc_readdir.h"

/* static */
std::atomic<double> nfs_client::ra_scale_factor = 1.0;
/* static */
std::atomic<double> nfs_client::fc_scale_factor = 1.0;

// The user should first init the client class before using it.
bool nfs_client::init()
{
    // init() must be called only once.
    assert(root_fh == nullptr);

    /*
     * Setup RPC transport.
     * This will create all required connections and perform NFS mount on
     * those, setting up libnfs nfs_context for each connection.
     * Once this is done the connections are ready to carry RPC req/resp.
     */
    if (!transport.start()) {
        AZLogError("Failed to start the RPC transport.");
        return false;
    }

    /*
     * Now we have negotiated wsize and dtpref with the server, set those values
     * in the NFS superblock. Later when FSTAT is called we will set rest of the
     * nfs_superblock fields.
     */
    {
        std::unique_lock<std::shared_mutex> lock(nfs_inode::get_sb_lock());

        assert(nfs_inode::get_sb().st.f_bsize == 0);
        assert(nfs_inode::get_sb().dtpref == 0);
        nfs_inode::get_sb().st.f_bsize = mnt_options.wsize_adj;
        nfs_inode::get_sb().dtpref = mnt_options.readdir_maxcount_adj;
    }

    /*
     * Also query the attributes for the root fh.
     * XXX: Though libnfs makes getattr call as part of mount but there is no
     *      way for us to fetch those attributes from libnfs, so we need to
     *      query again.
     */
    struct fattr3 fattr;
    const bool ret =
        getattr_sync(*(nfs_get_rootfh(transport.get_nfs_context())),
                     FUSE_ROOT_ID, fattr);

    /*
     * If we fail to successfully issue GETATTR RPC to the root fh,
     * then there's something non-trivially wrong, fail client init.
     */
    if (!ret) {
        AZLogError("First GETATTR to rootfh failed!");
        return false;
    }

    /*
     * Initialiaze the root file handle for this client.
     * This will grab the first reference on the root inode. This will be
     * dropped in nfs_client::shutdown().
     */
    root_fh = get_nfs_inode(nfs_get_rootfh(transport.get_nfs_context()),
                            &fattr,
                            true /* is_root_inode */);
    assert(root_fh->lookupcnt == 1);
    assert(root_fh->dircachecnt == 0);

    root_fh->alloc_dircache();

    // Initialize the RPC task list.
    rpc_task_helper = rpc_task_helper::get_instance(this);

    /*
     * Start the jukebox_runner thread for retrying requests that fail with
     * NFS3ERR_JUKEBOX.
     */
    jukebox_thread = std::thread(&nfs_client::jukebox_runner, this);

    return true;
}

void nfs_client::shutdown()
{
    assert(!shutting_down);
    shutting_down = true;

    /*
     * Shutdown libnfs RPC transport, so that we don't get any new callbacks
     * after we cleanup our data structures below.
     */
    transport.close();
    AZLogInfo("Stopped transport!");

    auto end_delete = inode_map.end();
    for (auto it = inode_map.begin(), next_it = it; it != end_delete; it = next_it) {
        ++next_it;
        struct nfs_inode *inode = it->second;
        assert(inode->magic == NFS_INODE_MAGIC);
        const bool unexpected_refs =
            ((inode->lookupcnt + inode->dircachecnt) == 0);

        if (unexpected_refs) {
            AZLogError("[BUG] [{}:{}] Inode with 0 ref still present in "
                       "inode_map at shutdown: lookupcnt={}, "
                       "dircachecnt={}, forget_expected={}, "
                       "is_cache_empty={}",
                       inode->get_filetype_coding(),
                       inode->get_fuse_ino(),
                       inode->lookupcnt.load(),
                       inode->dircachecnt.load(),
                       inode->forget_expected.load(),
                       inode->is_cache_empty());
        } else {
            AZLogDebug("[{}:{}] Inode still present at shutdown: "
                       "lookupcnt={}, dircachecnt={}, forget_expected={}, "
                       "is_cache_empty={}",
                       inode->get_filetype_coding(),
                       inode->get_fuse_ino(),
                       inode->lookupcnt.load(),
                       inode->dircachecnt.load(),
                       inode->forget_expected.load(),
                       inode->is_cache_empty());
        }
        /*
         * Fuse wants to treat an unmount as an implicit forget for
         * all inodes. Fuse does not gurantee that it will call forget
         * for each inode, hence we have to implicity forget all inodes.
         */
        if (inode->forget_expected) {
            assert(!inode->is_forgotten());

            /*
             * 'next_it' might get removed as a result of decref() of the
             * current inode, if 'it' corresponds to a directory inode and
             * 'next_it' corresponds to a file in that directory and
             * 'next_it' is present in inode_map only because of the
             * dircachecnt held by the readdir cache of the current dir.
             * To prevent next_it from being removed, we hold a lookupcnt
             * ref on next_inode and then drop that ref after the decref()
             * call.
             */
            struct nfs_inode *next_inode = nullptr;

            if (next_it != end_delete) {
                next_inode = next_it->second;
                assert(next_inode->magic == NFS_INODE_MAGIC);
                assert((next_inode->lookupcnt +
                        next_inode->dircachecnt) > 0);
                next_inode->incref();
            }
            inode->decref(inode->forget_expected, true /* from_forget */);
            if (next_inode) {
                /*
                 * If the following decref() is going to cause next_it to
                 * be removed, increment it before that.
                 */
                if (next_inode->lookupcnt == 1 &&
                    next_inode->dircachecnt == 0) {
                    ++next_it;
                }
                next_inode->decref();
            }

            /*
             * root_fh is not valid anymore, clear it now.
             * We do not expect forget_expected to be non-zero for root
             * inode, so we have the assert to confirm.
             * XXX If the assert hits, just remove it.
             */
            if (inode == root_fh) {
                assert(0);
                root_fh = nullptr;
            }
        }
    }

    /*
     * At this point root inode will have just the original reference
     * (acquired in nfs_client::init()), drop it now.
     * This will also purge the readdir cache for the root directory
     * dropping the last dircachecnt ref on all those entries and thus
     * causing those inodes to be deleted.
     */
    if (root_fh) {
        assert(root_fh->lookupcnt == 1);
        root_fh->decref(1, false /* from_forget */);
        root_fh = nullptr;
    }

    /*
     * Now we shouldn't have any left.
     */
    for (auto it : inode_map) {
        struct nfs_inode *inode = it.second;
        AZLogWarn("[BUG] [{}:{}] Inode still present at shutdown: "
                   "lookupcnt={}, dircachecnt={}, forget_expected={}, "
                   "is_cache_empty={}",
                   inode->get_filetype_coding(),
                   inode->get_fuse_ino(),
                   inode->lookupcnt.load(),
                   inode->dircachecnt.load(),
                   inode->forget_expected.load(),
                   inode->is_cache_empty());
    }

    assert(inode_map.size() == 0);

    jukebox_thread.join();
}

void nfs_client::periodic_updater()
{
    // Maximum cache size allowed in bytes.
    static const uint64_t max_cache =
        (aznfsc_cfg.cache.data.user.max_size_mb * 1024 * 1024ULL);
    assert(max_cache != 0);

    /*
     * #1 Calculate recent read/write throughput to the server.
     */
    static std::atomic<time_t> last_sec;
    static std::atomic<uint64_t> last_server_bytes_written;
    static std::atomic<uint64_t> last_server_bytes_read;
    static std::atomic<uint64_t> last_genid;
    const time_t now_sec = ::time(NULL);
    const int sample_intvl = 5;

    assert(GET_GBL_STATS(server_bytes_written) >= last_server_bytes_written);
    assert(GET_GBL_STATS(server_bytes_read) >= last_server_bytes_read);
    assert(now_sec >= last_sec);

    /*
     * Every sample_intvl, compute read/write throughput for the last
     * interval. Only one thread should update the throughput.
     */
    const int intvl = now_sec - last_sec;
    if (intvl >= sample_intvl) {
        uint64_t expected = last_genid.load();
        if (rw_genid.compare_exchange_strong(expected, expected + 1)) {
            w_MBps = (GET_GBL_STATS(server_bytes_written) - last_server_bytes_written) /
                     (intvl * 1000'000);
            r_MBps = (GET_GBL_STATS(server_bytes_read) - last_server_bytes_read) /
                     (intvl * 1000'000);

            last_sec = now_sec;
            last_server_bytes_read = GET_GBL_STATS(server_bytes_read);
            last_server_bytes_written = GET_GBL_STATS(server_bytes_written);
            last_genid = rw_genid.load();
        }
    }

    if (max_cache == 0) {
        return;
    }

    /*
     * #2 Update scaling factor for readahead and flush/commit.
     *    The way we decide optimal values of these scaling factors is by
     *    letting each of these grow to take up more space as soon as its
     *    share of the cache grows and reduce the scaling to take up less
     *    space as its share grows. These competing forces result in both
     *    reaching equilibrium.
     */

    /*
     * cache  => total cache allocated, read + write.
     * wcache => cache allocated by writers.
     * rcache => cache allocated by reades.
     *
     * Note: We use dirty and commit_pending to indicate cache used by writers.
     *       This assumes that cache is released immediately after write or
     *       commit completes, else we will account for write cache as read.
     */
    const uint64_t cache = bytes_chunk_cache::bytes_allocated_g;
    const uint64_t wcache = bytes_chunk_cache::bytes_dirty_g +
                            bytes_chunk_cache::bytes_commit_pending_g;
    const uint64_t rcache = (uint64_t) std::max((int64_t)(cache - wcache), 0L);

    /*
     * Read cache usage as percent of max_cache.
     * This tells how aggressively readers are filling up the cache by
     * readahead. We increase readahead if this is low and reduce readahead
     * as this grows.
     */
    const double pct_rcache = (rcache * 100.0) / max_cache;

    /*
     * Write cache usage as percent of max_cache.
     * This tells how aggressively writees are filling up the cache by adding
     * dirty data. We reduce max_dirty_extent_bytes() if this grows so that
     * dirty data is flushed faster, and increase max_dirty_extent_bytes() if
     * this is low and we want to accumulate more dirty data and flush in bigger
     * chunks, for fast backend write throughput.
     */
    const double pct_wcache = (wcache * 100.0) / max_cache;

    /*
     * Total cache usage (read + write) as percent of max_cache.
     * Reads and writes are controlled individually as per pct_rcache and
     * pct_wcache, but in the end total cache usage is consulted and the
     * read and write scale factors are reduced accordingly.
     */
    const double pct_cache = (cache * 100.0) / max_cache;

    assert(pct_cache <= 100.0);
    assert((pct_rcache + pct_wcache) <= pct_cache);

    double rscale = 1.0;
    double wscale = 1.0;

    /*
     * Stop readahead completely if we are beyond the max cache size, o/w scale
     * it down proportionately to keep the cache size less than max cache limit.
     * We also scale up the readahead to make better utilization of the allowed
     * cache size, when there are fewer reads they are allowed to use more of
     * the cache per user for readahead.
     *
     * Just like read, write also tries to mop up cache space. Those two apply
     * opposing forces finally reaching an equilibrium.
     */
    if (pct_rcache >= 100) {
        /*
         * reads taking up all the cache space, completely stop readaheads.
         * This will cause read cache utilization to drop and then we will
         * increase readaheads, finally it'll settle on an optimal value.
         */
        rscale = 0;
    } else if (pct_rcache > 95) {
        rscale = 0.5;
    } else if (pct_rcache > 90) {
        rscale = 0.7;
    } else if (pct_rcache > 80) {
        rscale = 0.8;
    } else if (pct_rcache > 70) {
        rscale = 0.9;
    } else if (pct_rcache < 3) {
        rscale = 32;
    } else if (pct_rcache < 5) {
        rscale = 24;
    } else if (pct_rcache < 10) {
        rscale = 12;
    } else if (pct_rcache < 20) {
        rscale = 6;
    } else if (pct_rcache < 30) {
        rscale = 4;
    } else if (pct_rcache < 50) {
        rscale = 2.5;
    }

    if (pct_wcache > 95) {
        /*
         * Every file has fundamental right to 100MB of cache space.
         * If we reduce it further we will end up in sub-optimal writes
         * to the server.
         */
        wscale = 1.0/10;
    } else if (pct_wcache > 90) {
        // 200MB
        wscale = 2.0/10;
    } else if (pct_wcache > 80) {
        // 300MB
        wscale = 3.0/10;
    } else if (pct_wcache > 70) {
        // 400MB
        wscale = 4.0/10;
    } else if (pct_wcache > 60) {
        // 600MB
        wscale = 6.0/10;
    } else if (pct_wcache > 50) {
        // 700MB
        wscale = 7.0/10;
    }

    static uint64_t last_log_sec;
    bool log_now = false;

    // Don't log more frequently than 5 secs.
    if ((now_sec - last_log_sec) >= 5) {
        log_now = true;
        last_log_sec = now_sec;
    }

    if (fc_scale_factor != wscale) {
        if (log_now) {
            AZLogInfo("[FC] Scale factor updated ({} -> {}), "
                      "cache util [R: {:0.2f}%, W: {:0.2f}%, T: {:0.2f}%]",
                      fc_scale_factor.load(), wscale,
                      pct_rcache, pct_wcache, pct_cache);
        }
        fc_scale_factor = wscale;
        assert(fc_scale_factor >= 1.0/10);
    }

    if (ra_scale_factor != rscale) {
        if (log_now) {
            AZLogInfo("[RA] Scale factor updated ({} -> {}), "
                      "cache util [R: {:0.2f}%, W: {:0.2f}%, T: {:0.2f}%]",
                      ra_scale_factor.load(), rscale,
                      pct_rcache, pct_wcache, pct_cache);
        }
        ra_scale_factor = rscale;
        assert(ra_scale_factor >= 0);
    }
}

void nfs_client::jukebox_runner()
{
    AZLogDebug("Started jukebox_runner");

    do {
        int jukebox_requests;

        {
            std::unique_lock<std::mutex> lock(jukebox_seeds_lock_39);
            jukebox_requests = jukebox_seeds.size();
        }

        /*
         * If no jukebox queued, wait more else wait less in order to meet the
         * 5 sec jukebox deadline.
         */
        if (jukebox_requests == 0) {
            ::sleep(5);
        } else {
            ::sleep(1);
        }

        {
            std::unique_lock<std::mutex> lock(jukebox_seeds_lock_39);
            jukebox_requests = jukebox_seeds.size();
            if (jukebox_requests == 0) {
                continue;
            }
        }

        AZLogDebug("jukebox_runner woken up ({} requests in queue)",
                   jukebox_requests);

        /*
         * Go over all queued requests and issue those which are ready to be
         * issued, i.e., they have been queued for more than JUKEBOX_DELAY_SECS
         * seconds. We issue the requests after releasing jukebox_seeds_lock_39.
         */
        std::vector<jukebox_seedinfo *> jsv;
        {
            std::unique_lock<std::mutex> lock(jukebox_seeds_lock_39);
            while (!jukebox_seeds.empty()) {
                struct jukebox_seedinfo *js = jukebox_seeds.front();

                if (js->run_at_msecs > get_current_msecs()) {
                    break;
                }

                jukebox_seeds.pop();

                jsv.push_back(js);
            }
        }

        for (struct jukebox_seedinfo *js : jsv) {
            switch (js->rpc_api->optype) {
                case FUSE_LOOKUP:
                    AZLogWarn("[JUKEBOX REISSUE] LOOKUP(req={}, "
                              "parent_ino={}, name={})",
                              fmt::ptr(js->rpc_api->req),
                              js->rpc_api->lookup_task.get_parent_ino(),
                              js->rpc_api->lookup_task.get_file_name());
                    lookup(js->rpc_api->req,
                           js->rpc_api->lookup_task.get_parent_ino(),
                           js->rpc_api->lookup_task.get_file_name());
                    break;
                case FUSE_ACCESS:
                    AZLogWarn("[JUKEBOX REISSUE] ACCESS(req={}, "
                              "ino={}, mask=0{:03o})",
                              fmt::ptr(js->rpc_api->req),
                              js->rpc_api->access_task.get_ino(),
                              js->rpc_api->access_task.get_mask());
                    access(js->rpc_api->req,
                           js->rpc_api->access_task.get_ino(),
                           js->rpc_api->access_task.get_mask());
                    break;
                case FUSE_GETATTR:
                    AZLogWarn("[JUKEBOX REISSUE] GETATTR(req={}, ino={}, "
                              "fi=null)",
                              fmt::ptr(js->rpc_api->req),
                              js->rpc_api->getattr_task.get_ino());
                    getattr(js->rpc_api->req,
                            js->rpc_api->getattr_task.get_ino(),
                            nullptr);
                    break;
                case FUSE_SETATTR:
                    AZLogWarn("[JUKEBOX REISSUE] SETATTR(req={}, ino={}, "
                              "to_set=0x{:x}, fi={})",
                              fmt::ptr(js->rpc_api->req),
                              js->rpc_api->setattr_task.get_ino(),
                              js->rpc_api->setattr_task.get_attr_flags_to_set(),
                              fmt::ptr(js->rpc_api->setattr_task.get_fuse_file()));
                    setattr(js->rpc_api->req,
                            js->rpc_api->setattr_task.get_ino(),
                            js->rpc_api->setattr_task.get_attr(),
                            js->rpc_api->setattr_task.get_attr_flags_to_set(),
                            js->rpc_api->setattr_task.get_fuse_file());
                    break;
                case FUSE_STATFS:
                    AZLogWarn("[JUKEBOX REISSUE] STATFS(req={}, ino={})",
                              fmt::ptr(js->rpc_api->req),
                              js->rpc_api->statfs_task.get_ino());
                    statfs(js->rpc_api->req,
                           js->rpc_api->statfs_task.get_ino());
                    break;
                case FUSE_CREATE:
                    AZLogWarn("[JUKEBOX REISSUE] CREATE(req={}, parent_ino={},"
                              " name={}, mode=0{:03o}, fi={})",
                              fmt::ptr(js->rpc_api->req),
                              js->rpc_api->create_task.get_parent_ino(),
                              js->rpc_api->create_task.get_file_name(),
                              js->rpc_api->create_task.get_mode(),
                              fmt::ptr(js->rpc_api->create_task.get_fuse_file()));
                    create(js->rpc_api->req,
                           js->rpc_api->create_task.get_parent_ino(),
                           js->rpc_api->create_task.get_file_name(),
                           js->rpc_api->create_task.get_mode(),
                           js->rpc_api->create_task.get_fuse_file());
                    break;
                case FUSE_MKNOD:
                    AZLogWarn("[JUKEBOX REISSUE] MKNOD(req={}, parent_ino={},"
                              " name={}, mode=0{:03o})",
                              fmt::ptr(js->rpc_api->req),
                              js->rpc_api->mknod_task.get_parent_ino(),
                              js->rpc_api->mknod_task.get_file_name(),
                              js->rpc_api->mknod_task.get_mode());
                    mknod(js->rpc_api->req,
                           js->rpc_api->mknod_task.get_parent_ino(),
                           js->rpc_api->mknod_task.get_file_name(),
                           js->rpc_api->mknod_task.get_mode());
                    break;
                case FUSE_MKDIR:
                    AZLogWarn("[JUKEBOX REISSUE] MKDIR(req={}, parent_ino={}, "
                              "name={}, mode=0{:03o})",
                              fmt::ptr(js->rpc_api->req),
                              js->rpc_api->mkdir_task.get_parent_ino(),
                              js->rpc_api->mkdir_task.get_dir_name(),
                              js->rpc_api->mkdir_task.get_mode());
                    mkdir(js->rpc_api->req,
                          js->rpc_api->mkdir_task.get_parent_ino(),
                          js->rpc_api->mkdir_task.get_dir_name(),
                          js->rpc_api->mkdir_task.get_mode());
                    break;
                case FUSE_RMDIR:
                    AZLogWarn("[JUKEBOX REISSUE] RMDIR(req={}, parent_ino={}, "
                              "name={})",
                              fmt::ptr(js->rpc_api->req),
                              js->rpc_api->rmdir_task.get_parent_ino(),
                              js->rpc_api->rmdir_task.get_dir_name());
                    rmdir(js->rpc_api->req,
                          js->rpc_api->rmdir_task.get_parent_ino(),
                          js->rpc_api->rmdir_task.get_dir_name());
                    break;
                case FUSE_UNLINK:
                    AZLogWarn("[JUKEBOX REISSUE] UNLINK(req={}, parent_ino={}, "
                              "name={}, for_silly_rename={})",
                              fmt::ptr(js->rpc_api->req),
                              js->rpc_api->unlink_task.get_parent_ino(),
                              js->rpc_api->unlink_task.get_file_name(),
                              js->rpc_api->unlink_task.get_for_silly_rename());
                    unlink(js->rpc_api->req,
                           js->rpc_api->unlink_task.get_parent_ino(),
                           js->rpc_api->unlink_task.get_file_name(),
                           js->rpc_api->unlink_task.get_for_silly_rename());
                    break;
                case FUSE_SYMLINK:
                    AZLogWarn("[JUKEBOX REISSUE] SYMLINK(req={}, link={}, "
                              "parent_ino={}, name={})",
                              fmt::ptr(js->rpc_api->req),
                              js->rpc_api->symlink_task.get_link(),
                              js->rpc_api->symlink_task.get_parent_ino(),
                              js->rpc_api->symlink_task.get_name());
                    symlink(js->rpc_api->req,
                            js->rpc_api->symlink_task.get_link(),
                            js->rpc_api->symlink_task.get_parent_ino(),
                            js->rpc_api->symlink_task.get_name());
                    break;
                case FUSE_READLINK:
                    AZLogWarn("[JUKEBOX REISSUE] READLINK(req={}, ino={})",
                              fmt::ptr(js->rpc_api->req),
                              js->rpc_api->readlink_task.get_ino());
                    readlink(js->rpc_api->req,
                             js->rpc_api->readlink_task.get_ino());
                    break;
                case FUSE_RENAME:
                    AZLogWarn("[JUKEBOX REISSUE] RENAME(req={}, parent_ino={}, "
                              "name={}, newparent_ino={}, newname={}, "
                              "silly_rename={}, silly_rename_ino={}, "
                              "oldparent_ino={}, oldname={})",
                              fmt::ptr(js->rpc_api->req),
                              js->rpc_api->rename_task.get_parent_ino(),
                              js->rpc_api->rename_task.get_name(),
                              js->rpc_api->rename_task.get_newparent_ino(),
                              js->rpc_api->rename_task.get_newname(),
                              js->rpc_api->rename_task.get_silly_rename(),
                              js->rpc_api->rename_task.get_silly_rename_ino(),
                              js->rpc_api->rename_task.get_oldparent_ino(),
                              js->rpc_api->rename_task.get_oldname());
                    rename(js->rpc_api->req,
                           js->rpc_api->rename_task.get_parent_ino(),
                           js->rpc_api->rename_task.get_name(),
                           js->rpc_api->rename_task.get_newparent_ino(),
                           js->rpc_api->rename_task.get_newname(),
                           js->rpc_api->rename_task.get_silly_rename(),
                           js->rpc_api->rename_task.get_silly_rename_ino(),
                           js->rpc_api->rename_task.get_oldparent_ino(),
                           js->rpc_api->rename_task.get_oldname());
                    break;
                case FUSE_READ:
                    AZLogWarn("[JUKEBOX REISSUE] READ(req={}, ino={}, "
                              "size={}, offset={} fi={})",
                              fmt::ptr(js->rpc_api->req),
                              js->rpc_api->read_task.get_ino(),
                              js->rpc_api->read_task.get_size(),
                              js->rpc_api->read_task.get_offset(),
                              fmt::ptr(js->rpc_api->read_task.get_fuse_file()));
                    jukebox_read(js->rpc_api);
                    break;
                case FUSE_READDIR:
                    AZLogWarn("[JUKEBOX REISSUE] READDIR(req={}, ino={}, "
                              "size={}, off={}, fi={})",
                              fmt::ptr(js->rpc_api->req),
                              js->rpc_api->readdir_task.get_ino(),
                              js->rpc_api->readdir_task.get_size(),
                              js->rpc_api->readdir_task.get_offset(),
                              fmt::ptr(js->rpc_api->readdir_task.get_fuse_file()));
                    readdir(js->rpc_api->req,
                            js->rpc_api->readdir_task.get_ino(),
                            js->rpc_api->readdir_task.get_size(),
                            js->rpc_api->readdir_task.get_offset(),
                            js->rpc_api->readdir_task.get_fuse_file());
                    break;
                case FUSE_READDIRPLUS:
                    AZLogWarn("[JUKEBOX REISSUE] READDIRPLUS(req={}, ino={}, "
                              "size={}, off={}, fi={})",
                              fmt::ptr(js->rpc_api->req),
                              js->rpc_api->readdir_task.get_ino(),
                              js->rpc_api->readdir_task.get_size(),
                              js->rpc_api->readdir_task.get_offset(),
                              fmt::ptr(js->rpc_api->readdir_task.get_fuse_file()));
                    readdirplus(js->rpc_api->req,
                                js->rpc_api->readdir_task.get_ino(),
                                js->rpc_api->readdir_task.get_size(),
                                js->rpc_api->readdir_task.get_offset(),
                                js->rpc_api->readdir_task.get_fuse_file());
                    break;
                case FUSE_WRITE:
                    AZLogWarn("[JUKEBOX REISSUE] WRITE(req={}, ino={})",
                              fmt::ptr(js->rpc_api->req),
                              js->rpc_api->write_task.get_ino());
                    jukebox_write(js->rpc_api);
                    break;
                case FUSE_FLUSH:
                    AZLogWarn("[JUKEBOX REISSUE] COMMIT(req={}, ino={})",
                              fmt::ptr(js->rpc_api->req),
                              js->rpc_api->flush_task.get_ino());
                    jukebox_flush(js->rpc_api);
                    break;
                /* TODO: Add other request types */
                default:
                    AZLogError("Unknown jukebox seed type: {}", (int) js->rpc_api->optype);
                    assert(0);
                    break;
            }

            delete js;
        }
    } while (!shutting_down);
}

struct nfs_inode *nfs_client::__inode_from_inode_map(const nfs_fh3 *fh,
                                                     const struct fattr3 *fattr,
                                                     bool acquire_lock,
                                                     bool *is_forgotten)
{
    assert(fh);
    assert(fattr);

#ifndef ENABLE_NON_AZURE_NFS
    // Blob NFS supports only these file types.
    assert((fattr->type == NF3REG) ||
           (fattr->type == NF3DIR) ||
           (fattr->type == NF3LNK));
#endif

    [[maybe_unused]] const uint32_t file_type =
        (fattr->type == NF3DIR) ? S_IFDIR :
         ((fattr->type == NF3LNK) ? S_IFLNK : S_IFREG);

    std::shared_mutex dummy_lock;
    std::shared_lock<std::shared_mutex> lock(
            acquire_lock ? inode_map_lock_0 : dummy_lock);

    /*
     * Search by fileid in the multimap. Since fileid is not guaranteed to be
     * unique, we need to check for FH match in the matched inode(s) list.
     */
    const auto range = inode_map.equal_range(fattr->fileid);

    for (auto i = range.first; i != range.second; ++i) {
        struct nfs_inode *inode = i->second;
        assert(i->first == fattr->fileid);
        assert(inode->magic == NFS_INODE_MAGIC);

        if (!FH_EQUAL(&(inode->get_fh()), fh)) {
            continue;
        }

        // File type must not change for an inode.
        assert(inode->file_type == file_type);

        if (is_forgotten) {
            *is_forgotten = inode->is_forgotten();
        }

        inode->incref();
        return inode;
    }

    return nullptr;
}

/**
 * Given a filehandle and fattr (containing fileid defining a file/dir),
 * get the nfs_inode for that file/dir. It searches in the global list of
 * all inodes and returns from there if found, else creates a new nfs_inode.
 * The returned inode has its refcnt incremented by 1.
 */
struct nfs_inode *nfs_client::__get_nfs_inode(LOC_PARAMS
                                              const nfs_fh3 *fh,
                                              const struct fattr3 *fattr,
                                              bool is_root_inode)
{
    assert(fh);
    assert(fattr);

#ifndef ENABLE_NON_AZURE_NFS
    // Blob NFS supports only these file types.
    assert((fattr->type == NF3REG) ||
           (fattr->type == NF3DIR) ||
           (fattr->type == NF3LNK));
#endif

    const uint32_t file_type = (fattr->type == NF3DIR) ? S_IFDIR :
                                ((fattr->type == NF3LNK) ? S_IFLNK : S_IFREG);

    /*
     * Search in the global inode list first and only if not found, create a
     * new one. This is very important as returning multiple inodes for the
     * same file is recipe for disaster.
     */
    bool is_forgotten = false;
    struct nfs_inode *inode =
        __inode_from_inode_map(fh, fattr, true /* acquire_lock */,
                               &is_forgotten);

    if (inode) {
        std::unique_lock<std::shared_mutex> lock(inode->ilock_1);

        if (is_forgotten) {
            AZLogDebug(LOC_FMT
                       "[{}:{} / 0x{:08x}] Reusing forgotten inode "
                       "(dircachecnt={}), "
                       "size {} -> {}, "
                       "ctime {}.{} -> {}.{}, "
                       "mtime {}.{} -> {}.{}",
                       LOC_ARGS
                       inode->get_filetype_coding(),
                       inode->get_fuse_ino(),
                       inode->get_crc(),
                       inode->dircachecnt.load(),
                       inode->get_attr_nolock().st_size, fattr->size,
                       inode->get_attr_nolock().st_ctim.tv_sec,
                       inode->get_attr_nolock().st_ctim.tv_nsec,
                       fattr->ctime.seconds,
                       fattr->ctime.nseconds,
                       inode->get_attr_nolock().st_mtim.tv_sec,
                       inode->get_attr_nolock().st_mtim.tv_nsec,
                       fattr->mtime.seconds,
                       fattr->mtime.nseconds);
        }

        /*
         * Copy the attributes to the inode as they would be the most
         * recent ones. Also reset the attribute cache timeout.
         * For correctness we update the inode attributes only if they
         * are newer than the cached ones.
         */
        const int fattr_compare =
            compare_timespec_and_nfstime(inode->get_attr_nolock().st_ctim,
                                         fattr->ctime);
        if (fattr_compare < 0) {
            AZLogWarn(LOC_FMT
                      "[{}:{} / 0x{:08x}] Updating inode attr, "
                      "size {} -> {}, "
                      "ctime {}.{} -> {}.{}, "
                      "mtime {}.{} -> {}.{}",
                      LOC_ARGS
                      inode->get_filetype_coding(),
                      inode->get_fuse_ino(),
                      inode->get_crc(),
                      inode->get_attr_nolock().st_size, fattr->size,
                      inode->get_attr_nolock().st_ctim.tv_sec,
                      inode->get_attr_nolock().st_ctim.tv_nsec,
                      fattr->ctime.seconds,
                      fattr->ctime.nseconds,
                      inode->get_attr_nolock().st_mtim.tv_sec,
                      inode->get_attr_nolock().st_mtim.tv_nsec,
                      fattr->mtime.seconds,
                      fattr->mtime.nseconds);

            nfs_client::stat_from_fattr3(inode->get_attr_nolock(), *fattr);

            inode->attr_timeout_secs = inode->get_actimeo_min();
            inode->attr_timeout_timestamp =
                get_current_msecs() + inode->attr_timeout_secs*1000;
        } else if (fattr_compare > 0) {
            AZLogWarn(LOC_FMT
                      "[{}:{} / 0x{:08x}] NOT updating inode attr, "
                      "size {} -> {}, "
                      "ctime {}.{} -> {}.{}, "
                      "mtime {}.{} -> {}.{}",
                      LOC_ARGS
                      inode->get_filetype_coding(),
                      inode->get_fuse_ino(),
                      inode->get_crc(),
                      inode->get_attr_nolock().st_size, fattr->size,
                      inode->get_attr_nolock().st_ctim.tv_sec,
                      inode->get_attr_nolock().st_ctim.tv_nsec,
                      fattr->ctime.seconds,
                      fattr->ctime.nseconds,
                      inode->get_attr_nolock().st_mtim.tv_sec,
                      inode->get_attr_nolock().st_mtim.tv_nsec,
                      fattr->mtime.seconds,
                      fattr->mtime.nseconds);
            /*
             * XXX This assert is seen to fail in following case:
             *     - We update the directory inode's attributes based
             *       on the postop attributes returned in some dirop
             *       request.
             *     - Later we query the actual directory attributes
             *       using a LOOKUP call. This can be less recent that
             *       above due to server attribute cacheing.
             */
#if 0
            assert(0);
#endif
        }

        assert(!inode->is_forgotten());
        return inode;
    }

    struct nfs_inode *new_inode =
        new nfs_inode(fh, fattr, this, file_type,
                      is_root_inode ? FUSE_ROOT_ID : 0);

    {
        std::unique_lock<std::shared_mutex> lock(inode_map_lock_0);

        /*
         * With the exclusive lock held, check once more if some other thread
         * added this inode before we could get the lock. If so, then delete
         * the inode created above, grab a refcnt on the inode created by the
         * other thread and return that.
         */

        struct nfs_inode *inode =
            __inode_from_inode_map(fh, fattr, false /* acquire_lock */);

        AZLogDebug(LOC_FMT
                   "[{}:{} / 0x{:08x}] Allocated new inode (map size: {})",
                   LOC_ARGS
                   new_inode->get_filetype_coding(),
                   new_inode->get_fuse_ino(), new_inode->get_crc(),
                   inode_map.size());

        if (inode) {
            AZLogWarn(LOC_FMT
                      "[{}] Another thread added inode {}, deleting ours",
                      LOC_ARGS
                      new_inode->get_fuse_ino(),
                      inode->get_fuse_ino());

            /*
             * If fattr is newer, update inode attr.
             */
            std::unique_lock<std::shared_mutex> lock1(inode->ilock_1);

            const bool fattr_is_newer =
                (compare_timespec_and_nfstime(inode->get_attr_nolock().st_ctim,
                                              fattr->ctime) == -1);
            if (fattr_is_newer) {
                AZLogWarn(LOC_FMT
                        "[{}:{} / 0x{:08x}] Updating inode attr, "
                        "size {} -> {}, "
                        "ctime {}.{} -> {}.{}, "
                        "mtime {}.{} -> {}.{}",
                        LOC_ARGS
                        inode->get_filetype_coding(),
                        inode->get_fuse_ino(),
                        inode->get_crc(),
                        inode->get_attr_nolock().st_size, fattr->size,
                        inode->get_attr_nolock().st_ctim.tv_sec,
                        inode->get_attr_nolock().st_ctim.tv_nsec,
                        fattr->ctime.seconds,
                        fattr->ctime.nseconds,
                        inode->get_attr_nolock().st_mtim.tv_sec,
                        inode->get_attr_nolock().st_mtim.tv_nsec,
                        fattr->mtime.seconds,
                        fattr->mtime.nseconds);

                nfs_client::stat_from_fattr3(inode->get_attr_nolock(), *fattr);

                inode->attr_timeout_secs = inode->get_actimeo_min();
                inode->attr_timeout_timestamp =
                    get_current_msecs() + inode->attr_timeout_secs*1000;
            }

            delete new_inode;

            return inode;
        }

        /*
         * Common case.
         * Bump lookupcnt ref on the newly allocated inode, add it to the
         * map and return.
         */
#ifdef ENABLE_PARANOID
        min_ino = std::min(min_ino.load(), (fuse_ino_t) new_inode);
        max_ino = std::max(max_ino.load(), (fuse_ino_t) new_inode);
#endif

        new_inode->incref();

        // Ok, insert the newly allocated inode in the global map.
        inode_map.insert({fattr->fileid, new_inode});
    }

    return new_inode;
}

void nfs_client::get_inode_stats(uint64_t& total_inodes,
                                 uint64_t& num_files,
                                 uint64_t& num_dirs,
                                 uint64_t& num_symlinks,
                                 uint64_t& open_files,
                                 uint64_t& open_dirs,
                                 uint64_t& num_files_cache_empty,
                                 uint64_t& num_dirs_cache_empty,
                                 uint64_t& num_forgotten,
                                 uint64_t& expecting_forget,
                                 uint64_t& num_dircached,
                                 uint64_t& num_silly_renamed) const
{
    total_inodes = 0;
    num_files = 0;
    num_dirs = 0;
    num_symlinks = 0;
    open_files = 0;
    open_dirs = 0;
    num_files_cache_empty = 0;
    num_dirs_cache_empty = 0;
    num_forgotten = 0;
    expecting_forget = 0;
    num_dircached = 0;
    num_silly_renamed = 0;

    /*
     * Go over all inodes in inode_map.
     */
    std::shared_lock<std::shared_mutex> _lock(inode_map_lock_0);
    for (auto it = inode_map.cbegin(); it != inode_map.cend(); ++it) {
        const struct nfs_inode *inode = it->second;
        assert(inode->magic == NFS_INODE_MAGIC);

        total_inodes++;

        switch (inode->file_type) {
            case S_IFREG:
                num_files++;
                if (inode->is_open()) {
                    open_files++;
                }
                if (inode->is_cache_empty()) {
                    num_files_cache_empty++;
                }
                break;
            case S_IFDIR:
                num_dirs++;
                if (inode->is_open()) {
                    open_dirs++;
                }
                if (inode->is_cache_empty()) {
                    num_dirs_cache_empty++;
                }
                break;
            case S_IFLNK:
                num_symlinks++;
                break;
        }

        // This inode is cached in one or more readdir caches?
        if (inode->is_dircached()) {
            num_dircached++;
        }

        // Fuse has called forget for this inode?
        if (inode->is_forgotten()) {
            assert(!inode->forget_expected);
            num_forgotten++;
        }

        // Do we expect a forget from fuse for this inode?
        if (inode->forget_expected > 0) {
            assert(!inode->is_forgotten());
            expecting_forget++;
        }

        // Is this inode silly-renamed?
        if (inode->is_silly_renamed) {
            num_silly_renamed++;
        }
    }

    /*
     * Let's perform some sanity checks.
     */
    assert(total_inodes == (num_files + num_dirs + num_symlinks));
}

// Caller must hold inode_map_lock_0.
void nfs_client::put_nfs_inode_nolock(struct nfs_inode *inode,
                                      size_t dropcnt)
{
    AZLogDebug("[{}] put_nfs_inode_nolock(dropcnt={}) called, lookupcnt={}, "
               "dircachecnt={}, forget_expected={}",
               inode->get_fuse_ino(), dropcnt, inode->lookupcnt.load(),
               inode->dircachecnt.load(), inode->forget_expected.load());

    assert(inode->magic == NFS_INODE_MAGIC);
    assert(inode->lookupcnt >= dropcnt);

    /*
     * We have to reduce the lookupcnt by dropcnt regardless of whether we
     * free the inode or not. After dropping the lookupcnt if it becomes 0
     * then we proceed to perform the other checks for deciding whether the
     * inode can be safely removed from inode_map and freed.
     */
    inode->lookupcnt -= dropcnt;

    /*
     * If this inode is referenced by some directory_entry then we cannot free
     * it. We will attempt to free it later when the parent directory is purged
     * and the inode loses its last dircachecnt reference.
     *
     * Note: It's important to first check dircachecnt before lookupcnt, as
     *       users who want to protect nfs_inode using dircachecnt, acquire
     *       dircachecnt before lookupcnt.
     *       Ref readdirectory_cache::dnlc_lookup().
     */
    if (inode->dircachecnt > 0) {
        AZLogVerbose("[{}] Inode is cached by readdir ({})",
                     inode->get_fuse_ino(), inode->dircachecnt.load());
        return;
    }

    /*
     * Caller should call us only for forgotten inodes but it's possible that
     * after we held inode_map_lock_0 some other thread got a reference on
     * this inode.
     */
    if (inode->lookupcnt > 0) {
        AZLogWarn("[{}] Inode no longer forgotten: lookupcnt={}",
                  inode->get_fuse_ino(), inode->lookupcnt.load());
        return;
    }

    /*
     * This inode is going to be freed, either we never conveyed the inode
     * to fuse (we couldn't fit the directory entry in readdirplus buffer
     * or we failed to call fuse_reply_entry(), fuse_reply_create() or
     * fuse_reply_buf()), or fuse called forget for the inode.
     */
    assert(!inode->forget_expected);

    /*
     * Directory inodes cannot be deleted while the directory cache is not
     * purged. Note that we purge directory cache from decref() when the
     * refcnt reaches 0, i.e., fuse is no longer referencing the directory.
     * So, a non-zero directory cache count means that some other thread
     * started enumerating the directory before we could delete the directory
     * inode. Fuse will call FORGET on the directory and then we can free this
     * inode.
     * XXX This should not happen as for enumerating a directory fuse would
     *     have open()ed the directory and must have a lookupcnt ref on the
     *     directory inode.
     */
    if (inode->is_dir() && !inode->is_cache_empty()) {
        AZLogWarn("[{}] Inode still has {} entries in dircache, skipping",
                  inode->get_fuse_ino(),
                  inode->get_dircache()->get_num_entries());
        assert(0);
        return;
    }

    /*
     * Ok, inode is not referenced by fuse VFS and it's not referenced by
     * any readdir cache, let's remove it from the inode_map. Once removed
     * from inode_map, any subsequent get_nfs_inode() calls for this file
     * (fh and fileid) will allocate a new nfs_inode, which will most likely
     * result in a new fuse inode number.
     */
    auto range = inode_map.equal_range(inode->get_fileid());

    for (auto i = range.first; i != range.second; ++i) {
        assert(i->first == inode->get_fileid());
        assert(i->second->magic == NFS_INODE_MAGIC);

        if (i->second == inode) {
            AZLogDebug("[{}:{}] Deleting inode (inode_map size: {})",
                       inode->get_filetype_coding(),
                       inode->get_fuse_ino(),
                       inode_map.size()-1);
            inode_map.erase(i);
            delete inode;
            return;
        }
    }

    // We must find the inode in inode_map.
    assert(0);
}

struct nfs_context* nfs_client::get_nfs_context(conn_sched_t csched,
                                                uint32_t fh_hash) const
{
    return transport.get_nfs_context(csched, fh_hash);
}

void nfs_client::lookup(fuse_req_t req, fuse_ino_t parent_ino, const char* name)
{
    struct rpc_task *tsk = rpc_task_helper->alloc_rpc_task(FUSE_LOOKUP);

    tsk->init_lookup(req, name, parent_ino);
    tsk->run_lookup();

    /*
     * Note: Don't access tsk after this as it may get freed anytime after
     *       the run_lookup() call. This applies to all APIs.
     */
}

static void lookup_sync_callback(
    struct rpc_context *rpc,
    int rpc_status,
    void *data,
    void *private_data)
{
    struct sync_rpc_context *ctx = (struct sync_rpc_context *) private_data;
    assert(ctx->magic == SYNC_RPC_CTX_MAGIC);

    rpc_task *task = ctx->task;
    assert(task->magic == RPC_TASK_MAGIC);
    assert(task->rpc_api->optype == FUSE_LOOKUP);

    fuse_ino_t *child_ino_p = (fuse_ino_t *) task->rpc_api->pvt;
    assert(child_ino_p != nullptr);
    *child_ino_p = 0;

    auto res = (LOOKUP3res *) data;
    const int status = task->status(rpc_status, NFS_STATUS(res));

    /*
     * Convey status to the issuer.
     */
    ctx->rpc_status = rpc_status;
    ctx->nfs_status = NFS_STATUS(res);

    /*
     * Now that the request has completed, we can query libnfs for the
     * dispatch time.
     */
    task->get_stats().on_rpc_complete(rpc_get_pdu(rpc), NFS_STATUSX(rpc_status, res));

    {
        std::unique_lock<std::mutex> lock(ctx->mutex);

        // Must be called only once.
        assert(!ctx->callback_called);
        ctx->callback_called = true;

        if (status == 0) {
            assert(res->LOOKUP3res_u.resok.obj_attributes.attributes_follow);

            const nfs_fh3 *fh = (const nfs_fh3 *) &res->LOOKUP3res_u.resok.object;
            const struct fattr3 *fattr =
                (const struct fattr3 *) &res->LOOKUP3res_u.resok.obj_attributes.post_op_attr_u.attributes;
            const struct nfs_inode *inode = task->get_client()->get_nfs_inode(fh, fattr);
            (*child_ino_p) = inode->get_fuse_ino();
            if (ctx->fattr) {
                *(ctx->fattr) = *fattr;
            }
            AZLogDebug("lookup_sync_callback() got child_ino={}", *child_ino_p);
        } else {
            AZLogDebug("lookup_sync_callback() failed, status={}", status);
        }

        /*
         * Notify inside the lock, since the other thread deletes ctx once
         * done. As soon as we notify the other thread will try to acquire
         * the lock and it may have to block as we have not released the lock
         * yet. Since these sync calls are not frequent, it's ok.
         */
        ctx->cv.notify_one();
    }
}

int nfs_client::lookup_sync(fuse_ino_t parent_ino,
                            const char* name,
                            fuse_ino_t& child_ino)
{
    assert(name != nullptr);

    struct nfs_inode *parent_inode = get_nfs_inode_from_ino(parent_ino);
    const uint32_t fh_hash = parent_inode->get_crc();
    struct nfs_context *nfs_context =
        get_nfs_context(CONN_SCHED_FH_HASH, fh_hash);
    struct rpc_task *task = nullptr;
    struct sync_rpc_context *ctx = nullptr;
    struct rpc_pdu *pdu = nullptr;
    struct rpc_context *rpc = nullptr;
    bool rpc_retry = false;
    int status = -1;

    child_ino = 0;
    AZLogDebug("lookup_sync({}/{})", parent_ino, name);

try_again:
    do {
        LOOKUP3args args;
        args.what.dir = parent_inode->get_fh();
        args.what.name = (char *) name;

        if (task) {
            task->free_rpc_task();
        }

        task = get_rpc_task_helper()->alloc_rpc_task(FUSE_LOOKUP);
        task->init_lookup(nullptr /* fuse_req */, name, parent_ino);
        task->rpc_api->pvt = &child_ino;

        if (ctx) {
            delete ctx;
        }

        ctx = new sync_rpc_context(task, nullptr);
        rpc = nfs_get_rpc_context(nfs_context);
        assert(!ctx->callback_called);

        rpc_retry = false;
        task->get_stats().on_rpc_issue();
        if ((pdu = rpc_nfs3_lookup_task(rpc, lookup_sync_callback,
                                        &args, ctx)) == NULL) {
            task->get_stats().on_rpc_cancel();
            /*
             * This call fails due to internal issues like OOM etc
             * and not due to an actual error, hence retry.
             */
            rpc_retry = true;
        }
    } while (rpc_retry);

    /*
     * If the LOOKUP response doesn't come for 60 secs we give up and send
     * a new one. We must cancel the old one.
     */
    {
        std::unique_lock<std::mutex> lock(ctx->mutex);
wait_more:
        if (!ctx->cv.wait_for(lock, std::chrono::seconds(60),
                              [&ctx] { return (ctx->callback_called == true); })) {
            if (rpc_cancel_pdu(rpc, pdu) == 0) {
                task->get_stats().on_rpc_cancel();
                AZLogWarn("Timed out waiting for lookup response, re-issuing "
                          "lookup!");
                // This goto will cause the above lock to unlock.
                goto try_again;
            } else {
                /*
                 * If rpc_cancel_pdu() fails it most likely means we got the RPC
                 * response right after we timed out waiting. It's best to wait
                 * for the callback to be called.
                 */
                AZLogWarn("Timed out waiting for lookup response, couldn't "
                          "cancel existing pdu, waiting some more!");
                // This goto will *not* cause the above lock to unlock.
                goto wait_more;
            }
        } else {
            assert(ctx->callback_called);
            assert(ctx->rpc_status != -1);
            assert(ctx->nfs_status != -1);

            status = task->status(ctx->rpc_status, ctx->nfs_status);
            if (status == 0) {
                assert(child_ino != 0);
            } else if (ctx->rpc_status == RPC_STATUS_SUCCESS &&
                       ctx->nfs_status == NFS3ERR_JUKEBOX) {
                AZLogInfo("Got NFS3ERR_JUKEBOX for LOOKUP, re-issuing "
                          "after 1 sec!");
                ::usleep(1000 * 1000);
                // This goto will cause the above lock to unlock.
                goto try_again;
            } else {
                AZLogDebug("lookup_sync({}/{}) failed, status={}, "
                           "rpc_status={}, nfs_status={}",
                           parent_ino, name, status, ctx->rpc_status,
                           ctx->nfs_status);
                assert(child_ino == 0);
            }
        }
    }

    if (task) {
        task->free_rpc_task();
    }

    delete ctx;

    assert(status >= 0);
    return status;
}

void nfs_client::access(fuse_req_t req, fuse_ino_t ino, int mask)
{
    struct rpc_task *tsk = rpc_task_helper->alloc_rpc_task(FUSE_ACCESS);

    tsk->init_access(req, ino, mask);
    tsk->run_access();
}

void nfs_client::flush(fuse_req_t req, fuse_ino_t ino)
{
    struct rpc_task *tsk = rpc_task_helper->alloc_rpc_task(FUSE_FLUSH);

    tsk->init_flush(req, ino);
    tsk->run_flush();
}

void nfs_client::write(fuse_req_t req, fuse_ino_t ino, struct fuse_bufvec *bufv, size_t size, off_t off)
{
    struct rpc_task *tsk = rpc_task_helper->alloc_rpc_task(FUSE_WRITE);

    tsk->init_write_fe(req, ino, bufv, size, off);
    tsk->run_write();
}

void nfs_client::getattr(
    fuse_req_t req,
    fuse_ino_t ino,
    struct fuse_file_info *file)
{
    struct nfs_inode *inode = get_nfs_inode_from_ino(ino);

    /*
     * This is to satisfy a POSIX requirement which expects utime/stat to
     * return updated attributes after sync'ing any pending writes.
     * If there is lot of dirty data cached this might take very long, as
     * it'll wait for the entire data to be written and acknowledged by the
     * NFS server.
     *
     * TODO: If it turns out to cause bad user experience, we can explore
     *       updating nfs_inode::attr during cached writes and then returning
     *       attributes from that instead of making a getattr call here.
     *       We need to think carefully though.
     */
    if (inode->is_regfile()) {
        AZLogDebug("[{}] Flushing file data ahead of getattr",
                   inode->get_fuse_ino());
        inode->flush_cache_and_wait();
    }

    struct rpc_task *tsk = rpc_task_helper->alloc_rpc_task(FUSE_GETATTR);

    tsk->init_getattr(req, ino);
    tsk->run_getattr();
}

void nfs_client::statfs(
    fuse_req_t req,
    fuse_ino_t ino)
{
    struct rpc_task *tsk = rpc_task_helper->alloc_rpc_task(FUSE_STATFS);

    tsk->init_statfs(req, ino);
    tsk->run_statfs();
}

void nfs_client::create(
    fuse_req_t req,
    fuse_ino_t parent_ino,
    const char* name,
    mode_t mode,
    struct fuse_file_info* file)
{
    struct rpc_task *tsk = rpc_task_helper->alloc_rpc_task(FUSE_CREATE);

    tsk->init_create_file(req, parent_ino, name, mode, file);
    tsk->run_create_file();
}

void nfs_client::mknod(
    fuse_req_t req,
    fuse_ino_t parent_ino,
    const char* name,
    mode_t mode)
{
    struct rpc_task *tsk = rpc_task_helper->alloc_rpc_task(FUSE_MKNOD);

    tsk->init_mknod(req, parent_ino, name, mode);
    tsk->run_mknod();
}

void nfs_client::mkdir(
    fuse_req_t req,
    fuse_ino_t parent_ino,
    const char* name,
    mode_t mode)
{
    struct rpc_task *tsk = rpc_task_helper->alloc_rpc_task(FUSE_MKDIR);

    tsk->init_mkdir(req, parent_ino, name, mode);
    tsk->run_mkdir();
}

/*
 * Returns:
 *  true  - silly rename was needed and done.
 *  false - silly rename not needed.
 */
bool nfs_client::silly_rename(
    fuse_req_t req,
    fuse_ino_t parent_ino,
    const char *name,
    fuse_ino_t oldparent_ino,
    const char *old_name)
{
    struct nfs_inode *parent_inode = get_nfs_inode_from_ino(parent_ino);
    // Inode of the file being silly renamed.
    int lookup_status = -1;
    struct nfs_inode *inode = parent_inode->lookup(name, &lookup_status);
    /*
     * Is this silly rename called to silly rename an outgoing file in a
     * rename workflow as opposed to silly renaming a to-be-unlinked file.
     */
    [[maybe_unused]]
    const bool rename_triggered_silly_rename = (old_name != nullptr);
    assert(rename_triggered_silly_rename == (oldparent_ino != 0));

    /*
     * This is called from aznfsc_ll_unlink() for all unlinked files,
     * or from aznfsc_ll_rename() for the destination file, so
     * this is a good place to remove the entry from DNLC.
     */
    if (parent_inode->has_dircache()) {
        parent_inode->get_dircache()->dnlc_remove(name);
    }

    if (inode && inode->is_dir()) {
        /*
         * inode cannot refer to a directory when silly_rename() is called
         * from unlink.
         * If it is called from rename and inode does refer to a directory
         * we don't need to silly rename as only empty directories can be
         * the target of rename.
         */
        assert(rename_triggered_silly_rename);

        /*
         * Since the inode is getting deleted, invalidate the attribute
         * cache.
         */
        inode->invalidate_attribute_cache();

        return false;
    }

    /*
     * Note: VFS will hold the inode lock for the target file, so it won't
     *       go away till the rename_callback() is called (and we respond to
     *       fuse).
     */
    if (inode && inode->is_open()) {
        char newname[64];
        ::snprintf(newname, sizeof(newname), ".nfs_%lu_%lu_%d",
                   inode->get_fuse_ino(), inode->get_generation(),
                   inode->get_silly_rename_level());

        AZLogInfo("silly_rename: Renaming {}/{} -> {}, ino={}"
                  "rename_triggered_silly_rename={}, opencnt={}",
                  parent_ino, name, newname, inode->get_fuse_ino(),
                  rename_triggered_silly_rename,
                  inode->opencnt.load());

        /*
         * Now that we have decided to proceed with the silly rename, we need
         * to ensure that inode->release() does delete the silly renamed file
         * when the last opencnt is dropped. If application drops the last
         * opencnt after the is_open() call above and before we set
         * inode->is_silly_renamed in the rename_callback(), then we will not
         * get a chance to delete the silly renamed file, hence we increment
         * the opencnt here and drop it in rename_callback(). If application
         * had dropped its opencnt, this release will delete the silly renamed
         * file.
         */
        inode->opencnt++;

        rename(req, parent_ino, name, parent_ino, newname,
               true /* silly_rename */, inode->get_fuse_ino(),
               oldparent_ino, old_name);

        return true;
    } else if (!inode) {
        assert(lookup_status > 0);
        if (lookup_status != ENOENT) {
            AZLogError("silly_rename: Failed to get inode for file {}/{} "
                       "(error: {}). File will be deleted at the server, any "
                       "process having file open will get stale filehandle "
                       "errors when accessing it!",
                       parent_ino, name, lookup_status);
        } else {
            /*
             * For unlink() if file doesn't exist fuse won't call
             * aznfsc_ll_unlink() hence silly_rename() will never be called
             * for cases where file doesn't exist.
             * For rename() this is a likely case and hence we should not
             * log an error.
             */
            assert(rename_triggered_silly_rename);
        }
    } else {
        /*
         * Since the inode is getting deleted, invalidate the attribute
         * cache.
         */
        inode->invalidate_attribute_cache();
    }

    return false;
}

void nfs_client::unlink(
    fuse_req_t req,
    fuse_ino_t parent_ino,
    const char* name,
    bool for_silly_rename)
{
    struct rpc_task *tsk = rpc_task_helper->alloc_rpc_task(FUSE_UNLINK);

    tsk->init_unlink(req, parent_ino, name, for_silly_rename);
    tsk->run_unlink();
}

void nfs_client::rmdir(
    fuse_req_t req,
    fuse_ino_t parent_ino,
    const char* name)
{
    struct rpc_task *tsk = rpc_task_helper->alloc_rpc_task(FUSE_RMDIR);
    struct nfs_inode *parent_inode = get_nfs_inode_from_ino(parent_ino);
    struct nfs_inode *inode = parent_inode->lookup(name);

    if (parent_inode->has_dircache()) {
        parent_inode->get_dircache()->dnlc_remove(name);
    }

    if (inode) {
        // Since we are removing the directory, invalidate its attribute cache.
        inode->invalidate_attribute_cache();
    }

    tsk->init_rmdir(req, parent_ino, name);
    tsk->run_rmdir();
}

void nfs_client::symlink(
    fuse_req_t req,
    const char* link,
    fuse_ino_t parent_ino,
    const char* name)
{
    struct rpc_task *tsk = rpc_task_helper->alloc_rpc_task(FUSE_SYMLINK);

    tsk->init_symlink(req, link, parent_ino, name);
    tsk->run_symlink();
}

/**
 * This is the nfs_client method to rename a file from its current name
 * (dirX/nameA) to its new name (dirY/nameB), where dirX and dirY can be
 * referring to same or different directories. dirY/nameB may refer to an
 * existing file or it could be a new file.
 */
void nfs_client::rename(
    fuse_req_t req,
    fuse_ino_t parent_ino,
    const char *name,
    fuse_ino_t newparent_ino,
    const char *new_name,
    bool silly_rename,
    fuse_ino_t silly_rename_ino,
    fuse_ino_t oldparent_ino,
    const char *old_name)
{
    struct rpc_task *tsk = rpc_task_helper->alloc_rpc_task(FUSE_RENAME);
    struct nfs_inode *parent_inode = get_nfs_inode_from_ino(parent_ino);
    struct nfs_inode *newparent_inode = get_nfs_inode_from_ino(newparent_ino);
    [[maybe_unused]]
    const bool rename_triggered_silly_rename = (old_name != nullptr);
    assert(rename_triggered_silly_rename == (oldparent_ino != 0));
    assert(!rename_triggered_silly_rename || silly_rename);

    /*
     * 'name' is going away and 'new_name', if exists, will no longer refer to
     * the same inode, remove both from dnlc cache.
     * Note that rename_callback() does check the postop attributes of both
     * source and target directories and purges their dir caches if the postop
     * attribute suggests change in mtime/size, but it's safe to remove it here
     * just in case the server doesn't return postop attributes or returns them
     * incorrectly.
     */
    if (parent_inode->has_dircache()) {
        parent_inode->get_dircache()->dnlc_remove(name);
    }

    if (newparent_inode->has_dircache()) {
        newparent_inode->get_dircache()->dnlc_remove(new_name);
    }

    tsk->init_rename(req, parent_ino, name, newparent_ino, new_name,
                     silly_rename, silly_rename_ino, oldparent_ino, old_name);
    tsk->run_rename();
}

void nfs_client::readlink(
    fuse_req_t req,
    fuse_ino_t ino)
{
    struct rpc_task *tsk = rpc_task_helper->alloc_rpc_task(FUSE_READLINK);

    tsk->init_readlink(req, ino);
    tsk->run_readlink();
}

void nfs_client::setattr(
    fuse_req_t req,
    fuse_ino_t ino,
    const struct stat* attr,
    int to_set,
    struct fuse_file_info* file)
{
    struct nfs_inode *inode = get_nfs_inode_from_ino(ino);

    /*
     * See similar comment in nfs_client::getattr().
     *
     * Note that fuse expects setattr() to return the updated attributes and
     * it can then use those as fresh file attributes, so we have to do the
     * flush-before-getattr logic even for the setattr call, else we may
     * end up returning stale attributes for the case where file has lot of
     * dirty data waiting to be flushed.
     *
     * TODO: Optimization for truncate case.
     */
    if (inode->is_regfile()) {
        AZLogDebug("[{}] Flushing file data ahead of setattr",
                   inode->get_fuse_ino());
        inode->flush_cache_and_wait();
    }

    struct rpc_task *tsk = rpc_task_helper->alloc_rpc_task(FUSE_SETATTR);

    tsk->init_setattr(req, ino, attr, to_set, file);
    tsk->run_setattr();
}

/*
 * This can be called in parallel for the same directory, if multiple threads
 * are enumerating the directory.
 */
void nfs_client::readdir(
    fuse_req_t req,
    fuse_ino_t ino,
    size_t size,
    off_t offset,
    struct fuse_file_info* file)
{
    readdirectory_cache::num_readdir_calls_g++;

    struct rpc_task *tsk = rpc_task_helper->alloc_rpc_task(FUSE_READDIR);
    struct nfs_inode *inode = get_nfs_inode_from_ino(ino);

    // Force revalidate for offset==0 to ensure cto consistency.
    inode->revalidate(offset == 0);

    tsk->init_readdir(req, ino, size, offset, 0 /* target_offset */, file);
    tsk->run_readdir();
}

void nfs_client::readdirplus(
    fuse_req_t req,
    fuse_ino_t ino,
    size_t size,
    off_t offset,
    struct fuse_file_info* file)
{
    readdirectory_cache::num_readdirplus_calls_g++;

    struct rpc_task *tsk = rpc_task_helper->alloc_rpc_task(FUSE_READDIRPLUS);
    struct nfs_inode *inode = get_nfs_inode_from_ino(ino);

    // Force revalidate for offset==0 to ensure cto consistency.
    inode->revalidate(offset == 0);

    tsk->init_readdirplus(req, ino, size, offset, 0 /* target_offset */, file);
    tsk->run_readdirplus();
}

void nfs_client::read(
    fuse_req_t req,
    fuse_ino_t ino,
    size_t size,
    off_t off,
    struct fuse_file_info *fi)
{
    struct rpc_task *tsk = rpc_task_helper->alloc_rpc_task(FUSE_READ);
    struct nfs_inode *inode = get_nfs_inode_from_ino(ino);

    /*
     * aznfsc_ll_read() can only be called after aznfsc_ll_open() so filecache
     * and readahead state must have been allocated when we reach here.
     */
    assert(inode->has_filecache());
    assert(inode->has_rastate());

    /*
     * Fuse doesn't let us decide the max file size supported, so kernel can
     * technically send us a request for an offset larger than we support.
     * Adjust size to not read beyond the max file size supported.
     * Note that we can pass it down to the Blob NFS server and it'll correctly
     * handle it, but we have many useful asserts, avoid those.
     */
    if ((off + size) > AZNFSC_MAX_FILE_SIZE) {
        const size_t adj_size =
            std::max((off_t) AZNFSC_MAX_FILE_SIZE - off, (off_t) 0);
        if (adj_size == 0) {
            AZLogWarn("[{}] Read beyond maximum file size suported ({}), "
                      "offset={}, size={}, adj_size={}",
                      ino, AZNFSC_MAX_FILE_SIZE, off, size, adj_size);
        }

        size = adj_size;
    }

    // Revalidate if attribute cache timeout expired.
    inode->revalidate();

    tsk->init_read_fe(req, ino, size, off, fi);

    if (size == 0) {
        INC_GBL_STATS(zero_reads, 1);
        tsk->reply_iov(nullptr, 0);
        return;
    }

    /*
     * Issue readaheads (if any) before application read.
     * Note that application read can block on membuf lock while readahead
     * read skips locked membufs. This way we can have readahead reads sent
     * to the server even while application read causes us to block.
     */
    [[maybe_unused]] const int num_ra =
        inode->get_rastate()->issue_readaheads();

    AZLogDebug("[{}] {} readaheads issued for client read offset: {} size: {}",
               ino, num_ra, off, size);

    tsk->run_read();
}

/*
 * This function will be called only to retry the commit requests that failed
 * with JUKEBOX error.
 * rpc_api defines the RPC request that need to be retried.
 */
void nfs_client::jukebox_flush(struct api_task_info *rpc_api)
{
    /*
     * For commit task pvt has bc_vec, which has copy of byte_chunk vector.
     * To proceed it should be valid.
     *
     * Note: Commit task is always a backend task, 'req' is nullptr.
     */
    assert(rpc_api->pvt != nullptr);
    assert(rpc_api->optype == FUSE_FLUSH);
    assert(rpc_api->req == nullptr);

    /*
     * Create a new FUSE_FLUSH task to retry the commit request.
     */
    struct rpc_task *commit_task =
        get_rpc_task_helper()->alloc_rpc_task(FUSE_FLUSH);
    commit_task->init_flush(nullptr /* fuse_req */,
                            rpc_api->flush_task.get_ino());
    commit_task->rpc_api->pvt = rpc_api->pvt;
    rpc_api->pvt = nullptr;

    // Any new task should start fresh as a parent task.
    assert(commit_task->rpc_api->parent_task == nullptr);

    commit_task->issue_commit_rpc();
}

/*
 * This function will be called only to retry the write requests that failed
 * with JUKEBOX error.
 * rpc_api defines the RPC request that need to be retried.
 */
void nfs_client::jukebox_write(struct api_task_info *rpc_api)
{
    // Only BE tasks can be retried.
    assert(rpc_api->write_task.is_be());

    /*
     * For write task pvt has write_iov_context, which has copy of byte_chunk vector.
     * To proceed it should be valid.
     */
    assert(rpc_api->pvt != nullptr);
    assert(rpc_api->optype == FUSE_WRITE);

    struct rpc_task *write_task =
        get_rpc_task_helper()->alloc_rpc_task(FUSE_WRITE);
    write_task->init_write_be(rpc_api->write_task.get_ino());

    // Any new task should start fresh as a parent task.
    assert(write_task->rpc_api->parent_task == nullptr);

    [[maybe_unused]] struct bc_iovec *bciov = (struct bc_iovec *) rpc_api->pvt;
    assert(bciov->magic == BC_IOVEC_MAGIC);

    // TODO: Make this a unique_ptr?
    write_task->rpc_api->pvt = rpc_api->pvt;
    rpc_api->pvt = nullptr;

#if 0
    /*
     * We currently only support buffered writes where the original fuse write
     * task completes after copying data to the bytes_chunk_cache and later
     * we sync the dirty membuf using one or more flush rpc_tasks whose sole
     * job is to ensure they sync the part of the blob they are assigned.
     * They don't need a parent_task which is usually the fuse task that needs
     * to be completed once the underlying tasks complete.
     *
     * Note: This is no longer true, see parent_task argument to sync_membufs().
     */
    assert(rpc_api->parent_task == nullptr);
#endif

    /*
     * If the write task that failed with jukebox is a child of a fuse write
     * task, then we have to complete the parent write task when the child
     * and all children complete. We need to set the parent_task of the retried
     * task too.
     */
    if (rpc_api->parent_task != nullptr) {
        assert(rpc_api->parent_task->magic == RPC_TASK_MAGIC);
        assert(rpc_api->parent_task->get_op_type() == FUSE_WRITE);
        assert(rpc_api->parent_task->rpc_api->write_task.is_fe());
        // At least this child task has not completed.
        assert(rpc_api->parent_task->num_ongoing_backend_writes > 0);

        write_task->rpc_api->parent_task = rpc_api->parent_task;
    }

    write_task->issue_write_rpc();
}

/*
 * This function will be called only to retry the read requests that failed
 * with JUKEBOX error.
 * rpc_api defines the RPC request that need to be retried.
 */
void nfs_client::jukebox_read(struct api_task_info *rpc_api)
{
    assert(rpc_api->optype == FUSE_READ);

    struct rpc_task *child_tsk =
        get_rpc_task_helper()->alloc_rpc_task(FUSE_READ);

    child_tsk->init_read_be(
        rpc_api->read_task.get_ino(),
        rpc_api->read_task.get_size(),
        rpc_api->read_task.get_offset());

    /*
     * Read API calls will be issued only for BE tasks, hence
     * copy the parent info from the original task to this retry task.
     */
    assert(rpc_api->parent_task != nullptr);
    assert(rpc_api->parent_task->magic == RPC_TASK_MAGIC);
    assert(rpc_api->parent_task->rpc_api->read_task.is_fe());
    // At least this child task has not completed.
    assert(rpc_api->parent_task->num_ongoing_backend_reads > 0);

    child_tsk->rpc_api->parent_task = rpc_api->parent_task;

    [[maybe_unused]]  const struct rpc_task *const parent_task =
        child_tsk->rpc_api->parent_task;

    /*
     * Since we are retrying this child task, the parent read task should have
     * atleast 1 ongoing read.
     */
    assert(parent_task->num_ongoing_backend_reads > 0);

    /*
     * Child task should always read a subset of the parent task.
     */
    assert(child_tsk->rpc_api->read_task.get_offset() >=
            parent_task->rpc_api->read_task.get_offset());
    assert(child_tsk->rpc_api->read_task.get_size() <=
            parent_task->rpc_api->read_task.get_size());

    assert(rpc_api->bc != nullptr);

    // Jukebox retry is for an existing request issued to the backend.
    assert(rpc_api->bc->num_backend_calls_issued > 0);

#ifdef ENABLE_PARANOID
    {
        unsigned int i;
        for (i = 0; i < parent_task->bc_vec.size(); i++) {
            if (rpc_api->bc == &parent_task->bc_vec[i])
                break;
        }

        /*
         * rpc_api->bc MUST refer to one of the elements in
         * parent_task->bc_vec.
         */
        assert(i != parent_task->bc_vec.size());
    }
#endif

    /*
     * The jukebox retry task also should read into the same bc.
     */
    child_tsk->rpc_api->bc = rpc_api->bc;

    /*
     * The bytes_chunk held by this task must have its inuse count
     * bumped as the get() call made to obtain this chunk initially would
     * have set it.
     */
    assert(rpc_api->bc->get_membuf()->is_inuse());

    // Issue the read to the server
    child_tsk->read_from_server(*(rpc_api->bc));
}

/*
 * Creates a new inode for the given fh and passes it to fuse layer.
 * This will be called by the APIs which must return a filehandle back to the
 * client like lookup, create etc.
 */
void nfs_client::reply_entry(
    struct rpc_task *task,
    const nfs_fh3 *fh,
    const struct fattr3 *fattr,
    const struct fuse_file_info *file)
{
    assert(task->magic == RPC_TASK_MAGIC);

    enum fuse_opcode optype = task->get_op_type();
    struct nfs_inode *inode = nullptr;
    fuse_entry_param entry;
    /*
     * Kernel must cache lookup result.
     */
    const bool cache_positive =
        (aznfsc_cfg.lookupcache_int == AZNFSCFG_LOOKUPCACHE_ALL ||
         aznfsc_cfg.lookupcache_int == AZNFSCFG_LOOKUPCACHE_POS);

    memset(&entry, 0, sizeof(entry));

    if (fh) {
        const fuse_ino_t parent_ino = task->rpc_api->get_parent_ino();
        struct nfs_inode *parent_inode = get_nfs_inode_from_ino(parent_ino);
        /*
         * This will grab a lookupcnt ref on the inode, which will be freed
         * from fuse forget callback.
         */
        inode = get_nfs_inode(fh, fattr);

        entry.ino = inode->get_fuse_ino();
        entry.generation = inode->get_generation();
        /*
         * This takes shared lock on inode->ilock_1.
         */
        entry.attr = inode->get_attr();
        if (cache_positive) {
            entry.attr_timeout = inode->get_actimeo();
            entry.entry_timeout = inode->get_actimeo();
        } else {
            entry.attr_timeout = 0;
            entry.entry_timeout = 0;
        }

        /*
         * If it's a proxy task, optype of the original task should be used.
         * Currently we use proxy task only for LOOKUP, so assert for that.
         */
        if (task->get_proxy_op_type() != (fuse_opcode) 0) {
            AZLogDebug("Completing proxy task {} -> {}",
                       rpc_task::fuse_opcode_to_string(optype),
                       rpc_task::fuse_opcode_to_string(
                           task->get_proxy_op_type()));

            assert(optype == FUSE_LOOKUP);
            optype = task->get_proxy_op_type();
            // LOOKUP cannot be proxying a LOOKUP.
            assert(optype != FUSE_LOOKUP);
        }

        /*
         * Note: reply_create()/reply_entry() below will increment
         *       forget_expected just before replying to fuse, so we log the
         *       updated count here.
         */
        AZLogDebug("[{}] <{}> Returning ino {} to fuse (filename: {}, "
                   "lookupcnt: {}, dircachecnt: {}, forget_expected: {})",
                   parent_ino,
                   rpc_task::fuse_opcode_to_string(optype),
                   inode->get_fuse_ino(),
                   task->rpc_api->get_file_name(),
                   inode->lookupcnt.load(),
                   inode->dircachecnt.load(),
                   inode->forget_expected.load() + 1);

        /*
         * This is the common place where we return inode to fuse.
         * After this fuse can call any of the functions that might need file
         * or dir cache, so allocate them now.
         */
        switch (optype) {
            case FUSE_CREATE:
                assert(file);
                inode->on_fuse_open(optype);
                break;
            case FUSE_LOOKUP:
            case FUSE_MKNOD:
            case FUSE_MKDIR:
            case FUSE_SYMLINK:
                assert(!file);
                inode->on_fuse_lookup(optype);
                break;
            default:
                AZLogError("[{}] Invalid optype: {}",
                           inode->get_fuse_ino(), (int) optype);
                assert(0);
        }

        /*
         * Add lookup results to DNLC cache.
         */
        parent_inode->dnlc_add(task->rpc_api->get_file_name(), inode);
    } else {
        /*
         * The only valid case where reply_entry() is called with null fh
         * is the case where lookup yielded "not found". We are using the
         * fuse support for negative dentry where we should respond with
         * success but ino set to 0 to convey to fuse that it must cache
         * the negative dentry for entry_timeout period.
         * This caching helps to improve performance by avoiding repeated
         * lookup requests for entries that are known not to exist.
         *
         * TODO: See if negative entries must be cached for lesser time.
         */
        assert(aznfsc_cfg.lookupcache_int == AZNFSCFG_LOOKUPCACHE_ALL);
        assert(!fattr);

        entry.attr_timeout = aznfsc_cfg.actimeo;
        entry.entry_timeout = aznfsc_cfg.actimeo;
    }

    if (file) {
        task->reply_create(&entry, file);
    } else {
        task->reply_entry(&entry);
    }
}

void nfs_client::jukebox_retry(struct rpc_task *task)
{
    {
        AZLogDebug("Queueing rpc_task {} for jukebox retry", fmt::ptr(task));

        /*
         * Transfer ownership of rpc_api from rpc_task to jukebox_seedinfo.
         */
        std::unique_lock<std::mutex> lock(jukebox_seeds_lock_39);
        jukebox_seeds.emplace(new jukebox_seedinfo(task->rpc_api));

        task->rpc_api = nullptr;
    }

    /*
     * Free the current task that failed with JUKEBOX error.
     * The retried task will use a new rpc_task structure (and new XID).
     * Note that we don't callback into fuse as yet.
     */
    task->free_rpc_task();
}

// Translate a NFS fattr3 into struct stat.
/* static */
void nfs_client::stat_from_fattr3(struct stat& st, const struct fattr3& fattr)
{
    /*
     * We should never be called with older fattr.
     */
    [[maybe_unused]] const bool fattr_is_newer =
        (compare_timespec_and_nfstime(st.st_ctim, fattr.ctime) == -1);
    assert(fattr_is_newer);

    // TODO: Remove this memset if we are setting all fields.
    ::memset(&st, 0, sizeof(st));

    st.st_dev = fattr.fsid;
    st.st_ino = fattr.fileid;
    st.st_mode = fattr.mode;
    st.st_nlink = fattr.nlink;
    st.st_uid = fattr.uid;
    st.st_gid = fattr.gid;
    // TODO: Uncomment the below line.
    // st.st_rdev = makedev(fattr.rdev.specdata1, fattr.rdev.specdata2);
    st.st_size = fattr.size;
    if (fattr.type == NF3DIR) {
        st.st_blksize = nfs_inode::get_sb().get_dtpref();
    } else {
        st.st_blksize = nfs_inode::get_sb().get_blocksize();
    }
    st.st_blocks = (fattr.used + 511) >> 9;
    st.st_atim.tv_sec = fattr.atime.seconds;
    st.st_atim.tv_nsec = fattr.atime.nseconds;
    st.st_mtim.tv_sec = fattr.mtime.seconds;
    st.st_mtim.tv_nsec = fattr.mtime.nseconds;
    st.st_ctim.tv_sec = fattr.ctime.seconds;
    st.st_ctim.tv_nsec = fattr.ctime.nseconds;

    switch (fattr.type) {
        case NF3REG:
            st.st_mode |= S_IFREG;
            break;
        case NF3DIR:
            st.st_mode |= S_IFDIR;
            break;
        case NF3BLK:
            st.st_mode |= S_IFBLK;
            break;
        case NF3CHR:
            st.st_mode |= S_IFCHR;
            break;
        case NF3LNK:
            st.st_mode |= S_IFLNK;
            break;
        case NF3SOCK:
            st.st_mode |= S_IFSOCK;
            break;
        case NF3FIFO:
            st.st_mode |= S_IFIFO;
            break;
        default:
            assert(0);
    }
}

// Translate struct stat into NFS fattr3.
/* static */
void nfs_client::fattr3_from_stat(struct fattr3& fattr, const struct stat& st)
{
    // TODO: Remove this memset if we are setting all fields.
    ::memset(&fattr, 0, sizeof(fattr));

    fattr.fsid = st.st_dev;
    fattr.fileid = st.st_ino;
    fattr.mode = st.st_mode;
    fattr.nlink = st.st_nlink;
    fattr.uid = st.st_uid;
    fattr.gid = st.st_gid;

    // TODO: set rdev.

    fattr.size = st.st_size;
    fattr.used = st.st_blocks * 512;

    fattr.atime.seconds = st.st_atim.tv_sec;
    fattr.atime.nseconds = st.st_atim.tv_nsec;
    fattr.mtime.seconds = st.st_mtim.tv_sec;
    fattr.mtime.nseconds = st.st_mtim.tv_nsec;
    fattr.ctime.seconds = st.st_ctim.tv_sec;
    fattr.ctime.nseconds = st.st_ctim.tv_nsec;

    if (S_ISREG(st.st_mode))
        fattr.type = NF3REG;
    else if (S_ISDIR(st.st_mode))
        fattr.type = NF3DIR;
    else if (S_ISLNK(st.st_mode))
        fattr.type = NF3LNK;
    else if (S_ISBLK(st.st_mode))
        fattr.type = NF3BLK;
    else if (S_ISCHR(st.st_mode))
        fattr.type = NF3CHR;
    else if (S_ISSOCK(st.st_mode))
        fattr.type = NF3SOCK;
    else if (S_ISFIFO(st.st_mode))
        fattr.type = NF3FIFO;
    else {
        /*
         * XXX This has been seen to randomly fail for regular files.
         *     Add instrumentation to understand better.
         */
        AZLogError("st.st_mode={} S_ISREG(st.st_mode)={} S_IFREG={}",
                   st.st_mode, S_ISREG(st.st_mode), S_IFREG);
        assert(0);
    }
}

/*
 * TODO: Once we add sync getattr API in libnfs, we can get rid of this
 *       code. Till then use getattr_sync() to get attributes from the server.
 */
#if 1
static void getattr_sync_callback(
    struct rpc_context *rpc,
    int rpc_status,
    void *data,
    void *private_data)
{
    auto ctx = (struct sync_rpc_context*) private_data;
    assert(ctx->magic == SYNC_RPC_CTX_MAGIC);
    auto res = (GETATTR3res*) data;

    rpc_task *task = ctx->task;

    ctx->rpc_status = rpc_status;
    ctx->nfs_status = NFS_STATUS(res);

    if (task) {
        assert(task->magic == RPC_TASK_MAGIC);
        assert(task->rpc_api->optype == FUSE_GETATTR);
        /*
         * Now that the request has completed, we can query libnfs for the
         * dispatch time.
         */
        task->get_stats().on_rpc_complete(rpc_get_pdu(rpc), NFS_STATUSX(rpc_status, res));
    }

    {
        std::unique_lock<std::mutex> lock(ctx->mutex);

        // Must be called only once.
        assert(!ctx->callback_called);
        ctx->callback_called = true;

        if ((ctx->rpc_status == RPC_STATUS_SUCCESS) &&
                (ctx->nfs_status == NFS3_OK)) {
            assert(ctx->fattr);
            *(ctx->fattr) = res->GETATTR3res_u.resok.obj_attributes;
        }

        /*
         * Notify inside the lock, since the other thread deletes ctx once
         * done. As soon as we notify the other thread will try to acquire
         * the lock and it may have to block as we have not released the lock
         * yet. Since these sync calls are not frequent, it's ok.
         */
        ctx->cv.notify_one();
    }
}

/**
 * Issue a sync GETATTR RPC call to filehandle 'fh' and save the received
 * attributes in 'fattr'.
 */
bool nfs_client::getattr_sync(const struct nfs_fh3& fh,
                              fuse_ino_t ino,
                              struct fattr3& fattr)
{
    const uint32_t fh_hash = calculate_crc32(
            (const unsigned char *) fh.data.data_val, fh.data.data_len);
    struct nfs_context *nfs_context = get_nfs_context(CONN_SCHED_FH_HASH, fh_hash);
    struct rpc_task *task = nullptr;
    struct sync_rpc_context *ctx = nullptr;
    struct rpc_pdu *pdu = nullptr;
    struct rpc_context *rpc;
    bool rpc_retry = false;
    bool success = false;

try_again:
    do {
        struct GETATTR3args args;
        args.object = fh;

        /*
         * Very first call to getattr_sync(), called from nfs_client::init(), for
         * getting the root filehandle attributes won't have the rpc_task_helper
         * set, so that single GETATTR RPC won't be accounted in rpc stats.
         */
        if (get_rpc_task_helper() != nullptr) {
            if (task) {
                task->free_rpc_task();
            }
            task = get_rpc_task_helper()->alloc_rpc_task(FUSE_GETATTR);
            task->init_getattr(nullptr /* fuse_req */, ino);
        } else {
            assert(ino == FUSE_ROOT_ID);
        }

        if (ctx) {
            delete ctx;
        }

        ctx = new sync_rpc_context(task, &fattr);
        rpc = nfs_get_rpc_context(nfs_context);

        rpc_retry = false;
        if (task) {
            task->get_stats().on_rpc_issue();
        }
        if ((pdu = rpc_nfs3_getattr_task(rpc, getattr_sync_callback,
                                         &args, ctx)) == NULL) {
            if (task) {
                task->get_stats().on_rpc_cancel();
            }
            /*
             * This call fails due to internal issues like OOM etc
             * and not due to an actual error, hence retry.
             */
            rpc_retry = true;
        }
    } while (rpc_retry);

    /*
     * If the GETATTR response doesn't come for 60 secs we give up and send
     * a new one. We must cancel the old one.
     */
    {
        std::unique_lock<std::mutex> lock(ctx->mutex);
wait_more:
        if (!ctx->cv.wait_for(lock, std::chrono::seconds(60),
                              [&ctx] { return (ctx->callback_called == true); })) {
            if (rpc_cancel_pdu(rpc, pdu) == 0) {
                if (task) {
                    task->get_stats().on_rpc_cancel();
                }
                AZLogWarn("Timed out waiting for getattr response, re-issuing "
                          "getattr!");
                // This goto will cause the above lock to unlock.
                goto try_again;
            } else {
                /*
                 * If rpc_cancel_pdu() fails it most likely means we got the RPC
                 * response right after we timed out waiting. It's best to wait
                 * for the callback to be called.
                 */
                AZLogWarn("Timed out waiting for getattr response, couldn't "
                          "cancel existing pdu, waiting some more!");
                // This goto will *not* cause the above lock to unlock.
                goto wait_more;
            }
        } else {
            assert(ctx->callback_called);
            assert(ctx->rpc_status != -1);
            assert(ctx->nfs_status != -1);

            if ((ctx->rpc_status == RPC_STATUS_SUCCESS) &&
                    (ctx->nfs_status == NFS3_OK)) {
                success = true;
            } else if (ctx->rpc_status == RPC_STATUS_SUCCESS &&
                       ctx->nfs_status == NFS3ERR_JUKEBOX) {
                AZLogInfo("Got NFS3ERR_JUKEBOX for GETATTR, re-issuing "
                          "after 1 sec!");
                ::usleep(1000 * 1000);
                // This goto will cause the above lock to unlock.
                goto try_again;
            }
        }
    }

    if (task) {
        task->free_rpc_task();
    }

    delete ctx;

    return success;
}
#endif
