#ifndef __NFS_CLIENT_H__
#define __NFS_CLIENT_H__

#include <queue>

#include "nfs_inode.h"
#include "rpc_transport.h"
#include "nfs_internal.h"

/**
 * This is an informal lock registry for all locks used in the aznfsclient code.
 * Any new lock introduced should be added here and it must pick a unique number
 * N for its name which is of the form <context>_lock_N. N is the order of the
 * lock. A thread can only hold a higher order lock (greater N) then the highest
 * order lock it's currently holding, i.e., a thread holding a lock *_lock_N
 * cannot hold any lock from *_lock_0 to *_lock_N-1 (it can only hold *_lock_N+1
 * and higher order locks).
 * - nfs_client::inode_map_lock_0
 * - nfs_inode::ilock_1
 * - nfs_inode::readdircache_lock_2
 * - nfs_inode::iflush_lock_3
 * - nfs_client::jukebox_seeds_lock_39
 * +++++++++++++++++++++++++++++++++
 * - ra_state::ra_lock_40
 * - rpc_task_helper::task_index_lock_41
 * - rpc_stats_az::stats_lock_42
 * - bytes_chunk_cache::chunkmap_lock_43
 * - membuf::mb_lock_44
 * - membuf::flush_waiters_lock_44
 */

extern "C" {
    /*
     * libnfs does not offer a prototype for this in any public header,
     * but exports it anyway.
     *
     * TODO: Update libnfs to export this and remove from here.
     */
    const struct nfs_fh3* nfs_get_rootfh(struct nfs_context* nfs);
}

/**
 * This represents the NFS client. Since we have only one NFS client at a time,
 * this is a singleton class.
 * Caller can make NFSv3 API calls by calling corresponding methods from this
 * class. Those methods will then call into libnfs to make the actual NFS RPC
 * User should first init the class by calling init() by specifying all the
 * parameters needed to mount the filesystem.
 * Once initialized, callers can get the singleton instance of this class by
 * calling the get_instance() static method.
 * The returned instance can then be used to call the APIs like getattr, write etc.
 */
#define NFS_CLIENT_MAGIC *((const uint32_t *)"NFSC")

/**
 * RPC requests that fail with JUKEBOX error are retried after these many secs.
 * We try after 5 seconds similar to Linux NFS client.
 */
#define JUKEBOX_DELAY_SECS 5

struct nfs_client
{
    const uint32_t magic = NFS_CLIENT_MAGIC;
private:
    /*
     * This is the RPC transport connected to the NFS server.
     * RPC transport is made up of one or more nfs_connection which are used
     * to carry the RPC requests/responses.
     */
    struct rpc_transport transport;

    /*
     * Root File Handle obtained after mounting the filesystem.
     * This will be set after calling nfs_mount which is done in the init()
     * method.
     */
    struct nfs_inode *root_fh = nullptr;

    /*
     * Map of all inodes returned to fuse and which are not FORGET'ed
     * by fuse. The idea behind this map is to make sure we never return
     * two different fuse_ino_t inode number for the same file, lest it'll
     * confuse the VFS layer. This is achieved by adding any inode we
     * return to fuse, to this map.
     * An inode will be removed from the map only when all the following
     * conditions are met:
     * 1. inode->lookupcnt becomes 0.
     *    This confirms that fuse vfs does not have this inode and hence
     *    it cannnot make any call on this inode.
     * 2. inode->dircachecnt becomes 0.
     *    Whenever we cache directory_entry for readdirplus, the
     *    directory_entry also refers to the inode and hence we need to
     *    make sure that the inode is not freed till any directory_entry
     *    is referring to it.
     */
    std::multimap<uint64_t /* fileid */, struct nfs_inode*> inode_map;
    mutable std::shared_mutex inode_map_lock_0;

    /*
     * Every RPC request is represented by an rpc_task which is created when
     * the fuse request is received and remains till the NFS server sends a
     * response. rpc_task_helper class allows efficient allocation of RPC
     * tasks.
     */
    class rpc_task_helper *rpc_task_helper = nullptr;

    /*
     * JUKEBOX errors are handled by re-running the nfs_client handler for the
     * given request, f.e., for a READDIRPLUS request failing with JUKEBOX error
     * we will call nfs_client::readdirplus() again after JUKEBOX_DELAY_SECS
     * seconds. For this we need to save enough information needed to run the
     * nfs_client handler. jukebox_seedinfo stores that information and we
     * queue that in jukebox_seeds.
     */
    std::thread jukebox_thread;
    void jukebox_runner();
    std::queue<struct jukebox_seedinfo*> jukebox_seeds;
    mutable std::mutex jukebox_seeds_lock_39;

    /*
     * Holds info about the server, queried by FSINFO.
     */
    struct nfs_server_info server_info;

    /*
     * Holds info about the server, queried by FSSTAT.
     */
    struct nfs_server_stat server_stat;

#ifdef ENABLE_PARANOID
    /*
     * Since we use the address of nfs_inode as the inode number we
     * return to fuse, this is a small sanity check we do to check if
     * fuse is passing us valid inode numbers.
     */
    std::atomic<uint64_t> min_ino = UINT64_MAX;
    std::atomic<uint64_t> max_ino = 0;
#endif

    /*
     * Latest read and write throughput.
     * rw_genid is updated everytime these values are updated, so can be used
     * to see throughput is changing.
     */
    std::atomic<uint64_t> r_MBps = 0;
    std::atomic<uint64_t> w_MBps = 0;
    std::atomic<uint64_t> rw_genid = 0;

    /*
     * Value returned by max_dirty_extent_bytes() is scaled down by this much
     * before it's used by:
     * - flush_required()
     * - commit_required()
     * - do_inline_write()
     *
     * fc_scale_factor is computed by update_adaptive() according to the global
     * cache pressure. If global cache pressure is high we want the local
     * flush/commit limits to be reduced so that each file flushes/commits
     * faster thus easing the global cache pressure. This promotes fair sharing
     * of global cache space while also maintaining enough contiguous data to
     * the server, needed for better write throughput. Stable and unstable
     * write may use this scale factor differently.
     */
    static std::atomic<double> fc_scale_factor;

    /*
     * update_adaptive() will update this scaling factor to force all ra_state
     * machines to slow down readahead in case of high memory pressure.
     */
    static std::atomic<double> ra_scale_factor;

    /*
     * Set in shutdown() to let others know that nfs_client is shutting
     * down. They can use this to quit what they are doing and plan for
     * graceful shutdown.
     */
    std::atomic<bool> shutting_down = false;

    nfs_client() :
        transport(this)
    {
    }

    ~nfs_client()
    {
        AZLogInfo("~nfs_client() called");

        /*
         * shutdown() should have cleared the root_fh.
         */
        assert(root_fh == nullptr);
    }

    /**
     * Internal method used by __get_nfs_inode() for querying nfs_inode from
     * inode_map. It returns nfs_inode after holding a lookupcnt ref so caller
     * can safely use that w/o worrying about the nfs_inode being removed from
     * inode_map.
     */
    struct nfs_inode *__inode_from_inode_map(const nfs_fh3 *fh,
                                             const struct fattr3 *fattr,
                                             bool acquire_lock = true,
                                             bool *is_forgotten = nullptr);
public:
    /*
     * Mount options (to be) used for mounting. These contain details of the
     * server and share that's mounted and also the mount options used.
     */
    struct mount_options mnt_options;

    /*
     * Return the instance of the singleton class.
     */
    static nfs_client& get_instance()
    {
        static nfs_client client;
        return client;
    }

    static double get_fc_scale_factor()
    {
        return fc_scale_factor;
    }

    static double get_ra_scale_factor()
    {
        return ra_scale_factor;
    }

    /**
     * Returns true if nfs_client is shutting down.
     */
    bool is_shutting_down() const
    {
        return shutting_down;
    }

    /**
     * Must be called on fuse unmount.
     * TODO: Audit this to make sure we perform cleanup for all components.
     */
    void shutdown();

    const struct rpc_transport& get_transport() const
    {
        return transport;
    }

    class rpc_task_helper *get_rpc_task_helper()
    {
        return rpc_task_helper;
    }

    std::shared_mutex& get_inode_map_lock()
    {
        return inode_map_lock_0;
    }

    /**
     * Update various adaptive scale factors that decide following things:
     * - how much we readahead, and
     * - how long we keep dirty data before flushing.
     *
     * It monitors various things like, how much of the cache is occupied
     * by read or write data, whether read/write speed is increasing by
     * chaning the various scale factors, etc.
     */
    void update_adaptive();

    /**
     * Call this whenever a read/write completes at the server.
     * This tracks the read/write speed provided by the server.
     */
    void on_rw_complete(uint64_t r_bytes, uint64_t w_bytes)
    {
        static std::atomic<uint64_t> last_usec;
        static std::atomic<uint64_t> last_read;
        static std::atomic<uint64_t> tot_read;
        static std::atomic<uint64_t> last_written;
        static std::atomic<uint64_t> tot_written;
        static std::atomic<uint64_t> last_genid;
        /*
         * Measure read/write speed no sooner than 10 msec interval.
         * Anything smaller and we may not get accurate reading and anything
         * larger and it will be less valuable for readers.
         */
        const uint64_t sample_intvl = 5 * 1000 * 1000;
        const uint64_t now_usec = get_current_usecs();

        tot_read += r_bytes;
        tot_written += w_bytes;

        /*
         * Every sample_intvl, compute read/write throughput for the last
         * interval.
         */
        const uint64_t intvl = now_usec - last_usec;
        if (intvl >= sample_intvl) {
            uint64_t expected = last_genid.load();
            if (rw_genid.compare_exchange_strong(expected, expected + 1)) {
                w_MBps = (tot_written - last_written) / intvl;
                r_MBps = (tot_read - last_read) / intvl;

                last_usec = now_usec;
                last_read = tot_read.load();
                last_written = tot_written.load();
                last_genid = rw_genid.load();
            }
        }
    }

    uint64_t get_read_MBps() const
    {
        return r_MBps;
    }

    uint64_t get_write_MBps() const
    {
        return w_MBps;
    }

    uint64_t get_rw_genid() const
    {
        return rw_genid;
    }

    /*
     * The user should first init the client class before using it.
     */
    bool init();

    /*
     * Get the libnfs context on which the libnfs API calls can be made.
     *
     * csched:  The connection scheduling type to be used when selecting the
     *          NFS context/connection.
     * fh_hash: Filehandle hash, used only when CONN_SCHED_FH_HASH scheduling
     *          mode is used. This provides a unique hash for the file/dir
     *          that is the target for this request. All requests to the same
     *          file/dir are sent over the same connection.
     */
    struct nfs_context* get_nfs_context(conn_sched_t csched,
                                        uint32_t fh_hash) const;

    /*
     * Given an inode number, return the nfs_inode structure.
     * For efficient access we use the address of the nfs_inode structure as
     * the inode number. Fuse should always pass inode numbers we return in
     * one of the create APIs, so it should be ok to trust fuse.
     * Once Fuse calls the forget() API for an inode, it won't pass that
     * inode number in any future request, so we can safely destroy the
     * nfs_inode on forget.
     */
    struct nfs_inode *get_nfs_inode_from_ino(fuse_ino_t ino)
    {
        // 0 is not a valid inode number.
        assert(ino != 0);

        if (ino == FUSE_ROOT_ID) {
            // root_fh must have been created by now.
            assert(root_fh != nullptr);
            assert(root_fh->magic == NFS_INODE_MAGIC);
            return root_fh;
        }

#ifdef ENABLE_PARANOID
        assert(ino >= min_ino);
        assert(ino <= max_ino);
#endif

        struct nfs_inode *const nfsi =
            reinterpret_cast<struct nfs_inode *>(ino);

        // Dangerous cast, deserves validation.
        assert(nfsi->magic == NFS_INODE_MAGIC);

        return nfsi;
    }

    /**
     * Given a filehandle and fattr (oontaining fileid defining a file/dir),
     * get the nfs_inode for that file/dir. It searches in the global list of
     * all inodes and returns from there if found, else creates a new nfs_inode.
     * Note that we don't want to return multiple fuse inodes for the same
     * file (represented by the filehandle). If fuse guarantees that it'll
     * never make a lookup or any other call that gets a new inode, until
     * it calls forget for that inode, then we can probably use different
     * inodes for the same file but not at the same time. Since fuse doesn't
     * guarantee we play safe and make sure for a given file we use the
     * same nfs_inode as long one is cached with us. New incarnation of
     * fuse driver will give a different fuse ino for the same file, but
     * that should be ok.
     * It'll grab a refcnt on the inode before returning. Caller must ensure
     * that the ref is duly dropped at an appropriate time. Most commonly
     * this refcnt held by get_nfs_inode() is trasferred to fuse and is
     * dropped when fuse FORGETs the inode.
     * 'is_root_inode' must be set when the inode being requested is the
     * root inode. Root inode is special in that it has the special fuse inode
     * number of 1, rest other inodes have inode number as the address of
     * the nfs_inode structure, which allows fast ino->inode mapping.
     */
    struct nfs_inode *__get_nfs_inode(LOC_PARAMS
                                      const nfs_fh3 *fh,
                                      const struct fattr3 *fattr,
                                      bool is_root_inode = false);

#define get_nfs_inode(fh, fattr, ...) \
    __get_nfs_inode(LOC_VAL fh, fattr, ## __VA_ARGS__)

    /**
     * Get various stats related to inodes/files.
     */
    void get_inode_stats(uint64_t& total_inodes,
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
                         uint64_t& num_silly_renamed) const;

    /**
     * Release the given inode, called when fuse FORGET call causes the
     * inode lookupcnt to drop to 0, i.e., the inode is no longer in use
     * by fuse VFS. Note that it takes a dropcnt parameter which is the
     * nlookup parameter passed by fuse FORGET. Instead of the caller
     * reducing lookupcnt and then calling put_nfs_inode(), the caller
     * passes the amount by which the lookupcnt must be dropped. This is
     * important as we need to drop the lookupcnt inside inode_map_lock_0,
     * else if we drop before the lock and lookupcnt becomes 0, some other
     * thread can delete the inode while we still don't have the lock, and
     * then when we proceed to delete the inode, we would be accessing the
     * already deleted inode.
     *
     * If the inode lookupcnt (after reducing by dropcnt), becomes 0 and it's
     * not referenced by any readdirectory_cache (inode->dircachecnt is 0)
     * then the inode is removed from the inode_map and freed.
     *
     * This nolock version does not hold inode_map_lock_0 so the caller
     * must hold the lock before calling this. Usually you will call one of
     * the other variants which hold the lock.
     *
     * Note: Call put_nfs_inode()/put_nfs_inode_nolock() only when you are
     *       sure dropping dropcnt refs will cause the lookupcnt to become 0.
     *       It's possible that before put_nfs_inode() acquires inode_map_lock_0,
     *       someone may grab a fresh ref on the inode, but that's fine as
     *       put_nfs_inode_nolock() handles that. Since it expects caller to
     *       only call it when the inode lookupcnt is going to be 0, it logs
     *       a "Inode no longer forgotten..." warning log in that case.
     */
    void put_nfs_inode_nolock(struct nfs_inode *inode, size_t dropcnt);

    void put_nfs_inode(struct nfs_inode *inode, size_t dropcnt)
    {
        /*
         * We need to hold inode_map_lock_0 while we check the inode for
         * eligibility to remove (and finally remove) from the inode_map.
         */
        std::unique_lock<std::shared_mutex> lock(inode_map_lock_0);
        put_nfs_inode_nolock(inode, dropcnt);
    }

    /*
     *
     * Define Nfsv3 API specific functions and helpers after this point.
     *
     * TODO: Add more NFS APIs as we implement them.
     */

    void getattr(
        fuse_req_t req,
        fuse_ino_t ino,
        struct fuse_file_info* file);

    /**
     * Issue a sync GETATTR RPC call to filehandle 'fh' and save the received
     * attributes in 'fattr'.
     * This is to be used internally and not for serving fuse requests.
     */
    bool getattr_sync(const struct nfs_fh3& fh,
                      fuse_ino_t ino,
                      struct fattr3& attr);

    void statfs(fuse_req_t req, fuse_ino_t ino);

    void create(
        fuse_req_t req,
        fuse_ino_t parent_ino,
        const char *name,
        mode_t mode,
        struct fuse_file_info* file);

    void mknod(
        fuse_req_t req,
        fuse_ino_t parent_ino,
        const char *name,
        mode_t mode);

    void mkdir(
        fuse_req_t req,
        fuse_ino_t parent_ino,
        const char *name,
        mode_t mode);

    /**
     * Try to perform silly rename of the given file (parent_ino/name) and
     * return true if silly rename was required (and done), else return false.
     * Note that silly rename is required for the following two cases:
     *
     * 1. When unlinking a file we need to silly rename the file if it has a
     *    non-zero open count.
     *    In this case caller just needs to pass parent_ino and name.
     *    In this case (silly) renaming the to-be-unlinked file is sufficient
     *    in order to serve the unlink requested by the user.
     * 2. When renaming oldparent_ino/old_name to parent_ino/name, after the
     *    rename parent_ino/name will start referring to the file originally
     *    referred by oldparent_ino/old_name and in case parent_ino/name existed
     *    at the time of rename that file would no longer be accessible after
     *    rename, so it's effectively deleted by the server. Hence we need to
     *    silly rename it if it has a non-zero open count.
     *    In this case caller needs to pass parent_ino and name and additionally
     *    oldparent_ino and old_name. The oldparent_ino and old_name are as such
     *    not used by silly rename but since the actual rename is performed when
     *    the silly rename succeeds (from rename_callback()), we need to store
     *    the oldparent_ino and old_name details in the silly rename task.
     *    In this case silly_rename() will do the following:
     *    - silly rename the outgoing file, and if/when silly rename succeeds,
     *      perform actual rename (oldparent_ino/old_name -> parent_ino/name).
     */
    bool silly_rename(
        fuse_req_t req,
        fuse_ino_t parent_ino,
        const char *name,
        fuse_ino_t oldparent_ino = 0,
        const char *old_name = nullptr);

    /**
     * for_silly_rename tells if this unlink() call is being made to delete
     * a silly-renamed file (.nfs_*), as a result of a release() call from
     * fuse that drops the final opencnt on the file. Note that an earlier
     * unlink  of the file would have caused the file to be (silly)renamed to
     * the .nfs_* name and now when the last opencnt is dropped we need to
     * delete the .nfs_* file. Since we hold the parent directory inode refcnt
     * in rename_callback() for silly renamed files, we need to drop the refcnt
     * now.
     */
    void unlink(
        fuse_req_t req,
        fuse_ino_t parent_ino,
        const char *name,
        bool for_silly_rename);

    void rmdir(
        fuse_req_t req,
        fuse_ino_t parent_ino,
        const char* name);

    void symlink(
        fuse_req_t req,
        const char *link,
        fuse_ino_t parent_ino,
        const char *name);

    /**
     * silly_rename must be passed as true if this is a silly rename and not
     * rename triggered by user. See silly_rename() for explanation of why and
     * when we need to silly rename a file. If this rename operation is
     * being performed to realize a silly rename, then silly_rename_ino must
     * contain the ino of the file that's being silly renamed.
     * Also in that case oldparent_ino and old_name refer to the source of the
     * actual rename triggered by user.
     *
     * See comments above init_rename() in rpc_task.h.
     */
    void rename(
        fuse_req_t req,
        fuse_ino_t parent_ino,
        const char *name,
        fuse_ino_t newparent_ino,
        const char *new_name,
        bool silly_rename = false,
        fuse_ino_t silly_rename_ino = 0,
        fuse_ino_t oldparent_ino = 0,
        const char *old_name = nullptr);

    void readlink(
        fuse_req_t req,
        fuse_ino_t ino);

    void setattr(
        fuse_req_t req,
        fuse_ino_t ino,
        const struct stat* attr,
        int to_set,
        struct fuse_file_info* file);

    void lookup(
        fuse_req_t req,
        fuse_ino_t parent_ino,
        const char* name);

    /**
     * Sync version of lookup().
     * This is to be used internally and not for serving fuse requests.
     * It returns 0 if we are able to get a success response for the
     * LOOKUP RPC that we sent, in that case child_ino will contain the
     * child's fuse inode number.
     * In case of a failed lookup it'll return a +ve errno value.
     */
    int lookup_sync(
        fuse_ino_t parent_ino,
        const char *name,
        fuse_ino_t& child_ino);

    void access(
        fuse_req_t req,
        fuse_ino_t ino,
        int mask);

    void write(
        fuse_req_t req,
        fuse_ino_t ino,
        struct fuse_bufvec *bufv,
        size_t size,
        off_t off);

    void flush(
        fuse_req_t req,
        fuse_ino_t ino);

    void readdir(
        fuse_req_t req,
        fuse_ino_t ino,
        size_t size,
        off_t off,
        struct fuse_file_info* file);

    void readdirplus(
        fuse_req_t req,
        fuse_ino_t ino,
        size_t size,
        off_t off,
        struct fuse_file_info* file);

    void read(
        fuse_req_t req,
        fuse_ino_t ino,
        size_t size,
        off_t off,
        struct fuse_file_info *fi);

    void jukebox_read(struct api_task_info *rpc_api);

    void jukebox_write(struct api_task_info *rpc_api);

    void jukebox_flush(struct api_task_info *rpc_api);

    /**
     * Convert between NFS fattr3 and POSIX struct stat.
     */
    static void stat_from_fattr3(struct stat& st, const struct fattr3& fattr);
    static void fattr3_from_stat(struct fattr3& fattr, const struct stat& st);

    void reply_entry(
        struct rpc_task* ctx,
        const nfs_fh3* fh,
        const struct fattr3* attr,
        const struct fuse_file_info* file);

    /**
     * Call this to handle NFS3ERR_JUKEBOX error received for rpc_task.
     * This will save information needed to re-issue the call and queue
     * it in jukebox_seeds from where jukebox_runner will issue the call
     * after JUKEBOX_DELAY_SECS seconds.
     */
    void jukebox_retry(struct rpc_task *task);
};

/**
 * Sync RPC calls can use this context structure to communicate between
 * issuer and the callback.
 */
#define SYNC_RPC_CTX_MAGIC *((const uint32_t *)"SRCX")

struct sync_rpc_context
{
    const uint32_t magic = SYNC_RPC_CTX_MAGIC;
    /*
     * Set by the callback to convey that callback is indeed called.
     * Issuer can find this to see if it timed out waiting for the callback.
     */
    bool callback_called = false;

    /*
     * RPC and NFS status, only valid if callback_called is true.
     * Also, nfs_status is only valid if rpc_status is RPC_STATUS_SUCCESS.
     */
    int rpc_status = -1;
    int nfs_status = -1;

    /*
     * Condition variable on which the issuer will wait for the callback to
     * be called.
     */
    std::condition_variable cv;
    std::mutex mutex;

    /*
     * The rpc_task tracking the actual RPC call.
     */
    struct rpc_task *const task;

    /*
     * Most NFS RPCs carry postop attributes. If this is not null, callback
     * will fill this with the postop attributes received.
     */
    struct fattr3 *const fattr = nullptr;

    sync_rpc_context(struct rpc_task *_task, struct fattr3 *_fattr):
        task(_task),
        fattr(_fattr)
    {
    }
};

/**
 * nfs_client is a singleton, so this just returns the singleton instance
 * pointer.
 * We also store the nfs_client pointer inside the fuse req private pointer.
 * We use that for asserting.
 */
static inline
struct nfs_client *get_nfs_client_from_fuse_req(
        [[maybe_unused]] const fuse_req_t req = nullptr)
{
    struct nfs_client *const client = &nfs_client::get_instance();

#ifndef ENABLE_NO_FUSE
#ifdef ENABLE_PARANOID
    assert(client == reinterpret_cast<struct nfs_client*>(fuse_req_userdata(req)));
#endif
#else
    /*
     * In nofuse mode req must be a pointer to posix_task.
     */
    assert(_FR2PXT(req)->magic == POSIX_TASK_MAGIC);
#endif

    // Dangerous cast, make sure we got a correct pointer.
    assert(client->magic == NFS_CLIENT_MAGIC);

    return client;
}

#endif /* __NFS_CLIENT_H__ */
