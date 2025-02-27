#ifndef __NFS_INODE_H__
#define __NFS_INODE_H__

#include <atomic>
#include <chrono>
#include "aznfsc.h"
#include "rpc_readdir.h"
#include "file_cache.h"
#include "readahead.h"
#include "fcsm.h"

#define NFS_INODE_MAGIC *((const uint32_t *)"NFSI")

// Compare two nfs_fh3 filehandles.
#define FH_EQUAL(fh1, fh2) \
    (((fh1)->data.data_len == (fh2)->data.data_len) && \
     (!::memcmp((fh1)->data.data_val, \
                (fh2)->data.data_val, \
                (fh1)->data.data_len)))

#define FH_VALID(fh) \
    (((fh)->data.data_len > 0) && ((fh)->data.data_val != nullptr))

/**
 * C++ object to hold struct nfs_fh3 from libnfs.
 */
struct nfs_fh3_deep
{
    nfs_fh3_deep(const struct nfs_fh3& _fh)
    {
#ifndef ENABLE_NON_AZURE_NFS
        // Blob NFS FH is at least 50 bytes.
        assert(_fh.data.data_len > 50 && _fh.data.data_len <= 64);
#else
        assert(_fh.data.data_len <= 64);
#endif
        fh.data.data_len = _fh.data.data_len;
        fh.data.data_val = &fh_data[0];
        ::memcpy(fh.data.data_val, _fh.data.data_val, fh.data.data_len);
    }

    /**
     * Return the libnfs nfs_fh3 object ref.
     */
    const struct nfs_fh3& get_fh() const
    {
        assert(FH_VALID(&fh));
        return fh;
    }

private:
    struct nfs_fh3 fh;
    char fh_data[64];
};

/**
 * Properties common to the entire filesystem.
 */
struct nfs_superblock
{
    mutable std::shared_mutex sb_lock;

    /*
     * Blocksize and other filesystem properties.
     */
    struct statvfs st;

    /*
     * Preferred readdir size (for directory enumeration).
     */
    uint64_t dtpref;

    uint64_t get_blocksize() const
    {
        assert(st.f_bsize >= 4096);
        return st.f_bsize;
    }

    uint64_t get_dtpref() const
    {
        assert(dtpref >= 4096);
        return dtpref;
    }
};

/**
 * This is the NFS inode structure. There is one of these per file/directory
 * and contains any global information about the file/directory., f.e.,
 * - NFS filehandle for accessing the file/directory.
 * - FUSE inode number of the file/directory.
 * - File/Readahead cache (if any).
 * - Anything else that we want to maintain per file.
 */
struct nfs_inode
{
    /*
     * As we typecast back-n-forth between the fuse inode number and our
     * nfs_inode structure, we use the magic number to confirm that we
     * have the correct pointer.
     */
    const uint32_t magic = NFS_INODE_MAGIC;

    /*
     * Filesystem properties, common to all inodes.
     */
    static struct nfs_superblock sb;

    /*
     * Inode lock.
     * Inode must be updated only with this lock held.
     * VFS can make multiple calls (not writes) to the same file in parallel.
     */
    mutable std::shared_mutex ilock_1;

    /*
     * Note on inode flush locking.
     * is_flushing atomic boolean (aided by iflush_lock_3 and flush_cv) is used
     * for synchronizing changes to backend file size as a result of
     * flush/commit along with application initiated truncate calls forcing a
     * specific file size. Note that the inode lock ilock_1 is for synchronizing
     * the application visible state of the inode (attr cache, etc), while inode
     * flush locking is for synchronizing changes to the on-disk file (through
     * flush, commit and truncate).
     * Any flush done to an inode will mark all the to-be-flushed membufs as
     * flushing while holding this lock and any truncate call will hold this
     * lock to ensure no new flush/commit operations are started while it
     * updates the file size using SETATTR RPC.
     *
     * See flush_lock()/flush_unlock() for the actual locking.
     *
     * Note: Though it's called flush lock, but it protects backend file size
     *       changes through both flush and/or commit.
     */
    mutable std::atomic<bool> is_flushing = false;
    mutable std::condition_variable_any flush_cv;
    mutable std::mutex iflush_lock_3;

    /*
     * S_IFREG, S_IFDIR, etc.
     * 0 is not a valid file type.
     */
    const uint32_t file_type = 0;

    /*
     * Ref count of this inode.
     * Fuse expects that whenever we make one of the following calls, we
     * must increment the lookupcnt of the inode:
     * - fuse_reply_entry()
     * - fuse_reply_create()
     * - Lookup count of every entry returned by readdirplus(), except "."
     *   and "..", is incremented by one. Note that readdir() does not
     *   affect the lookup count of any of the entries returned.
     *
     * Since an nfs_inode is created only in response to one of the above,
     * we set the lookupcnt to 1 when the nfs_inode is created. Later if
     * we are not able to successfully convey creation of the inode to fuse
     * we drop the ref. This is important as unless fuse knows about an
     * inode it'll never call forget() for it and we will leak the inode.
     * forget() causes lookupcnt for an inode to be reduced by the "nlookup"
     * parameter count. forget_multi() does the same for multiple inodes in
     * a single call.
     * On umount the lookupcnt for all inodes implicitly drops to zero, and
     * fuse may not call forget() for the affected inodes.
     *
     * Till the lookupcnt of an inode drops to zero, we MUST not free the
     * nfs_inode structure, as kernel may send requests for files with
     * non-zero lookupcnt, even after calls to unlink(), rmdir() or rename().
     *
     * dircachecnt is another refcnt which is the number of readdirplus
     * directory_entry,s that refer to this nfs_inode. An inode can only be
     * deleted when both lookupcnt and dircachecnt become 0, i.e., fuse
     * vfs does not have a reference to the inode and it's not cached in
     * any of our readdirectory_cache,s.
     *
     * See comment above inode_map.
     *
     * See comment above forget_expected.
     */
    mutable std::atomic<uint64_t> lookupcnt = 0;
    mutable std::atomic<uint64_t> dircachecnt = 0;

    /*
     * How many open fds for this file are currently present in fuse.
     * Incremented when fuse calls open()/creat().
     */
    std::atomic<uint64_t> opencnt = 0;

    /*
     * Silly rename related info.
     * If this inode has been successfully silly renamed, is_silly_renamed will
     * be set and silly_renamed_name will contain the silly renamed name and
     * parent_ino is the parent directory ino. These will be needed for
     * deleting ths silly renamed file once the last handle on the file is
     * closed by user.
     * silly_rename_level helps to get unique names in case the silly renamed
     * file itself is deleted.
     */
    bool is_silly_renamed = false;
    std::string silly_renamed_name;
    fuse_ino_t parent_ino = 0;
    int silly_rename_level = 0;

private:
    /*
     * NFSv3 filehandle returned by the server.
     * We use this to identify this file/directory to the server.
     */
    const nfs_fh3_deep fh;

    /*
     * CRC32 hash of fh.
     * This serves multiple purposes, most importantly it can be used to print
     * filehandle hashes in a way that can be used to match with wireshark.
     * Also used for affining writes to a file to one RPC transport.
     */
    const uint32_t crc = 0;

    /*
     * This is a handle to the chunk cache which caches data for this file.
     * Valid only for regular files.
     * filecache_handle starts null in the nfs_inode constructor and is later
     * initialized only in on_fuse_open() (when we return the inode to fuse in
     * a lookup response or the application calls open()/creat()). The idea is
     * to allocate the cache only when really needed. For inodes returned to
     * fuse in a readdirplus response we don't initialize the filecache_handle.
     * Once initialized we never make it null again, though we can make the
     * cache itself empty by invalidate_cache(). So if has_filecache() returns
     * true we can safely access the filecache_handle shared_ptr returned by
     * get_filecache().
     * alloc_filecache() initializes filecache_handle and sets filecache_alloced
     * to true.
     * Access to this shared_ptr must be protect by ilock_1, whereas access to
     * the bytes_chunk_cache itself must be protected by chunkmap_lock_43.
     */
    std::shared_ptr<bytes_chunk_cache> filecache_handle;
    std::atomic<bool> filecache_alloced = false;

    /*
     * Pointer to the readdirectory cache.
     * Only valid for a directory, this will be nullptr for a non-directory.
     * Access to this shared_ptr must be protect by ilock_1, whereas access to
     * the readdirectory_cache itself must be protected by readdircache_lock_2.
     * Also see comments above filecache_handle.
     */
    std::shared_ptr<readdirectory_cache> dircache_handle;
    std::atomic<bool> dircache_alloced = false;

    /*
     * For maintaining readahead state.
     * Valid only for regular files.
     * Access to this shared_ptr must be protect by ilock_1, whereas access to
     * the ra_state itself must be protected by ra_lock_40.
     * Also see comments above filecache_handle.
     */
    std::shared_ptr<ra_state> readahead_state;
    std::atomic<bool> rastate_alloced = false;

    /*
     * Flush-commit state machine, used for performing flush/commit to the
     * backend file.
     * Valid only for regular files.
     * Also see comments above filecache_handle.
     */
    std::shared_ptr<struct fcsm> fcsm;
    std::atomic<bool> fcsm_alloced = false;

    /*
     * Cached attributes for this inode.
     * These cached attributes are valid till the absolute milliseconds value
     * attr_timeout_timestamp. On expiry of this we will revalidate the inode
     * by querying the attributes from the server. If the revalidation is
     * successful (i.e., inode has not changed since we cached), then we
     * increase attr_timeout_secs in an exponential fashion (upto the max
     * actimeout value) and set attr_timeout_timestamp accordingly.
     *
     * If attr_timeout_secs is -1 that implies that cached attributes are
     * not valid and we need to fetch the attributes from the server. This
     * should never happen as we set attr in the nfs_inode constructor and
     * from then on it's always set.
     *
     * See update_nolock() how these attributes are compared with freshly
     * fetched preop or postop attributes to see if file/dir has changed
     * (and thus the cache must be invalidated).
     *
     * Note: This MUST be accessed under ilock_1.
     *
     * Note: External users can access it using the get_attr() method which
     *       correctly accesses it under ilock_1.
     *       Callers already holding ilock_1 must use the nolock version
     *       get_attr_nolock().
     */
    struct stat attr;

    /**
     * We maintain following multiple views of the file and thus multiple file
     * sizes for those views.
     * - Cached.
     *   This is the view of the file that comprises of data that has been
     *   written by the application and saved in file cache. It may or may not
     *   have been flushed and/or committed. This is the most uptodate view of
     *   the file and applications must use this view.
     *   get_cached_filesize() returns the cached file size.
     * - Uncommited.
     *   This is the view of the file that tracks data that has been flushed
     *   using UNSTABLE writes but not yet COMMITted to the Blob. This view of
     *   the file is only used to see if the next PB call will write after the
     *   last PB'ed byte and thus can be appended.
     *   putblock_filesize tracks the file size for this view.
     * - Committed.
     *   This is the view of the file that tracks data committed to the Blob.
     *   Other clients will see this view.
     *   attr.st_size tracks the file size for this view.
     */
    off_t putblock_filesize = 0;

    /*
     * For any file stable_write starts as false as write pattern is unknown.
     * At the time of flushing cached writes to Blob we check if the given
     * write causes an append write on the Blob, or an overwrite or sparse
     * write. Append writes can be sent as unstable write, while non-append
     * writes (either overwrite or sparse write) must go as a stable write
     * (since server knows best how to allocate blocks for them).
     * Once set to true, it remains true for the life of the inode.
     * 
     * TODO: Set this to false once we have servers with unstable write
     *       support. Also uncomment the assert in nfs_inode constructor.
     */
    bool stable_write = true;

    /*
     * XXX This is for debugging.
     *     It's set in truncate_start() and cleared in truncate_end().
     */
    std::atomic<bool> truncate_in_progress = false;

public:
    /*
     * Fuse inode number.
     * This is how fuse identifies this file/directory to us.
     * Fuse expects us to ensure that if we reuse ino we must ensure that the
     * ino/generation pair is unique for the life of the fuse filesystem (and
     * not just unique for one mount). This is specially useful if this fuse
     * filesystem is exported over NFS. Since NFS would issue filehandles
     * based on the ino number and generation pair, if ino number and generation
     * pair is not unique NFS server might issue the same FH to two different
     * files if "fuse driver + NFS server" is restarted. To avoid that make
     * sure generation id is unique. We use the current epoch in usecs to
     * ensure uniqueness. Note that even if the time goes back, it's highly
     * unlikely that we use the same ino number and usec combination, but
     * it's technically possible.
     *
     * IMPORTANT: Need to ensure time is sync'ed and it doesn't go back.
     */
    const fuse_ino_t ino;
    const uint64_t generation;

    /*
     * attr_timeout_secs will have a value between [acregmin, acregmax] or
     * [acdirmin, acdirmax], depending on the filetype, and holds the current
     * attribute cache timeout value for this inode, adjusted by exponential
     * backoff and capped by the max limit.
     * attr_timeout_timestamp is the absolute time in msecs when the attribute
     * cache is going to expire.
     *
     * attr_timeout_secs is protected by ilock_1.
     * attr_timeout_timestamp is updated inder ilock_1, but can be accessed
     * w/o ilock_1, f.e., run_getattr()->attr_cache_expired().
     */
    std::atomic<int64_t> attr_timeout_secs = -1;
    std::atomic<int64_t> attr_timeout_timestamp = -1;

    /*
     * Time in usecs we received the last cached write for this inode.
     * See discussion in stamp_cached_write() for details.
     */
    std::atomic<int64_t> last_cached_write = 0;

    // nfs_client owning this inode.
    struct nfs_client *const client;

    /*
     * How many forget count we expect from fuse.
     * It'll be incremented whenever we are able to successfully call one of
     * the following:
     * - fuse_reply_create()
     * - fuse_reply_entry()
     * - fuse_reply_buf() (for readdirplus and not for readdir)
     *
     * Fuse must call exactly these many forgets on this inode and the inode
     * can only be freed when forget_expected becomes 0. Fuse must not call
     * more forgets than forget_expected.
     *
     * Note: forget_expected may become 0 indicating that fuse doesn't know
     *       about this inode but inode may still be in use (lookupcnt or
     *       dircachecnt can be non-zero), then we don't free the inode.
     *
     * We use this for forgetting all inodes on unmount, and also for
     * debugging to see if fuse forgets to call forget :-)
     *
     * Note: In nfs_inode::decref() we assert that lookupcnt is always
     *       greater than or equal to forget_expected, hence wherever we
     *       increment both we must increment forget_expected after lookupcnt
     *       and v.v. we must decrement forget_expected before lookupcnt.
     */
    std::atomic<int64_t> forget_expected = 0;

#ifdef ENABLE_PARANOID
    uint64_t last_forget_seen_usecs = 0;
#endif

    /*
     * Stores the write error observed when performing backend writes to this
     * Blob. This helps us duly fail close(), if one or more IOs have failed
     * for the Blob. Note that the application read may complete immediately
     * after copying the data to the cache but later when sync'ing dirty
     * membufs with the Blob we might encounter write failures. These failures
     * MUST be conveyed to the application via close(), else it'll never know.
     *
     * This is either 0 (no error) or a +ve errno value.
     */
    int write_error = 0;

    /*
     * Commit state for this inode.
     * This is used to track the state of commit operation for this inode, which
     * can be one of:
     * COMMIT_NOT_NEEDED:  No or not enough uncommitted (written using unstable
     *                     writes) data.
     *                     Note that we want to commit multiple blocks at a time
     *                     to amortize the latency introduced by commit, given the
     *                     fact that all writes have to stop till the commit
     *                     completes.
     * NEEDS_COMMIT:       There's enough uncommitted data that needs to be
     *                     committed.
     *                     This indicates to the running write(flush) task that
     *                     it must start the commit task when ongoing flushing
     *                     completes (bytes_flushing == 0).
     * COMMIT_IN_PROGRESS: There's an outstanding commit operation.
     *                     Till it completes no write or commit for this inode
     *                     can be sent to the server.
     *
     * Valid state transitions:
     * COMMIT_NOT_NEEDED -> NEEDS_COMMIT -> COMMIT_IN_PROGRESS
     * COMMIT_NOT_NEEDED -> COMMIT_IN_PROGRESS
     * COMMIT_IN_PROGRESS -> COMMIT_NOT_NEEDED
     */
    enum class commit_state_t
    {
        INVALID = 0,
        COMMIT_NOT_NEEDED,
        NEEDS_COMMIT,
        COMMIT_IN_PROGRESS,
    };

    std::atomic<commit_state_t> commit_state = commit_state_t::COMMIT_NOT_NEEDED;

    /**
     * TODO: Initialize attr with postop attributes received in the RPC
     *       response.
     */
    nfs_inode(const struct nfs_fh3 *filehandle,
              const struct fattr3 *fattr,
              struct nfs_client *_client,
              uint32_t _file_type,
              fuse_ino_t _ino = 0);

    ~nfs_inode();

    /**
     * Does this nfs_inode have cache allocated?
     * It correctly checks cache for both directory and file inodes and it
     * only checks if the cache is allocated and not whether cache has some
     * data.
     *
     * Note: Only files/directories which are open()ed will have cache
     *       allocated, also since directory cache doubles as DNLC, for
     *       directories if at least one file/subdir inside this directory is
     *       looked up by fuse, the cache will be allocated.
     *
     * LOCKS: None.
     */
    bool has_cache() const
    {
        if (is_dir()) {
            return has_dircache();
        } else if (is_regfile()) {
            return has_filecache();
        }

        return false;
    }

    /**
     * Is the inode cache (filecache_handle or dircache_handle) empty?
     *
     * Note: This returns the current inode cache status at the time of this
     *       call, it my change right after this function returns. Keep this
     *       in mind when using the result.
     *
     * LOCKS: None.
     */
    bool is_cache_empty() const
    {
        if (is_regfile()) {
            return !has_filecache() || filecache_handle->is_empty();
        } else if (is_dir()) {
            return !has_dircache() || dircache_handle->is_empty();
        } else {
            return true;
        }
    }

    /**
     * Allocate file cache if not already allocated.
     * This must be called from code that returns an inode after a regular
     * file is opened or created.
     * It's a no-op if the filecache is already allocated.
     *
     * LOCKS: If not already allocated it'll take exclusive ilock_1.
     */
    void alloc_filecache()
    {
        assert(is_regfile());

        if (filecache_alloced) {
            // Once allocated it cannot become null again.
            assert(filecache_handle);
            return;
        }

        std::unique_lock<std::shared_mutex> lock(ilock_1);
        if (!filecache_handle) {
            assert(!filecache_alloced);

            if (aznfsc_cfg.filecache.enable && aznfsc_cfg.filecache.cachedir) {
                const std::string backing_file_name =
                    std::string(aznfsc_cfg.filecache.cachedir) + "/" + std::to_string(get_fuse_ino());
                filecache_handle =
                    std::make_shared<bytes_chunk_cache>(this, backing_file_name.c_str());
            } else {
                filecache_handle = std::make_shared<bytes_chunk_cache>(this);
            }
            filecache_alloced = true;
        }
    }

    /**
     * We split the truncate operation in two separate apis truncate_start()
     * and truncate_end(). truncate_start() must be called before issuing the
     * SETATTR RPC and truncate_end() must be called from SETATTR callback.
     * truncate_start() grabs the flush_lock to ensure no new flush/commit
     * operations can be issued for this inode, and waits for any ongoing
     * flush/commit operations to complete, before truncating the filecache to
     * the new size.
     * truncate_end() calls bytes_chunk_cache::truncate(post=true) to finish
     * cache truncate and calls flush_unlock() to release the flush_lock
     * held by truncate_start().
     * This two apis together ensure that any flush/commit operation cannot
     * change the file size after truncate sets it.
     */
    bool truncate_start(size_t size);
    void truncate_end(size_t size);

    /**
     * This MUST be called only after has_filecache() returns true, else
     * there's a possibility of data race, as the returned filecache_handle
     * ref may be updated by alloc_filecache() right after get_filecache()
     * returns and while the caller is accessing the shared_ptr.
     * So f.e., calling "if (get_filecache())" to check presence of cache is
     * not safe as get_filecache() is being used as a boolean here so it calls
     * "shared_ptr::operator bool()" which returns true even while the
     * shared_ptr is being initialized by alloc_filecache(), thus it causes
     * a data race.
     * Once filecache_handle is allocated by alloc_filecache() it remains set
     * for the life of the inode, so we can safely use the shared_ptr w/o the
     * inode lock.
     *
     * Note: This MUST be called only when has_filecache() returns true.
     *
     * LOCKS: None.
     */
    std::shared_ptr<bytes_chunk_cache>& get_filecache()
    {
        assert(is_regfile());
        assert(filecache_alloced);
        assert(filecache_handle);

        return filecache_handle;
    }

    const std::shared_ptr<bytes_chunk_cache>& get_filecache() const
    {
        assert(is_regfile());
        assert(filecache_alloced);
        assert(filecache_handle);

        return filecache_handle;
    }

    /**
     * External users of this nfs_inode can check for presence of filecache by
     * calling has_filecache().
     *
     * LOCKS: None.
     */
    bool has_filecache() const
    {
        assert(is_regfile());
        assert(!filecache_alloced || filecache_handle);

        return filecache_alloced;
    }

    /**
     * Allocate directory cache if not already allocated.
     * This must be called from code that returns an inode after a directory
     * is opened or created.
     * It's a no-op if the dircache is already allocated.
     *
     * LOCKS: If not already allocated it'll take exclusive ilock_1.
     */
    void alloc_dircache(bool newly_created_directory = false)
    {
        assert(is_dir());

        if (dircache_alloced) {
            // Once allocated it cannot become null again.
            assert(dircache_handle);
            return;
        }

        std::unique_lock<std::shared_mutex> lock(ilock_1);
        if (!dircache_handle) {
            assert(!dircache_alloced);

            dircache_handle = std::make_shared<readdirectory_cache>(client, this);
            /*
             * If this directory is just created, mark it as "confirmed".
             */
            if (newly_created_directory) {
                dircache_handle->set_confirmed();
            }

            dircache_alloced = true;
        }
    }

    /**
     * This MUST be called only after has_dircache() returns true.
     * See comment above get_filecache().
     *
     * Note: This MUST be called only when has_dircache() returns true.
     *
     * LOCKS: None.
     */
    std::shared_ptr<readdirectory_cache>& get_dircache()
    {
        assert(is_dir());
        assert(dircache_alloced);
        assert(dircache_handle);

        return dircache_handle;
    }

    const std::shared_ptr<readdirectory_cache>& get_dircache() const
    {
        assert(is_dir());
        assert(dircache_alloced);
        assert(dircache_handle);

        return dircache_handle;
    }

    /**
     * External users of this nfs_inode can check for presence of dircache by
     * calling has_dircache().
     *
     * LOCKS: None.
     */
    bool has_dircache() const
    {
        assert(is_dir());
        assert(!dircache_alloced || dircache_handle);

        return dircache_alloced;
    }

    /**
     * Allocate readahead_state if not already allocated.
     * This must be called from code that returns an inode after a file
     * is opened or created.
     * It's a no-op if the rastate is already allocated.
     *
     * LOCKS: If not already allocated it'll take exclusive ilock_1.
     */
    void alloc_rastate()
    {
        assert(is_regfile());

        if (rastate_alloced) {
            // Once allocated it cannot become null again.
            assert(readahead_state);
            return;
        }

        std::unique_lock<std::shared_mutex> lock(ilock_1);
        /*
         * readahead_state MUST only be created if filecache_handle is set.
         */
        assert(filecache_handle);
        if (!readahead_state) {
            assert(!rastate_alloced);
            readahead_state = std::make_shared<ra_state>(client, this);
            rastate_alloced = true;
        }
    }

    /**
     * This MUST be called only after has_rastate() returns true.
     * See comment above get_filecache().
     *
     * Note: This MUST be called only when has_rastate() returns true.
     *
     * LOCKS: None.
     */
    const std::shared_ptr<ra_state>& get_rastate() const
    {
        assert(is_regfile());
        assert(rastate_alloced);
        assert(readahead_state);

        return readahead_state;
    }

    std::shared_ptr<ra_state>& get_rastate()
    {
        assert(is_regfile());
        assert(rastate_alloced);
        assert(readahead_state);

        return readahead_state;
    }

    /**
     * External users of this nfs_inode can check for presence of readahead
     * state by calling has_rastate().
     *
     * LOCKS: None.
     */
    bool has_rastate() const
    {
        assert(is_regfile());
        assert(!rastate_alloced || readahead_state);

        return rastate_alloced;
    }

    /**
     * Allocate fcsm (flush-commit state machine) if not already allocated.
     * This must be called from code that returns an inode after a file
     * is opened or created.
     * It's a no-op if the fcsm is already allocated.
     *
     * LOCKS: If not already allocated it'll take exclusive ilock_1.
     */
    void alloc_fcsm()
    {
        assert(is_regfile());

        if (fcsm_alloced) {
            // Once allocated it cannot become null again.
            assert(fcsm);
            return;
        }

        std::unique_lock<std::shared_mutex> lock(ilock_1);
        /*
         * fcsm MUST only be created if filecache_handle is set.
         */
        assert(filecache_handle);
        if (!fcsm) {
            assert(!fcsm_alloced);
            fcsm = std::make_shared<struct fcsm>(client, this);
            fcsm_alloced = true;
        }
    }

    /**
     * This MUST be called only after has_fcsm() returns true.
     * See comment above get_filecache().
     *
     * Note: This MUST be called only when has_fcsm() returns true.
     *
     * LOCKS: None.
     */
    const std::shared_ptr<struct fcsm>& get_fcsm() const
    {
        assert(is_regfile());
        assert(fcsm_alloced);
        assert(fcsm);

        return fcsm;
    }

    std::shared_ptr<struct fcsm>& get_fcsm()
    {
        assert(is_regfile());
        assert(fcsm_alloced);
        assert(fcsm);

        return fcsm;
    }

    /**
     * External users of this nfs_inode can check for presence of fcsm
     * by calling has_fcsm().
     *
     * LOCKS: None.
     */
    bool has_fcsm() const
    {
        assert(is_regfile());
        assert(!fcsm_alloced || fcsm);

        return fcsm_alloced;
    }

    /**
     * This must be called from all paths where we respond to a fuse request
     * that amounts to open()ing a file/directory. Once a file/directory is
     * open()ed, application can call all the POSIX APIs that take an fd, so if
     * we defer anything in the nfs_inode constructor (as we are not sure if
     * application will call any POSIX API on the file) perform the allocation
     * here.
     *
     * LOCKS: Exclusive ilock_1.
     */
    void on_fuse_open(enum fuse_opcode optype)
    {
        /*
         * Only these fuse ops correspond to open()/creat() which return an
         * fd.
         */
        assert((optype == FUSE_CREATE) ||
               (optype == FUSE_OPEN) ||
               (optype == FUSE_OPENDIR));

        opencnt++;

        AZLogDebug("[{}:{}] on_fuse_open({}), new opencnt is {}",
                   get_filetype_coding(), ino, (int) optype, opencnt.load());

        if (is_regfile()) {
            /*
             * Allocate filecache_handle before readahead_state and fcsm as we
             * assert for filecache_handle in alloc_rastate() and alloc_fcsm().
             */
            alloc_filecache();
            alloc_rastate();
            alloc_fcsm();
        } else if (is_dir()) {
            alloc_dircache();
        }
    }

    /**
     * This must be called from all paths where we respond to a fuse request
     * that makes fuse aware of this inode. It could be lookup or readdirplus.
     * Once fuse receives an inode it can call operations like lookup/getattr.
     * See on_fuse_open() which is called by paths which not only return the inode
     * but also an fd to the application, f.e. creat().
     *
     * LOCKS: Exclusive ilock_1.
     */
    void on_fuse_lookup(enum fuse_opcode optype)
    {
        /*
         * Only these fuse ops correspond to operations that return an inode
         * to fuse, but don't cause a fd to be returned to the application.
         * FUSE_READDIR and FUSE_READDIRPLUS are the only other ops that return
         * inode to fuse but we don't call on_fuse_lookup() for those as they
         * could be a lot and most commonly applications will not perform IO
         * on all files returned by readdir/readdirplus.
         */
        assert((optype == FUSE_LOOKUP) ||
               (optype == FUSE_MKNOD) ||
               (optype == FUSE_MKDIR) ||
               (optype == FUSE_SYMLINK));

        if (is_regfile()) {
            assert(optype == FUSE_LOOKUP ||
                   optype == FUSE_MKNOD);
        } else if (is_dir()) {
            assert(optype == FUSE_LOOKUP ||
                   optype == FUSE_MKDIR);
            /*
             * We have a unified cache for readdir/readdirplus and lookup, so
             * we need to create the readdir cache on lookup.
             */
            alloc_dircache(optype == FUSE_MKDIR);
        }
    }

    /**
     * Return the fuse inode number for this inode.
     */
    fuse_ino_t get_fuse_ino() const
    {
        assert(ino != 0);
        return ino;
    }

    /**
     * Return the generation number for this inode.
     */
    uint64_t get_generation() const
    {
        assert(generation != 0);
        return generation;
    }

    /**
     * Get ref to the superblock structure.
     * Caller must ensure that any access to the superblock structure is done
     * while duly holding the sb_lock.
     */
    static struct nfs_superblock& get_sb()
    {
        return sb;
    }

    static std::shared_mutex& get_sb_lock()
    {
        return sb.sb_lock;
    }

    /**
     * Use this to safely fetch the inode attributes.
     *
     * LOCKS: Shared ilock_1.
     */
    struct stat get_attr() const
    {
        /*
         * Following inode lock will be released after attr is copied to the
         * caller.
         */
        std::shared_lock<std::shared_mutex> lock(ilock_1);
        return attr;
    }

    /**
     * Caller MUST hold shared ilock_1.
     */
    const struct stat& get_attr_nolock() const
    {
        return attr;
    }

    /**
     * Caller MUST hold exclusive ilock_1.
     */
    struct stat& get_attr_nolock()
    {
        return attr;
    }

    /**
     * Populate 'fattr' with this inode's attributes.
     */
    void fattr3_from_stat(struct fattr3& fattr) const;

    int get_silly_rename_level()
    {
        return silly_rename_level++;
    }

    /**
     * Return the NFS fileid. This is also the inode number returned by
     * stat(2).
     * Caller MUST hold ilock_1.
     */
    uint64_t get_fileid() const
    {
        assert(attr.st_ino != 0);
        return attr.st_ino;
    }

    /**
     * Marks the attribute cache as expired for the inode.
     * Any call to attr_cache_expired() after this call MUST return true and
     * hence caller MUST NOT try to use the saved attribute cache of this inode.
     * Typically this is called when a file/dir is deleted and we don't want
     * any subsequent getattr call to return attributes for deleted file/dir.
     */
    void invalidate_attribute_cache()
    {
        // Set it to 0 to force attr_cache_expired() to always return true.
        attr_timeout_timestamp = 0;
    }

    /**
     * Checks whether inode->attr is expired as per the current actimeo.
     */
    bool attr_cache_expired() const
    {
        /*
         * This is set in the constructor as a newly created nfs_inode always
         * has attributes cached in nfs_inode::attr.
         */
        assert(attr_timeout_timestamp != -1);

        const int64_t now_msecs = get_current_msecs();
        const bool attr_expired = (attr_timeout_timestamp < now_msecs);

        return attr_expired;
    }

    void set_truncate_in_progress()
    {
        assert(!truncate_in_progress);
        truncate_in_progress = true;
    }

    void clear_truncate_in_progress()
    {
        assert(truncate_in_progress);
        truncate_in_progress = false;
    }

    bool is_truncate_in_progress() const
    {
        return truncate_in_progress;
    }

    int64_t get_cached_filesize() const
    {
        assert(is_regfile());
        assert(has_filecache());

        const int64_t cached_filesize = get_filecache()->get_cache_size();
        assert(cached_filesize >= 0);
        assert(cached_filesize <= (off_t) AZNFSC_MAX_FILE_SIZE);
        return cached_filesize;
    }

    /**
     * Get the estimated file size on the server. Note that this is based on
     * cached attributes hence the returned size is at best an estimate and may
     * not exactly match the most recent file size on the server. Callers are
     * warned about that and they should not use it for any hard failures that
     * may be in violation of the protocol.
     * If cached attributes have expired (as per the configured actimeo) then
     * it returns -1 and caller must handle it, unless caller does not care
     * and passed dont_check_expiry as true.
     *
     * Note: Use get_file_sizes() if you need both server and client file
     *       sizes.
     */
    int64_t get_server_file_size(const bool dont_check_expiry = false) const
    {
        /*
         * XXX We access attr.st_size w/o holding ilock_1 as aligned access
         *     to uint64_t should be safe, moreover we want to avoid the
         *     ilock_1 in the read fastpath.
         */
        assert((size_t) attr.st_size <= AZNFSC_MAX_FILE_SIZE);

        if (dont_check_expiry) {
            return attr.st_size;
        }

        return attr_cache_expired() ? -1 : attr.st_size;
    }

    /**
     * Get client's most recent estimate of the file size.
     * Note that unlike get_server_file_size() which estimates the file size
     * strictly as present on the server, this is a size estimate that matters
     * from the client applications' pov. It considers the cached filesize
     * also and returns the max of the server file size and cached filesize.
     * Note that cached filesize corresponds to data which has not yet been
     * synced with the server, so won't be reflected in the server file size,
     * but reader applications would be interested in cached data too.
     *
     * Returns -1 to indicate that we do not have a good estimate of the file
     * size. Since we always know the cached filesize for sure, this happens
     * when we do not know the recent server file size (within the last
     * attributes cache timeout period).
     *
     * Note: Use get_file_sizes() if you need both server and client file
     *       sizes.
     */
    int64_t get_client_file_size() const
    {
        const int64_t sfsize = get_server_file_size();

        if (sfsize == -1) {
            /*
             * We don't know server size, so we cannot estimate
             * effective client file size for sure.
             */
            return -1;
        }

        return std::max(sfsize, get_cached_filesize());
    }

    /**
     * Get both server and client file sizes.
     * Use this when you need to know both server and client file sizes
     * atomically, i.e., it will either return -1 for both client and server
     * file sizes or it'll return valid value for both.
     */
    void get_file_sizes(int64_t& cfsize, int64_t& sfsize) const
    {
        sfsize = get_server_file_size();

        if (sfsize == -1) {
            cfsize = -1;
            // We don't know either.
            assert((cfsize == -1) && (sfsize == -1));
            return;
        }

        cfsize = std::max(sfsize, get_cached_filesize());

        // We know both.
        assert((cfsize != -1) && (sfsize != -1));
    }

    /**
     * This must be called from copy_to_cache() whenever we successfully copy
     * some data to filecache.
     *
     * Note: It doesn't update attr.ctime and attr.mtime deliberately as this
     *       is not authoritative info and we would want to fetch attributes
     *       from server when needed.
     */
    void on_cached_write(off_t offset, size_t length)
    {
        [[maybe_unused]]
        const off_t new_size = offset + length;
        [[maybe_unused]]
        const off_t cached_filesize = (off_t) get_filecache()->get_cache_size();

        /*
         * on_cached_write() is called after set_uptodate() so cached_filesize
         * must already have been updated.
         */
        assert(cached_filesize >= new_size);
    }

    /**
     * Check if [offset, offset+length) lies within the current RA window.
     * bytes_chunk_cache would call this to find out if a particular membuf
     * can be purged. Membufs in RA window would mostly be used soon and
     * should not be purged.
     * Note that it checks if there is any overlap and not whether it fits
     * entirely within the RA window.
     *
     * LOCKS: None.
     */
    bool in_ra_window(uint64_t offset, uint64_t length) const;

    /**
     * Is this file currently open()ed by any application.
     */
    bool is_open() const
    {
        return opencnt > 0;
    }

    /**
     * Return the nfs_inode corresponding to filename in the directory
     * represented by this inode.
     * It'll hold a lookupcnt ref on the returned inode and caller must drop
     * that ref by calling decref().
     *
     * Note: Shared readdircache_lock_2.
     */
    struct nfs_inode *dnlc_lookup(const char *filename,
                                  bool *negative_confirmed = nullptr) const
    {
        assert(is_dir());

        if (has_dircache()) {
            struct nfs_inode *inode =
                dircache_handle->dnlc_lookup(filename, negative_confirmed);
            // dnlc_lookup() must have held a lookupcnt ref.
            assert(!inode || inode->lookupcnt > 0);

            return inode;
        }

        return nullptr;
    }

    /**
     * Add DNLC entry "filename -> inode".
     */
    void dnlc_add(const char *filename, struct nfs_inode *inode)
    {
        assert(filename);
        assert(inode);
        assert(inode->magic == NFS_INODE_MAGIC);
        assert(is_dir());

        /*
         * Directory inodes returned by READDIRPLUS won't have dircache
         * allocated, and fuse may call lookup on them, allocate dircache now
         * before calling dnlc_add().
         */
        alloc_dircache();

        dircache_handle->dnlc_add(filename, inode);
    }

    /*
     * Find nfs_inode for 'filename' in this directory.
     * It first searches in dnlc and if not found there makes a sync LOOKUP
     * call. If sync LOOKUP fails it returns nullptr and sets failure_status
     * to a +ve errno value.
     * This calls revalidate().
     */
    struct nfs_inode *lookup(const char *filename,
                             int *failure_status = nullptr);

    /**
     * Note usecs when the last cached write was received for this inode.
     * A cached write is not a direct application write but writes cached
     * by fuse kernel driver and then dispatched later as possibly bigger
     * writes. These have fi->writepage set.
     * We use this to decide if we need to no-op a setattr(mtime) call.
     * Note that fuse does not provide filesystems a way to convey "nocmtime",
     * i.e. fuse should not call setattr(mtime) to set file mtime during
     * cached write calls. Fuse will not call setattr(mtime) if we are not
     * using kernel cache as it expects the filesystem to manage mtime itself,
     * but if kernel cache is used fuse calls setattr(mtime) very often which
     * slows down the writes. Since our backing filesystem is NFS it'll take
     * care of updating mtime and hence we can ignore such setattr(mtime)
     * calls. To distinguish setattr(mtime) done as a result of writes from
     * ones that are done as a result of explicit utime() call by application,
     * we check if we have seen cached write recently.
     */
     void stamp_cached_write()
     {
         if (aznfsc_cfg.cache.data.kernel.enable) {
             last_cached_write = get_current_usecs();
         }
     }

     /**
      * Should we skip setattr(mtime) call for this inode?
      * See discussion above stamp_cached_write().
      * new_mtime is the updated mtime that fuse wants to set.
      * If we propose to skip mtime update, and inode's cached mtime is older
      * than new_mtime, we refresh inode's cached mtime and ctime.
      *
      * LOCKS: Exclusive ilock_1.
      */
     bool skip_mtime_update(const struct timespec& new_mtime)
     {
        // Caller must pass a valid mtime.
        assert(new_mtime.tv_sec != 0);

        static const int64_t one_sec = 1000 * 1000ULL;
        const int64_t now_usecs = get_current_usecs();
        const int64_t now_msecs = now_usecs / 1000ULL;
        const bool attrs_valid = (attr_timeout_timestamp >= now_msecs);
        /*
         * Kernel can be sending multiple writes/setattr in parallel over
         * multiple fuse threads, hence last_cached_write may be greater
         * than now_usecs.
         */
        const bool write_seen_recently =
            ((last_cached_write > now_usecs) ||
             ((now_usecs - last_cached_write) < one_sec));

        /*
         * We skip setattr(mtime) if we have seen a cached write in the last
         * one sec and if we have valid cached attributes for this inode.
         * Note that we need to return updated attributes in setattr response.
         */
        const bool skip = (write_seen_recently && attrs_valid);

        if (skip) {
            std::unique_lock<std::shared_mutex> lock(ilock_1);
            if (compare_timespec(new_mtime, attr.st_mtim) > 0) {
                attr.st_mtim = new_mtime;
                if (compare_timespec(new_mtime, attr.st_ctim) > 0) {
                    attr.st_ctim = new_mtime;
                }
            }
        }

        return skip;
     }

    /**
     * Is commit pending for this inode?
     */
    bool is_commit_pending() const
    {
        assert(commit_state != commit_state_t::INVALID);
        return (commit_state == commit_state_t::NEEDS_COMMIT);
    }

    /**
     * set needs_commit state for this inode.
     * Note this is set to let flushing task know that commit is pending and start commit task.
     */
    void set_commit_pending()
    {
        // Commit can be set to pending only if it is in commit_not_needed state.
        assert(commit_state == commit_state_t::COMMIT_NOT_NEEDED);
        commit_state = commit_state_t::NEEDS_COMMIT;
    }

    /**
     * Is commit in progress for this inode?
     */
    bool is_commit_in_progress() const
    {
        assert(commit_state != commit_state_t::INVALID);
        return (commit_state == commit_state_t::COMMIT_IN_PROGRESS);
    }

    /**
     * Set commit_in_progress state for this inode.
     */
    void set_commit_in_progress()
    {
        assert(commit_state != commit_state_t::INVALID);
        assert(commit_state != commit_state_t::COMMIT_IN_PROGRESS);
        commit_state = commit_state_t::COMMIT_IN_PROGRESS;
    }

    /**
     * Clear commit_in_progress state for this inode.
     */
    void clear_commit_in_progress()
    {
        assert(commit_state == commit_state_t::COMMIT_IN_PROGRESS);
        commit_state = commit_state_t::COMMIT_NOT_NEEDED;
    }

    /**
     * Increment lookupcnt of the inode.
     */
    void incref() const
    {
        lookupcnt++;

        AZLogDebug("[{}] lookupcnt incremented to {} (dircachecnt: {}, "
                   "forget_expected: {})",
                   ino, lookupcnt.load(), dircachecnt.load(),
                   forget_expected.load());
    }

    /**
     * Decrement lookupcnt of the inode and delete it if lookupcnt
     * reaches 0.
     * 'cnt' is the amount by which the lookupcnt must be decremented.
     * This is usually the nlookup parameter passed by fuse FORGET, when
     * decref() is called from fuse FORGET, else it's 1.
     * 'from_forget' should be set to true when calling decref() for
     * handling fuse FORGET. Note that fuse FORGET is special as it
     * conveys important information about the inode. Since FORGET may
     * mean that fuse VFS does not have any reference to the inode, we can
     * use that to perform some imp tasks like, purging the readdir cache
     * for directory inodes. This is imp as it makes the client behave
     * like the kernel NFS client where flushing the cache causes the
     * directory cache to be flushed, and this can be a useful technique
     * in cases where NFS client is not being consistent with the server.
     */
    void decref(size_t cnt = 1, bool from_forget = false);

    /**
     * Returns true if inode is FORGOTten by fuse.
     * Forgotten inodes will not be referred by fuse in any api call.
     * Note that forgotten inodes may still hang around if they are
     * referenced by at least one directory_entry cache.
     */
    bool is_forgotten() const
    {
        return (lookupcnt == 0);
    }

    /**
     * Is this inode cached by any readdirectory_cache?
     */
    bool is_dircached() const
    {
        return (dircachecnt > 0);
    }

    nfs_client *get_client() const
    {
        assert(client != nullptr);
        return client;
    }

    const struct nfs_fh3& get_fh() const
    {
        return fh.get_fh();
    }

    uint32_t get_crc() const
    {
        return crc;
    }

    bool is_dir() const
    {
        return (file_type == S_IFDIR);
    }

    // Is regular file?
    bool is_regfile() const
    {
        return (file_type == S_IFREG);
    }

    /**
     * Short character code for file_type, useful for logs.
     */
    char get_filetype_coding() const
    {
#ifndef ENABLE_NON_AZURE_NFS
        assert(file_type == S_IFDIR ||
               file_type == S_IFREG ||
               file_type == S_IFLNK);
#endif
        return (file_type == S_IFDIR) ? 'D' :
               ((file_type == S_IFLNK) ? 'S' :
                ((file_type == S_IFREG) ? 'R' : 'U'));
    }

    /**
     * Get the minimum attribute cache timeout value in seconds, to be used
     * for this file.
     */
    int get_actimeo_min() const;

    /**
     * Get the maximum attribute cache timeout value in seconds, to be used
     * for this file.
     */
    int get_actimeo_max() const;

    /**
     * Get current attribute cache timeout value (in secs) for this inode.
     * Note that the attribute cache timeout moves between the min and max
     * values returned by the above methods, depending on whether the last
     * revalidation attempt was a success or not.
     */
    int get_actimeo() const
    {
        // If not set, return the min configured value.
        return (attr_timeout_secs != -1) ? attr_timeout_secs.load()
                                         : get_actimeo_min();
    }
    
    /**
     * Copy application data into the inode's file cache.
     *
     * bufv: fuse_bufvec containing application data, passed by fuse.
     * offset: starting offset in file where the data should be written.
     * extent_left: after this copy what's the left edge of the longest dirty
     *              extent containing this latest write.
     * extent_right: after this copy what's the right edge of the longest dirty
     *               extent containing this latest write.
     * Caller can use the extent length information to decide if it wants to
     * dispatch an NFS write right now or wait and batch more, usually by
     * comparing it with the wsize value.
     *
     * Returns 0 if copy was successful, else a +ve errno value indicating the
     * error. This can be passed as-is to the rpc_task reply_error() method to
     * convey the error to fuse.
     * EAGAIN is the special error code that would mean that caller must retry
     * the current copy_to_cache() call.
     *
     * Note: The membufs to which the data is copied will be marked dirty and
     *       uptodate once copy_to_cache() returns.
     */
    int copy_to_cache(const struct fuse_bufvec* bufv,
                      off_t offset,
                      uint64_t *extent_left,
                      uint64_t *extent_right);

    /**
     * Flush the dirty file cache represented by filecache_handle and wait
     * till all dirty data is sync'ed with the NFS server. Only dirty data
     * in the given range is flushed if provided, else all dirty data is
     * flushed.
     * Note that filecache_handle is the only writeback cache that we have
     * and hence this only flushes that.
     * For a non-reg file inode this will be a no-op.
     * Returns 0 on success and a positive errno value on error.
     *
     * Note: This doesn't take the inode lock but instead it would grab the
     *       filecache_handle lock and get the list of dirty membufs at this
     *       instant and flush those. Any new dirty membufs added after it
     *       queries the dirty membufs list, are not flushed.
     *
     * Note: This grabs the inode flush_lock to ensure that it doesn't
     *       initiate any new flush operations while some truncate call is in
     *       progress (which must have held the flush_lock).
     */
    int flush_cache_and_wait();

    /**
     * Wait for currently flushing/committing membufs to complete.
     * It will wait till the currently flushing membufs complete and then
     * issue a commit and wait for that. If no flush is ongoing but there's
     * commit_pending data, it'll commit that and return after the commit
     * completes.
     * Returns 0 on success and a positive errno value on error.
     * Once it returns, commit_pending will be 0.
     *
     * Note : Caller must hold the inode flush_lock to ensure that
     *        no new membufs are added till this call completes.
     *        It may release the flush_lock() if it has to wait for ongoing
     *        flush/write requests to complete, but it'll exit with flush_lock
     *        held.
     */
    int wait_for_ongoing_flush();

    /**
     * commit_membufs() is called to commit uncommitted membufs to the Blob.
     * It creates commit RPC and sends it to the NFS server.
     */
    void commit_membufs(std::vector<bytes_chunk> &bcs);

    /**
     * switch_to_stable_write() is called to switch the inode to stable write
     * mode. It waits for all ongoing flush and subsequent commit to complete.
     * If not already scheduled, it'll perform an explicit commit after the
     * flush complete.
     * Post that it'll mark inode for stable write and return. From then on
     * any writes to this inode will be sent as stable writes.
     */
    void switch_to_stable_write();

    /**
     * Check if stable write is required for the given offset.
     * Given offset is the start of contiguous dirty membufs that need to be
     * flushed to the Blob.
     */
    bool check_stable_write_required(off_t offset);

    /**
     * Wait for ongoing commit operation to complete.
     */
    void wait_for_ongoing_commit();

    /**
     * Sync the dirty membufs in the file cache to the NFS server.
     * All contiguous dirty membufs are clubbed together and sent to the
     * NFS server in a single write call.
     * If parent_task is non-null, it's the frontend write task that must be
     * completed once all these flushes complete. This can be used by the
     * caller in case of memory pressure when we want to delay fuse callbacks
     * to slow down writes which can cause more memory to be dirtied.
     *
     * Note: sync_membufs() can free parent_task if all issued backend
     *       writes complete before sync_membufs() could return.
     *       DO NOT access parent_task after sync_membufs() returns.
     */
    void sync_membufs(std::vector<bytes_chunk> &bcs, bool is_flush,
                      struct rpc_task *parent_task = nullptr);

    /**
     * Called when last open fd is closed for a file/dir.
     * inode release() drops an opencnt on the inode.
     * If this was not the last opencnt or if it's called for a dir, then it
     * doesn't do anything more, else it does the following for regular files:
     * - If release is called for a silly-renamed file, then it drops the
     *   cache (no need to flush as the file ie being deleted anyways) and
     *   unlinks the file.
     * - If not a silly-renamed file, then it flushes the cache.
     *   This is needed for CTO consistency.
     *
     * When called from a fuse handler, req parameter must be passed and it'll
     * arrange to call the fuse callback for req, once it completes the above.
     * When not called from a fuse handler, req must not be passed.
     *
     * It returns true if it wants the caller to call the fuse callback, else
     * it has already arranged to call the fuse callback and caller doesn't
     * need to call.
     */
    bool release(fuse_req_t req = nullptr);

    /**
     * Lock the inode for flushing.
     *
     * Note: DO NOT TAKE flush_lock WHILE WAITING FOR NFS WRITE RPC RESPONSE.
     *       THIS CAN CAUSE A DEADLOCK AS write_iov_callback()->on_flush_complete()
     *       TAKES THE flush_lock() TOO.
     */
    void flush_lock() const;
    void flush_unlock() const;

    /**
     * Revalidate the inode.
     * Revalidation is done by querying the inode attributes from the server
     * and comparing them against the saved attributes. If the freshly fetched
     * attributes indicate "change in file/dir content" by indicators such as
     * mtime and/or size, then we invalidate the cached data of the inode.
     * If 'force' is false then inode attributes are fetched only if the last
     * fetched attributes are older than attr_timeout_secs, while if 'force'
     * is true we fetch the attributes regardless. This could f.e., be needed
     * when a file/dir is opened (for close-to-open consistency reasons).
     * Other reasons for force invalidating the caches could be if file/dir
     * was updated by calls to write()/create()/rename().
     *
     * LOCKS: If revalidating it'll take exclusive ilock_1.
     */
    void revalidate(bool force = false);

    /**
     * Update the inode given that we have received fresh attributes from
     * the server. These fresh attributes could have been received as
     * postop (and preop) attributes to any of the requests or it could be a
     * result of explicit GETATTR call that we make from revalidate() when the
     * attribute cache times out.
     * We process the freshly received attributes as follows:
     * - If the ctime has not changed, then the file has not changed, and
     *   we don't do anything, else
     * - If mtime has changed then the file data and metadata has changed
     *   and we need to drop the caches and update nfs_inode::attr, else
     * - If just ctime has changed then only the file metadata has changed
     *   and we update nfs_inode::attr from the received attributes.
     *
     * Returns true if preattr/postattr indicate that file has changed (either
     * metadata, or both) since we cached it, false indicates that file has not
     * changed.
     *
     * LOCKS: Caller must take exclusive ilock_1.
     */
    bool update_nolock(const struct fattr3 *postattr,
                       const struct wcc_attr *preattr = nullptr);

    /**
     * Convenience function that calls update_nolock() after holding the
     * inode lock.
     *
     * LOCKS: Exclusive ilock_1.
     *
     * XXX This MUST be called whenever we get fresh attributes for a file,
     *     most commonly as post-op attributes along with some RPC response.
     */
    bool update(const struct fattr3 *postattr,
                const struct wcc_attr *preattr = nullptr)
    {
        std::unique_lock<std::shared_mutex> lock(ilock_1);
        return update_nolock(postattr, preattr);
    }

    /**
     * Force update inode->attr with fattr.
     * Unlike update_nolock() it doesn't invalidate the cache.
     * Use it when you know that cache need not be invalidated, as it's
     * already done.
     */
    void force_update_attr_nolock(const struct fattr3& fattr);

    void force_update_attr(const struct fattr3& fattr)
    {
        std::unique_lock<std::shared_mutex> lock(ilock_1);
        force_update_attr_nolock(fattr);
    }

    /**
     * Invalidate/zap the cached data. This will correctly invalidate cached
     * data for both file and directory caches.
     * By default it will just mark the cache as invalid and the actual purging
     * will be deferred till the next access to the cache, and will be done in
     * the context that accesses the cache, but the caller can request the cache
     * to be purged inline by passing purge_now as true.
     *
     * LOCKS: None when purge_now is false.
     *        When purge_now is true, exclusive chunkmap_lock_43 for files and
     *        exclusive readdircache_lock_2 for directories.
     */
    void invalidate_cache(bool purge_now = false)
    {
        if (is_dir()) {
            if (has_dircache()) {
                assert(dircache_handle);
                AZLogDebug("[{}] Invalidating dircache", get_fuse_ino());
                dircache_handle->invalidate();

                if (purge_now) {
                    AZLogDebug("[{}] (Purgenow) Purging dircache", get_fuse_ino());
                    dircache_handle->clear();
                    AZLogDebug("[{}] (Purgenow) Purged dircache", get_fuse_ino());
                }
            }
        } else if (is_regfile()) {
            if (has_filecache()) {
                assert(filecache_handle);
                AZLogDebug("[{}] Invalidating filecache", get_fuse_ino());
                filecache_handle->invalidate();

                if (purge_now) {
                    AZLogDebug("[{}] (Purgenow) Purging filecache", get_fuse_ino());
                    filecache_handle->clear(true /* shutdown */);
                    AZLogDebug("[{}] (Purgenow) Purged filecache", get_fuse_ino());
                }
            }
        }
    }

    /**
     * Store the first error encountered while writing dirty
     * membuf to Blob.
     */
    void set_write_error(int error)
    {
        assert(error > 0);

        if (this->write_error == 0) {
            this->write_error = error;
        }
    }

    /**
     * Returns the error, saved by prior call to set_write_error().
     * Can be 0 for success, or a +ve errno value.
     */
    int get_write_error() const
    {
        assert(write_error >= 0);
        return write_error;
    }

    /**
     * Set the stable write flag.
     */
    void set_stable_write()
    {
        assert(!stable_write);
        stable_write = true;

        // Only unstable writes use putblock_filesize.
        putblock_filesize = AZNFSC_BAD_OFFSET;
    }

    /**
     * Check if the inode has stable write flag set.
     */
    bool is_stable_write() const
    {
        return stable_write;
    }

    /**
     * Directory cache lookup method.
     *
     * cookie: offset in the directory from which the entries should be listed.
     * max_size: do not return entries more than these many bytes.
     * results: returned entries are populated in this vector. Each of these
     *          entry has a shared_ptr ref held so they can be safely used even
     *          if the actual directory_entry in readdirectory_cache is deleted.
     * eof: will be set if there are no more entries in the directory, after
     *      the last entry returned.
     * readdirplus: consumer of the returned directory entries is readdirplus.
     *              This will affect how the size of entries is added while
     *              comparing with max_size. If readdirplus is true, then we
     *              account for attribute size too, since readdirplus would
     *              be sending attributes too.
     */
    void lookup_dircache(
        cookie3 cookie,
        size_t max_size,
        std::vector<std::shared_ptr<const directory_entry>>& results,
        bool& eof,
        bool readdirplus);
};
#endif /* __NFS_INODE_H__ */
