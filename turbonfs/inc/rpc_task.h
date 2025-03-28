#ifndef __RPC_TASK_H__
#define __RPC_TASK_H__

#include <cstddef>
#include <string>
#include <mutex>
#include <stack>
#include <shared_mutex>
#include <vector>
#include <set>
#include <thread>

#include "nfs_client.h"
#include "file_cache.h"
#include "rpc_stats.h"
#include "log.h"

// Maximum number of simultaneous rpc tasks (sync + async).
#define MAX_OUTSTANDING_RPC_TASKS 65536

// Maximum number of simultaneous async rpc tasks.
#define MAX_ASYNC_RPC_TASKS 1024

/**
 * Update cached inode attributes from freshly received postop attributes.
 * This should be called for (read) operations which do not update file/dir
 * and hence NFS server returns just the postop attributes.
 *
 * Note: Blob NFS server must always return postop attributes for success
 *       returns, hence assert to check.
 *
 * XXX There are certain scenarios where Blob NFS may fail to provide postop
 *     attributes for success return. If getattr fails after the operation
 *     then operation will complete successfully but postop attributes won't
 *     be returned, f.e., if file is deleted right after the operation.
 * XXX The attributes_follow assert is disabled as we have a PP in the server
 *     which emulates postop attributes not being sent. When running against
 *     prod tenants where PPs are disabled, you can enable the assert check.
 * Note: We use has_filecache() for printing get_cached_filesize() in place of
 *     is_regfile(). This is because we have a special case of regular files
 *     created by aznfsc_ll_mknod(). These do not have on_fuse_open() called
 *     for them as mknod() (unlike creat()) does not return an open fd and
 *     caller need to call aznfsc_ll_open(), which calls on_fuse_open(). Such
 *     files return true for is_regfile() but do not have file cache created.
 */
#define UPDATE_INODE_ATTR(inode, postop) \
do { \
    assert(inode->magic == NFS_INODE_MAGIC); \
    /* assert(postop.attributes_follow); */\
    if (postop.attributes_follow) { \
        AZLogDebug("[{}] UPDATE_INODE_ATTR() from {}", \
                   inode->get_fuse_ino(), \
                   __FUNCTION__); \
        inode->update(&(postop.post_op_attr_u.attributes)); \
        AZLogDebug("[{}] UPDATE_INODE_ATTR(): sfsize: {}, cfsize: {}, " \
                   "csfsize: {}", \
                   inode->get_fuse_ino(), \
                   inode->get_server_file_size(), \
                   (inode->is_regfile() && inode->has_filecache()) ? \
                                     inode->get_client_file_size() : -1, \
                   (inode->is_regfile() && inode->has_filecache()) ? \
                                     inode->get_cached_filesize() : -1); \
    } \
} while (0)

/**
 * Update cached inode attributes from freshly received wcc attributes.
 * This should be called for (update) operations which update file/dir
 * and hence NFS server returns both preop and postop attributes.
 * The preop attributes are compared with the cached attributes to see if
 * the file/dir has changed from what we have cached, and if yes then we
 * invalidate the file/dir cache. If the postop attribute are present and
 * newer (based on ctime comparison) than the cached attributes, inode cached
 * attributes are updated.
 *
 * Note: Blob NFS server must always return both preop and postop attributes
 *       for success returns, hence assert to check.
 */
#define UPDATE_INODE_WCC(inode, wcc_data) \
do { \
    assert(inode->magic == NFS_INODE_MAGIC); \
    const struct post_op_attr& postop = wcc_data.after; \
    const struct pre_op_attr& preop = wcc_data.before; \
    const struct fattr3 *postattr = nullptr; \
    const struct wcc_attr *preattr = nullptr; \
    /* \
    assert(postop.attributes_follow); \
    assert(preop.attributes_follow); \
    */ \
    if (postop.attributes_follow) { \
        postattr = &postop.post_op_attr_u.attributes; \
    } \
    if (preop.attributes_follow) { \
        preattr = &preop.pre_op_attr_u.attributes; \
    } \
    if (preattr || postattr) { \
        AZLogDebug("[{}] UPDATE_INODE_WCC() from {}", \
                   inode->get_fuse_ino(), \
                   __FUNCTION__); \
        inode->update(postattr, preattr); \
        AZLogDebug("[{}] UPDATE_INODE_WCC(): sfsize: {}, cfsize: { }" \
                   "csfsize: {}", \
                   inode->get_fuse_ino(), \
                   inode->get_server_file_size(), \
                   (inode->is_regfile() && inode->has_filecache()) ? \
                                     inode->get_client_file_size() : -1, \
                   (inode->is_regfile() && inode->has_filecache()) ? \
                                     inode->get_cached_filesize() : -1); \
    } \
} while (0)


/**
 * LOOKUP RPC task definition.
 */
struct lookup_rpc_task
{
    void set_file_name(const char *name)
    {
        file_name = ::strdup(name);
    }

    void set_parent_ino(fuse_ino_t parent)
    {
        parent_ino = parent;
    }

    /*
     * Note: fileinfo is not passed by fuse for lookup request, this is only
     *       used for storing the fileinfo of the original request, when this
     *       lookup_rpc_task is used for proxy lookup.
     *       See do_proxy_lookup().
     */
    void set_fuse_file(fuse_file_info *fileinfo)
    {
        if (fileinfo != nullptr) {
            file = *fileinfo;
            file_ptr = &file;
        } else {
            file_ptr = nullptr;
        }
    }

    fuse_ino_t get_parent_ino() const
    {
        return parent_ino;
    }

    const char *get_file_name() const
    {
        return file_name;
    }

    struct fuse_file_info *get_fuse_file() const
    {
        return file_ptr;
    }

    /**
     * Release any resources used up by this task.
     */
    void release()
    {
        ::free(file_name);
    }

private:
    fuse_ino_t parent_ino;
    char *file_name;
    struct fuse_file_info file;
    struct fuse_file_info *file_ptr;
};

struct access_rpc_task
{
    void set_ino(fuse_ino_t _ino)
    {
        ino = _ino;
    }

    void set_mask(int _mask)
    {
        mask = _mask;
    }

    fuse_ino_t get_ino() const
    {
        return ino;
    }

    int get_mask() const
    {
        return mask;
    }

private:
    fuse_ino_t ino;
    int mask;
};

/**
 * WRITE RPC task definition.
 */
struct write_rpc_task
{
    void set_ino(fuse_ino_t ino)
    {
        file_ino = ino;
    }

    void set_offset(off_t off)
    {
        offset = off;
    }

    void set_size(size_t size)
    {
        /*
         * length is how much this WRITE RPC wants to write.
         */
        length = size;
    }

    void set_buffer_vector(struct fuse_bufvec *bufv)
    {
        write_bufv = bufv;
    }

    fuse_ino_t get_ino() const
    {
        return file_ino;
    }

    off_t get_offset() const
    {
        return offset;
    }

    size_t get_size() const
    {
        return length;
    }

    struct fuse_bufvec *get_buffer_vector() const
    {
        return write_bufv;
    }

    bool is_fe() const
    {
        const bool is_fe = (write_bufv != nullptr);
        assert(is_fe == (length > 0));
        assert(is_fe || (offset == 0));
        assert(file_ino != 0);

        return is_fe;
    }

    bool is_be() const
    {
        const bool is_be = (write_bufv == nullptr);
        assert(is_be == (length == 0));
        assert(!is_be || (offset == 0));
        assert(file_ino != 0);

        return is_be;
    }

    /**
     * Release any resources used up by this task.
     */
    void release()
    {
    }

private:
    fuse_ino_t file_ino;
    size_t length;
    off_t  offset;
    struct fuse_bufvec *write_bufv;
};

/**
 * This is an io vector of bytes_chunks.
 * Anyone trying to perform IOs to/from a vector of bytes_chunks should use
 * this instead of the vanilla std::vector<bytes_chunk>. Apart from acting
 * as the storage for bytes_chunks (which helps to grab reference on
 * underlying membufs so that they are not freed) this also provides iovecs
 * needed for performing vectored IO, with support for updating the iovecs
 * as IOs complete (partially or fully), and the updated offset and length
 * into the file where the IO is performed.
 *
 * Note: Currently it's used only for writing a vector of bytes_chunks, so
 *       the code sets membuf flags accordingly. If we want to use it for
 *       vectored reads also then we will have to make those conditional.
 */
#define BC_IOVEC_MAGIC *((const uint32_t *)"BIOV")

/*
 * This must not be greater than libnfs RPC_MAX_VECTORS.
 * We limit it to 1000 as libnfs adds some more iovecs for header, marker etc.
 */
#define BC_IOVEC_MAX_VECTORS 1000

struct bc_iovec
{
    const uint32_t magic = BC_IOVEC_MAGIC;

    /**
     * Constructor must initialize max_iosize, the maximum IO size that we
     * will issue to the file using this bc_iovec.
     * It takes nfs_inode for releasing the cache chunks as IOs get completed
     * for the queued bytes_chunks.
     *
     * Note: If the inode has stable writes enabled then we set max_iosize to
     *       wsize_adj as advertised by the server (since server can only deal
     *       with that big write size), else writes are sent as UNSTABLE writes
     *       for which we use AZNFSCFG_WSIZE_MAX.
     * Note: This takes shared lock on ilock_1.
     */
    bc_iovec(struct nfs_inode *_inode) :
        inode(_inode),
        max_iosize(inode->is_stable_write() ?
                inode->get_client()->mnt_options.wsize_adj : AZNFSCFG_WSIZE_MAX)
    {
        assert(inode->magic == NFS_INODE_MAGIC);
        assert(inode->is_regfile());
        /*
         * bc_iovec is used to perform writeback of cached data, so cache must
         * be present.
         */
        assert(inode->has_filecache());

        /*
         * Grab a ref on the inode as we will need it for releasing cache
         * chunks as IOs complete.
         */
        inode->incref();

        assert(max_iosize > 0);
        /*
         * TODO: Currently we don't support wsize smaller than 1MB.
         *       See below.
         */
        assert(max_iosize >= AZNFSCFG_WSIZE_MIN);
        assert(max_iosize <= AZNFSCFG_WSIZE_MAX);

        assert(iovcnt == 0);
        assert(iov == base);
    }

    /*
     * Note: This takes shared lock on ilock_1.
     */
    ~bc_iovec()
    {
        assert(bcq.empty());
        assert(inode->magic == NFS_INODE_MAGIC);
        /*
         * We don't want to cache the data after the write completes.
         * We do it here once for the entire bc_iovec and not in
         * on_io_complete() as every bytes_chunk completes as scanning the
         * bytes_chunk_cache is expensive.
         */
        assert(inode->has_filecache());
        inode->get_filecache()->release(orig_offset, orig_length);
        inode->decref();
    }

    /**
     * Add a new bytes_chunk to this bc_iovec.
     * If added successfully it returns true else returns false.
     * A bytes_chunk is added successfully if all the following conditions
     * are met:
     * - This is the first bytes_chunk to be added, or
     *   this is contiguos to the last bytes_chunk.
     * - After adding this bytes_chunk the total queued bytes does not
     *   exceed max_iosize.
     * - After adding this bytes_chunk the total number of iovecs don't exceed
     *   BC_IOVEC_MAX_VECTORS.
     *
     * It sets flushing for a successfully added membuf.
     * bc must be set locked and inuse by the caller.
     *
     * A false return signifies to the caller that no more bytes_chunks can be
     * packed into this bc_iovec and it should dispatch it now. A true return
     * otoh indicates that there is still space for more bytes_chunks and caller
     * should wait.
     */
    bool add_bc(const struct bytes_chunk& bc)
    {
        /*
         * Caller must be holding inode->flush_lock().
         */
        assert(inode->is_flushing);

        /*
         * All bytes_chunks must be added in the beginning before dispatching
         * the first write, till then iov will be same as base.
         */
        assert(iov == base);

        // There's one iov per bytes_chunk.
        assert(iovcnt == (int) bcq.size());

        /*
         * We don't support single bytes_chunk having length greater than the
         * max_iosize.
         *
         * Note: This means we should not set wsize less than 1MB, since fuse
         *       can send writes upto 1MB.
         */
        assert(bc.length <= max_iosize);

        // pvt must start as 0.
        assert(bc.pvt == 0);

        /*
         * We should never write a partial membuf, that will cause issues as
         * membuf flags (dirty, flushing, in this case) are tracked at membuf
         * granularity. Check maps_full_membuf() to see how the membuf itself
         * may have been trimmed by a release() call, but the bc must refer to
         * whatever membuf part is currently valid.
         */
        assert(bc.maps_full_membuf());

        struct membuf *const mb = bc.get_membuf();

        /*
         * Caller must have held the membuf inuse count and the lock.
         * Also only uptodate membufs can be written.
         */
        assert(mb->is_inuse());
        assert(mb->is_locked());
        assert(mb->is_uptodate());

        // First iovec being added.
        if (iovcnt == 0) {
            assert(offset == 0);
            assert(length == 0);

            /*
             * XXX This should be the entire bytes_chunk as stored in the
             *     chunkmap, though because of trimming it may be smaller than
             *     the underlying membuf. Unfortunately today we do not have a
             *     safe way to assert for that.
             */
            iov[0].iov_base = bc.get_buffer();
            iov[0].iov_len = bc.length;
            orig_offset = offset = bc.offset;
            orig_length = length = bc.length;
            iovcnt++;
            mb->set_flushing();
            /*
             * Add new bytes_chunk to the tail of the queue.
             * This will now hold the reference on the underlying membuf till
             * the bytes_chunk is removed from the queue.
             */
            bcq.emplace(bc);

            /*
             * Update fcsm::flushing_seq_num, as we have now arranged to flush
             * bc.length bytes. They will be flushed later once we have
             * accumulated enough, but they will definitely be flushed.
             * We want to update flushing_seq_num before they are actually
             * flushed as flush callbacks can start getting called anytime after
             * this.
             */
            inode->get_fcsm()->add_flushing(bc.length);

            return true;
        } else if (((offset + length) == bc.offset) &&
                   ((length + bc.length) <= max_iosize) &&
                   (iovcnt + 1) <= BC_IOVEC_MAX_VECTORS) {
            iov[iovcnt].iov_base = bc.get_buffer();
            iov[iovcnt].iov_len = bc.length;
            length += bc.length;
            orig_length = length;
            iovcnt++;
            mb->set_flushing();
            bcq.emplace(bc);
            inode->get_fcsm()->add_flushing(bc.length);

            return true;
        }

        // Could not add this bc.
        return false;
    }

    /**
     * Must be called when bytes_completed bytes are successfully read/written.
     */
    void on_io_complete(uint64_t bytes_completed, bool is_unstable_write = false);

    /**
     * Call on IO failure.
     */
    void on_io_fail(int status);

    /*
     * Current iovec we should be performing IO to/from, updated as we finish
     * reading/writing whole iovecs. iovcnt holds the count of iovecs remaining
     * to be read/written and is decremented as we read whole iovecs. We also
     * update the iov_base and iov_len as we read/write data from the current
     * iov[], so at any point iov and iovcnt can be passed to any function
     * that operates on iovecs.
     */
    struct iovec *iov = base;
    int iovcnt = 0;

    /*
     * Offset and length in the file where the IO should be performed.
     * These are updated as partial IOs complete.
     * orig_offset and orig_length track the originally requested offset and
     * length, used only for logging.
     */
    uint64_t offset = 0;
    uint64_t length = 0;
    uint64_t orig_offset = 0;
    uint64_t orig_length = 0;

    /*
     * Hold refs to the bytes_chunks.
     * add_bc() adds new bytes_chunk to the front of this and on_io_complete()
     * removes from the tail (if the completed IO covers the entire bytes_chunk).
     */
    std::queue<bytes_chunk> bcq;

private:
    struct nfs_inode *const inode;
    /*
     * Fixed iovec array, iov points into it.
     *
     * TODO: See if we should allocate this as a variable sized vector
     *       dynamically. That will be useful only when we know the size of
     *       the vector in advance.
     */
    struct iovec base[BC_IOVEC_MAX_VECTORS];

    /*
     * Maximum IO size for performing IO to the backing file.
     */
    const uint64_t max_iosize;
};

/**
 * FLUSH RPC task definition.
 */
struct flush_rpc_task
{
    void set_ino(fuse_ino_t ino)
    {
        file_ino = ino;
    }

    fuse_ino_t get_ino() const
    {
        return file_ino;
    }

    /**
     * Release any resources used up by this task.
     */
    void release()
    {
    }

private:
    fuse_ino_t file_ino;
};

/**
 * GETATTR RPC task definition.
 */
struct getattr_rpc_task
{
    void set_ino(fuse_ino_t ino)
    {
        this->ino = ino;
    }

    fuse_ino_t get_ino() const
    {
        return ino;
    }

private:
    fuse_ino_t ino;
};


/**
 * SETATTR RPC task definition.
 */
struct setattr_rpc_task
{
    void set_ino(fuse_ino_t ino)
    {
        this->ino = ino;
    }

    void set_fuse_file(fuse_file_info *fileinfo)
    {
        /*
         * fuse can pass this as nullptr.
         * The fuse_file_info pointer passed to the fuse lowlevel API is only
         * valid in the issue path. Since we want to use it after that, we have
         * to make a deep copy of that.
         */
        if (fileinfo != nullptr) {
            file = *fileinfo;
            file_ptr = &file;
        } else {
            file_ptr = nullptr;
        }
    }

    void set_attribute_and_mask(const struct stat *_attr, int mask)
    {
        // TODO: Should we only copy the required fields?
        attr = *_attr;
        /*
         * We don't make use of FUSE_SET_ATTR_CTIME, ignore it.
         */
        to_set = mask & ~FUSE_SET_ATTR_CTIME;
    }

    const struct stat *get_attr() const
    {
        return &attr;
    }

    int get_attr_flags_to_set() const
    {
        return to_set;
    }

    struct fuse_file_info *get_fuse_file() const
    {
        return file_ptr;
    }

    fuse_ino_t get_ino() const
    {
        return ino;
    }

private:
    // Inode of the file for which attributes have to be set.
    fuse_ino_t ino;

    // File info passed by the fuse layer.
    fuse_file_info file;
    fuse_file_info *file_ptr;

    /*
     * Attributes value to be set to.
     */
    struct stat attr;

    // Valid attribute mask to be set.
    int to_set;
};

struct statfs_rpc_task
{
    fuse_ino_t get_ino() const
    {
        return ino;
    }

    void set_ino(fuse_ino_t _ino)
    {
        ino = _ino;
    }

private:
    fuse_ino_t ino;
};

struct create_file_rpc_task
{
    fuse_ino_t get_parent_ino() const
    {
        return parent_ino;
    }

    const char *get_file_name() const
    {
        return file_name;
    }

    uid_t get_uid() const
    {
        return uid;
    }

    gid_t get_gid() const
    {
        return gid;
    }

    mode_t get_mode() const
    {
        return mode;
    }

    struct fuse_file_info *get_fuse_file() const
    {
        return file_ptr;
    }

    void set_parent_ino(fuse_ino_t parent)
    {
        parent_ino = parent;
    }

    void set_file_name(const char *name)
    {
        file_name = ::strdup(name);
    }

    void set_uid(uid_t _uid)
    {
        uid = _uid;
    }

    void set_gid(gid_t _gid)
    {
        gid = _gid;
    }

    void set_mode(mode_t _mode)
    {
        mode = _mode;
    }

    void set_fuse_file(fuse_file_info *fileinfo)
    {
        assert(fileinfo != nullptr);
        file = *fileinfo;
        file_ptr = &file;
    }

    void release()
    {
        ::free(file_name);
    }

private:
    fuse_ino_t parent_ino;
    char *file_name;
    uid_t uid;
    gid_t gid;
    mode_t mode;
    struct fuse_file_info file;
    struct fuse_file_info *file_ptr;
};

struct mknod_rpc_task
{
    fuse_ino_t get_parent_ino() const
    {
        return parent_ino;
    }

    const char *get_file_name() const
    {
        return file_name;
    }

    uid_t get_uid() const
    {
        return uid;
    }

    gid_t get_gid() const
    {
        return gid;
    }

    mode_t get_mode() const
    {
        return mode;
    }

    void set_parent_ino(fuse_ino_t parent)
    {
        parent_ino = parent;
    }

    void set_file_name(const char *name)
    {
        file_name = ::strdup(name);
    }

    void set_uid(uid_t _uid)
    {
        uid = _uid;
    }

    void set_gid(gid_t _gid)
    {
        gid = _gid;
    }

    void set_mode(mode_t _mode)
    {
        mode = _mode;
    }

    void release()
    {
        ::free(file_name);
    }

private:
    fuse_ino_t parent_ino;
    char *file_name;
    uid_t uid;
    gid_t gid;
    mode_t mode;
};

struct mkdir_rpc_task
{
    fuse_ino_t get_parent_ino() const
    {
        return parent_ino;
    }

    const char *get_dir_name() const
    {
        return dir_name;
    }

    uid_t get_uid() const
    {
        return uid;
    }

    gid_t get_gid() const
    {
        return gid;
    }

    mode_t get_mode() const
    {
        return mode;
    }

    void set_parent_ino(fuse_ino_t parent)
    {
        parent_ino = parent;
    }

    void set_dir_name(const char *name)
    {
        dir_name = ::strdup(name);
    }

    void set_uid(uid_t _uid)
    {
        uid = _uid;
    }

    void set_gid(gid_t _gid)
    {
        gid = _gid;
    }

    void set_mode(mode_t _mode)
    {
        mode = _mode;
    }

    void release()
    {
        ::free(dir_name);
    }

private:
    fuse_ino_t parent_ino;
    char *dir_name;
    uid_t uid;
    gid_t gid;
    mode_t mode;
};

struct unlink_rpc_task
{
    fuse_ino_t get_parent_ino() const
    {
        return parent_ino;
    }

    const char *get_file_name() const
    {
        return file_name;
    }

    bool get_for_silly_rename() const
    {
        return for_silly_rename;
    }

    void set_parent_ino(fuse_ino_t parent)
    {
        parent_ino = parent;
    }

    void set_file_name(const char *name)
    {
        file_name = ::strdup(name);
    }

    void set_for_silly_rename(bool _for_silly_rename)
    {
        for_silly_rename = _for_silly_rename;
    }

    void release()
    {
        ::free(file_name);
    }

private:
    fuse_ino_t parent_ino;
    char *file_name;

    /*
     * Is this unlink task deleting a silly-renamed file when the last opencnt
     * is dropped? If yes, then we need to drop the extra ref on the parent
     * inode held by rename_callback().
     */
    bool for_silly_rename;
};

struct rmdir_rpc_task
{
    fuse_ino_t get_parent_ino() const
    {
        return parent_ino;
    }

    const char *get_dir_name() const
    {
        return dir_name;
    }

    void set_parent_ino(fuse_ino_t parent)
    {
        parent_ino = parent;
    }

    void set_dir_name(const char *name)
    {
        dir_name = ::strdup(name);
    }

    void release()
    {
        ::free(dir_name);
    }

private:
    fuse_ino_t parent_ino;
    char *dir_name;
};

struct symlink_rpc_task
{
    fuse_ino_t get_parent_ino() const
    {
        return parent_ino;
    }

    const char *get_name() const
    {
        return name;
    }

    const char *get_link() const
    {
        return link;
    }

    uid_t get_uid() const
    {
        return uid;
    }

    gid_t get_gid() const
    {
        return gid;
    }

    void set_parent_ino(fuse_ino_t parent)
    {
        parent_ino = parent;
    }

    void set_name(const char *_name)
    {
        name = ::strdup(_name);
    }

    void set_link(const char *_link)
    {
        link = ::strdup(_link);
    }

   void set_uid(uid_t _uid)
    {
        uid = _uid;
    }

    void set_gid(gid_t _gid)
    {
        gid = _gid;
    }

    void release()
    {
        ::free(name);
        ::free(link);
    }

private:
    fuse_ino_t parent_ino;
    char *name;
    char *link;
    uid_t uid;
    gid_t gid;
};

/**
 * NFS RENAME is performed from parent_ino/name -> newparent_ino/newname.
 * These will be the original {oldpath, newpath} in case of user requested
 * rename while for silly rename we rename the outgoing file.
 * For details of various members and methods see init_rename() prototype
 * below.
 */
struct rename_rpc_task
{
    void set_parent_ino(fuse_ino_t parent)
    {
        parent_ino = parent;
        assert(parent_ino != 0);
    }

    fuse_ino_t get_parent_ino() const
    {
        assert(parent_ino != 0);
        return parent_ino;
    }

    void set_name(const char *_name)
    {
        assert(_name != nullptr);
        name = ::strdup(_name);
    }

    const char *get_name() const
    {
        return name;
    }

    void set_newparent_ino(fuse_ino_t parent)
    {
        newparent_ino = parent;
        assert(newparent_ino != 0);
    }

    fuse_ino_t get_newparent_ino() const
    {
        assert(newparent_ino != 0);
        return newparent_ino;
    }

    void set_newname(const char *name)
    {
        assert(name != nullptr);
        newname = ::strdup(name);
    }

    const char *get_newname() const
    {
        return newname;
    }

    /*
     * oldparent_ino/oldname will be non-zero/non-null only for silly rename
     * triggered by user requested rename operation.
     */
    void set_oldparent_ino(fuse_ino_t parent)
    {
        oldparent_ino = parent;
    }

    fuse_ino_t get_oldparent_ino() const
    {
        return oldparent_ino;
    }

    void set_oldname(const char *name)
    {
        oldname = name ? ::strdup(name) : nullptr;
    }

    const char *get_oldname() const
    {
        return oldname;
    }

    void set_silly_rename(bool is_silly)
    {
        // For silly rename olddir and newdir must be same.
        assert(!is_silly || (parent_ino == newparent_ino));
        silly_rename = is_silly;
    }

    bool get_silly_rename() const
    {
        // For silly rename olddir and newdir must be same.
        assert(!silly_rename || (parent_ino == newparent_ino));
        return silly_rename;
    }

    void set_silly_rename_ino(fuse_ino_t _silly_rename_ino)
    {
        silly_rename_ino = _silly_rename_ino;
        assert(silly_rename == (silly_rename_ino != 0));
    }

    fuse_ino_t get_silly_rename_ino() const
    {
        return silly_rename_ino;
    }

    bool get_rename_triggered_silly_rename() const
    {
        assert((oldparent_ino != 0) == (oldname != nullptr));
        return (oldname != nullptr);
    }

    void release()
    {
        ::free(name);
        ::free(newname);
        ::free(oldname);
    }

private:
    fuse_ino_t parent_ino;
    fuse_ino_t newparent_ino;
    fuse_ino_t oldparent_ino;
    char *name;
    char *newname;
    char *oldname;
    bool silly_rename;
    fuse_ino_t silly_rename_ino;
};

struct readlink_rpc_task
{
    void set_ino(fuse_ino_t _ino)
    {
        ino = _ino;
    }

    fuse_ino_t get_ino() const
    {
        return ino;
    }

private:
    fuse_ino_t ino;
};

struct readdir_rpc_task
{
public:
    void set_size(size_t sz)
    {
        size = sz;
    }

    void set_offset(off_t off)
    {
        offset = off;
    }

    void set_target_offset(off_t offset)
    {
        target_offset = offset;
    }

    void set_ino(fuse_ino_t ino)
    {
        inode = ino;
    }

    void set_fuse_file(fuse_file_info* fileinfo)
    {
        // The fuse can pass this as nullptr.
        if (fileinfo != nullptr) {
            file = *fileinfo;
            file_ptr = &file;
        } else {
            file_ptr = nullptr;
        }
    }

    /**
     * Unlike other set methods, this should not be called from
     * init_readdir{plus}(), but must be called from
     * fetch_readdir{plus}_entries_from_server() when we are about to send
     * READDIR{PLUS} RPC to the server and we have the correct cookieverf
     * value being sent to the server.
     * readdir{plus}_callback() will then look this up and assert that server
     * sent the same cookieverf in the response as we sent in the request,
     * unless request was a fresh one carrying cookieverf=0.
     */
    void set_cookieverf(const cookieverf3& cookieverf)
    {
        ::memcpy(&cookie_verifier, &cookieverf, sizeof(cookie_verifier));
    }

    fuse_ino_t get_ino() const
    {
        return inode;
    }

    off_t get_offset() const
    {
        return offset;
    }

    off_t get_target_offset() const
    {
        return target_offset;
    }

    size_t get_size() const
    {
        return size;
    }

    struct fuse_file_info *get_fuse_file() const
    {
        return file_ptr;
    }

    /**
     * We return the cookieverf converted to uint64_t as caller mostly wants
     * to compare this as an integer.
     */
    uint64_t get_cookieverf() const
    {
        return cv2i(cookie_verifier);
    }

private:
    // Inode of the directory.
    fuse_ino_t inode;

    // Maximum size of entries requested by the caller.
    size_t size;

    off_t offset;

    /*
     * Target offset to reach if this is a re-enumeration.
     * This is one more than the last cookie seen before we got a badcookie
     * error, so only cookies >= target_offset are of interest on
     * re-enumeration. Only those we can send in our response to fuse.
     */
    off_t target_offset;

    // File info passed by the fuse layer.
    fuse_file_info file;
    fuse_file_info* file_ptr;
    cookieverf3 cookie_verifier;
};

struct read_rpc_task
{
public:
    void set_size(size_t sz)
    {
        size = sz;
    }

    void set_offset(off_t off)
    {
        offset = off;
    }

    void set_ino(fuse_ino_t ino)
    {
        inode = ino;
    }

    void set_fuse_file(fuse_file_info* fileinfo)
    {
        // The fuse can pass this as nullptr.
        if (fileinfo != nullptr) {
            file = *fileinfo;
            file_ptr = &file;
        } else {
            file_ptr = nullptr;
        }
    }

    fuse_ino_t get_ino() const
    {
        return inode;
    }

    off_t get_offset() const
    {
        return offset;
    }

    size_t get_size() const
    {
        return size;
    }

    struct fuse_file_info *get_fuse_file() const
    {
        return file_ptr;
    }

    bool is_fe() const
    {
        return (file_ptr != nullptr);
    }

    bool is_be() const
    {
        return !is_fe();
    }

private:
    // Inode of the file.
    fuse_ino_t inode;

    // Size of data to be read.
    size_t size;

    // Offset from which the file data should be read.
    off_t offset;

    // File info passed by the fuse layer.
    fuse_file_info file;
    fuse_file_info *file_ptr;
};

/**
 * RPC API specific task info.
 * This must be sufficient information needed to retry the task in case of
 * JUKEBOX failures.
 */
struct api_task_info
{
    ~api_task_info()
    {
        /*
         * Don't call release() from here as it must have been called before
         * we reach here. Duplicate release() call might cause double free of
         * members in various *_rpc_task union members.
         * See rpc_task::free_rpc_task() and ~jukebox_seedinfo().
         */
    }

    /*
     * Fuse request structure.
     * This is the request structure passed from the fuse layer, on behalf of
     * which this RPC task is run.
     */
    fuse_req *req = nullptr;


    /*
     * Only valid for FUSE_READ and FUSE_WRITE.
     *
     * This will refer to the parent task for a child task.
     * This will be nullptr for parent task.
     *
     * When do we need parent tasks?
     * Note that one fuse request is tracked using one rpc_task, so if we
     * have to issue multiple backend RPCs to serve a single fuse req, then
     * each of those multiple backend RPCs become a new (child) rpc_task and
     * the rpc_task tracking the fuse request becomes the parent task.
     * We do this for a couple of reasons, most importantly it helps RPC
     * accounting/stats (which needs to track every RPC issued to the backend)
     * and secondly it helps to use the RPC pool size for limiting the max
     * outstanding RPCs to the backend.
     *
     * When do we need multiple backend RPCs to serve a single fuse RPC?
     * We have the following known cases:
     * 1. Used by fuse read when bytes_chunk_cache::get() returns more than
     *    one bytes_chunk for a given fuse read. Note that each of these
     *    bytes_chunk is issued as an individual RPC READ to the NFS server.
     *    We allocate child rpc_task structures for each of these READs and
     *    the fuse read is tracked by the parent rpc_task. Note that we can
     *    make use of rpc_nfs3_readv_task() API to issue a single RPC READ,
     *    but if the to-be-read data is not contiguous inside the file (this
     *    can happen if some data in the middle is already in the cache) we
     *    may still need multiple RPC READs.
     *    This should not be very common though.
     * 2. Used by fuse write in case where we copy a user write request into
     *    the cache and find out that we are under memory pressure and need to
     *    hold the fuse request till we flush enough dirty data to release the
     *    memory pressure. Each of the dirty chunks will be issued as a child
     *    rpc_task, while the frontend write RPC will be tracked by the parent
     *    rpc_task. The parent RPC task will be completed, causing fuse callback
     *    to be called, when all the child RPC tasks complete.
     */
    rpc_task *parent_task = nullptr;

    /*
     * Only valid for FUSE_READ.
     *
     * This is the byte chunk where the data has to be read by this READ RPC.
     * Note that the parent task calls bytes_chunk_cache::get() and populates
     * the chunks in rpc_task::bc_vec[]. This points to one of those chunks.
     */
    struct bytes_chunk *bc = nullptr;

    /*
     * User can use this to store anything that they want to be available with
     * the task.
     * Writes use it to store a pointer to bc_iovec, so that the write
     * context (offset, length and address to write to) is available across
     * partial writes, jukebox retries, etc.
     */
    void *pvt = nullptr;

    /*
     * Operation type.
     * Used to access the following union.
     * Note that 0 is an invalid fuse opcode.
     */
    enum fuse_opcode optype = (fuse_opcode) 0;

    /*
     * Proxy operation type.
     * If the RPC task is issued on behalf of another task, this will be set
     * to the optype of the original RPC task issuing this.
     */
    enum fuse_opcode proxy_optype = (fuse_opcode) 0;

    /*
     * Unnamed union for easy access.
     */
    union
    {
        struct lookup_rpc_task lookup_task;
        struct access_rpc_task access_task;
        struct write_rpc_task write_task;
        struct flush_rpc_task flush_task;
        struct getattr_rpc_task getattr_task;
        struct setattr_rpc_task setattr_task;
        struct statfs_rpc_task statfs_task;
        struct create_file_rpc_task create_task;
        struct mknod_rpc_task mknod_task;
        struct mkdir_rpc_task mkdir_task;
        struct unlink_rpc_task unlink_task;
        struct rmdir_rpc_task rmdir_task;
        struct symlink_rpc_task symlink_task;
        struct rename_rpc_task rename_task;
        struct readlink_rpc_task readlink_task;
        struct readdir_rpc_task readdir_task;
        struct read_rpc_task read_task;
    };

    /**
     * Is this a directory operation?
     */
    bool is_dirop() const
    {
        switch(optype) {
            case FUSE_LOOKUP:
            case FUSE_CREATE:
            case FUSE_MKNOD:
            case FUSE_MKDIR:
            case FUSE_SYMLINK:
            case FUSE_UNLINK:
            case FUSE_RMDIR:
            case FUSE_RENAME:
                return true;
            default:
                return false;
        }
    }

    /**
     * For ops that take an inode, this returns the inode number.
     */
    fuse_ino_t get_ino() const
    {
        switch(optype) {
            case FUSE_ACCESS:
                return access_task.get_ino();
            case FUSE_WRITE:
                return write_task.get_ino();
            case FUSE_FLUSH:
                return flush_task.get_ino();
            case FUSE_GETATTR:
                return getattr_task.get_ino();
            case FUSE_SETATTR:
                return setattr_task.get_ino();
            case FUSE_STATFS:
                return statfs_task.get_ino();
            case FUSE_READLINK:
                return readlink_task.get_ino();
            case FUSE_READDIR:
            case FUSE_READDIRPLUS:
                return readdir_task.get_ino();
            case FUSE_READ:
                return read_task.get_ino();
            default:
                assert(0);
                return 0;
        }
    }

    /**
     * For ops that take a parent directory and filename, this returns the
     * parent directory inode.
     */
    fuse_ino_t get_parent_ino() const
    {
        switch(optype) {
            case FUSE_LOOKUP:
                return lookup_task.get_parent_ino();
            case FUSE_CREATE:
                return create_task.get_parent_ino();
            case FUSE_MKNOD:
                return mknod_task.get_parent_ino();
            case FUSE_MKDIR:
                return mkdir_task.get_parent_ino();
            case FUSE_SYMLINK:
                return symlink_task.get_parent_ino();
            case FUSE_UNLINK:
                return unlink_task.get_parent_ino();
            case FUSE_RMDIR:
                return rmdir_task.get_parent_ino();
            case FUSE_RENAME:
                return rename_task.get_parent_ino();
            default:
                assert(0);
                return 0;
        }
    }

    /**
     * For ops that take a parent directory and filename, this returns the
     * filename.
     */
    const char *get_file_name() const
    {
        switch(optype) {
            case FUSE_LOOKUP:
                return lookup_task.get_file_name();
            case FUSE_CREATE:
                return create_task.get_file_name();
            case FUSE_MKNOD:
                return mknod_task.get_file_name();
            case FUSE_MKDIR:
                return mkdir_task.get_dir_name();
            case FUSE_SYMLINK:
                return symlink_task.get_name();
            case FUSE_UNLINK:
                return unlink_task.get_file_name();
            case FUSE_RMDIR:
                return rmdir_task.get_dir_name();
            case FUSE_RENAME:
                return rename_task.get_name();
            default:
                assert(0);
                return nullptr;
        }
    }

    /**
     * We cannot specify destructors for the <api>_rpc_task structures, since
     * they are part of a C union. Use release() method for performing any
     * cleanup.
     */
    void release()
    {
        assert(optype > 0 && optype <= FUSE_OPCODE_MAX);

        req = nullptr;
        parent_task = nullptr;
        bc = nullptr;
        pvt = nullptr;

        switch(optype) {
            case FUSE_LOOKUP:
                lookup_task.release();
                break;
            case FUSE_CREATE:
                create_task.release();
                break;
            case FUSE_MKNOD:
                mknod_task.release();
                break;
            case FUSE_MKDIR:
                mkdir_task.release();
                break;
            case FUSE_UNLINK:
                unlink_task.release();
                break;
            case FUSE_RMDIR:
                rmdir_task.release();
                break;
            case FUSE_SYMLINK:
                symlink_task.release();
                break;
            case FUSE_RENAME:
                rename_task.release();
                break;
            default :
                break;
        }
    }
};

#define RPC_TASK_MAGIC *((const uint32_t *)"RTSK")

/**
 * This describes an RPC task which is created to handle a fuse request.
 * The RPC task tracks the progress of the RPC request sent to the server and
 * remains valid till the RPC request completes.
 */
struct rpc_task
{
    friend class rpc_task_helper;

    const uint32_t magic = RPC_TASK_MAGIC;

    /*
     * The client for which the context is created.
     * This is initialized when the rpc_task is added to the free tasks list
     * and never changed afterwards, since we have just one nfs_client used by
     * all rpc tasks.
     */
    struct nfs_client *const client;

    // This is the index of the object in the rpc_task_list vector.
    const int index;
private:
    /*
     * Flag to identify async tasks.
     * All rpc_tasks start sync, but the caller can make an rpc_task
     * async by calling set_async_function(). The std::function object
     * passed to set_async_function() will be run asynchronously by the
     * rpc_task. That should call the run*() method at the least.
     */
    std::atomic<bool> is_async_task = false;

    // Put a cap on how many async tasks we can start.
    static std::atomic<int> async_slots;

    /*
     * Connection scheduling type to be used for this RPC.
     * Issuer of the RPC will know what connection scheduling type is most
     * optimal for the RPC, it must set it and RPC layer will then honor that.
     */
    conn_sched_t csched = CONN_SCHED_INVALID;

    /*
     * FH hash to be used for connection scheduling if/for CONN_SCHED_FH_HASH.
     */
    uint32_t fh_hash = 0;

public:
    /*
     * Issuing thread's tid. Useful for debugging.
     * Only set if ENABLE_PARANOID is defined.
     */
    pid_t issuing_tid = -1;

    /*
     * Valid only for read RPC tasks.
     * To serve single client read call we may issue multiple NFS reads
     * depending on the chunks returned by bytes_chunk_cache::get().
     *
     * num_ongoing_backend_reads tracks how many of the backend reads are
     * currently pending. We cannot complete the application read until all
     * reads complete (either success or failure).
     *
     * read_status is the final read status we need to send to fuse.
     * This is set when we get an error, so that even if later reads complete
     * successfully we fail the fuse read.
     */
    std::atomic<int> num_ongoing_backend_reads = 0;
    std::atomic<int> read_status = 0;

    /*
     * Valid only for write RPC tasks.
     * When under memory pressure we do not complete fuse write requests
     * immediately after copying the user data to the cache, instead we want
     * to slow down application writes by delaying fuse callback till we flush
     * sufficient dirty chunks to relieve the memory pressure. To achieve that
     * we issue one or more write RPCs to flush the dirty data and complete the
     * fuse callback only when all these write RPCs complete.
     *
     * num_ongoing_backend_writes tracks how many of these backend writes are
     * currently pending. We complete the application write only after all
     * writes complete (either success or failure).
     */
    std::atomic<int> num_ongoing_backend_writes = 0;

    /*
     * This is currently valid only for reads.
     * This contains vector of byte chunks which is returned by making a call
     * to bytes_chunk_cache::get().
     * This is populated by only one thread that calls run_read() for this
     * task, once populated multiple parallel threads may read it, so we
     * don't need to synchronize access to this with a lock.
     */
    std::vector<bytes_chunk> bc_vec;

    enum fuse_opcode optype = (fuse_opcode) 0;

protected:
    /*
     * RPC stats. This has both stats specific to this RPC as well as
     * aggregated RPC stats for all RPCs of this type and also global stats
     * for all RPCs.
     */
    rpc_stats_az stats;

public:
    rpc_task(struct nfs_client *_client, int _index) :
        client(_client),
        index(_index)
    {
    }

    /*
     * RPC API specific task info.
     * This is a pointer so that it can be quickly xferred to jukebox_seedinfo.
     */
    api_task_info *rpc_api = nullptr;

    // TODO: Add valid flag here for APIs?

    /**
     * Set a function to be run by this rpc_task asynchronously.
     * Calling set_async_function() makes an rpc_task async.
     * The callback function takes two parameters:
     * 1. rpc_task pointer.
     * 2. Optional arbitrary data that caller may want to pass.
     */
    bool set_async_function(
            std::function<void(struct rpc_task*)> func)
    {
        // Must not already be async.
        assert(!is_async());
        assert(func);

        if (--async_slots < 0) {
            ++async_slots;
            AZLogError("Too many async rpc tasks: {}", async_slots.load());
            assert(0);
            /*
             * TODO: Add a condition_variable where caller can wait and
             *       will be woken up once it can create an async task.
             *       Till then caller can wait for try again.
             */
            return false;
        }

        /*
         * Mark this task async.
         * This has to be done before calling func() as it may check it
         * for the rpc_task.
         */
        is_async_task = true;

        std::thread thread([this, func]()
        {
            func(this);
            /*
             * We increase the async_slots here and not in free_rpc_task()
             * as the task is technically done, it just needs to be reaped.
             */
            async_slots++;
        });

        /*
         * We detach from this thread to avoid having to join it, as
         * that causes problems with some caller calling free_rpc_task()
         * from inside func(). Moreover this is more like the sync tasks
         * where the completion context doesn't worry whether the issuing
         * thread has completed.
         * Since we don't have a graceful exit scenario, waiting for the
         * async threads is not really necessary.
         */
        thread.detach();

        return true;
    }

    /**
     * Return a string representation of opcode for logging.
     */
    static const std::string fuse_opcode_to_string(fuse_opcode opcode);

    /**
     * Check if this rpc_task is an async task.
     */
    bool is_async() const
    {
        return is_async_task;
    }

    /*
     * init/run methods for the LOOKUP RPC.
     */
    void init_lookup(fuse_req *request,
                     const char *name,
                     fuse_ino_t parent_ino);
    void run_lookup();

    /*
     * Proxy lookup task is used for sending a LOOKUP RPC on behalf of some
     * other RPC which failed to return the filehandle in postop data, f.e.,
     * CREATE may fail to return FH, this is fine for NFS but fuse expects us
     * to convey the FH in our create callback, hence we issue a LOOKUP RPC
     * to query the FH for the newly created file.
     *
     * do_proxy_lookup() is called on the original task, it creates a new proxy
     * lookup task properly initialized with data from the original task, sends
     * the LOOKUP RPC, and on completion calls the fuse callback of the original
     * fuse request.
     */
    void do_proxy_lookup() const;

    /*
     * init/run methods for the ACCESS RPC.
     */
    void init_access(fuse_req *request,
                     fuse_ino_t ino,
                     int mask);
    void run_access();

    /*
     * init/run methods for the WRITE RPC.
     *
     * Note: init_write_fe() is used to initialize the application write (frontend write).
     *       It has valid buffer, offset and size we received from the application.
     *
     * Note: init_write_be() is used to initialize the backend write on a inode. It is used
     *       to flush cached application writes to the backend.
     */
    void init_write_fe(fuse_req *request,
                       fuse_ino_t ino,
                       struct fuse_bufvec *buf,
                       size_t size,
                       off_t offset);

    void init_write_be(fuse_ino_t ino);

    void run_write();

    /*
     * init/run methods for the FLUSH/RELEASE RPC.
     */
    void init_flush(fuse_req *request,
                    fuse_ino_t ino);
    void run_flush();

    /*
     * init/run methods for the GETATTR RPC.
     */
    void init_getattr(fuse_req *request,
                      fuse_ino_t ino);
    void run_getattr();

    /*
     * Ref do_proxy_lookup() for details.
     */
    void do_proxy_getattr() const;

    /*
     * init/run methods for the SETATTR RPC.
     */
    void init_setattr(fuse_req *request,
                      fuse_ino_t ino,
                      const struct stat *attr,
                      int to_set,
                      struct fuse_file_info *file);
    void run_setattr();

    void init_statfs(fuse_req *request,
                     fuse_ino_t ino);
    void run_statfs();

    /*
     * init/run methods for the CREATE RPC.
     */
    void init_create_file(fuse_req *request,
                          fuse_ino_t parent_ino,
                          const char *name,
                          mode_t mode,
                          struct fuse_file_info *file);
    void run_create_file();

    /*
     * init/run methods for the MKNOD RPC.
     */
    void init_mknod(fuse_req *request,
                    fuse_ino_t parent_ino,
                    const char *name,
                    mode_t mode);
    void run_mknod();

    /*
     * init/run methods for the MKDIR RPC.
     */
    void init_mkdir(fuse_req *request,
                    fuse_ino_t parent_ino,
                    const char *name,
                    mode_t mode);
    void run_mkdir();

    /*
     * init/run methods for the REMOVE RPC.
     */
    void init_unlink(fuse_req *request,
                     fuse_ino_t parent_ino,
                     const char *name,
                     bool for_silly_rename);

    void run_unlink();

    /*
     * init/run methods for the RMDIR RPC.
     */
    void init_rmdir(fuse_req *request,
                    fuse_ino_t parent_ino,
                    const char *name);

    void run_rmdir();

    /*
     * init/run methods for the SYMLINK RPC.
     */
    void init_symlink(fuse_req *request,
                      const char *link,
                      fuse_ino_t parent_ino,
                      const char *name);

    void run_symlink();

    /*
     * init/run methods for the RENAME RPC.
     * Note that this can be called both for performing a user requested rename
     * and for silly rename. silly rename in turn can be called for a user
     * requested unlink or rename.
     *
     * For user requested rename:
     * - parent_ino/name -> newparent_ino/newname, and
     * - silly_rename silly_rename, silly_rename_ino, oldparent_ino, old_name
     *   must not be provided (and their default values are used).
     *
     * For silly rename called in response to user requested unlink:
     * - parent_ino/name is the to-be-unlinked file.
     * - newparent_ino/newname is the silly rename file. Since silly rename file
     *   is created in the same directory, newparent_ino MUST be same as
     *   parent_ino.
     * - silly_rename must be true.
     * - silly_rename_ino must be the ino of the to-be-silly-renamed file
     *   parent_ino/name.
     * - oldparent_ino/old_name must not be passed.
     *
     * For silly rename called in response to user requested rename:
     * - parent_ino/name is the outgoing file i.e., the newfile passed by the
     *   user requested rename.
     * - newparent_ino/newname is the silly rename file. Since silly rename file
     *   is created in the same directory, newparent_ino MUST be same as
     *   parent_ino.
     * - silly_rename must be true.
     * - silly_rename_ino must be the ino of the to-be-silly-renamed file
     *   parent_ino/name.
     * - oldparent_ino/old_name is the orignal to-be-renamed file, i.e., the
     *   oldfile passed by the user requested rename. This is not used by silly
     *   rename but is used to initiate the actual rename once silly rename
     *   completes successfully.
     */
    void init_rename(fuse_req *request,
                     fuse_ino_t parent_ino,
                     const char *name,
                     fuse_ino_t newparent_ino,
                     const char *newname,
                     bool silly_rename = false,
                     fuse_ino_t silly_rename_ino = 0,
                     fuse_ino_t oldparent_ino = 0,
                     const char *old_name = nullptr);

    void run_rename();

    /*
     * init/run methods for the READLINK RPC.
     */
    void init_readlink(fuse_req *request,
                       fuse_ino_t ino);

    void run_readlink();

    // This function is responsible for setting up the members of readdir_task.
    void init_readdir(fuse_req *request,
                     fuse_ino_t inode,
                     size_t size,
                     off_t offset,
                     off_t target_offset,
                     struct fuse_file_info *file);

    void run_readdir();

    // This function is responsible for setting up the members of readdirplus_task.
    void init_readdirplus(fuse_req *request,
                         fuse_ino_t inode,
                         size_t size,
                         off_t offset,
                         off_t target_offset,
                         struct fuse_file_info *file);

    void run_readdirplus();

    // This function is responsible for setting up the members of read task.
    void init_read_fe(fuse_req *request,
                      fuse_ino_t inode,
                      size_t size,
                      off_t offset,
                      struct fuse_file_info *file);

    void init_read_be(fuse_ino_t inode,
                      size_t size,
                      off_t offset);

    void run_read();

    void set_csched(conn_sched_t _csched)
    {
        assert(_csched > CONN_SCHED_INVALID &&
               _csched <= CONN_SCHED_FH_HASH);
        csched = _csched;
    }

    conn_sched_t get_csched() const
    {
        assert(csched > CONN_SCHED_INVALID &&
               csched <= CONN_SCHED_FH_HASH);
        return csched;
    }

    uint32_t get_fh_hash() const
    {
        // When get_fh_hash() is called, fh_hash must be set.
        assert(fh_hash != 0);
        return fh_hash;
    }

    void set_fuse_req(fuse_req *request)
    {
        rpc_api->req = request;
    }

    struct fuse_req *get_fuse_req() const
    {
        return rpc_api->req;
    }

    void set_op_type(enum fuse_opcode _optype)
    {
        optype = rpc_api->optype = _optype;
        rpc_api->proxy_optype = (fuse_opcode) 0;
    }

    void set_proxy_op_type(enum fuse_opcode _optype)
    {
        rpc_api->proxy_optype = _optype;
    }

    /**
     * See rpc_task::free_rpc_task() for why we need rpc_task::optype along
     * with api_task_info::optype.
     */
    enum fuse_opcode get_op_type() const
    {
        assert(!rpc_api || optype == rpc_api->optype);
        return optype;
    }

    enum fuse_opcode get_proxy_op_type() const
    {
        assert(rpc_api != nullptr);
        return rpc_api->proxy_optype;
    }

    rpc_stats_az& get_stats()
    {
        return stats;
    }

    struct nfs_context *get_nfs_context() const;

    struct rpc_context *get_rpc_ctx() const
    {
        return nfs_get_rpc_context(get_nfs_context());
    }

    nfs_client *get_client() const
    {
        assert (client != nullptr);
        return client;
    }

    int get_index() const
    {
        return index;
    }

    // The task should not be accessed after this function is called.
    void free_rpc_task();

    /*
     * This method will reply with error and free the rpc task.
     * rc is either 0 for success, or a +ve errno value.
     */
    void reply_error(int rc)
    {
        assert(rc >= 0);
        const int fre = fuse_reply_err(get_fuse_req(), rc);
        if (fre != 0) {
            INC_GBL_STATS(fuse_reply_failed, 1);
            AZLogError("fuse_reply_err({}) failed: {}",
                       fmt::ptr(get_fuse_req()), fre);
            assert(0);
        } else {
            DEC_GBL_STATS(fuse_responses_awaited, 1);
        }

        free_rpc_task();
    }

    void reply_statfs(const struct statvfs *statbuf)
    {
        const int fre = fuse_reply_statfs(get_fuse_req(), statbuf);
        if (fre != 0) {
            INC_GBL_STATS(fuse_reply_failed, 1);
            AZLogError("fuse_reply_statfs({}) failed: {}",
                       fmt::ptr(get_fuse_req()), fre);
            assert(0);
        } else {
            DEC_GBL_STATS(fuse_responses_awaited, 1);
        }

        free_rpc_task();
    }

    void reply_readlink(const char *linkname)
    {
        const int fre = fuse_reply_readlink(get_fuse_req(), linkname);
        if (fre != 0) {
            INC_GBL_STATS(fuse_reply_failed, 1);
            AZLogError("fuse_reply_readlink({}) failed: {}",
                       fmt::ptr(get_fuse_req()), fre);
            assert(0);
        } else {
            DEC_GBL_STATS(fuse_responses_awaited, 1);
        }

        free_rpc_task();
    }

    void reply_attr(const struct stat& attr, double attr_timeout)
    {
        const int fre = fuse_reply_attr(get_fuse_req(), &attr, attr_timeout);
        if (fre != 0) {
            INC_GBL_STATS(fuse_reply_failed, 1);
            AZLogError("fuse_reply_attr({}) failed: {}",
                       fmt::ptr(get_fuse_req()), fre);
            assert(0);
        } else {
            DEC_GBL_STATS(fuse_responses_awaited, 1);
        }

        free_rpc_task();
    }

    void reply_write(size_t count)
    {
        /*
         * Currently fuse sends max 1MiB write requests, so we should never
         * be responding more than that.
         * This is a sanity assert for catching unintended bugs, update if
         * fuse max write size changes.
         */
        assert(count <= 1048576);

        INC_GBL_STATS(app_bytes_written, count);

        /*
         * We should not respond to fuse when there are still ongoing
         * backend writes.
         */
        assert(num_ongoing_backend_writes == 0);

        const int fre = fuse_reply_write(get_fuse_req(), count);
        if (fre != 0) {
            INC_GBL_STATS(fuse_reply_failed, 1);
            AZLogError("fuse_reply_write({}) failed: {}",
                       fmt::ptr(get_fuse_req()), fre);
            assert(0);
        } else {
            DEC_GBL_STATS(fuse_responses_awaited, 1);
        }

        free_rpc_task();
    }

    void reply_iov(struct iovec *iov, size_t count)
    {
        // If count is non-zero iov must be valid and v.v.
        assert((iov == nullptr) == (count == 0));

        /*
         * fuse_reply_iov() cannot handle count > FUSE_REPLY_IOV_MAX_COUNT,
         * o/w it fails with "fuse: writing device: Invalid argument" and fuse
         * communication stalls.
         *
         * Note:  Though the callers are aware of this and they won't send more
         *        than FUSE_REPLY_IOV_MAX_COUNT iov elements, but to be safe we
         *        cap it here also as the final gatekeeper.
         */
        if (count > FUSE_REPLY_IOV_MAX_COUNT) {
            AZLogError("[BUG] reply_iov called with count ({}) > {}, "
                       "capping at {}",
                       count, FUSE_REPLY_IOV_MAX_COUNT,
                       FUSE_REPLY_IOV_MAX_COUNT);
            count = FUSE_REPLY_IOV_MAX_COUNT;
            assert(0);
        }

        const int fre = fuse_reply_iov(get_fuse_req(), iov, count);
        if (fre != 0) {
            INC_GBL_STATS(fuse_reply_failed, 1);
            AZLogError("fuse_reply_iov({}) failed (count={}): {}",
                       fmt::ptr(get_fuse_req()), count, fre);
            assert(0);
        } else {
            DEC_GBL_STATS(fuse_responses_awaited, 1);
        }

        free_rpc_task();
    }

    void reply_entry(const struct fuse_entry_param *e)
    {
        struct nfs_inode *inode = nullptr;

        /*
         * As per fuse on a successful call to fuse_reply_create() the
         * inode's lookup count must be incremented. We increment the
         * inode's lookupcnt in get_nfs_inode(), this lookup count will
         * be transferred to fuse on successful fuse_reply_create() call,
         * but if that fails then we need to drop the ref.
         * "ino == 0" implies a failed lookup call, so we don't have a valid
         * inode number to return.
         */
        if (e->ino != 0) {
            inode = client->get_nfs_inode_from_ino(e->ino);
            assert(inode->lookupcnt >= 1);
            assert(e->generation == inode->get_generation());

            /*
             * This might be an existing inode from inode_map which we didn't
             * free earlier as it was in use when fuse called forget and then
             * some other thread looked up the inode. It could be a fresh inode
             * too. In any case increment forget_expected as we are now letting
             * fuse know about this inode.
             */
            inode->forget_expected++;
            assert(inode->lookupcnt >= (uint64_t) inode->forget_expected);
        }

        assert((int64_t) e->generation <= get_current_usecs());

        const int fre = fuse_reply_entry(get_fuse_req(), e);
        if (fre != 0) {
            INC_GBL_STATS(fuse_reply_failed, 1);
            AZLogError("fuse_reply_entry({}) failed: {}",
                       fmt::ptr(get_fuse_req()), fre);
            assert(0);

            if (inode) {
                /*
                 * Not able to convey to fuse, drop forget_expected count
                 * incremented above.
                 */
                assert(inode->forget_expected > 0);
                inode->forget_expected--;
                inode->decref();
                assert(inode->lookupcnt >= (uint64_t) inode->forget_expected);
            }
        } else {
            DEC_GBL_STATS(fuse_responses_awaited, 1);
        }

        free_rpc_task();
    }

    void reply_create(
        const struct fuse_entry_param *entry,
        const struct fuse_file_info *file)
    {
        // inode number cannot be 0 in a create response().
        assert(entry->ino != 0);

        /*
         * As per fuse on a successful call to fuse_reply_create() the
         * inode's lookup count must be incremented. We increment the
         * inode's lookupcnt in get_nfs_inode(), this lookup count will
         * be transferred to fuse on successful fuse_reply_create() call,
         * but if that fails then we need to drop the ref.
         */
        struct nfs_inode *inode = client->get_nfs_inode_from_ino(entry->ino);
        assert(inode->lookupcnt >= 1);
        assert(entry->generation == inode->get_generation());
        assert((int64_t) entry->generation <= get_current_usecs());

        /*
         * See comment in reply_entry().
         */
        inode->forget_expected++;
        assert(inode->lookupcnt >= (uint64_t) inode->forget_expected);

        /*
         * nfs_client::reply_entry()->on_fuse_open() must have incremented
         * the inode opencnt.
         * Note that it's important to increment opencnt before calling
         * fuse_reply_create() as once we respond with the inode to fuse, it
         * may call release for that inode and we have an assert in
         * aznfsc_ll_release() that opencnt must be non-zero. If we fail to
         * convey to fuse we decrement the opencnt.
         */
        assert(inode->opencnt > 0);

        const int fre = fuse_reply_create(get_fuse_req(), entry, file);
        if (fre != 0) {
            INC_GBL_STATS(fuse_reply_failed, 1);
            AZLogError("[{}] fuse_reply_create({}) failed: {}",
                       inode->get_fuse_ino(), fmt::ptr(get_fuse_req()), fre);
            assert(0);

            /*
             * Not able to convey to fuse, drop forget_expected count
             * incremented above.
             */
            assert(inode->forget_expected > 0);
            inode->forget_expected--;
            /*
             * Drop opencnt incremented in
             * nfs_client::reply_entry()->on_fuse_open().
             */
            inode->opencnt--;
            inode->decref();
            assert(inode->lookupcnt >= (uint64_t) inode->forget_expected);
        } else {
            DEC_GBL_STATS(fuse_responses_awaited, 1);
        }

        free_rpc_task();
    }

    /**
     * Check RPC and NFS status to find completion status of the RPC task.
     * Returns 0 if rpc_task succeeded execution at the server, else returns
     * a +ve errno value.
     * If user has passed the last argument errstr as non-null, then it'll
     * additionally store an error string there.
     */
    static int status(int rpc_status,
                      int nfs_status,
                      const char **errstr = nullptr)
    {
        if (rpc_status != RPC_STATUS_SUCCESS) {
            if (errstr) {
                *errstr = "RPC error";
            }

            /*
             * TODO: libnfs only returns the following RPC errors
             *       RPC status can indicate access denied error too,
             *       need to support that.
             */
            assert(rpc_status == RPC_STATUS_ERROR ||
                   rpc_status == RPC_STATUS_TIMEOUT ||
                   rpc_status == RPC_STATUS_CANCEL);

            // For now just EIO.
            return EIO;
        }

        if (nfs_status == NFS3_OK) {
            if (errstr) {
                *errstr = "Success";
            }
            return 0;
        }

        if (errstr) {
            *errstr = nfsstat3_to_str(nfs_status);
        }

        return -nfsstat3_to_errno(nfs_status);
    }

    void send_readdir_or_readdirplus_response(
        const std::vector<std::shared_ptr<const directory_entry>>& readdirentries);

    void get_readdir_entries_from_cache();

    void fetch_readdir_entries_from_server();
    void fetch_readdirplus_entries_from_server();

    void send_read_response();
    void read_from_server(struct bytes_chunk &bc);

    /*
     * Flush RPC related methods.
     * Flush supports vectored writes so caller can use add_bc() to add
     * bytes_chunk to the flush task till the supported wsize. If the bc can be
     * safely added to the vector it's added to the bytes_chunk queue and
     * add_bc() returns true, else bc is not added and it returns false. On a
     * false return the caller must call issue_write_rpc() to dispatch all the
     * queued bytes_chunks, and add the remaining bytes_chunks to a new flush
     * task.
     */
    bool add_bc(const bytes_chunk& bc);
    void issue_write_rpc();
    void issue_commit_rpc();

#ifdef ENABLE_NO_FUSE
    /*
     * In nofuse mode we re-define these fuse_reply functions to copy the
     * result into the response buffer (passed by the POSIX API) and notify
     * the issuer thread.
     */
    int fuse_reply_none(fuse_req_t req);
    int fuse_reply_iov(fuse_req_t req, const struct iovec *iov, int count);
    int fuse_reply_err(fuse_req_t req, int err);
    int fuse_reply_entry(fuse_req_t req, const struct fuse_entry_param *e);
    int fuse_reply_create(fuse_req_t req, const struct fuse_entry_param *e,
                          const struct fuse_file_info *f);
    int fuse_reply_attr(fuse_req_t req, const struct stat *attr,
                        double attr_timeout);
    int fuse_reply_readlink(fuse_req_t req, const char *linkname);
    int fuse_reply_open(fuse_req_t req, const struct fuse_file_info *f);
    int fuse_reply_write(fuse_req_t req, size_t count);
    int fuse_reply_buf(fuse_req_t req, const char *buf, size_t size);
    int fuse_reply_data(fuse_req_t req, struct fuse_bufvec *bufv,
                        enum fuse_buf_copy_flags flags);
    size_t fuse_add_direntry_plus(fuse_req_t req, char *buf, size_t bufsize,
                                  const char *name,
                                  const struct fuse_entry_param *e, off_t off);
    size_t fuse_add_direntry(fuse_req_t req, char *buf, size_t bufsize,
                             const char *name, const struct stat *stbuf,
                             off_t off);
    const struct fuse_ctx *fuse_req_ctx(fuse_req_t req);
#endif
};

class rpc_task_helper
{
private:
    // Mutex for synchronizing access to free_task_index stack.
    std::shared_mutex task_index_lock_41;

    // Stack containing index into the rpc_task_list vector.
    std::stack<int> free_task_index;

#ifdef ENABLE_PARANOID
    // Set for catching double free.
    std::set<int> free_task_index_set;
#endif

    /*
     * List of RPC tasks which is used to run the task.
     * Making this a vector of rpc_task* instead of rpc_task saves any
     * restrictions on the members of rpc_task. With rpc_task being the
     * element type, it needs to be move constructible, so we cannot have
     * atomic members f.e.
     * Anyway these rpc_task once allocated live for the life of the program.
     */
    std::vector<struct rpc_task*> rpc_task_list;

    // Condition variable to wait for free task index availability.
    std::condition_variable_any cv;

    // This is a singleton class, hence make the constructor private.
    rpc_task_helper(struct nfs_client *client)
    {
        assert(client != nullptr);

        // There should be no elements in the stack.
        assert(free_task_index.empty());

        // Initialize the index stack.
        for (int i = 0; i < MAX_OUTSTANDING_RPC_TASKS; i++) {
            free_task_index.push(i);

#ifdef ENABLE_PARANOID
            const auto p = free_task_index_set.insert(i);
            assert(p.second);
            assert(free_task_index_set.size() == free_task_index.size());
#endif
            rpc_task_list.emplace_back(new rpc_task(client, i));
        }

        // There should be MAX_OUTSTANDING_RPC_TASKS index available.
        assert(free_task_index.size() == MAX_OUTSTANDING_RPC_TASKS);
    }

public:
    ~rpc_task_helper()
    {
        AZLogInfo("~rpc_task_helper() called");

#ifdef ENABLE_PARANOID
        assert(free_task_index_set.size() == free_task_index.size());
#endif

        /*
         * We should be called when there are no outstanding tasks.
         */
        assert(free_task_index.size() == MAX_OUTSTANDING_RPC_TASKS);

        while (!free_task_index.empty()) {
            free_task_index.pop();
        }

        for (int i = 0; i < MAX_OUTSTANDING_RPC_TASKS; i++) {
            assert(rpc_task_list[i]);
            delete rpc_task_list[i]->rpc_api;
            delete rpc_task_list[i];
        }
        rpc_task_list.clear();
    }

    static rpc_task_helper *get_instance(struct nfs_client *client = nullptr)
    {
        static rpc_task_helper helper(client);
        return &helper;
    }

    /**
     * This returns a free rpc task instance from the pool of rpc tasks.
     * This call will block till a free rpc task is available.
     *
     * Also see alloc_rpc_task_reserved().
     */
    struct rpc_task *alloc_rpc_task(fuse_opcode optype,
                                    bool use_reserved = false)
    {
        // get_free_idx() can block, collect start time before that.
        const uint64_t start_usec = get_current_usecs();
        const int free_index = get_free_idx(use_reserved);
        struct rpc_task *task = rpc_task_list[free_index];

        assert(task->magic == RPC_TASK_MAGIC);
        assert(task->client != nullptr);
        assert(task->index == free_index);
        // Every rpc_task starts as sync.
        assert(!task->is_async());

        /*
         * Only first time around rpc_api will be null for a rpc_task, after
         * that it can be null only if the task failed with a JUKEBOX error in
         * which case the rpc_api would have been xferred to jukebox_seedinfo
         * by nfs_client::jukebox_retry().
         */
        if (!task->rpc_api) {
            task->rpc_api = new api_task_info();
        }

        task->set_op_type(optype);
        task->stats.on_rpc_create(optype, start_usec);

        // No task starts as a child task.
        assert(task->rpc_api->parent_task == nullptr);

#ifndef ENABLE_NON_AZURE_NFS
        assert(task->client->mnt_options.nfs_port == 2047 ||
               task->client->mnt_options.nfs_port == 2048);
#endif
        /*
         * Set the default connection scheduling type based on the NFS port
         * used. Later init_*() method can set it to a more appropriate value.
         */
        task->csched = (task->client->mnt_options.nfs_port == 2047) ?
                        CONN_SCHED_RR_W : CONN_SCHED_FH_HASH;

#ifdef ENABLE_PARANOID
        task->issuing_tid = ::gettid();
#endif

        // New task must have these as 0.
        assert(task->num_ongoing_backend_writes == 0);
        assert(task->num_ongoing_backend_reads == 0);

        INC_GBL_STATS(rpc_tasks_allocated, 1);
        return task;
    }

    /**
     * Use this when allocating rpc_task in a libnfs callback context.
     * This will avoid blocking the caller by reaching into the reserved pool
     * if the regular pool of rpc_task is exhausted.
     * Note that it's important to not block libnfs threads as they help
     * complete RPC requests and thus free up rpc_task structures.
     */
    struct rpc_task *alloc_rpc_task_reserved(fuse_opcode optype)
    {
        return alloc_rpc_task(optype, true /* use_reserved */);
    }

    int get_free_idx(bool use_reserved = false)
    {
        /*
         * If caller is special allow them to eat into the reserved pool
         * of tasks. We should keep as many tasks in the reserved pool as
         * there are libnfs threads, so that in the worst case if every libnfs
         * callback allocates a task they don't have to block.
         * Don't allow more than 25% of total tasks as reserved tasks.
         */
        static const size_t RESERVED_TASKS = 1000;
        static_assert(RESERVED_TASKS < MAX_OUTSTANDING_RPC_TASKS / 4);
        const size_t spare_count = use_reserved ? 0 : RESERVED_TASKS;

        std::unique_lock<std::shared_mutex> lock(task_index_lock_41);

        // Wait until a free rpc task is available.
        while (free_task_index.size() <= spare_count) {
#ifdef ENABLE_PARANOID
            assert(free_task_index_set.size() == free_task_index.size());
#endif
            if (!cv.wait_for(lock, std::chrono::seconds(30),
                             [this, spare_count] {
                                return free_task_index.size() > spare_count;
                             })) {
                AZLogError("Timed out waiting for free rpc_task ({}), "
                           "re-trying!", free_task_index.size());
            }
        }

        const int free_index = free_task_index.top();
        free_task_index.pop();

#ifdef ENABLE_PARANOID
        // Must also be free as per free_task_index_set.
        const size_t cnt = free_task_index_set.erase(free_index);
        assert(cnt == 1);
        assert(free_task_index_set.size() == free_task_index.size());
#endif

        // Must be a valid index.
        assert(free_index >= 0 && free_index < MAX_OUTSTANDING_RPC_TASKS);

        return free_index;
    }

    void release_free_index(int index)
    {
        // Must be a valid index.
        assert(index >= 0 && index < MAX_OUTSTANDING_RPC_TASKS);

        {
            std::unique_lock<std::shared_mutex> lock(task_index_lock_41);

#ifdef ENABLE_PARANOID
            assert(free_task_index_set.size() == free_task_index.size());
            // Must not already be free.
            const auto p = free_task_index_set.insert(index);
            assert(p.second);
#endif

            free_task_index.push(index);
        }

        // Notify any waiters blocked in alloc_rpc_task().
        cv.notify_one();
    }

    void free_rpc_task(struct rpc_task *task)
    {
        assert(task->magic == RPC_TASK_MAGIC);
        task->is_async_task = false;

        release_free_index(task->get_index());
        DEC_GBL_STATS(rpc_tasks_allocated, 1);
    }
};

/**
 * Seed info needed to re-run a task that had failed with JUKEBOX error.
 */
struct jukebox_seedinfo
{
    ~jukebox_seedinfo()
    {
        /*
         * This will also call api_task_info::release().
         */
        rpc_api->release();
        delete rpc_api;
    }

    /*
     * Information needed to restart the task.
     */
    api_task_info *rpc_api;

    /*
     * When to rerun the task.
     */
    int64_t run_at_msecs;

    jukebox_seedinfo(api_task_info *_rpc_api) :
        rpc_api(_rpc_api),
        run_at_msecs(get_current_msecs() + JUKEBOX_DELAY_SECS*1000)
    {
        assert(rpc_api != nullptr);
    }
};

#endif /*__RPC_TASK_H__*/
