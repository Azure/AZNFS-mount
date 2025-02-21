#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "rpc_stats.h"
#include "rpc_task.h"
#include "nfs_client.h"

namespace aznfsc {

/* static */ struct rpc_opstat rpc_stats_az::opstats[FUSE_OPCODE_MAX + 1];
/* static */ std::mutex rpc_stats_az::stats_lock_42;
/* static */ std::atomic<uint64_t> rpc_stats_az::tot_read_reqs = 0;
/* static */ std::atomic<uint64_t> rpc_stats_az::failed_read_reqs = 0;
/* static */ std::atomic<uint64_t> rpc_stats_az::zero_reads = 0;
/* static */ std::atomic<uint64_t> rpc_stats_az::tot_bytes_read = 0;
/* static */ std::atomic<uint64_t> rpc_stats_az::bytes_read_from_cache = 0;
/* static */ std::atomic<uint64_t> rpc_stats_az::bytes_zeroed_from_cache = 0;
/* static */ std::atomic<uint64_t> rpc_stats_az::bytes_read_ahead = 0;
/* static */ std::atomic<uint64_t> rpc_stats_az::num_readhead = 0;
/* static */ std::atomic<uint64_t> rpc_stats_az::tot_getattr_reqs = 0;
/* static */ std::atomic<uint64_t> rpc_stats_az::getattr_served_from_cache = 0;
/* static */ std::atomic<uint64_t> rpc_stats_az::tot_lookup_reqs = 0;
/* static */ std::atomic<uint64_t> rpc_stats_az::lookup_served_from_cache = 0;
/* static */ std::atomic<uint64_t> rpc_stats_az::tot_write_reqs = 0;
/* static */ std::atomic<uint64_t> rpc_stats_az::failed_write_reqs = 0;
/* static */ std::atomic<uint64_t> rpc_stats_az::tot_bytes_written = 0;
/* static */ std::atomic<uint64_t> rpc_stats_az::inline_writes = 0;
/* static */ std::atomic<uint64_t> rpc_stats_az::inline_writes_lp = 0;
/* static */ std::atomic<uint64_t> rpc_stats_az::inline_writes_gp = 0;
/* static */ std::atomic<uint64_t> rpc_stats_az::flush_seq = 0;
/* static */ std::atomic<uint64_t> rpc_stats_az::flush_lp = 0;
/* static */ std::atomic<uint64_t> rpc_stats_az::flush_gp = 0;
/* static */ std::atomic<uint64_t> rpc_stats_az::commit_lp = 0;
/* static */ std::atomic<uint64_t> rpc_stats_az::commit_gp = 0;
/* static */ std::atomic<uint64_t> rpc_stats_az::writes_np = 0;
/* static */ std::atomic<uint64_t> rpc_stats_az::num_sync_membufs = 0;
/* static */ std::atomic<uint64_t> rpc_stats_az::tot_bytes_sync_membufs = 0;
/* static */ std::atomic<uint64_t> rpc_stats_az::rpc_tasks_allocated = 0;
/* static */ std::atomic<uint64_t> rpc_stats_az::fuse_responses_awaited = 0;
/* static */ std::atomic<uint64_t> rpc_stats_az::fuse_reply_failed = 0;

/* static */
void rpc_stats_az::dump_stats()
{
    const struct nfs_client& client = nfs_client::get_instance();
    const struct rpc_transport& transport = client.get_transport();
    const std::vector<struct nfs_connection*> connections =
        transport.get_all_connections();
    const struct mount_options& mo = client.mnt_options;
    const struct sockaddr_storage *saddr = nullptr;
    struct rpc_stats cum_stats = {};
    std::string str;
    uint64_t total_inodes, num_files, num_dirs, num_symlinks,
             open_files, open_dirs, num_files_cache_empty, num_dirs_cache_empty,
             num_forgotten, expecting_forget, num_dircached, num_silly_renamed;

    // Gather files/inode related stats.
    client.get_inode_stats(total_inodes,
                           num_files,
                           num_dirs,
                           num_symlinks,
                           open_files,
                           open_dirs,
                           num_files_cache_empty,
                           num_dirs_cache_empty,
                           num_forgotten,
                           expecting_forget,
                           num_dircached,
                           num_silly_renamed);

    /*
     * Take exclusive lock to avoid mixing dump from simultaneous dump
     * requests.
     */
    std::unique_lock<std::mutex> _lock(stats_lock_42);

    /*
     * Go over all connections, query libnfs for stats for each and accumulate
     * them.
     */
    for (struct nfs_connection *conn : connections) {
        struct rpc_stats stats;
        struct rpc_context *rpc = nfs_get_rpc_context(conn->get_nfs_context());

        /*
         * All nconnect connections will terminate at the same IPv4 address,
         * so use the one corresponding to the first connection.
         */
        if (!saddr) {
            saddr = nfs_get_server_address(conn->get_nfs_context());
            // Currently Blob NFS only supports IPv4 address.
            assert(((struct sockaddr_in *)saddr)->sin_family == AF_INET);
        }

        rpc_get_stats(rpc, &stats);

#define _CUM(s) cum_stats.s += stats.s
        _CUM(num_req_sent);
        _CUM(num_resp_rcvd);
        _CUM(num_timedout);
        _CUM(num_timedout_in_outqueue);
        _CUM(num_major_timedout);
        _CUM(num_retransmitted);
        _CUM(num_reconnects);
        _CUM(outqueue_len);
        _CUM(waitpdu_len);
#undef _CUM
    }

    str += "---[RPC stats]----------\n";
    str += "Stats for " + mo.server + ":" + mo.export_path +
           " mounted on " + mo.mountpoint + ":\n";
    str += "  NFS mount options:" +
           std::string(mo.readonly ? "ro" : "rw") +
           std::string(",vers=3") +
           ",rsize=" + std::to_string(mo.rsize_adj) +
           ",wsize=" + std::to_string(mo.wsize_adj) +
           ",acregmin=" + std::to_string(mo.acregmin) +
           ",acregmax=" + std::to_string(mo.acregmax) +
           ",acdirmin=" + std::to_string(mo.acdirmin) +
           ",acdirmax=" + std::to_string(mo.acdirmax) +
           std::string(",hard,proto=tcp") +
           ",nconnect=" + std::to_string(mo.num_connections) +
           ",port=" + std::to_string(mo.nfs_port) +
           ",timeo=" + std::to_string(mo.timeo) +
           ",retrans=" + std::to_string(mo.retrans) +
           std::string(",sec=sys") +
           std::string(",xprtsec=") + mo.xprtsec +
           std::string(",mountaddr=") +
           ::inet_ntoa(((struct sockaddr_in *)saddr)->sin_addr) +
           ",mountport=" + std::to_string(mo.mount_port) +
           std::string(",mountproto=tcp\n");

    str += "RPC statistics:\n";
    str += "  " + std::to_string(cum_stats.num_req_sent) +
                  " RPC requests sent\n";
    str += "  " + std::to_string(cum_stats.num_resp_rcvd) +
                  " RPC replies received\n";
    str += "  " + std::to_string(cum_stats.outqueue_len) +
                  " RPC requests in libnfs outqueue\n";
    str += "  " + std::to_string(cum_stats.waitpdu_len) +
                  " RPC requests in libnfs waitpdu queue\n";
    str += "  " + std::to_string(cum_stats.num_timedout_in_outqueue) +
                  " RPC requests timed out in outqueue\n";
    str += "  " + std::to_string(cum_stats.num_timedout) +
                  " RPC requests timed out waiting for response\n";
    str += "  " + std::to_string(cum_stats.num_major_timedout) +
                  " RPC requests major timed out\n";
    str += "  " + std::to_string(cum_stats.num_retransmitted) +
                  " RPC requests retransmitted\n";
    str += "  " + std::to_string(cum_stats.num_reconnects) +
                  " Reconnect attempts\n";

    str += "File/Inode statistics:\n";
    str += "  " + std::to_string(total_inodes) +
                  " total inodes\n";
    str += "  " + std::to_string(num_files) +
                  " regular files\n";
    str += "  " + std::to_string(num_dirs) +
                  " directories\n";
    str += "  " + std::to_string(num_symlinks) +
                  " symlinks\n";
    str += "  " + std::to_string(open_files) +
                  " files currently open\n";
    str += "  " + std::to_string(open_dirs) +
                  " directories currently open\n";
    str += "  " + std::to_string(num_files_cache_empty) +
                  " files have empty cache\n";
    str += "  " + std::to_string(num_dirs_cache_empty) +
                  " directories have empty cache\n";
    str += "  " + std::to_string(num_forgotten) +
                  " inodes forgotten by fuse, still in inode cache\n";
    str += "  " + std::to_string(expecting_forget) +
                  " inodes not yet forgotten by fuse\n";
    str += "  " + std::to_string(num_dircached) +
                  " inodes cached by one or more readdir cache\n";
    str += "  " + std::to_string(num_silly_renamed) +
                  " inodes silly-renamed (waiting for last close)\n";

    str += "File Cache statistics:\n";
    if (aznfsc_cfg.cache.data.user.enable) {
        str += "  " + std::to_string(aznfsc_cfg.cache.data.user.max_size_mb) +
                      " MB user cache size configured\n";
    } else {
        str += "  user cache disabled\n";
    }
    if (aznfsc_cfg.cache.data.kernel.enable) {
        str += "  kernel cache enabled\n";
    } else {
        str += "  kernel cache disabled\n";
    }
    str += "  " + std::to_string(bytes_chunk_cache::get_num_caches()) +
                  " file caches\n";
    str += "  " + std::to_string(bytes_chunk_cache::num_chunks_g) +
                  " chunks in chunkmap\n";
    str += "  " + std::to_string(bytes_chunk_cache::bytes_allocated_g) +
                  " bytes allocated\n";
    str += "  " + std::to_string(bytes_chunk_cache::bytes_cached_g) +
                  " bytes cached\n";
    str += "  " + std::to_string(bytes_chunk_cache::bytes_dirty_g) +
                  " bytes dirty\n";
    str += "  " + std::to_string(bytes_chunk_cache::bytes_flushing_g) +
                  " bytes currently flushing\n";
    str += "  " + std::to_string(bytes_chunk_cache::bytes_commit_pending_g) +
                  " bytes pending commit\n";
    str += "  " + std::to_string(bytes_chunk_cache::bytes_uptodate_g) +
                  " bytes uptodate\n";
    str += "  " + std::to_string(bytes_chunk_cache::bytes_inuse_g) +
                  " bytes inuse\n";
    str += "  " + std::to_string(bytes_chunk_cache::bytes_locked_g) +
                  " bytes locked\n";
    str += "  " + std::to_string(bytes_chunk_cache::bytes_get_g) +
                  " bytes mapped via " +
                  std::to_string(bytes_chunk_cache::num_get_g) +
                  " get calls\n";
    str += "  " + std::to_string(bytes_chunk_cache::bytes_release_g) +
                  " bytes released via " +
                  std::to_string(bytes_chunk_cache::num_release_g) +
                  " release calls\n";
    str += "  " + std::to_string(bytes_chunk_cache::bytes_truncate_g) +
                  " bytes truncated via " +
                  std::to_string(bytes_chunk_cache::num_truncate_g) +
                  " truncate calls\n";

    if (bytes_chunk_cache::num_lockwait_g) {
        const double lockwait_pct =
            ((bytes_chunk_cache::num_lockwait_g * 100.0) / bytes_chunk_cache::num_locked_g);
        str += "  " + std::to_string(bytes_chunk_cache::lock_wait_usecs_g /
                                     (bytes_chunk_cache::num_lockwait_g * 1000.0)) +
                      " msec avg lock wait (" +
                      std::to_string(lockwait_pct) + "% had to wait)\n";
    }

    str += "Application statistics:\n";
    const uint64_t avg_read_size =
        tot_read_reqs ? (tot_bytes_read / tot_read_reqs) : 0;
    str += "  " + std::to_string(GET_GBL_STATS(tot_bytes_read)) +
                  " bytes read by application(s) in " +
                  std::to_string(tot_read_reqs) + " calls with avg size " +
                  std::to_string(avg_read_size) + " bytes\n";
    if (failed_read_reqs) {
        str += "  " + std::to_string(GET_GBL_STATS(failed_read_reqs)) +
                      " application reads failed\n";
    }

    if (zero_reads) {
        str += "  " + std::to_string(GET_GBL_STATS(zero_reads)) +
                      " reads completed with 0 bytes\n";
    }

    const double read_cache_pct =
        tot_bytes_read ?
        ((bytes_read_from_cache * 100.0) / tot_bytes_read) : 0;
    assert(read_cache_pct <= 100);
    str += "  " + std::to_string(GET_GBL_STATS(bytes_read_from_cache)) +
                  " bytes served from read cache (" +
                  std::to_string(read_cache_pct) + "%)\n";

    const double hole_cache_pct =
        tot_bytes_read ?
        ((bytes_zeroed_from_cache * 100.0) / tot_bytes_read) : 0;
    assert(hole_cache_pct <= 100);
    str += "  " + std::to_string(GET_GBL_STATS(bytes_zeroed_from_cache)) +
                  " bytes holes read from cache (" +
                  std::to_string(hole_cache_pct) + "%)\n";

    const uint64_t avg_ra_size =
        num_readhead ? (bytes_read_ahead / num_readhead) : 0;
    str += "  " + std::to_string(GET_GBL_STATS(bytes_read_ahead)) +
                  " bytes read by readahead with avg size " +
                  std::to_string(avg_ra_size) + " bytes\n";

    const uint64_t avg_write_size =
        tot_write_reqs ? (tot_bytes_written / tot_write_reqs) : 0;
    str += "  " + std::to_string(GET_GBL_STATS(tot_bytes_written)) +
                  " bytes written by application(s) in " +
                  std::to_string(tot_write_reqs) + " calls with avg size " +
                  std::to_string(avg_write_size) + " bytes\n";
    if (failed_write_reqs) {
        str += "  " + std::to_string(GET_GBL_STATS(failed_write_reqs)) +
                      " application writes failed\n";
    }

    str += "  " + std::to_string(GET_GBL_STATS(writes_np)) +
                  " writes did not hit any memory pressure\n";
    str += "  " + std::to_string(GET_GBL_STATS(inline_writes)) +
                  " writes had to wait inline\n";
    str += "  " + std::to_string(GET_GBL_STATS(inline_writes_lp)) +
                  " writes were inlined due to per-file cache limit\n";
    str += "  " + std::to_string(GET_GBL_STATS(inline_writes_gp)) +
                  " writes were inlined due to global cache limit\n";
    str += "  " + std::to_string(GET_GBL_STATS(flush_seq)) +
                  " flushes triggered as sequential limit was reached\n";
    str += "  " + std::to_string(GET_GBL_STATS(flush_lp)) +
                  " flushes triggered as per-file cache limit was reached\n";
    str += "  " + std::to_string(GET_GBL_STATS(flush_gp)) +
                  " flushes triggered as global cache limit was reached\n";
    str += "  " + std::to_string(GET_GBL_STATS(commit_lp)) +
                  " commits triggered as per-file cache limit was reached\n";
    str += "  " + std::to_string(GET_GBL_STATS(commit_gp)) +
                  " commits triggered as global cache limit was reached\n";

    const uint64_t avg_sync_membufs_size =
        num_sync_membufs ? (tot_bytes_sync_membufs / num_sync_membufs) : 0;
    str += "  " + std::to_string(GET_GBL_STATS(num_sync_membufs)) +
                  " sync_membufs calls with avg size " +
                  std::to_string(avg_sync_membufs_size) + " bytes\n";

    const double getattr_cache_pct =
        tot_getattr_reqs ?
        ((getattr_served_from_cache * 100.0) / tot_getattr_reqs) : 0;
    str += "  " + std::to_string(GET_GBL_STATS(tot_getattr_reqs)) +
                  " getattr requests received\n";
    str += "  " + std::to_string(GET_GBL_STATS(getattr_served_from_cache)) +
                  " getattr served from cache (" +
                  std::to_string(getattr_cache_pct) + "%)\n";
    const double lookup_cache_pct =
        tot_lookup_reqs ?
        ((lookup_served_from_cache * 100.0) / tot_lookup_reqs) : 0;
    str += "  " + std::to_string(GET_GBL_STATS(tot_lookup_reqs)) +
                  " lookup requests received\n";
    str += "  " + std::to_string(GET_GBL_STATS(lookup_served_from_cache)) +
                  " lookup served from cache (" +
                  std::to_string(lookup_cache_pct) + "%)\n";

    str += "Misc statistics:\n";
    str += "  " + std::to_string(GET_GBL_STATS(rpc_tasks_allocated)) +
                  " rpc tasks currently running\n";
    str += "  " + std::to_string(GET_GBL_STATS(fuse_responses_awaited)) +
                  " responses awaited by fuse\n";
    str += "  " + std::to_string(GET_GBL_STATS(fuse_reply_failed)) +
                  " fuse replies failed to send\n";

#define DUMP_OP(opcode) \
do { \
    const auto& ops = opstats[opcode]; \
    if (ops.count != 0) { \
        const std::string opstr = rpc_task::fuse_opcode_to_string(opcode); \
        const int pcent_ops = (ops.count * 100.0) / cum_stats.num_req_sent; \
        str += opstr + ":\n"; \
        str += "        " + std::to_string(ops.count) + \
                        " ops (" + std::to_string(pcent_ops) + "%)\n"; \
        if (ops.pending > 0) { \
            str += "        " + std::to_string((int64_t) ops.pending) + \
                            " pending\n"; \
        } \
        str += "        Avg bytes sent per op: " + \
                        std::to_string(ops.bytes_sent / ops.count) + "\n"; \
        str += "        Avg bytes received per op: " + \
                        std::to_string(ops.bytes_rcvd / ops.count) + "\n"; \
        str += "        Avg RTT: " + \
                        std::to_string(ops.rtt_usec / (ops.count * 1000.0)) + \
                        " msec\n"; \
        str += "        Avg dispatch wait: " + \
                        std::to_string(ops.dispatch_usec / (ops.count * 1000.0)) + \
                        " msec\n"; \
        str += "        Avg fuse issue time: " + \
                        std::to_string(ops.fuse_handler_usec / (ops.count * 1000.0)) + \
                        " msec\n"; \
        str += "        Avg Total execute time: " + \
                        std::to_string(ops.total_usec / (ops.count * 1000.0)) + \
                        " msec\n"; \
        if (!ops.error_map.empty()) { \
            str += "        Errors encountered: \n"; \
            for (const auto& entry : ops.error_map) { \
                str += "            " + \
                        std::string((entry.first == NFS3ERR_RPC_ERROR) ? \
                                    "RPC Errors" : nfsstat3_to_str(entry.first)) +  ": " + \
                        std::to_string(entry.second) + "\n"; \
            } \
        } \
    } \
} while (0)

    DUMP_OP(FUSE_STATFS);
    DUMP_OP(FUSE_LOOKUP);
    DUMP_OP(FUSE_ACCESS);
    DUMP_OP(FUSE_GETATTR);
    DUMP_OP(FUSE_SETATTR);
    DUMP_OP(FUSE_CREATE);
    DUMP_OP(FUSE_MKNOD);
    DUMP_OP(FUSE_MKDIR);
    DUMP_OP(FUSE_SYMLINK);
    DUMP_OP(FUSE_READLINK);
    DUMP_OP(FUSE_RMDIR);
    DUMP_OP(FUSE_UNLINK);
    DUMP_OP(FUSE_RENAME);
    DUMP_OP(FUSE_READDIR);
    DUMP_OP(FUSE_READDIRPLUS);
    DUMP_OP(FUSE_READ);
    DUMP_OP(FUSE_WRITE);
    // FUSE_FLUSH corresponds to the COMMIT RPC
    DUMP_OP(FUSE_FLUSH);

    /*
     * TODO: Add more ops.
     */

    AZLogWarn("\n{}\n", str.c_str());
}

}
