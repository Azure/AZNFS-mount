#include "rpc_transport.h"
#include "nfs_client.h"

#include <thread>
#include <vector>

bool rpc_transport::start()
{
    // constructor must have resized the connection vector correctly.
    assert((int) nfs_connections.size() == client->mnt_options.num_connections);

    /*
     * An RPC transport is composed of one or more connections.
     * Starting the transport involves setting up these connections.
     *
     * Note: Currently we create all the connections upfront for simplicity.
     *       We might consider setting up connections when needed and then
     *       destroying them if idle for some time.
     * Note: We perform all the mounts in parallel else it takes a long time
     *       to startup.
     */
    std::vector<std::thread> vt;
    std::atomic<int> successful_connections = 0;

    for (int i = 0; i < client->mnt_options.num_connections; i++) {
        vt.emplace_back(std::thread([&, i]() {
            AZLogDebug("Starting thread for creating connection #{}", i);

            struct nfs_connection *connection = new nfs_connection(client, i);

            if (!connection->open()) {
                AZLogError("Failed to setup connection #{}", i);

                /*
                 * Failed to establish this connection.
                 * Convey failure to the main thread by storing a nullptr for
                 * this connection. It'll then perform the cleanup.
                 */
                delete connection;

                assert(nfs_connections[i] == nullptr);
                nfs_connections[i] = nullptr;

                return;
            }

            /*
             * TODO: assert that rootfh received over each connection is same.
             */

            /*
             * Ok, connection setup properly, add it to the list of connections
             * for this transport and update number of successful connections,
             * so that caller knows whether all connections were successfully
             * created.
             */
            assert(nfs_connections[i] == nullptr);
            nfs_connections[i] = connection;
            successful_connections++;

            return;
        }));
    }

    /*
     * Now wait for all connections to mount and setup correctly..
     */
    AZLogDebug("Waiting for {} nconnect connection(s) to setup",
               client->mnt_options.num_connections);

    for (auto& t : vt) {
        t.join();
    }

    /*
     * TODO: Continue if we have minimum number of connections?
     */
    if (successful_connections != client->mnt_options.num_connections) {
        AZLogError("One or more connection setup failed, cleaning up!");
        close();
        return false;
    }

    assert((int) nfs_connections.size() == client->mnt_options.num_connections);

    AZLogDebug("Successfully created all {} nconnect connection(s)",
               client->mnt_options.num_connections);
    return true;
}

void rpc_transport::close()
{
    assert((int) nfs_connections.size() == client->mnt_options.num_connections);

    for (int i = 0; i < (int) nfs_connections.size(); i++) {
        struct nfs_connection *connection = nfs_connections[i];
        if (connection != nullptr) {
            connection->close();
            delete connection;
        }
    }

    nfs_connections.clear();
}

/*
 * This function decides which connection should be chosen for sending
 * the current request.
 */
struct nfs_context *rpc_transport::get_nfs_context(conn_sched_t csched,
                                                   uint32_t fh_hash) const
{
    int idx = 0;
    const int nconn = client->mnt_options.num_connections;
    assert(nconn > 0);
    const int rconn = nconn / 2;
    const int wconn = nconn - rconn;

    static std::atomic<uint64_t> last_sec;
    static std::atomic<bool> rnw = false;
    uint64_t now_sec = ::time(NULL);

    assert(now_sec >= last_sec);

    /*
     * Take stock of things, no sooner than 5 secs.
     */
    if (now_sec > (last_sec + 5)) {
        /*
         * Refresh read/write MBps if not already done.
         * We call periodic_updater() from inline_prune() which is only
         * called when there are read/write IOs, so we might be using stale
         * read/write MBps values if read/write requests are not happening.
         */
        client->periodic_updater();

        const uint64_t r_MBps = client->get_read_MBps();
        const uint64_t w_MBps = client->get_write_MBps();

        /*
         * If both read and write are happening, assign them to separate
         * connection pool, else writes may slow down reads as small write
         * responses have to wait behind large read responses and v.v.
         */
        if (w_MBps > 100 && r_MBps > 100) {
            rnw = (nconn >= 4);
            AZLogInfoNR("[RNW=true] Write: {} Gbps, Read: {} Gbps",
                        (w_MBps * 8.0) / 1000, (r_MBps * 8.0) / 1000);
        } else {
            rnw = false;
            if (w_MBps > 0 || r_MBps > 0) {
                AZLogInfoNR("[RNW=false] Write: {} Gbps, Read: {} Gbps",
                            (w_MBps * 8.0) / 1000, (r_MBps * 8.0) / 1000);
            }
        }

        assert(!rnw || (rconn > 0 && wconn > 0));
        last_sec = now_sec;
    }

    struct nfs_context *nfs = nullptr;
    uint32_t qlen = 0, avg_qlen = 0;

    switch (csched) {
        case CONN_SCHED_FIRST:
            idx = 0;
            break;
        case CONN_SCHED_RR_R:
            /*
             * Reads get top half of connections when there are simultaneous
             * readers and writers, else they get all the connections.
             * The for loop is to keep connections balanced.
             */
            for (int i = 0; i < nconn; i++) {
                idx = (rnw ? (wconn + (last_context++ % rconn))
                           : (last_context++ % nconn));
                nfs = nfs_connections[idx]->get_nfs_context();
                qlen = nfs_queue_length(nfs);
                max_qlen_r = std::max(max_qlen_r, qlen);
                cum_qlen_r += qlen;
                // Reset cum/cnt stats every few requests to drop stale info.
                if (cnt_qlen_r++ == 1000) {
                    AZLogDebug("[CONN_SCHED_RR_R] i: {} idx: {} qlen: {} "
                               "avg: {} max: {}",
                               i, idx, qlen, cum_qlen_r / cnt_qlen_r,
                               max_qlen_r);

                    cnt_qlen_r = 1;
                    cum_qlen_r = qlen;
                    max_qlen_r = qlen;
                }
                avg_qlen = cum_qlen_r / cnt_qlen_r;
                if (qlen <= avg_qlen) {
                    break;
                }
            }
            break;
        case CONN_SCHED_RR_W:
            /*
             * Writes get lower half  connections when there are simultaneous
             * readers and writers, else they get all the connections.
             *
             * TODO: We should not change write connection ranges while there
             *       are old writes still pending else we will get slowed down
             *       by optimistic concurrency backoff.
             */
            for (int i = 0; i < nconn; i++) {
                idx = (rnw ? (last_context++ % wconn)
                           : (last_context++ % nconn));
                nfs = nfs_connections[idx]->get_nfs_context();
                qlen = nfs_queue_length(nfs);
                max_qlen_w = std::max(max_qlen_w, qlen);
                cum_qlen_w += qlen;
                if (cnt_qlen_w++ == 1000) {
                    AZLogDebug("[CONN_SCHED_RR_W] i: {} idx: {} qlen: {} "
                               "avg: {} max: {}",
                               i, idx, qlen, cum_qlen_w / cnt_qlen_w,
                               max_qlen_w);

                    cnt_qlen_w = 1;
                    cum_qlen_w = qlen;
                    max_qlen_w = qlen;
                }
                avg_qlen = cum_qlen_w / cnt_qlen_w;
                if (qlen <= avg_qlen) {
                    break;
                }
            }
            break;
        case CONN_SCHED_FH_HASH:
            assert(fh_hash != 0);
            idx = rnw ? (fh_hash % wconn) : (fh_hash % nconn);
            break;
        default:
            assert(0);
    }

    assert(idx >= 0 && idx < client->mnt_options.num_connections);

    return nfs_connections[idx]->get_nfs_context();
}
