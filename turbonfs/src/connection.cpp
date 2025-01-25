#include "connection.h"
#include "nfs_client.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <arpa/inet.h>

/*
 * Return a unique id to identify this client to the server.
 * As of now we use the interface IPv4 address string, 
 * but it can be changed to anything else in future.
 */
std::string get_clientid() {
    struct ifaddrs *ifaddr = nullptr;
    struct ifaddrs *ifa = nullptr;
    char ip[INET_ADDRSTRLEN] = {0};
    static std::string client_id = std::to_string(get_current_usecs()) + "-";

    /*
     * Whatever is encoded here should not exceed the maximum possible that can be 
     * encoded in AZAuth RPC
     */
    [[maybe_unused]]
    constexpr size_t MAX_IP_LENGTH = 64;

    // Get the list of network interfaces
    if (::getifaddrs(&ifaddr) == -1) {
        AZLogError("Failed to get network interfaces: {}", strerror(errno));
        goto failed_get_clientip;
    }

    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {

        if (ifa->ifa_addr == nullptr)
            continue;
        // Skip non IPv4 address. 
        if (ifa->ifa_addr->sa_family != AF_INET) 
            continue;
        // Skip loopback interface.
        if (::strcmp(ifa->ifa_name, "lo") == 0) 
            continue;

        struct sockaddr_in *addr = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr);

        // Convert binary address to string.
        if (::inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip)) == nullptr) {
            AZLogError("Failed to convert binary IP to string: {}", strerror(errno));
            goto failed_get_clientip;
        }
        break;
    }

    freeifaddrs(ifaddr);

    if (ip[0] == '\0') {
        AZLogError("No valid IPv4 address found.");
        goto failed_get_clientip;
    }

    client_id += std::string(ip);

failed_get_clientip:
    // We cannot send clientid of size more than MAX_IP_LENGTH.
    assert(client_id.length() <= MAX_IP_LENGTH);
    AZLogDebug("Using clientid {}", client_id);

    return client_id;
}

bool nfs_connection::open()
{
    const int nodelay = 1;

    // open() must be called only for a closed connection.
    assert(nfs_context == nullptr);

    nfs_context = nfs_init_context();
    if (nfs_context == nullptr) {
        AZLogError("Failed to init libnfs nfs_context");
        return false;
    }

    struct mount_options& mo = client->mnt_options;
    const std::string url_str = mo.get_url_str();

    AZLogDebug("Parsing NFS URL string: {}", url_str);

    struct nfs_url *url = nfs_parse_url_full(nfs_context, url_str.c_str());
    if (url == NULL) {
        AZLogError("Failed to parse nfs url {}", url_str);
        goto destroy_context;
    }

    assert(mo.server == url->server);
    assert(mo.export_path == url->path);

    nfs_destroy_url(url);

    if (mo.auth) {
        // 16 should be sufficient to hold the version string.
        char client_version[16];

        [[maybe_unused]]
        const uint64_t n = snprintf(client_version, sizeof(client_version),
                                    "%d.%d.%d", AZNFSCLIENT_VERSION_MAJOR,
                                    AZNFSCLIENT_VERSION_MINOR,
                                    AZNFSCLIENT_VERSION_PATCH);
        assert(n < sizeof(client_version));

        std::string client_id = get_clientid();

        assert(!mo.export_path.empty());
        assert(!mo.authtype.empty());
        assert(strlen(client_version) > 0);
        assert(!client_id.empty());

        const int ret = nfs_set_auth_context(nfs_context,
                                             mo.export_path.c_str(),
                                             mo.authtype.c_str(),
                                             client_version,
                                             client_id.c_str());
        if (ret != 0) {
            AZLogError("Failed to set auth values in nfs context, "
                       "exportpath={} authtype={} "
                       "clientversion={} clientid={}",
                       mo.export_path.c_str(),
                       mo.authtype.c_str(),
                       client_version,
                       client_id.c_str());
            goto destroy_context;
        }
    }

    /*
     * Call libnfs for mounting the share.
     * This will create a connection to the NFS server and perform mount.
     * After this the nfs_context can be used for sending NFS requests.
     */
    int status;
    do {
        status = nfs_mount(nfs_context, mo.server.c_str(),
                           mo.export_path.c_str());
        if (status == -EAGAIN) {
            AZLogWarn("[{}] JUKEBOX error mounting nfs share ({}:{}): {}, "
                      "retrying in 5 secs!",
                      (void *) nfs_context,
                      mo.server,
                      mo.export_path,
                      nfs_get_error(nfs_context));
            ::sleep(5);
            continue;
        } else if (status != 0) {
            AZLogError("[{}] Failed to mount nfs share ({}:{}): {} ({})",
                       (void *) nfs_context,
                       mo.server,
                       mo.export_path,
                       nfs_get_error(nfs_context),
                       status);
            goto destroy_context;
        }
    } while (status == -EAGAIN);

    /*
     * A successful mount must have negotiated valid values for these.
     */
    assert(nfs_get_readmax(nfs_context) >= AZNFSCFG_RSIZE_MIN);
    assert(nfs_get_readmax(nfs_context) <= AZNFSCFG_RSIZE_MAX);

    assert(nfs_get_writemax(nfs_context) >= AZNFSCFG_WSIZE_MIN);
    assert(nfs_get_writemax(nfs_context) <= AZNFSCFG_WSIZE_MAX);

    assert(nfs_get_readdir_maxcount(nfs_context) >= AZNFSCFG_READDIR_MIN);
    assert(nfs_get_readdir_maxcount(nfs_context) <= AZNFSCFG_READDIR_MAX);

    /*
     * Save the final negotiated value in mount_options for future ref.
     */
    if (mo.rsize_adj == 0) {
        mo.rsize_adj = nfs_get_readmax(nfs_context);
    } else {
        // All connections must have the same negotiated value.
        assert(mo.rsize_adj == (int) nfs_get_readmax(nfs_context));
    }

    if (mo.wsize_adj == 0) {
        mo.wsize_adj = nfs_get_writemax(nfs_context);
    } else {
        // All connections must have the same negotiated value.
        assert(mo.wsize_adj == (int) nfs_get_writemax(nfs_context));
    }

    if (mo.readdir_maxcount_adj == 0) {
        mo.readdir_maxcount_adj = nfs_get_readdir_maxcount(nfs_context);
    } else {
        // All connections must have the same negotiated value.
        assert(mo.readdir_maxcount_adj ==
               (int) nfs_get_readdir_maxcount(nfs_context));
    }

    /*
     * We must send requests promptly w/o waiting for nagle delay.
     *
     * TODO: Once this is moved to libnfs, it can be removed from here.
     */
    if (::setsockopt(nfs_get_fd(nfs_context), IPPROTO_TCP, TCP_NODELAY,
                     &nodelay, sizeof(nodelay)) != 0) {
        AZLogError("Cannot enable TCP_NODELAY for fd {}: {}",
                   nfs_get_fd(nfs_context), strerror(errno));
        // Let's assert in debug builds and continue o/w.
        assert(0);
    }

    /*
     * libnfs service loop wakes up every poll_timeout msecs to see if there
     * is any request pdu to send. Though lone request pdus are sent in the
     * requester's context, we use eventfd to notify the service thread when
     * a new PDU is queued for sending. Use infinite poll timeout in debug
     * builds to catch any bugs with eventfd notification.
     */
#ifdef ENABLE_DEBUG
    nfs_set_poll_timeout(nfs_context, INT_MAX);
#else
    nfs_set_poll_timeout(nfs_context, 1000);
#endif

    /*
     * We use libnfs in multithreading mode as we want 1 thread to do the IOs
     * on the nfs context and another thread to service this nfs context to
     * send/recv data over the socket. Hence we must initialize and start the
     * service thread.
     *
     * Note: We set the stack size to 16MB as the default 8MB is not sufficient
     *       for very large readdir/readdirplus responses as the zdr decoder
     *       is recursive.
     * TODO: See if we need to making this a config option.
     */
    if (nfs_mt_service_thread_start_ss(nfs_context, 16ULL * 1024 * 1024)) {
        AZLogError("[{}] Failed to start libnfs service thread.",
                   (void *) nfs_context);
        goto unmount_and_destroy_context;
    }

    AZLogInfo("[{} / {}] Successfully mounted nfs share ({}:{}). "
              "Negotiated values: readmax={}, writemax={}, readdirmax={}",
              (void *) nfs_context,
              nfs_get_tid(nfs_context),
              mo.server,
              mo.export_path,
              nfs_get_readmax(nfs_context),
              nfs_get_writemax(nfs_context),
              nfs_get_readdir_maxcount(nfs_context));

    return true;

unmount_and_destroy_context:
    nfs_umount(nfs_context);
destroy_context:
    nfs_destroy_context(nfs_context);
    nfs_context = nullptr;
    return false;
}
