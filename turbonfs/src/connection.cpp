#include "connection.h"
#include "nfs_client.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <uuid/uuid.h>



/*
 * Return a unique id to identify this client to the server.
 * As of now we use a random guid + current time in seconds + interface IPv4 address string,
 * but it can be changed to anything else in future.
 * We have the following requirements:
 * 1. Unique accross all turbonfs clients.
 * 2. If turbonfs client restarts, it should get a new client id so that server does not confuse the blocks written
 *    by previous client with the restarted one. 
 * Sample client ID: 1c0732a9-dc6f-436a-adcb-7fab6a9848e71753788278-10.1.0.4.
 */

std::string get_clientid() 
{
    struct ifaddrs *ifaddr = nullptr;
    struct ifaddrs *ifa = nullptr;
    char ip[INET_ADDRSTRLEN] = {0};

    /*
     * Whatever is encoded here should not exceed the maximum possible that can be 
     * encoded in AZAuth RPC
     */
    [[maybe_unused]]
    constexpr size_t MAX_CLIENT_ID_LENGTH = 64;

    std::string clientid_ipaddress = "unknown";

    // Get the list of network interfaces
    if (::getifaddrs(&ifaddr) == -1) {
        AZLogError("Failed to get network interfaces: {}", strerror(errno));
        
    } else {
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
            } else {
                clientid_ipaddress = std::string(ip);
            }
            break;
        }
    
        freeifaddrs(ifaddr);

    }

    if (ip[0] == '\0') {
        AZLogError("No valid IPv4 address found.");
    }

    // Build and cache the client ID only once.
    static std::string client_id = [clientid_ipaddress]() {
        
        uuid_t uuid;
        char uuid_str[37]; // 36 characters + null terminator

        // Generate the UUID
        uuid_generate(uuid);

        // Convert to string with dashes
        uuid_unparse(uuid, uuid_str);

        long current_secs = static_cast<long>(time(nullptr));
        std::string client_id_str = std::string(uuid_str) + std::to_string(current_secs) + "-" + clientid_ipaddress;

        // Ensure length fits within MAX_CLIENT_ID_LENGTH
        if (client_id_str.length() > MAX_CLIENT_ID_LENGTH) {
            client_id_str = client_id_str.substr(0, MAX_CLIENT_ID_LENGTH);
        }

        AZLogDebug("Using clientid {}", client_id_str);
        return client_id_str;
    }();

    // We cannot send clientid of size more than MAX_CLIENT_ID_LENGTH.
    assert(client_id.length() <= MAX_CLIENT_ID_LENGTH);

    return client_id;
}

bool nfs_connection::open()
{
    const int nodelay = 1;
    uint64_t n;
    int ret;

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

    // 16 should be sufficient to hold the version string.
    char client_version[16];

    n = snprintf(client_version, sizeof(client_version),
                                "%d.%d.%d", AZNFSCLIENT_VERSION_MAJOR,
                                AZNFSCLIENT_VERSION_MINOR,
                                AZNFSCLIENT_VERSION_PATCH);
    assert(n < sizeof(client_version));

    static const std::string client_id = get_clientid();

    assert(!mo.export_path.empty());
    assert(!mo.authtype.empty());
    assert(strlen(client_version) > 0);
    assert(!client_id.empty());

    ret = nfs_set_auth_context(nfs_context,
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

    /*
     * Default hash size used for queueing RPC requests is very small.
     * Since we can keep thousands of RPC requests outstanding, bump
     * it up.
     */
    if (nfs_set_hash_size(nfs_context, 1024)) {
        AZLogError("Failed to set libnfs hash size to 1024");
        goto destroy_context;
    }

    /*
     * LLAM may cause Blob NFS endpoint IP to change, direct libnfs to resolve
     * before reconnect.
     */
    if (aznfsc_cfg.sys.resolve_before_reconnect) {
        nfs_set_resolve_on_reconnect(nfs_context);
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
     *
     * XXX We cannot safely do this as setting infinite poll timeout causes
     *     libnfs to not handle RPC timeouts. Note that for libnfs to detect
     *     RPC timeouts it must run the rpc_service() loop and if there is
     *     say request(s) lying only in the waitpdu queue and no incoming
     *     data then poll() will never come out.
     */
#ifdef ENABLE_DEBUG
    //nfs_set_poll_timeout(nfs_context, INT_MAX);
    nfs_set_poll_timeout(nfs_context, 1000);
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