#include "aznfsc.h"
#include "rpc_stats.h"

#include <signal.h>

#include <azure/identity/azure_cli_credential.hpp>
#include <azure/core/datetime.hpp>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

/*
 * Note: This file should only contain code needed for fuse interfacing.
 */

using namespace std;

/**
 * This holds the global options for the fuse like max_write, max_readahead etc,
 * passed from command line.
 */
struct fuse_conn_info_opts* fuse_conn_info_opts_ptr;

/*
 * These are aznfsclient specific options.
 * These can be passed to aznfsclient fuse program, in addition to the standard
 * fuse options.
 */
#define AZNFSC_OPT(templ, key) { templ, offsetof(struct aznfsc_cfg, key), 0}

std::atomic<bool> client_started = false;

/*
 * Is 'az login' required?
 * It is set when the user has enabled auth in config but they have not done 'az login'.
 */ 
bool is_azlogin_required = false; 

/*
 * Stores the error string to be returned to the mount program over the status pipe.
 */
std::string status_pipe_error_string;

static const struct fuse_opt aznfsc_opts[] =
{
    AZNFSC_OPT("--config-file=%s", config_yaml),
    AZNFSC_OPT("--account=%s", account),
    AZNFSC_OPT("--container=%s", container),
    AZNFSC_OPT("--cloud-suffix=%s", cloud_suffix),
    AZNFSC_OPT("--port=%u", port),
    AZNFSC_OPT("--nconnect=%u", nconnect),
    FUSE_OPT_END
};

struct auth_info
{
    std::string tenantid;
    std::string subscriptionid;
    std::string username;
    std::string usertype;
    std::string resourcegroupname;
};

void aznfsc_help(const char *argv0)
{
    printf("usage: %s [options] <mountpoint>\n\n", argv0);
    printf("    --config-file=<config.yaml file path>\n");
    printf("    --account=<storage account>\n");
    printf("    --container=<container>\n");
    printf("    --cloud-suffix=<cloud suffix>\n");
    printf("    --port=<Blob NFS port, can be 2048 or 2047>\n");
    printf("    --nconnect=<number of simultaneous connections>\n");
}

/*
 * FS handler definitions common between fuse and nofuse.
 */
#include "fs-handler.h"

/*
 * Handlers specific to fuse.
 */
static void aznfsc_ll_init(void *userdata,
                           struct fuse_conn_info *conn)
{
    /*
     * TODO: Kernel conveys us the various filesystem limits by passing the
     *       fuse_conn_info pointer. If we need to reduce any of the limits
     *       we can do so. Usually we may not be interested in reducing any
     *       of those limits.
     *       We can at least log from here so that we know the limits.
     */

    /*
     * Apply the user passed options (-o). This must be done before
     * the overrides we have below. This is because those overrides are
     * our limitation and we cannot let user bypass them.
     *
     * Note: fuse_session_new() no longer accepts arguments
     *       command line options can only be set using
     *       fuse_apply_conn_info_opts().
     */
    fuse_apply_conn_info_opts(fuse_conn_info_opts_ptr, conn);

    /*
     * XXX Disable readdir temporarily while I work on fixing readdirplus.
     *     Once readdirplus is audited/fixed, enable readdir and audit/fix
     *     that.
     * TODO: Readdir works fine but just that for readdir fuse kernel
     *       will not send FORGET and thus we currently don't delete those
     *       entries and the inodes. Need to add memory pressure based
     *       deletion for those.
     */
    conn->want |= FUSE_CAP_READDIRPLUS;
    conn->want |= FUSE_CAP_READDIRPLUS_AUTO;

    /*
     * Fuse kernel driver must issue parallel readahead requests.
     */
    // conn->want |= FUSE_CAP_ASYNC_READ;

    // Blob NFS doesn't support locking.
    conn->want &= ~FUSE_CAP_POSIX_LOCKS;
    conn->want &= ~FUSE_CAP_FLOCK_LOCKS;

    // TODO: See if we can support O_TRUNC.
    conn->want &= ~FUSE_CAP_ATOMIC_O_TRUNC;

    /*
     * For availing perf advantage of splice() we must add splice()/sendfile()
     * support to libnfs. Till then just disable splicing so fuse never sends
     * us fd+offset but just a plain buffer.
     * Test splice read/write performance before enabling.
     */
    conn->want &= ~FUSE_CAP_SPLICE_WRITE;
    conn->want &= ~FUSE_CAP_SPLICE_MOVE;
    conn->want &= ~FUSE_CAP_SPLICE_READ;

    // conn->want |= FUSE_CAP_AUTO_INVAL_DATA;
    // conn->want |= FUSE_CAP_ASYNC_DIO;

    if (aznfsc_cfg.cache.data.kernel.enable) {
        conn->want |= FUSE_CAP_WRITEBACK_CACHE;
    } else {
        conn->want &= ~FUSE_CAP_WRITEBACK_CACHE;
    }

    // conn->want |= FUSE_CAP_PARALLEL_DIROPS;
    conn->want &= ~FUSE_CAP_POSIX_ACL;

    // TODO: See if we should enable this.
    conn->want &= ~FUSE_CAP_CACHE_SYMLINKS;
#if 0
    conn->want &= ~FUSE_CAP_SETXATTR_EXT;
#endif

#if 0
    /*
     * Fuse wants max_read set here to match the mount option passed
     * -o max_read=<n>
     */
    if (conn->max_read) {
        conn->max_read =
            std::min<unsigned int>(conn->max_read, AZNFSC_MAX_CHUNK_SIZE);
    } else {
        conn->max_read = AZNFSC_MAX_CHUNK_SIZE;
    }

    if (conn->max_readahead) {
        conn->max_readahead =
            std::min<unsigned int>(conn->max_readahead, AZNFSC_MAX_CHUNK_SIZE);
    } else {
        conn->max_readahead = AZNFSC_MAX_CHUNK_SIZE;
    }
    if (conn->max_write) {
        conn->max_write =
            std::min<unsigned int>(conn->max_write, AZNFSC_MAX_CHUNK_SIZE);
    } else {
        conn->max_write = AZNFSC_MAX_CHUNK_SIZE;
    }
#endif

    /*
     * If user has explicitly specified "-o max_background=", honour that,
     * else if he has specified fuse_max_background config, use that, else
     * pick a good default.
     */
    if (conn->max_background == 0) {
        if (aznfsc_cfg.fuse_max_background != -1) {
            conn->max_background = aznfsc_cfg.fuse_max_background;
        } else {
            conn->max_background = AZNFSCFG_FUSE_MAX_BG_DEF;
        }
    }

    /*
     * Set kernel readahead_kb if kernel data cache is enabled.
     */
    set_kernel_readahead();

    /*
     * Disable OOM killing for aznfsclient process if user has selected.
     */
    disable_oom_kill();

    AZLogDebug("===== fuse_conn_info fields start =====");
    AZLogDebug("proto_major = {}", conn->proto_major);
    AZLogDebug("proto_minor = {}", conn->proto_minor);
    AZLogDebug("max_write = {}", conn->max_write);
    AZLogDebug("max_read = {}", conn->max_read);
    AZLogDebug("max_readahead = {}", conn->max_readahead);
    AZLogDebug("capable = 0x{:x}", conn->capable);
    AZLogDebug("want = 0x{:x}", conn->want);
    AZLogDebug("max_background = {}", conn->max_background);
    AZLogDebug("congestion_threshold = {}", conn->congestion_threshold);
    AZLogDebug("time_gran = {}", conn->time_gran);
    AZLogDebug("===== fuse_conn_info fields end =====");
}

static void aznfsc_ll_destroy(void *userdata)
{
    /*
     * TODO: Again, we can just log from here or any cleanup we want to do
     *       when a fuse nfs filesystem is unmounted. Note that connection to
     *       the kernel may be gone by the time this is called so we cannot
     *       make any call that calls into kernel.
     */
}

static std::atomic<uint64_t> total_forgotten = 0;

static void aznfsc_ll_forget(fuse_req_t req,
                             fuse_ino_t ino,
                             uint64_t nlookup)
{
    total_forgotten++;

    AZLogDebug("aznfsc_ll_forget(req={}, ino={}, nlookup={}) "
               "total_forgotten={}",
               fmt::ptr(req), ino, nlookup, total_forgotten.load());

    struct nfs_client *client = get_nfs_client_from_fuse_req(req);
    struct nfs_inode *inode = client->get_nfs_inode_from_ino(ino);

    /*
     * Decrement refcnt of the inode and free the inode if refcnt becomes 0.
     */
    inode->decref(nlookup, true /* from_forget */);
    fuse_reply_none(req);
}

void aznfsc_ll_forget_multi(fuse_req_t req,
                            size_t count,
                            struct fuse_forget_data *forgets)
{
    total_forgotten += count;

    AZLogDebug("aznfsc_ll_forget_multi(req={}, count={}) total_forgotten={}",
               fmt::ptr(req), count, total_forgotten.load());

    struct nfs_client *client = get_nfs_client_from_fuse_req(req);

    for (size_t i = 0; i < count; i++) {
        const uint64_t nlookup = forgets[i].nlookup;
        const fuse_ino_t ino = forgets[i].ino;
        struct nfs_inode *inode = client->get_nfs_inode_from_ino(ino);

        AZLogDebug("forget(ino={}, nlookup={})", ino, nlookup);
        /*
         * Decrement refcnt of the inode and free the inode if refcnt
         * becomes 0.
         */
        inode->decref(nlookup, true /* from_forget */);
    }

    fuse_reply_none(req);
}

static struct fuse_lowlevel_ops aznfsc_ll_ops = {
    .init               = aznfsc_ll_init,
    .destroy            = aznfsc_ll_destroy,
    .lookup             = aznfsc_ll_lookup,
    .forget             = aznfsc_ll_forget,
    .getattr            = aznfsc_ll_getattr,
    .setattr            = aznfsc_ll_setattr,
    .readlink           = aznfsc_ll_readlink,
    .mknod              = aznfsc_ll_mknod,
    .mkdir              = aznfsc_ll_mkdir,
    .unlink             = aznfsc_ll_unlink,
    .rmdir              = aznfsc_ll_rmdir,
    .symlink            = aznfsc_ll_symlink,
    .rename             = aznfsc_ll_rename,
    .link               = aznfsc_ll_link,
    .open               = aznfsc_ll_open,
    .read               = aznfsc_ll_read,
    .write              = aznfsc_ll_write,
    .flush              = aznfsc_ll_flush,
    .release            = aznfsc_ll_release,
    .fsync              = aznfsc_ll_fsync,
    .opendir            = aznfsc_ll_opendir,
    .readdir            = aznfsc_ll_readdir,
    .releasedir         = aznfsc_ll_releasedir,
    .fsyncdir           = aznfsc_ll_fsyncdir,
    .statfs             = aznfsc_ll_statfs,
    .setxattr           = aznfsc_ll_setxattr,
    .getxattr           = aznfsc_ll_getxattr,
    .listxattr          = aznfsc_ll_listxattr,
    .removexattr        = aznfsc_ll_removexattr,
    .access             = aznfsc_ll_access,
    .create             = aznfsc_ll_create,
    .getlk              = aznfsc_ll_getlk,
    .setlk              = aznfsc_ll_setlk,
    .bmap               = aznfsc_ll_bmap,
    .ioctl              = aznfsc_ll_ioctl,
    .poll               = aznfsc_ll_poll,
    .write_buf          = aznfsc_ll_write_buf,
    .retrieve_reply     = aznfsc_ll_retrieve_reply,
    .forget_multi       = aznfsc_ll_forget_multi,
    .flock              = aznfsc_ll_flock,
    .fallocate          = aznfsc_ll_fallocate,
    .readdirplus        = aznfsc_ll_readdirplus,
    .copy_file_range    = aznfsc_ll_copy_file_range,
    .lseek              = aznfsc_ll_lseek,
};

/*
 * Setup signal handler for the given signal.
 */
static int set_signal_handler(int signum, void (*handler)(int))
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(struct sigaction));
    sa.sa_handler = handler;
    sigemptyset(&(sa.sa_mask));
    sa.sa_flags = 0;

    return sigaction(signum, &sa, NULL);
}

static void handle_usr1([[maybe_unused]] int signum)
{
    /*
     * Till all nfs_context are setup, it's not safe to run dump_stats().
     */
    if (!client_started) {
        return;
    }

    const int saved_errno = errno;
    assert(signum == SIGUSR1);
    rpc_stats_az::dump_stats();
    errno = saved_errno;
}

/**
 * Block various signals that can cause process termination.
 * This is a safety thing to prevent fuse process from being killed causing
 * mount to become unavailable.
 *
 * Note: There are few other signals like SIGABRT, SIGALRM, etc, but those are
 *       rarely sent from commandline, so we leave them unchanged.
 */
#ifdef ENABLE_RELEASE_BUILD
static void block_termination_signals()
{
    if (set_signal_handler(SIGHUP, SIG_IGN) != 0) {
        AZLogError("set_signal_handler(SIGHUP) failed: {}", ::strerror(errno));
    }

    if (set_signal_handler(SIGINT, SIG_IGN) != 0) {
        AZLogError("set_signal_handler(SIGINT) failed: {}", ::strerror(errno));
    }

    // SIGTERM may be used in the shutdown path, gracefully unmount.
#if 0
    if (set_signal_handler(SIGTERM, SIG_IGN) != 0) {
        AZLogError("set_signal_handler(SIGTERM) failed: {}", ::strerror(errno));
    }
#endif
}
#endif

std::string run_command(const std::string& command)
{
    /*
     * Currently we only use this to run 'az account show' command.
     * 4KB should be sufficient to store the output of above command.
     */
    constexpr size_t BUFFER_SIZE = 4096;
    std::string output(BUFFER_SIZE, '\0');

    // Open a pipe to execute the command
    FILE *pipe = ::popen(command.c_str(), "r");
    if (!pipe) {
        AZLogError("Failed to open pipe for command execution: {}", command);
        return "";
    }

    size_t bytes_read = ::fread(const_cast<char *>(output.data()), 1,
                                BUFFER_SIZE, pipe);
    if (::ferror(pipe) || (bytes_read <= 0)) {
        AZLogError("Failed to read from the pipe: {}, command: {}",
                   bytes_read, command);
        bytes_read = 0;
        goto close_pipe;
    }

    // We expect the entire command output to fit in BUFFER_SIZE bytes.
    if (!::feof(pipe)) {
        AZLogError("Command output exceeds {} bytes, command: {}",
                   BUFFER_SIZE, command);
        bytes_read = 0;
        goto close_pipe;
    }

close_pipe:
    const int ret = ::pclose(pipe);
    if (ret != 0) {
        AZLogError("Command failed with return code: {}, command: {}",
                   ret, command);
        return "";
    }

    if (bytes_read > 0) {
        output.resize(bytes_read);
        return output;
    }

    return "";
}

int get_authinfo_data(struct auth_info& auth_info)
{
    // We should not be here without a valid account. 
    assert(aznfsc_cfg.account != nullptr);

    std::string output = run_command("az account show --output json");
    if (output.empty()) {
        AZLogError("'az account show --output json' failed to get account details");
        // User is required to perform 'az login'.
        is_azlogin_required = true;
        return -1;
    }

    // Extract tenantid, subscriptionid, and user details from the output json.
    try {
        const auto json_data = json::parse(output);

        auth_info.tenantid = json_data["tenantId"].get<std::string>();
        auth_info.subscriptionid = json_data["id"].get<std::string>();
        auth_info.username = json_data["user"]["name"].get<std::string>();
        auth_info.usertype = json_data["user"]["type"].get<std::string>();
    } catch (json::parse_error& ev) {
        AZLogError("Failed to parse json: {}, error: {}", output, ev.what());
        return -1;
    }

    const std::string command = std::string("az storage account show -n ") + std::string(aznfsc_cfg.account);
    output = run_command(command);
    if (output.empty()) {
        AZLogError("'{}' failed to get storage account details", command);
        status_pipe_error_string = "Storage account '" + std::string(aznfsc_cfg.account) + 
                                   "' not found in the subscription " + auth_info.subscriptionid;
        return -1;
    }

    // Extract resource group from the output json.
    try {
        const auto json_data = json::parse(output);
        auth_info.resourcegroupname = json_data["resourceGroup"].get<std::string>();
    } catch (json::parse_error& ev) {
        AZLogError("Failed to parse json: {}, error: {}", output, ev.what());
        return -1;
    }

    // Caller expects valid values for tenantid, subscriptionid and resourcegroupname.
    if (auth_info.tenantid.empty() ||
        auth_info.subscriptionid.empty() ||
        auth_info.resourcegroupname.empty()) {
        AZLogError("Invalid authdata parameters returned from azcli commands: "
                   "tenantid: {} subscriptionid: {} username: {} "
                   "usertype: {} resourcegroupname: {}",
                   auth_info.tenantid,
                   auth_info.subscriptionid,
                   auth_info.username,
                   auth_info.usertype,
                   auth_info.resourcegroupname);
        return -1;
    }

    AZLogDebug("Authdata parameters returned from azcli commands: "
               "tenantid: {} subscriptionid: {} username: {} "
               "usertype: {} resourcegroupname: {}",
               auth_info.tenantid,
               auth_info.subscriptionid,
               auth_info.username,
               auth_info.usertype,
               auth_info.resourcegroupname);

    return 0;
}

/*
 *  Generates an authentication token, sets the necessary arguments, 
 *  and returns a response structure.
 * 
 * This function retrieves authentication context details, requests an access token 
 * from Azure CLI, and prepares a response structure containing the token and other 
 * metadata required for authentication.
 * 
 * auth: Pointer to the authentication context structure containing user details.
 * auth_token_cb_res: Pointer to an `auth_token_cb_res` structure with authentication details.
 */    
auth_token_cb_res *get_auth_token_and_setargs_cb(struct auth_context *auth) 
{
    if (!auth) {
        AZLogError("Null auth_context received");
        assert(0);
        return nullptr;
    }

    // is_azlogin_required should be false when we enter this function.
    assert(is_azlogin_required == false);

    // Allocate response structure
    auth_token_cb_res *cb_res = (auth_token_cb_res *) malloc(sizeof(auth_token_cb_res));    
    if (!cb_res) {
        AZLogError("Failed to allocate memory for auth_token_cb_res");
        return nullptr;
    }

    struct auth_info auth_info;

    if (get_authinfo_data(auth_info) == -1) {
        AZLogError("Failed to get auth data from az cli");
        free(cb_res);
        return nullptr;
    }

    AZLogInfo("get_auth_token_and_setargs_cb: tenantid: {} subscriptionid: {} "
              "resourcegroupname: {}", 
               auth_info.tenantid.c_str(),
               auth_info.subscriptionid.c_str(),
               auth_info.resourcegroupname.c_str());

    assert(!auth_info.resourcegroupname.empty());
    assert(!auth_info.tenantid.empty());
    assert(!auth_info.subscriptionid.empty());

    Azure::Core::Credentials::AccessToken token;

    try {
        // Create Azure Token Request Context
        Azure::Core::Credentials::TokenRequestContext tokenRequestContext;
        tokenRequestContext.Scopes = { "https://storage.azure.com/.default" };

        Azure::Identity::AzureCliCredentialOptions options;
        Azure::Identity::AzureCliCredential azcli(options);

        token = azcli.GetToken(tokenRequestContext, Azure::Core::Context());
    } 
    // Special exception handled when user has not logged in. 
    catch (const Azure::Core::Credentials::AuthenticationException& e) {
        AZLogError("Error in getting the token: AuthenticationException thrown, "
                   "Reason Phrase: {}, setting is_azlogin_required=true", 
                   e.what());
        // User is required to perform 'az login'.
        is_azlogin_required = true;
        free(cb_res);
        return nullptr;
    }
    catch (std::exception const& e) {
        AZLogError("Error in getting the token: Reason Phrase: {}", e.what());
        free(cb_res);
        return nullptr;
    }

    const uint64_t expirytime = Azure::Core::_internal::PosixTimeConverter::DateTimeToPosixTime(token.ExpiresOn);

    // Prepare the authdata object. 
    json authdataObject = {
        {"AuthToken", token.Token},
        {"SubscriptionId", auth_info.subscriptionid},
        {"TenantId", auth_info.tenantid},
        {"ResourceGroupName", auth_info.resourcegroupname},
        {"AuthorizedTill", std::to_string(expirytime)}
    };

    // Convert authdata object to string.
    const std::string authdataString = authdataObject.dump();

    if (authdataString.empty()) {
        AZLogError("Unable to create jsonObject with token related information, "
                   "token: {} SubscriptionID: {} TenantID: {} AuthorizedTill: {}",
                   token.Token,
                   auth_info.subscriptionid,
                   auth_info.tenantid,
                   expirytime);
        free(cb_res);
        return nullptr;
    }

    // Set auth_data in auth_token_cb_res.
    assert(authdataString.c_str());
    cb_res->azauth_data = strdup(authdataString.c_str());

    // Set expirytime in auth_token_cb_res.
    assert(expirytime != 0);
    assert(expirytime >= static_cast<uint64_t>(time(NULL)));
    cb_res->expiry_time = expirytime;

    return cb_res;
}

int main(int argc, char *argv[])
{
    // Initialize logger first thing.
    init_log();

    AZLogInfo("aznfsclient version %s", AZNFSCLIENT_VERSION);

    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct fuse_session *se = NULL;
    struct fuse_cmdline_opts opts;
    struct fuse_loop_config *loop_config = fuse_loop_cfg_create();
    int ret = -1;
    int wait_iter;
    std::string mount_source;
    std::string extra_options;

    /* 
     * There can only be 1 reader of this pipe. Hence, we should ensure we 
     * don't send messages multiple times to avoid wait loops.
     */
    bool status_pipe_closed = false;

    // Check if the status mount pipe is set.
    const char *pipe_name = std::getenv("MOUNT_STATUS_PIPE");
    if (!pipe_name) {
        status_pipe_closed = true;
        AZLogWarn("MOUNT_STATUS_PIPE environment variable is not set.");
    }

    /* Don't mask creation mode, kernel already did that */
    umask(0);

    /*
     * Parse general cmdline options first for properly honoring help
     * and debug level arguments.
     */
    if (fuse_parse_cmdline(&args, &opts) != 0) {
        goto err_out0;
    }

    if (opts.mountpoint == nullptr) {
        AZLogError("Mountpoint must be provided!");
        goto err_out0;
    }

    if (opts.show_help) {
        aznfsc_help(argv[0]);
        fuse_cmdline_help();
        fuse_lowlevel_help();
        ret = 0;
        goto err_out1;
    } else if (opts.show_version) {
        printf("FUSE library version %s\n", fuse_pkgversion());
        fuse_lowlevel_version();
        ret = 0;
        goto err_out1;
    }

    /*
     * If -d or "-o debug" cmdline option was passed, reset log level to
     * debug.
     */
    if (opts.debug) {
        enable_debug_logs = true;
        spdlog::set_level(spdlog::level::debug);
    }

    // Parse fuse_conn_info_opts options like -o writeback_cache.
    fuse_conn_info_opts_ptr = fuse_parse_conn_info_opts(&args);

    // Parse aznfsclient specific options.
    if (fuse_opt_parse(&args, &aznfsc_cfg, aznfsc_opts, NULL) == -1) {
        goto err_out1;
    }

    /*
     * TODO: Add validity checks for aznfsc_cfg cmdline options, similar to
     *       parse_config_yaml().
     */

    // Parse config yaml if --config-yaml option provided.
    if (!aznfsc_cfg.parse_config_yaml()) {
        goto err_out1;
    }

    /*
     * If config yaml had debug config set to true, reset log level to debug.
     */
    if (aznfsc_cfg.debug) {
        opts.debug = true;
    }

    if (opts.debug) {
        enable_debug_logs = true;
        spdlog::set_level(spdlog::level::debug);
    }

    /*
     * account and container are mandatory parameters which do not have a
     * default value, so ensure they are set before proceeding further.
     */
    if (aznfsc_cfg.account == nullptr) {
        AZLogError("Account name must be set either from cmdline or config yaml!");
        goto err_out1;
    }

    if (aznfsc_cfg.container == nullptr) {
        AZLogError("Container name must be set either from cmdline or config yaml!");
        goto err_out1;
    }

    aznfsc_cfg.mountpoint = opts.mountpoint;

    // Set default values for config variables not set using the above.
    if (!aznfsc_cfg.set_defaults_and_sanitize()) {
        AZLogError("Error setting one or more default config!");
        goto err_out1;
    }

    /*
     * Honour "-o max_threads=" cmdline option, else use the fuse_max_threads
     * value from the config, if set.
     */
    if (opts.max_threads == 10 /* FUSE_LOOP_MT_DEF_MAX_THREADS */) {
        if (aznfsc_cfg.fuse_max_threads != -1) {
            opts.max_threads = aznfsc_cfg.fuse_max_threads;
        }
    }

    /*
     * Honour "-o max_idle_threads=" cmdline option, else use the
     * fuse_max_idle_threads value from the config, if set.
     */
    if (opts.max_idle_threads == (UINT_MAX) -1 /* FUSE_LOOP_MT_DEF_IDLE_THREADS */) {
        if (aznfsc_cfg.fuse_max_idle_threads != -1) {
            opts.max_idle_threads = aznfsc_cfg.fuse_max_idle_threads;
        }
    }

    /*
     * Hide fuse'ism and behave like a normal POSIX fs.
     * Note that we ask fuse to do the permission checks instead of the NFS
     * server. This way we get 16+ groups handling for free.
     * TODO: Make this configurable?
     *
     * Also set fsname to the correct mount source for clearer mount output.
     * Also PID of the fuse process is useful to associate a mount with the
     * fuse process, which helps in debugging.
     */
    mount_source = aznfsc_cfg.server + ":" + aznfsc_cfg.export_path +
                   "[PID=" + std::to_string(::getpid()) + ",vers=" + AZNFSCLIENT_VERSION + "]";
    extra_options = std::string("-oallow_other,default_permissions,fsname=") +
                               mount_source;

    if (fuse_opt_add_arg(&args, extra_options.c_str()) == -1) {
        goto err_out1;
    }

    se = fuse_session_new(&args, &aznfsc_ll_ops, sizeof(aznfsc_ll_ops),
                          &nfs_client::get_instance());
    if (se == NULL) {
        AZLogError("fuse_session_new failed");
        goto err_out1;
    }

    if (fuse_set_signal_handlers(se) != 0) {
        AZLogError("fuse_set_signal_handlers failed");
        goto err_out2;
    }

#ifdef ENABLE_RELEASE_BUILD
    block_termination_signals();
#endif

    /*
     * Setup SIGUSR1 handler for dumping RPC stats.
     */
    if (set_signal_handler(SIGUSR1, handle_usr1) != 0) {
        AZLogError("set_signal_handler(SIGUSR1) failed: {}", ::strerror(errno));
        goto err_out3;
    }

    if (fuse_session_mount(se, opts.mountpoint) != 0) {
        AZLogError("fuse_session_mount failed");
        goto err_out3;
    }

    if (fuse_daemonize(opts.foreground) != 0) {
        AZLogError("fuse_daemonize failed");
        goto err_out4;
    }

    if (aznfsc_cfg.auth) {
        // Set the auth token callback for this connection if auth is enabled.
        set_auth_token_callback(get_auth_token_and_setargs_cb);
    }

    /*
     * Initialize nfs_client singleton.
     * This creates the libnfs polling thread(s) and hence it MUST be called
     * after fuse_daemonize(), else those threads will get killed.
     */
    if (!nfs_client::get_instance().init()) {
        AZLogError("Failed to init the NFS client");
        goto err_out4;
    }

    client_started = true;
    AZLogInfo("==> Aznfsclient fuse driver ready to serve requests!");
    
    // Open the pipe for writing.
    if (!status_pipe_closed) {
        std::ofstream pipe(pipe_name);

        if (!pipe.is_open()) {
            AZLogError("Aznfsclient unable to send mount status on pipe.");
        } else {
            pipe << 0 << endl;
            status_pipe_closed = true;
        }
    }

    if (opts.singlethread) {
        ret = fuse_session_loop(se);
    } else {
        fuse_loop_cfg_set_clone_fd(loop_config, opts.clone_fd);
        fuse_loop_cfg_set_max_threads(loop_config, opts.max_threads);
        fuse_loop_cfg_set_idle_threads(loop_config, opts.max_idle_threads);

        ret = fuse_session_loop_mt(se, loop_config);
    }

    /*
     * We come here when user unmounts the fuse filesystem.
     */
    AZLogInfo("Shutting down!");

    /*
     * Clear the stats signal, else it may cause a crash if received while
     * we start cleaning up things.
     */
    if (set_signal_handler(SIGUSR1, SIG_DFL) != 0) {
        AZLogWarn("set_signal_handler(SIG_DFL) failed: {}", ::strerror(errno));
        /* Continue and hope we don't get the signal */
    }

    /*
     * After we exit the fuse session loop above, libfuse won't read any more
     * messages from kernel, but we may have some fuse messages that we have
     * received but still not responded. We must wait for those fuse messages
     * to be responded before proceeding with the tear down.
     */
    wait_iter = 0;
    while (rpc_stats_az::fuse_responses_awaited) {
        if (wait_iter++ == 100) {
            AZLogWarn("Giving up on {} pending fuse requests",
                      rpc_stats_az::fuse_responses_awaited.load());
            break;
        }

        AZLogWarn("Waiting for {} pending fuse requests to complete",
                  rpc_stats_az::fuse_responses_awaited.load());

        /*
         * 100ms wait should be large enough to let those requests complete
         * and small enough to not make unmount wait unnecessarily long.
         */
        ::usleep(100 * 1000);
    }

err_out4:
    fuse_loop_cfg_destroy(loop_config);
    /*
     * Note: fuse_session_unmount() calls kernel umount which causes a statfs()
     *       call. This causes statfs_callback() to be called in libnfs thread
     *       context. TSAN shows a data race with this thread which is winding
     *       down fuse data structures.
     */
    fuse_session_unmount(se);
err_out3:
    fuse_remove_signal_handlers(se);
err_out2:
    fuse_session_destroy(se);
err_out1:
    free(opts.mountpoint);
    fuse_opt_free_args(&args);
err_out0:
    if (!status_pipe_closed && ret != 0) {
        // Open the pipe for writing.
        std::ofstream pipe(pipe_name);

        if (!pipe.is_open()) {
            AZLogError("Aznfsclient unable to send mount status on pipe.");
        } else {
            // If is_azlogin_required is true, share the error code = -2 over the pipe.
            if (is_azlogin_required) {
                ret = -2;
                AZLogError("Not logged in using 'az login' when auth is enabled");
                pipe << ret << endl;
            } else if (!status_pipe_error_string.empty()) {
                ret = -3;
                AZLogError("Returing error string '-3 {}' on the pipe", status_pipe_error_string);
                pipe << "-3 " << status_pipe_error_string << endl;
            } else {
                // TODO: Extend this with meaningful error codes.
                pipe << ret << endl;
            }
            status_pipe_closed = true;
        }
        return 1;
    }

    /*
     * Shutdown the client after fuse cleanup is performed so that we don't
     * get any more requests from fuse.
     */
    if (client_started) {
        nfs_client::get_instance().shutdown();
    }

    return ret ? 1 : 0;
}
