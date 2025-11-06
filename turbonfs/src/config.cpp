#include "aznfsc.h"
#include "yaml-cpp/yaml.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

using namespace std;

/*
 * Global aznfsc config instance holding all the aznfs client configuration.
 */
struct aznfsc_cfg aznfsc_cfg;

/*
 * This function parses the contents of the yaml config file denoted by path
 * config_file into the aznfsc_cfg structure.
 */
bool aznfsc_cfg::parse_config_yaml()
{

#define __CHECK_INT(var, min, max, zeroisvalid) \
do { \
    if (((var) == -1) && config[#var]) { \
        (var) = config[#var].as<int>(); \
        if ((var) < min || (var) > max) { \
            if ((zeroisvalid) && ((var) == 0)) { \
                break; \
            } \
            throw YAML::Exception( \
                    config[#var].Mark(), \
                    std::string("Invalid value for config "#var": ") + \
                    std::to_string(var) + \
                    std::string(" (valid range [") + \
                    std::to_string(min) + ", " + std::to_string(max) + "])"); \
        }\
    } \
} while (0);

/*
 * Macro to check validity of config var of integer type.
 */
#define _CHECK_INT(var, min, max) __CHECK_INT(var, min, max, false)

/*
 * Macro to check validity of config var of integer type with 0 being a
 * valid value.
 */
#define _CHECK_INTZ(var, min, max) __CHECK_INT(var, min, max, true)

/*
 * Macro to check validity of config var of boolean type.
 */
#define _CHECK_BOOL(var) \
do { \
    if (config[#var]) { \
        (var) = config[#var].as<bool>(); \
    } \
} while (0);


/*
 * Macro to check validity of config var of string type.
 */
#define __CHECK_STR(var, is_valid, ignore_empty) \
do { \
    if (((var) == nullptr) && config[#var]) { \
        /* Empty key is returned as "null" by the yaml parser */ \
        if ((ignore_empty) && config[#var].as<std::string>() == "null") { \
            break; \
        } \
        (var) = ::strdup(config[#var].as<std::string>().c_str()); \
        if (!is_valid(var)) { \
            throw YAML::Exception( \
                    config[#var].Mark(), \
                    std::string("Invalid value for config "#var": ") + \
                    std::string(var)); \
        } \
    } \
} while (0);

#define _CHECK_STR(var) __CHECK_STR(var, is_valid_##var, false)
#define _CHECK_STR2(var, is_valid) __CHECK_STR(var, is_valid, false)

/*
 * Macro to check validity of config var of percentage type.
 * var can be set to one of the following values:
 * 1) -2 => var is not specified in the config.
 * 2) -1 => var is not a valid percentage string. Caller must try other valid
 *          interpretations.
 * 3) var >= 0 && var <= 100 => var is specified as a percentage value.
 */
#define _MAYBE_PERCENT(var) \
do { \
    if (!config[#var] || config[#var].as<std::string>() == "null") { \
        var = -2; \
        break; \
    }\
    var = get_percent_value(config[#var].as<std::string>()); \
    assert((var == -1) || (var >= 0 && var <= 100)); \
} while (0);

    if (config_yaml == nullptr) {
        return true;
    }

    AZLogDebug("Parsing config yaml {}", config_yaml);

    /*
     * We parse the config yaml and set *only* those options which are not yet
     * set by cmdline. Thus cmdline options are given higher priority than the
     * corresponding option in the config yaml.
     */
    try {
        YAML::Node config = YAML::LoadFile(config_yaml);

        _CHECK_BOOL(debug);

        _CHECK_STR(account);
        _CHECK_STR(container);
        _CHECK_STR(cloud_suffix);

        if ((port == -1) && config["port"]) {
            port = config["port"].as<int>();
#ifndef ENABLE_NON_AZURE_NFS
            if (port != 2048 && port != 2047) {
                throw YAML::Exception(
                    config["port"].Mark(),
                    std::string("Invalid port number: ") +
                    std::to_string(port) +
                    std::string(" (can be 2048 or 2047)"));
            }
#endif
        }

        _CHECK_INT(nconnect, AZNFSCFG_NCONNECT_MIN, AZNFSCFG_NCONNECT_MAX);
        _CHECK_INT(timeo, AZNFSCFG_TIMEO_MIN, AZNFSCFG_TIMEO_MAX);
        _CHECK_INT(acregmin, AZNFSCFG_ACTIMEO_MIN, AZNFSCFG_ACTIMEO_MAX);
        _CHECK_INT(acregmax, AZNFSCFG_ACTIMEO_MIN, AZNFSCFG_ACTIMEO_MAX);
        _CHECK_INT(acdirmin, AZNFSCFG_ACTIMEO_MIN, AZNFSCFG_ACTIMEO_MAX);
        _CHECK_INT(acdirmax, AZNFSCFG_ACTIMEO_MIN, AZNFSCFG_ACTIMEO_MAX);
        _CHECK_INT(actimeo, AZNFSCFG_ACTIMEO_MIN, AZNFSCFG_ACTIMEO_MAX);
        _CHECK_STR(lookupcache);
        _CHECK_STR(consistency);

        _CHECK_BOOL(auth);

        /*
         * bc_iovec::add_bc() does not accept bytes_chunk larger than wsize.
         * Since fuse can send max 1MiB sized writes, we must not allow wsize
         * to be set less than 1MiB.
         * Since write can get a bytes_chunk allocated by read/readahead, rsize
         * must not be allowed to be greater than wsize.
         */
        _CHECK_INT(wsize, AZNFSCFG_WSIZE_MIN, AZNFSCFG_WSIZE_MAX);
        _CHECK_INT(rsize, AZNFSCFG_RSIZE_MIN, std::min(wsize, AZNFSCFG_RSIZE_MAX));

        _CHECK_INT(retrans, AZNFSCFG_RETRANS_MIN, AZNFSCFG_RETRANS_MAX);
        _CHECK_INT(readdir_maxcount, AZNFSCFG_READDIR_MIN, AZNFSCFG_READDIR_MAX);
        /*
         * Allow special value of 0 to disable readahead.
         * Mostly useful for testing.
         */
        _CHECK_INTZ(readahead_kb, AZNFSCFG_READAHEAD_KB_MIN, AZNFSCFG_READAHEAD_KB_MAX);
        _CHECK_INT(fuse_max_background, AZNFSCFG_FUSE_MAX_BG_MIN, AZNFSCFG_FUSE_MAX_BG_MAX);
        _CHECK_INT(fuse_max_threads, AZNFSCFG_FUSE_MAX_THR_MIN, AZNFSCFG_FUSE_MAX_THR_MAX);
        _CHECK_INT(fuse_max_idle_threads, AZNFSCFG_FUSE_MAX_IDLE_THR_MIN, AZNFSCFG_FUSE_MAX_IDLE_THR_MAX);

        _CHECK_STR(xprtsec);
        _CHECK_BOOL(oom_kill_disable);

        _CHECK_BOOL(cache.attr.user.enable);
        _CHECK_BOOL(cache.readdir.kernel.enable);
        _CHECK_INT(cache.readdir.user.max_size_mb,
                   AZNFSCFG_CACHE_MAX_MB_MIN, AZNFSCFG_CACHE_MAX_MB_MAX);
        // User readdir cache cannot be turned off.
        assert(cache.readdir.user.enable);
        _CHECK_BOOL(cache.data.kernel.enable);

        // User data cache cannot be turned off.
        assert(cache.data.user.enable);
        if (cache.data.user.enable) {
            /*
             * cache.data.user.max_size_mb can be specified as a percentage
             * value, in which case it's the percentage of the total RAM size
             * else it's an absolute size in MB.
             */
            _MAYBE_PERCENT(cache.data.user.max_size_mb);

            if (cache.data.user.max_size_mb >= 0) {
                AZLogDebug("Using {}% of total RAM {}MB for "
                           "cache.data.user.max_size_mb",
                           cache.data.user.max_size_mb,
                           (get_total_ram() / (1024 * 1024)));
                cache.data.user.max_size_mb =
                    (cache.data.user.max_size_mb / 100.0) *
                    (get_total_ram() / (1024 * 1024));
                if (cache.data.user.max_size_mb < AZNFSCFG_CACHE_MAX_MB_MIN ||
                    cache.data.user.max_size_mb > AZNFSCFG_CACHE_MAX_MB_MAX) {
                    throw YAML::Exception(
                            config["cache.data.user.max_size_mb"].Mark(),
                            std::string("Invalid value for config cache.data.user.max_size_mb: ") +
                            config["cache.data.user.max_size_mb"].as<std::string>().c_str() +
                            std::string(", resultant value ") +
                            std::to_string(cache.data.user.max_size_mb) +
                            std::string(" is not in valid range [") +
                            std::to_string(AZNFSCFG_CACHE_MAX_MB_MIN) +
                            std::string(", ") +
                            std::to_string(AZNFSCFG_CACHE_MAX_MB_MAX) +
                            std::string("]"));
                }
            } else if (cache.data.user.max_size_mb == -1) {
                /*
                 * Not expressed as a percentage, try absolute MB.
                 */
                _CHECK_INT(cache.data.user.max_size_mb,
                           AZNFSCFG_CACHE_MAX_MB_MIN, AZNFSCFG_CACHE_MAX_MB_MAX);
            }
        } else {
            cache.data.user.max_size_mb = 0;
        }

        _CHECK_BOOL(filecache.enable);
        if (filecache.enable) {
            _CHECK_STR2(filecache.cachedir, is_valid_cachedir);
            _CHECK_INT(filecache.max_size_gb, AZNFSCFG_FILECACHE_MAX_GB_MIN, AZNFSCFG_FILECACHE_MAX_GB_MAX);
        } else {
            filecache.max_size_gb = 0;
        }

        /*
         * Config affecting misc system behaviour.
         */
        _CHECK_BOOL(sys.force_stable_writes);
        _CHECK_BOOL(sys.resolve_before_reconnect);
        _CHECK_BOOL(sys.nodrc.remove_noent_as_success);
        _CHECK_BOOL(sys.nodrc.create_exist_as_success);
        _CHECK_BOOL(sys.nodrc.rename_noent_as_success);

    } catch (const YAML::BadFile& e) {
        AZLogError("Error loading config file {}: {}", config_yaml, e.what());
        return false;
    } catch (const YAML::Exception& e) {
        AZLogError("Error parsing config file {}: {}", config_yaml, e.what());
        return false;
    } catch (...) {
        AZLogError("Unknown error parsing config file {}", config_yaml);
        return false;
    }

    return true;
}

#ifdef ENABLE_PRESSURE_POINTS
/*
 * Default percentage probability for error injection.
 * Settable using env variable AZNFSC_INJECT_ERROR_PERCENT.
 */
double inject_err_prob_pct_def = 0.01;
#endif

/**
 * Set default values for options not yet assigned.
 * This must be called after fuse_opt_parse() and parse_config_yaml()
 * assign config values from command line and the config yaml file.
 * Also sanitizes various values.
 */
bool aznfsc_cfg::set_defaults_and_sanitize()
{
#ifdef ENABLE_PRESSURE_POINTS
    const char *err_prob = ::getenv("AZNFSC_INJECT_ERROR_PERCENT");
    if (err_prob) {
        inject_err_prob_pct_def = ::atof(err_prob);
        if (inject_err_prob_pct_def < 0) {
            AZLogWarn("Capping AZNFSC_INJECT_ERROR_PERCENT ({}) to 0",
                      err_prob);
            inject_err_prob_pct_def = 0;
        } else if (inject_err_prob_pct_def > 100) {
            AZLogWarn("Capping AZNFSC_INJECT_ERROR_PERCENT ({}) to 100",
                      err_prob);
            inject_err_prob_pct_def = 100;
        }
    }
#endif
    if (port == -1)
        port = 2048;
    if (nconnect == -1)
        nconnect = 1;
    if (rsize == -1)
        rsize = 1048576;
    if (wsize == -1)
        wsize = 1048576;
    if (retrans == -1)
        retrans = 3;
    if (timeo == -1)
        timeo = 600;
    if (acregmin == -1)
        acregmin = 3;
    if (acregmax == -1)
        acregmax = 60;
    if (acdirmin == -1)
        acdirmin = 30;
    if (acdirmax == -1)
        acdirmax = 60;
    if (actimeo != -1) {
        acregmin = acregmax = acdirmin = acdirmax = actimeo;
    } else {
        /*
         * This is used only by nfs_client::reply_entry() for setting the
         * timeout of negative lookup result.
         * Rest everywhere we will use ac{reg|dir}{min|max}.
         */
        actimeo = AZNFSCFG_ACTIMEO_MIN;
    }
    if (acregmin > acregmax)
        acregmin = acregmax;
    if (acdirmin > acdirmax)
        acdirmin = acdirmax;

    if (lookupcache) {
        if (std::string(lookupcache) == "all") {
            lookupcache_int = AZNFSCFG_LOOKUPCACHE_ALL;
        } else if (std::string(lookupcache) == "none") {
            lookupcache_int = AZNFSCFG_LOOKUPCACHE_NONE;
        } else if (std::string(lookupcache) == "pos" ||
                   std::string(lookupcache) == "positive") {
            lookupcache_int = AZNFSCFG_LOOKUPCACHE_POS;
        } else {
            // We should not come here with an invalid value.
            assert(0);
            lookupcache_int = AZNFSCFG_LOOKUPCACHE_DEF;
        }
    } else {
        lookupcache = "";
        lookupcache_int = AZNFSCFG_LOOKUPCACHE_DEF;
    }

    if (readdir_maxcount == -1)
        readdir_maxcount = 1048576;
    if (readahead_kb == -1)
        readahead_kb = AZNFSCFG_READAHEAD_KB_DEF;
    if (cache.data.user.enable) {
        if (cache.data.user.max_size_mb < 0) {
            /*
             * 60% of the total RAM, and capped at 16GiB.
             */
            cache.data.user.max_size_mb =
                (AZNFSCFG_CACHE_MAX_MB_PERCENT_DEF / 100.0) *
                (get_total_ram() / (1024 * 1024));
            if (cache.data.user.max_size_mb > 16384) {
                cache.data.user.max_size_mb = 16384;
            }
        }
    }

    if (cache.readdir.user.enable) {
        /*
         * If not set from config, set to default value of 4GB.
         */
        if (cache.readdir.user.max_size_mb == -1) {
            cache.readdir.user.max_size_mb = 4096;
        }

        assert(cache.readdir.user.max_size_mb > 0);
    }

    if (filecache.enable) {
        if (filecache.max_size_gb == -1)
            filecache.max_size_gb = AZNFSCFG_FILECACHE_MAX_GB_DEF;
    }

    if (consistency) {
        if (std::string(consistency) == "solowriter") {
            consistency_int = consistency_t::SOLOWRITER;
            consistency_solowriter = true;
            /*
             * Set actimeo to the max value. and lookupcache for caching positive
             * and negative lookup responses.
             */
            actimeo = AZNFSCFG_ACTIMEO_MAX;
            lookupcache_int = AZNFSCFG_LOOKUPCACHE_ALL;
        } else if (std::string(consistency) == "standardnfs") {
            consistency_int = consistency_t::STANDARDNFS;
            consistency_standardnfs = true;
        } else if (std::string(consistency) == "azurempa") {
            consistency_int = consistency_t::AZUREMPA;
            consistency_azurempa = true;
        } else {
            // We should not come here with an invalid value.
            assert(0);
            consistency_int = consistency_t::STANDARDNFS;
            consistency_standardnfs = true;
        }
    } else {
        consistency = "";
        consistency_int = consistency_t::STANDARDNFS;
        consistency_standardnfs = true;
    }

    /*
     * One and only one consistency mode boolean must be set.
     */
    assert(((int) consistency_solowriter +
            (int) consistency_standardnfs +
            (int) consistency_azurempa) == 1);

    /*
     * If user has not provided cloud_suffix, try to make a good guess.
     */
    if (cloud_suffix == nullptr) {
        struct addrinfo *ai = NULL;

        AZLogDebug("cloud_suffix not specified, trying to guess it!");
        AZLogDebug("trying blob.core.windows.net ...");
        std::string try_server = std::string(account) + ".blob.core.windows.net";
        if (::getaddrinfo(try_server.c_str(), NULL, NULL, &ai) == 0) {
            cloud_suffix = ::strdup("blob.core.windows.net");
            goto done_cloud_suffix;
        }
        AZLogDebug("it is not blob.core.windows.net!");

        AZLogDebug("trying blob.preprod.core.windows.net ...");
        try_server = std::string(account) + ".blob.preprod.core.windows.net";
        if (::getaddrinfo(try_server.c_str(), NULL, NULL, &ai) == 0) {
            cloud_suffix = ::strdup("blob.preprod.core.windows.net");
            goto done_cloud_suffix;
        }
        AZLogDebug("it is not blob.preprod.core.windows.net!");
        AZLogError("Failed to find a valid endpoint, make sure you provided "
                   "a valid account ({}) else provide a valid cloud_suffix!",
                   account);
        return false;

done_cloud_suffix:
        AZLogDebug("it is {}!", cloud_suffix);
        assert(ai);
        ::freeaddrinfo(ai);
    }

    if (xprtsec == nullptr)
        xprtsec = ::strdup("none");

    assert(account != nullptr);
    assert(container != nullptr);

    // Set aggregates.
    server = std::string(account) + "." + std::string(cloud_suffix);
    if (int n = std::string(account).find("-secondary"); n != std::string::npos) {
        export_path = "/" + account.substr(0, n) + "/" + std::string(container);
    } else {
        export_path = "/" + std::string(account) + "/" + std::string(container);
    }

    // Dump the final config values for debugging.
    AZLogDebug("===== config start =====");
#ifdef ENABLE_PRESSURE_POINTS
    AZLogDebug("inject_err_prob_pct_def = {}", inject_err_prob_pct_def);
#endif
    AZLogDebug("auth = {}", auth);
    AZLogDebug("port = {}", port);
    AZLogDebug("nconnect = {}", nconnect);
    AZLogDebug("rsize = {}", rsize);
    AZLogDebug("wsize = {}", wsize);
    AZLogDebug("retrans = {}", retrans);
    AZLogDebug("xprtsec = {}", xprtsec);
    AZLogDebug("oom_kill_disable = {}", oom_kill_disable);
    AZLogDebug("timeo = {}", timeo);
    AZLogDebug("acregmin = {}", acregmin);
    AZLogDebug("acregmax = {}", acregmax);
    AZLogDebug("acdirmin = {}", acdirmin);
    AZLogDebug("acdirmax = {}", acdirmax);
    AZLogDebug("actimeo = {}", actimeo);
    AZLogDebug("lookupcache = <{}> ({})", lookupcache, lookupcache_int);
    AZLogDebug("consistency = <{}> ({})", consistency, (int) consistency_int);
    AZLogDebug("readdir_maxcount = {}", readdir_maxcount);
    AZLogDebug("readahead_kb = {}", readahead_kb);
    AZLogDebug("fuse_max_background = {}", fuse_max_background);
    AZLogDebug("fuse_max_threads = {}", fuse_max_threads);
    AZLogDebug("fuse_max_idle_threads = {}", fuse_max_idle_threads);
    AZLogDebug("cache.attr.user.enable = {}", cache.attr.user.enable);
    AZLogDebug("cache.readdir.kernel.enable = {}", cache.readdir.kernel.enable);
    AZLogDebug("cache.readdir.user.enable = {}", cache.readdir.user.enable);
    AZLogDebug("cache.readdir.user.max_size_mb = {}", cache.readdir.user.max_size_mb);
    AZLogDebug("cache.data.kernel.enable = {}", cache.data.kernel.enable);
    AZLogDebug("cache.data.user.enable = {}", cache.data.user.enable);
    AZLogDebug("cache.data.user.max_size_mb = {}", cache.data.user.max_size_mb);
    AZLogDebug("filecache.enable = {}", filecache.enable);
    AZLogDebug("filecache.cachedir = {}", filecache.cachedir ? filecache.cachedir : "");
    AZLogDebug("filecache.max_size_gb = {}", filecache.max_size_gb);
    AZLogDebug("sys.force_stable_writes = {}", sys.force_stable_writes);
    AZLogDebug("sys.resolve_before_reconnect = {}", sys.resolve_before_reconnect);
    AZLogDebug("sys.nodrc.remove_noent_as_success = {}", sys.nodrc.remove_noent_as_success);
    AZLogDebug("sys.nodrc.create_exist_as_success = {}", sys.nodrc.create_exist_as_success);
    AZLogDebug("sys.nodrc.rename_noent_as_success = {}", sys.nodrc.rename_noent_as_success);
    AZLogDebug("account = {}", account);
    AZLogDebug("container = {}", container);
    AZLogDebug("cloud_suffix = {}", cloud_suffix);
    AZLogDebug("mountpoint = {}", mountpoint);
    AZLogDebug("===== config end =====");

    return true;
}
