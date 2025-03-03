#include "aznfsc.h"
#include "util.h"

#include <unistd.h>
#include <sys/sysmacros.h>

namespace aznfsc {


/**
 * Get total RAM size in bytes.
 * Note that this is the total RAM and not available RAM (which will be lesser
 * and can be much lesser).
 * If it cannot find the RAM size, which is extremely unlikely, it returns 0.
 */
uint64_t get_total_ram()
{
    long page_size = ::sysconf(_SC_PAGE_SIZE);
    if (page_size == -1) {
        AZLogError("sysconf(_SC_PAGE_SIZE) failed: {}", ::strerror(errno));
        page_size = 4096;
        assert(0);
    }
    assert(page_size == 4096);

    const long num_pages = ::sysconf(_SC_PHYS_PAGES);
    if (num_pages == -1) {
        AZLogError("sysconf(_SC_PHYS_PAGES) failed: {}", ::strerror(errno));
        assert(0);
        return 0;
    }
    assert(num_pages != 0);

    return num_pages * page_size;
}

/**
 * Set readahead_kb for kernel readahead.
 * This sets the kernel readahead value of aznfsc_cfg.readahead_kb iff kernel
 * data cache is enabled and user cache is not enabled. We don't want double
 * readahead.
 */
void set_kernel_readahead()
{
    const char *mountpoint = aznfsc_cfg.mountpoint.c_str();
    const int readahead_kb = aznfsc_cfg.readahead_kb;

    if (readahead_kb < 0)
        return;

    if (!aznfsc_cfg.cache.data.kernel.enable) {
        AZLogDebug("Not setting kernel readahead_kb for {}: "
                   "cache.data.kernel.enable=false", mountpoint);
        return;
    } else if (aznfsc_cfg.cache.data.user.enable) {
        AZLogDebug("Not setting kernel readahead_kb for {}: "
                   "cache.data.user.enable=true", mountpoint);
        return;
    }

    /*
     * Do this asynchronously in a thread as we call it from init() and it
     * will cause a callback into fuse as it performs stat() of the root.
     */
    std::thread thr([=]() {
            struct stat sb;
            char sysfs_file[64];
            char readahead_kb_str[16];
            int ret, fd;

            if (::stat(mountpoint, &sb) != 0) {
                AZLogWarn("Failed to set readahead_kb for {}: stat() failed: {}",
                           mountpoint, ::strerror(errno));
                return;
            }

            ret = ::snprintf(sysfs_file, sizeof(sysfs_file),
                             "/sys/class/bdi/%d:%d/read_ahead_kb",
                              major(sb.st_dev), minor(sb.st_dev));
            if (ret == -1 || ret >= (int) sizeof(sysfs_file)) {
                AZLogWarn("Failed to set readahead_kb for {}: "
                          "snprintf(sysfs) failed : {}",
                          mountpoint, ret);
                return;
            }

            fd = ::open(sysfs_file, O_WRONLY);
            if (fd == -1) {
                AZLogWarn("Failed to set readahead_kb for {}: "
                          "open({}) failed: {}",
                          mountpoint, sysfs_file, ::strerror(errno));
                return;
            }

            ret = ::snprintf(readahead_kb_str, sizeof(readahead_kb_str), "%d",
                             readahead_kb);
            if (ret == -1 || ret >= (int) sizeof(readahead_kb_str)) {
                ::close(fd);
                AZLogWarn("Failed to set readahead_kb for {}: "
                          "snprintf(readahead_kb) failed: {}",
                          mountpoint, ret);
                return;
            }

            if (::write(fd, readahead_kb_str,
                        ::strlen(readahead_kb_str)) == -1) {
                ::close(fd);
                AZLogWarn("Failed to set readahead_kb for {}: "
                          "write({}) failed: {}",
                          mountpoint, sysfs_file, ::strerror(errno));
                return;
            }

            ::close(fd);

            AZLogInfo("Set readahead_kb {} for {}",
                      readahead_kb_str, sysfs_file);
            return;
    });

    thr.detach();
}

void disable_oom_kill()
{
    if (!aznfsc_cfg.oom_kill_disable) {
        AZLogDebug("Not disabling OOM killing!");
        return;
    }

    const pid_t pid = ::getpid();
    const std::string oom_odj_file = std::string("/proc/") +
                                     std::to_string(pid) + "/oom_score_adj";
    char oom_adj_str[16];
    int ret, fd;

    fd = ::open(oom_odj_file.c_str(), O_WRONLY);
    if (fd == -1) {
        AZLogWarn("Failed to disable OOM killing: open({}) failed: {}",
                  oom_odj_file, ::strerror(errno));
        return;
    }

    // -1000 is the lowest we can set, implying "do not oom kill".
    ret = ::snprintf(oom_adj_str, sizeof(oom_adj_str), "%d", -1000);
    if (ret == -1 || ret >= (int) sizeof(oom_adj_str)) {
        ::close(fd);
        AZLogWarn("Failed to disable OOM killing: snprintf() failed: {}", ret);
        return;
    }

    if (::write(fd, oom_adj_str, ::strlen(oom_adj_str)) == -1) {
        ::close(fd);
        AZLogWarn("Failed to disable OOM killing: write({}) failed: {}",
                  oom_adj_str, ::strerror(errno));
        return;
    }

    ::close(fd);

    AZLogInfo("Disabled OOM killing, set {} to {}",
              oom_odj_file, oom_adj_str);
    return;
}

#ifdef ENABLE_PRESSURE_POINTS
bool inject_error(double pct_prob)
{
    if (pct_prob == 0) {
        pct_prob = inject_err_prob_pct_def;
    }
    /*
     * We multiply double pct_prob with 10000, this enables us to consider
     * values as less as 0.0001% i.e., 1 in a million.
     * Anything less will result in a 0% probability.
     */
    assert(pct_prob >= 0 && pct_prob <= 100);
    const uint64_t rnd = random_number(0, 1000'000);
    return rnd < (pct_prob * 10'000);
}
#endif

}
