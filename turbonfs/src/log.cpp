#include "log.h"

bool enable_debug_logs = false;

void init_log() 
{
    /*
     * TODO: Initialize the logger to set the log format and anything
     *       else.
     */

    /*
     * Log info and above by default.
     * Later when we parse cmdline options, if -d or "-o debug" option
     * is passed we set the log level to debug.
     */
    spdlog::set_level(spdlog::level::info);

    /*
     * Add thread id in the log pattern, helps to debug when multiple
     * processes are accessing the mounted filesystem.
     */
    spdlog::set_pattern("[%t]%+");

    AZLogDebug("Logger initialized");
}

void set_file_logger(const std::string& log_file_path) {
    // Rotate when file size exceeds 10MB.
    std::size_t max_size = 10 * 1024 * 1024;
    std::size_t max_files = 5;
    auto rotating_file_sink =
            std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
                    log_file_path, max_size, max_files);
    
    auto log_level = spdlog::get_level();

    /*
     * Create new stdout sink explicitly, we need to do this because we want to
     * merge the file and console sinks into one logger.
     */
    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    
    /*
     * Create a combined logger which will log to both sinks, this will now replace
     * the old default logger.
     */
    auto logger = std::make_shared<spdlog::logger>
                  ("multi_sink", spdlog::sinks_init_list{rotating_file_sink, console_sink});
    
    /*
     * We need to register this logger, set it as default and set the flush_on level
     * and log level.
     */
    spdlog::register_logger(logger);
    spdlog::set_default_logger(logger);
    spdlog::set_level(log_level);
    spdlog::flush_on(log_level);
    
    spdlog::set_pattern("[%t]%+");

    AZLogDebug("File logger init.");
}
