#ifndef NEXAPACK_CORE_LOGGING_HPP
#define NEXAPACK_CORE_LOGGING_HPP

#include <cstdint>
#include <iostream>
#include <mutex>
#include <ostream>
#include <string>
#include <string_view>

namespace nexapack {

enum class LogLevel : uint8_t {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Fatal,
};

class Logger {
public:
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    static Logger& instance() noexcept;

    void set_level(LogLevel level) noexcept;
    LogLevel level() const noexcept;

    void log(LogLevel level, std::string_view message);

    // Redirect output to a custom stream (default: std::cerr).
    void set_stream(std::ostream* stream) noexcept;

private:
    Logger() = default;
    LogLevel level_ = LogLevel::Info;
    std::ostream* stream_ = &std::cerr;
    mutable std::mutex mutex_;
};

inline std::string_view log_level_name(LogLevel l) noexcept {
    switch (l) {
        case LogLevel::Trace: return "TRACE";
        case LogLevel::Debug: return "DEBUG";
        case LogLevel::Info: return "INFO";
        case LogLevel::Warn: return "WARN";
        case LogLevel::Error: return "ERROR";
        case LogLevel::Fatal: return "FATAL";
    }
    return "UNKNOWN";
}

// Inline logging helper that respects the current log level.
// Avoids macro token-expansion issues with level names such as Debug/Info.
inline void nxp_log(LogLevel level, std::string_view message) {
    if (static_cast<uint8_t>(level) >= static_cast<uint8_t>(Logger::instance().level())) {
        Logger::instance().log(level, message);
    }
}

} // namespace nexapack

#endif // NEXAPACK_CORE_LOGGING_HPP

