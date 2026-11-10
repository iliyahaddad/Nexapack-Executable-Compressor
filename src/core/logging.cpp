#include "core/logging.hpp"

#include <chrono>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace nexapack {

Logger& Logger::instance() noexcept {
    static Logger inst;
    return inst;
}

void Logger::set_level(LogLevel level) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    level_ = level;
}

LogLevel Logger::level() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return level_;
}

void Logger::log(LogLevel level, std::string_view message) {
    if (static_cast<uint8_t>(level) < static_cast<uint8_t>(level_)) {
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (!stream_) {
        return;
    }
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream ts;
    ts << std::put_time(std::gmtime(&time), "%Y-%m-%dT%H:%M:%SZ");
    *stream_ << "[" << ts.str() << "] " << log_level_name(level)
             << " " << message << "\n";
    stream_->flush();
}

void Logger::set_stream(std::ostream* stream) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    stream_ = stream;
}

} // namespace nexapack


