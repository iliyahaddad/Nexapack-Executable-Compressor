#ifndef NEXAPACK_CORE_ERROR_HPP
#define NEXAPACK_CORE_ERROR_HPP

#include <cstdint>
#include <exception>
#include <string>
#include <string_view>

namespace nexapack {

enum class ErrorCategory : uint8_t {
    None,
    InvalidArgument,
    NotFound,
    Io,
    Format,
    Codec,
    Runtime,
    Protection,
    Integrity,
    Unsupported,
    Internal,
};

class Error {
public:
    Error() noexcept : category_(ErrorCategory::None), code_(0) {}

    Error(ErrorCategory category, uint32_t code, std::string message) noexcept
        : category_(category), code_(code), message_(std::move(message)) {}

    [[nodiscard]] ErrorCategory category() const noexcept { return category_; }
    [[nodiscard]] constexpr uint32_t code() const noexcept { return code_; }
    [[nodiscard]] constexpr bool ok() const noexcept { return category_ == ErrorCategory::None; }
    [[nodiscard]] const std::string& message() const noexcept { return message_; }

    constexpr explicit operator bool() const noexcept { return ok(); }

private:
    ErrorCategory category_;
    uint32_t code_;
    std::string message_;
};

[[nodiscard]] inline Error make_error(ErrorCategory category, uint32_t code, std::string_view message) {
    return Error{category, code, std::string(message)};
}

[[nodiscard]] inline Error ok_error() noexcept { return Error{}; }

inline std::string_view error_category_name(ErrorCategory c) noexcept {
    switch (c) {
        case ErrorCategory::None: return "None";
        case ErrorCategory::InvalidArgument: return "InvalidArgument";
        case ErrorCategory::NotFound: return "NotFound";
        case ErrorCategory::Io: return "Io";
        case ErrorCategory::Format: return "Format";
        case ErrorCategory::Codec: return "Codec";
        case ErrorCategory::Runtime: return "Runtime";
        case ErrorCategory::Protection: return "Protection";
        case ErrorCategory::Integrity: return "Integrity";
        case ErrorCategory::Unsupported: return "Unsupported";
        case ErrorCategory::Internal: return "Internal";
    }
    return "Unknown";
}

} // namespace nexapack

#endif // NEXAPACK_CORE_ERROR_HPP