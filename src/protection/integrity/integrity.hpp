#ifndef NEXAPACK_PROTECTION_INTEGRITY_INTEGRITY_HPP
#define NEXAPACK_PROTECTION_INTEGRITY_INTEGRITY_HPP

#include "core/error.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace nexapack {
namespace nexaprotect {
namespace integrity {

// Integrity validation result.
struct IntegrityResult {
    bool valid = false;
    bool tampered = false;
    uint32_t checksum = 0;
    std::string details;
};

// Compute integrity metadata for a protected executable.
// Returns a checksum and metadata that can be verified at runtime.
Error compute_integrity(std::string_view input,
                        IntegrityResult& out);

// Verify integrity metadata; detects unexpected modification.
// Sets out_tampered = true if the protected data has been modified.
Error verify_integrity(std::string_view protected_data,
                       std::string_view integrity_meta,
                       bool& out_tampered);

} // namespace integrity
} // namespace nexaprotect
} // namespace nexapack

#endif // NEXAPACK_PROTECTION_INTEGRITY_INTEGRITY_HPP

