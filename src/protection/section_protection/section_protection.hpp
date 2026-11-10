#ifndef NEXAPACK_PROTECTION_SECTION_PROTECTION_SECTION_PROTECTION_HPP
#define NEXAPACK_PROTECTION_SECTION_PROTECTION_SECTION_PROTECTION_HPP

#include "core/error.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace nexapack {
namespace nexaprotect {
namespace section_protection {

// Section protection mode.
enum class SectionMode {
    None = 0,        // No section protection
    EncryptSelected, // Authenticated encryption of eligible sections
    EncryptAll,      // Encrypt all eligible sections
};

// Result of section protection.
struct SectionResult {
    std::vector<uint8_t> protected_data;
    uint32_t sections_protected = 0;
    uint64_t protected_bytes = 0;
    bool authenticated_encryption = false;
    std::vector<std::pair<uint32_t, uint64_t>> encrypted_sections;
    Error error;
};

// Apply section protection to an executable buffer.
// Only eligible code/data sections are protected; sections required for
// runtime (relocations, imports, TLS, exception data) are excluded.
Error protect_sections(std::string_view input,
                       SectionMode mode,
                       SectionResult& out);

} // namespace section_protection
} // namespace nexaprotect
} // namespace nexapack

#endif // NEXAPACK_PROTECTION_SECTION_PROTECTION_SECTION_PROTECTION_HPP

