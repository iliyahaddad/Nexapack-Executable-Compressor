#ifndef NEXAPACK_PROTECTION_NEXAPROTECT_HPP
#define NEXAPACK_PROTECTION_NEXAPROTECT_HPP

#include "core/error.hpp"
#include "core/metadata.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace nexapack {
namespace nexaprotect {

// Feature enumeration for compatibility reporting.
enum class ProtectionFeature : uint32_t {
    SymbolStripping = 1,
    SectionEncryption = 2,
    MBATransformations = 3,
    ControlFlowIntegrity = 4,
    AntiTamper = 5,
};

// Protection profile levels. Each profile describes real features and their
// overhead. No feature is claimed active unless implemented and tested.
//
// Implemented features:
//   - SymbolStripping: removes .debug, .note.gnu.build-id, .comment, .note.ABI-tag sections
//   - SectionEncryption: XOR-encrypts eligible non-code data sections
//   - AntiTamper: CRC32 integrity checksum with tamper detection
//
// Not yet implemented:
//   - MBATransformations (mba.cpp returns input unchanged)
//   - ControlFlowIntegrity (no implementation)
enum class ProtectionProfile : uint32_t {
    None = 0,      // No protection (plain compression only)
    Basic = 1,     // Integrity (anti-tamper) metadata only
    Standard = 2,  // Integrity + Symbol stripping
    Advanced = 3,  // Integrity + Symbol stripping + Section encryption
    Maximum = 4,   // Integrity + Symbol stripping + Section encryption (max levels)
};

// Result of applying protection to an executable.
struct ProtectionResult {
    std::vector<uint8_t> protected_data;   // protected executable bytes
    std::vector<uint8_t> protection_meta;  // protection metadata block
    uint64_t overhead_bytes = 0;           // added bytes vs unprotected
    bool symbols_stripped = false;
    bool sections_protected = false;
    bool mba_applied = false;
    bool integrity_enabled = false;
    // Encrypted section entries: (section_index, xor_key) pairs
    // for runtime stub decryption.
    std::vector<std::pair<uint32_t, uint64_t>> encrypted_sections;
    Error error;
};

// Protection configuration. Independently configurable from compression.
struct ProtectionConfig {
    ProtectionProfile profile = ProtectionProfile::None;
    bool strip_symbols = false;
    bool preserve_debug = false;   // keep required runtime metadata
    bool protect_sections = false; // selective section encryption
    bool apply_mba = false;        // MBA transformations
    bool integrity_check = false;  // anti-tamper validation
    uint32_t mba_intensity = 1;    // 1..3 transformation complexity
};

// Query whether a given profile implies a feature.
bool profile_includes(ProtectionProfile profile, ProtectionFeature feature);

// Apply protection to an executable buffer. Returns protected bytes + metadata.
Error apply_protection(std::string_view input,
                       const ProtectionConfig& config,
                       ProtectionResult& out);

// Verify protection metadata and detect tampering.
Error verify_protection(std::string_view protected_data,
                        std::string_view protection_meta,
                        bool& out_tampered);

} // namespace nexaprotect
} // namespace nexapack

#endif // NEXAPACK_PROTECTION_NEXAPROTECT_HPP
