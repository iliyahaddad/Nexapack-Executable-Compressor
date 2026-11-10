#include "protection/integrity/integrity.hpp"
#include "core/error.hpp"
#include "core/logging.hpp"

#include <cstring>

namespace nexapack {
namespace nexaprotect {
namespace integrity {

// Simple CRC32 for integrity metadata (not cryptographic, for tamper
// detection only).
static uint32_t crc32(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; ++i) {
        crc ^= data[i];
        for (int b = 0; b < 8; ++b) {
            crc = (crc & 1) ? (0xEDB88320u ^ (crc >> 1)) : (crc >> 1);
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

Error compute_integrity(std::string_view input,
                        IntegrityResult& out) {
    out = IntegrityResult{};
    out.checksum = crc32(reinterpret_cast<const uint8_t*>(input.data()),
                         input.size());
    out.valid = true;
    out.details = "integrity checksum computed";
    nexapack::nxp_log(nexapack::LogLevel::Debug, "integrity: checksum computed");
    return ok_error();
}

Error verify_integrity(std::string_view protected_data,
                       std::string_view integrity_meta,
                       bool& out_tampered) {
    out_tampered = false;

    // integrity_meta is expected to be 4 bytes (CRC32) little-endian.
    if (integrity_meta.size() < 4) {
        return make_error(ErrorCategory::Format, 1,
                          "integrity metadata too small");
    }

    uint32_t stored = 0;
    std::memcpy(&stored, integrity_meta.data(), 4);

    uint32_t computed = crc32(reinterpret_cast<const uint8_t*>(
                                  protected_data.data()),
                              protected_data.size());

    if (stored != computed) {
        out_tampered = true;
        nexapack::nxp_log(nexapack::LogLevel::Warn, "integrity: tamper detected");
    } else {
        out_tampered = false;
        nexapack::nxp_log(nexapack::LogLevel::Debug, "integrity: verification passed");
    }

    return ok_error();
}

} // namespace integrity
} // namespace nexaprotect
} // namespace nexapack


