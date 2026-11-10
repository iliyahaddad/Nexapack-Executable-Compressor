#include "protection/section_protection/section_protection.hpp"
#include "core/error.hpp"
#include "core/logging.hpp"

#include <algorithm>
#include <cstring>
#include <random>

namespace nexapack {
namespace nexaprotect {
namespace section_protection {

// XOR-based section encryption. Uses a repeating key derived from a seed
// via xorshift32 PRNG.
static void encrypt_section(uint8_t* data, size_t size, uint64_t seed) {
    uint32_t s = static_cast<uint32_t>(seed);
    for (size_t i = 0; i < size; i++) {
        s ^= s << 13;
        s ^= s >> 17;
        s ^= s << 5;
        data[i] ^= static_cast<uint8_t>(s & 0xFF);
    }
}

Error protect_sections(std::string_view input,
                       SectionMode mode,
                       SectionResult& out) {
    out = SectionResult{};

    if (input.empty()) {
        return make_error(ErrorCategory::InvalidArgument, 1,
                          "empty input buffer");
    }

    const uint8_t* data = reinterpret_cast<const uint8_t*>(input.data());
    size_t size = input.size();

    if (size < 64 || data[0] != 'M' || data[1] != 'Z') {
        out.protected_data.assign(input.begin(), input.end());
        return ok_error();
    }

    uint32_t e_lfanew = 0;
    std::memcpy(&e_lfanew, data + 60, 4);
    if (e_lfanew > size - 4 ||
        std::memcmp(data + e_lfanew, "PE\0\0", 4) != 0) {
        out.protected_data.assign(input.begin(), input.end());
        return ok_error();
    }

    const uint8_t* nt_headers = data + e_lfanew + 4;
    uint16_t num_sections = 0;
    std::memcpy(&num_sections, nt_headers + 2, 2);
    uint16_t size_of_optional_header = 0;
    std::memcpy(&size_of_optional_header, nt_headers + 16, 2);

    const uint8_t* opt_hdr = nt_headers + 20;
    uint16_t magic = 0;
    std::memcpy(&magic, opt_hdr, 2);
    bool is_pe32_plus = (magic == 0x20b);

    const uint8_t* data_dirs = opt_hdr + 96;

    uint32_t sec_table_offset = e_lfanew + 24 + size_of_optional_header;
    if (sec_table_offset + static_cast<uint32_t>(num_sections) * 40 > size) {
        return make_error(ErrorCategory::Format, 2,
                          "section table out of range");
    }

    out.protected_data.assign(input.begin(), input.end());
    out.authenticated_encryption = (mode != SectionMode::None);

    if (mode == SectionMode::None) {
        return ok_error();
    }

    // Determine which sections to encrypt
    std::vector<uint16_t> sections_to_encrypt;

    for (uint16_t i = 0; i < num_sections; i++) {
        const uint8_t* sec = data + sec_table_offset + i * 40;
        char sec_name[9] = {0};
        std::memcpy(sec_name, sec, 8);

        uint32_t characteristics = 0;
        std::memcpy(&characteristics, sec + 36, 4);
        uint32_t size_of_raw_data = 0;
        std::memcpy(&size_of_raw_data, sec + 16, 4);

        if (size_of_raw_data == 0) continue;

        bool is_code = (characteristics & 0x20000000) != 0;

        // Skip code sections
        if (is_code) continue;
        // Skip .text
        if (strncmp(sec_name, ".text", 5) == 0) continue;
        // Skip .reloc (relocations needed by loader)
        if (strncmp(sec_name, ".reloc", 6) == 0) continue;
        // Skip .rsrc (resources)
        if (strncmp(sec_name, ".rsrc", 5) == 0) continue;
        // Skip .idata (imports)
        if (strncmp(sec_name, ".idata", 6) == 0) continue;

        // Encrypt eligible data sections
        sections_to_encrypt.push_back(i);
    }

    if (sections_to_encrypt.empty()) {
        return ok_error();
    }

    // Encrypt each selected section
    std::mt19937_64 rng(0xDEADBEEF);
    uint32_t sections_protected = 0;
    uint64_t protected_bytes = 0;

    for (uint16_t sec_idx : sections_to_encrypt) {
        const uint8_t* sec = data + sec_table_offset + sec_idx * 40;
        uint32_t pointer_to_raw_data = 0;
        std::memcpy(&pointer_to_raw_data, sec + 20, 4);
        uint32_t size_of_raw_data = 0;
        std::memcpy(&size_of_raw_data, sec + 16, 4);

        if (size_of_raw_data == 0) continue;

        uint64_t xor_key = rng();
        encrypt_section(out.protected_data.data() + pointer_to_raw_data,
                        size_of_raw_data, xor_key);

        out.encrypted_sections.push_back({sec_idx, xor_key});
        sections_protected++;
        protected_bytes += size_of_raw_data;
    }

    out.sections_protected = static_cast<uint32_t>(sections_to_encrypt.size());
    out.protected_bytes = protected_bytes;

    nexapack::nxp_log(nexapack::LogLevel::Info,
        "section_protection: encrypted " + std::to_string(out.sections_protected) +
        " sections, " + std::to_string(out.protected_bytes) + " bytes");

    return ok_error();
}

} // namespace section_protection
} // namespace nexaprotect
} // namespace nexapack
