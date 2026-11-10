#include "protection/symbols/symbols.hpp"
#include "core/error.hpp"
#include "core/logging.hpp"

#include <algorithm>
#include <cstring>
#include <vector>

namespace nexapack {
namespace nexaprotect {
namespace symbols {

Error process_symbols(std::string_view input,
                      SymbolPolicy policy,
                      SymbolResult& out) {
    out = SymbolResult{};

    if (input.empty()) {
        return make_error(ErrorCategory::InvalidArgument, 1,
                          "empty input buffer");
    }

    const uint8_t* data = reinterpret_cast<const uint8_t*>(input.data());
    size_t size = input.size();

    // Min PE detection: MZ + PE signature
    if (size < 64 || data[0] != 'M' || data[1] != 'Z') {
        out.processed_data.assign(input.begin(), input.end());
        return ok_error();
    }

    uint32_t e_lfanew = 0;
    std::memcpy(&e_lfanew, data + 60, 4);
    if (e_lfanew > size - 4) {
        return make_error(ErrorCategory::Format, 2,
                          "e_lfanew out of range");
    }
    if (std::memcmp(data + e_lfanew, "PE\0\0", 4) != 0) {
        out.processed_data.assign(input.begin(), input.end());
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

    uint32_t num_rva_and_sizes = 0;
    std::memcpy(&num_rva_and_sizes, opt_hdr + 92, 4);

    const uint8_t* data_dirs = opt_hdr + 96;

    uint32_t sec_table_offset = e_lfanew + 24 + size_of_optional_header;
    if (sec_table_offset + static_cast<uint32_t>(num_sections) * 40 > size) {
        return make_error(ErrorCategory::Format, 4,
                          "section table out of range");
    }

    out.processed_data.assign(input.begin(), input.end());
    out.runtime_metadata_preserved = true;

    std::vector<uint16_t> sections_to_remove;

    for (uint16_t i = 0; i < num_sections; i++) {
        const uint8_t* sec = data + sec_table_offset + i * 40;
        char sec_name[9] = {0};
        std::memcpy(sec_name, sec, 8);

        bool is_debug_section = (strncmp(sec_name, ".debug", 6) == 0);

        if (policy == SymbolPolicy::StripDebug) {
            if (is_debug_section) {
                sections_to_remove.push_back(i);
            }
        } else if (policy == SymbolPolicy::StripNonRuntime ||
                   policy == SymbolPolicy::StripAllEligible) {
            if (is_debug_section) {
                sections_to_remove.push_back(i);
            }
            if (strncmp(sec_name, ".note.gnu.build-id", 17) == 0) {
                sections_to_remove.push_back(i);
            }
            if (strncmp(sec_name, ".comment", 8) == 0) {
                sections_to_remove.push_back(i);
            }
            if (strncmp(sec_name, ".note.ABI-tag", 13) == 0) {
                sections_to_remove.push_back(i);
            }
        }
    }

    std::vector<uint8_t> new_sec_table;
    new_sec_table.reserve((num_sections - sections_to_remove.size()) * 40);

    for (uint16_t i = 0; i < num_sections; i++) {
        bool skip = false;
        for (uint16_t r : sections_to_remove) {
            if (i == r) {
                skip = true;
                break;
            }
        }
        if (!skip) {
            const uint8_t* sec = data + sec_table_offset + i * 40;
            new_sec_table.insert(new_sec_table.end(), sec, sec + 40);
        }
    }

    out.processed_data.assign(input.begin(), input.end());

    uint16_t* num_sections_ptr = reinterpret_cast<uint16_t*>(
        &out.processed_data[e_lfanew + 6]);
    *num_sections_ptr = static_cast<uint16_t>(num_sections - sections_to_remove.size());

    uint32_t removed_bytes = 0;
    for (uint16_t r : sections_to_remove) {
        const uint8_t* sec = data + sec_table_offset + r * 40;
        uint32_t raw_size = 0;
        std::memcpy(&raw_size, sec + 16, 4);
        removed_bytes += raw_size;
    }

    uint32_t size_of_image = 0;
    std::memcpy(&size_of_image, opt_hdr + 56, 4);
    size_of_image -= removed_bytes;
    uint8_t* out_opt_hdr = &out.processed_data[e_lfanew + 24];
    std::memcpy(out_opt_hdr + 56, &size_of_image, 4);

    uint8_t* out_sec_table = &out.processed_data[e_lfanew + 24 + size_of_optional_header];
    for (uint16_t i = 0; i < new_sec_table.size() / 40; i++) {
        std::memcpy(out_sec_table + i * 40, new_sec_table.data() + i * 40, 40);
    }

    if (num_rva_and_sizes > 6) {
        uint32_t debug_rva = 0;
        uint32_t debug_size = 0;
        std::memcpy(&debug_rva, data_dirs + 6 * 8, 4);
        std::memcpy(&debug_size, data_dirs + 6 * 8 + 4, 4);

        if (debug_size > 0) {
            uint32_t zero = 0;
            uint8_t* out_dirs = &out.processed_data[e_lfanew + 24 + size_of_optional_header + 96];
            std::memcpy(out_dirs + 6 * 8, &zero, 4);
            std::memcpy(out_dirs + 6 * 8 + 4, &zero, 4);
        }
    }

    out.symbols_removed = static_cast<uint32_t>(sections_to_remove.size());
    out.bytes_saved = removed_bytes;

    nexapack::nxp_log(nexapack::LogLevel::Info,
        "symbols: stripped " + std::to_string(out.symbols_removed) +
        " sections, saved ~" + std::to_string(out.bytes_saved) + " bytes");

    return ok_error();
}

} // namespace symbols
} // namespace nexaprotect
} // namespace nexapack
