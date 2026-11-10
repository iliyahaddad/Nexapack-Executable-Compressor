#ifndef NEXAPACK_FORMATS_PE_PE_ANALYZER_HPP
#define NEXAPACK_FORMATS_PE_PE_ANALYZER_HPP

#include "core/error.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace nexapack {
namespace pe {

// PE32+ (x64) executable analysis result.
// Only capabilities actually verified by this analyzer are reported as
// supported. Parsing a binary does NOT imply it can be packed/executed.
struct PeAnalysis {
    bool is_pe = false;
    bool is_pe32_plus = false;  // true only for PE32+ (x64)
    bool is_exe = false;
    bool is_dll = false;

    // DOS header
    uint16_t e_magic = 0;       // "MZ"
    uint32_t e_lfanew = 0;      // offset to NT headers

    // NT headers
    uint32_t signature = 0;     // "PE\0\0"
    uint16_t machine = 0;       // IMAGE_FILE_MACHINE_*
    uint16_t number_of_sections = 0;
    uint32_t time_date_stamp = 0;
    uint16_t size_of_optional_header = 0;
    uint16_t characteristics = 0;

    // Optional header (PE32+)
    uint16_t magic = 0;         // 0x20b = PE32+
    uint8_t major_linker_version = 0;
    uint8_t minor_linker_version = 0;
    uint32_t size_of_code = 0;
    uint32_t size_of_initialized_data = 0;
    uint32_t size_of_uninitialized_data = 0;
    uint32_t address_of_entry_point = 0;
    uint32_t base_of_code = 0;
    uint64_t image_base = 0;
    uint32_t section_alignment = 0;
    uint32_t file_alignment = 0;
    uint16_t major_os_version = 0;
    uint16_t minor_os_version = 0;
    uint16_t major_image_version = 0;
    uint16_t minor_image_version = 0;
    uint16_t major_subsystem_version = 0;
    uint16_t minor_subsystem_version = 0;
    uint32_t size_of_image = 0;
    uint32_t size_of_headers = 0;
    uint32_t checksum = 0;
    uint16_t subsystem = 0;
    uint16_t dll_characteristics = 0;
    uint64_t size_of_stack_reserve = 0;
    uint64_t size_of_stack_commit = 0;
    uint64_t size_of_heap_reserve = 0;
    uint64_t size_of_heap_commit = 0;
    uint32_t loader_flags = 0;
    uint32_t number_of_rva_and_sizes = 0;

    // Sections
    struct Section {
        std::string name;
        uint32_t virtual_size = 0;
        uint32_t virtual_address = 0;
        uint32_t size_of_raw_data = 0;
        uint32_t pointer_to_raw_data = 0;
        uint32_t pointer_to_relocations = 0;
        uint32_t pointer_to_linenumbers = 0;
        uint16_t number_of_relocations = 0;
        uint16_t number_of_linenumbers = 0;
        uint32_t characteristics = 0;
    };
    std::vector<Section> sections;

    // Data directories (first few important ones)
    struct DataDirectory {
        uint32_t virtual_address = 0;
        uint32_t size = 0;
    };
    DataDirectory export_table;
    DataDirectory import_table;
    DataDirectory resource_table;
    DataDirectory exception_table;
    DataDirectory certificate_table;
    DataDirectory base_relocation_table;
    DataDirectory debug;
    DataDirectory architecture;
    DataDirectory global_ptr;
    DataDirectory tls_table;
    DataDirectory load_config_table;
    DataDirectory bound_import;
    DataDirectory iat;
    DataDirectory delay_import_descriptor;
    DataDirectory clr_runtime_header;
    DataDirectory reserved;

    // Import / export / relocation summary
    uint32_t import_descriptor_count = 0;
    uint32_t export_name_count = 0;
    uint32_t base_relocation_count = 0;

    // Compatibility
    bool supports_x64 = false;
    bool has_entry_point = false;
    bool has_relocations = false;
    bool has_tls = false;
    bool has_exception_data = false;
    bool has_debug_info = false;
    bool has_authenticode = false;
};

// Analyze a PE32+ binary buffer. Returns full analysis including whether the
// file is a valid PE, whether it is PE32+/x64, EXE or DLL, and structural
// details. Does NOT verify packability or executability.
Error analyze_pe(std::string_view data, PeAnalysis& out);

} // namespace pe
} // namespace nexapack

#endif // NEXAPACK_FORMATS_PE_PE_ANALYZER_HPP

