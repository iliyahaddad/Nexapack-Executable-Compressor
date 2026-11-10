#ifndef NEXAPACK_FORMATS_ELF_ELF_ANALYZER_HPP
#define NEXAPACK_FORMATS_ELF_ELF_ANALYZER_HPP

#include "core/error.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace nexapack {
namespace elf {

// ELF64 executable analysis result.
// Parsing a binary does NOT imply it can be packed/executed.
struct ElfAnalysis {
    bool is_elf = false;
    bool is_elf64 = false;
    bool is_little_endian = false;
    bool is_executable = false;  // ET_EXEC
    bool is_shared = false;      // ET_DYN (PIE or shared library)
    bool is_pie = false;         // ET_DYN with EXEC-like flags (heuristic)
    bool is_x86_64 = false;

    // ELF header
    unsigned char ei_magic[4] = {0, 0, 0, 0}; // "\x7fELF"
    uint8_t ei_class = 0;     // 1=32, 2=64
    uint8_t ei_data = 0;      // 1=LE, 2=BE
    uint8_t ei_version = 0;
    uint8_t ei_osabi = 0;
    uint8_t ei_abiversion = 0;
    uint8_t ei_pad[7] = {0};

    uint16_t e_type = 0;      // ET_NONE/REL/EXEC/DYN/CORE
    uint16_t e_machine = 0;   // EM_X86_64 = 62
    uint32_t e_version = 0;
    uint64_t e_entry = 0;     // entry point virtual address
    uint64_t e_phoff = 0;     // program header offset
    uint64_t e_shoff = 0;     // section header offset
    uint32_t e_flags = 0;
    uint16_t e_ehsize = 0;
    uint16_t e_phentsize = 0;
    uint16_t e_phnum = 0;
    uint16_t e_shentsize = 0;
    uint16_t e_shnum = 0;
    uint16_t e_shstrndx = 0;

    // Program headers
    struct Phdr {
        uint32_t p_type = 0;   // PT_NULL/LOAD/DYNAMIC/INTERP/etc.
        uint32_t p_flags = 0;  // PF_R/W/X
        uint64_t p_offset = 0;
        uint64_t p_vaddr = 0;
        uint64_t p_paddr = 0;
        uint64_t p_filesz = 0;
        uint64_t p_memsz = 0;
        uint64_t p_align = 0;
    };
    std::vector<Phdr> program_headers;

    // Section headers (names unresolved; raw index table)
    struct Shdr {
        uint32_t sh_name = 0;
        uint32_t sh_type = 0;
        uint64_t sh_flags = 0;
        uint64_t sh_addr = 0;
        uint64_t sh_offset = 0;
        uint64_t sh_size = 0;
        uint32_t sh_link = 0;
        uint32_t sh_info = 0;
        uint64_t sh_addralign = 0;
        uint64_t sh_entsize = 0;
    };
    std::vector<Shdr> section_headers;

    // Segment summary
    uint32_t pt_load_count = 0;
    bool has_pt_interp = false;
    bool has_pt_dynamic = false;
    bool has_pt_tls = false;
    bool has_gnu_stack = false;
    bool has_gnu_relro = false;

    // Entry point
    bool has_entry_point = false;

    // Compatibility
    bool supports_x86_64 = false;
    bool is_dynamic = false;  // requires dynamic linker (has PT_INTERP or PT_DYNAMIC)
};

// Analyze an ELF64 binary buffer. Returns full structural analysis.
// Does NOT verify packability or executability.
Error analyze_elf(std::string_view data, ElfAnalysis& out);

} // namespace elf
} // namespace nexapack

#endif // NEXAPACK_FORMATS_ELF_ELF_ANALYZER_HPP

