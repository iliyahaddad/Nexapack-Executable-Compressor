#include "formats/elf/elf_analyzer.hpp"
#include "core/error.hpp"
#include "core/logging.hpp"

#include <cstring>
#include <string>

namespace nexapack {
namespace elf {

namespace {

#pragma pack(push, 1)
struct Elf64Ehdr {
    unsigned char e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};
static_assert(sizeof(Elf64Ehdr) == 64, "Elf64Ehdr must be 64 bytes");

struct Elf64Phdr {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
};
static_assert(sizeof(Elf64Phdr) == 56, "Elf64Phdr must be 56 bytes");

struct Elf64Shdr {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
};
static_assert(sizeof(Elf64Shdr) == 64, "Elf64Shdr must be 64 bytes");
#pragma pack(pop)

// e_ident indices
constexpr uint8_t kEiMagic0 = 0;
constexpr uint8_t kEiMagic1 = 1;
constexpr uint8_t kEiMagic2 = 2;
constexpr uint8_t kEiMagic3 = 3;
constexpr uint8_t kEiClass = 4;
constexpr uint8_t kEiData = 5;
constexpr uint8_t kEiVersion = 6;

// ELF class
constexpr uint8_t kElfClass64 = 2;

// ELF data encoding
constexpr uint8_t kElfData2Lsb = 1; // little-endian

// e_type
constexpr uint16_t kEtExec = 2;
constexpr uint16_t kEtDyn = 3;

// e_machine
constexpr uint16_t kEmX86_64 = 62;

// Program header types
constexpr uint32_t kPtNull = 0;
constexpr uint32_t kPtLoad = 1;
constexpr uint32_t kPtDynamic = 2;
constexpr uint32_t kPtInterp = 3;
constexpr uint32_t kPtTls = 7;

// Program header flags
constexpr uint32_t kPfX = 1;
constexpr uint32_t kPfW = 2;
constexpr uint32_t kPfR = 4;

// Section header types (subset)
constexpr uint32_t kShtNull = 0;
constexpr uint32_t kShtProgbits = 1;
constexpr uint32_t kShtSymtab = 2;
constexpr uint32_t kShtStrtab = 3;
constexpr uint32_t kShtRelax = 4;
constexpr uint32_t kShtHash = 5;
constexpr uint32_t kShtDynamic = 6;
constexpr uint32_t kShtNote = 7;
constexpr uint32_t kShtNoBits = 8;
constexpr uint32_t kShtRel = 9;
constexpr uint32_t kShtShlib = 10;
constexpr uint32_t kShtDynsym = 11;
constexpr uint32_t kShtInitArray = 14;
constexpr uint32_t kShtFiniArray = 15;
constexpr uint32_t kShtPreinitArray = 16;
constexpr uint32_t kShtGroup = 17;
constexpr uint32_t kShtSymtabShndx = 18;
constexpr uint32_t kShtNum = 19;

// GNU-specific program header types (not in standard enum)
constexpr uint32_t kPtGnuStack = 0x6474e551;
constexpr uint32_t kPtGnuRelro = 0x6474e552;

} // namespace

Error analyze_elf(std::string_view data, ElfAnalysis& out) {
    out = ElfAnalysis{};

    if (data.size() < sizeof(Elf64Ehdr)) {
        return make_error(ErrorCategory::Format, 1,
                          "file too small for ELF header: " +
                          std::to_string(data.size()) + " bytes");
    }

    const uint8_t* p = reinterpret_cast<const uint8_t*>(data.data());

    // Magic
    std::memcpy(out.ei_magic, p, 4);
    if (out.ei_magic[0] != 0x7f || out.ei_magic[1] != 'E' ||
        out.ei_magic[2] != 'L' || out.ei_magic[3] != 'F') {
        return make_error(ErrorCategory::Format, 2, "not an ELF file");
    }
    out.is_elf = true;

    out.ei_class = p[kEiClass];
    out.ei_data = p[kEiData];
    out.ei_version = p[kEiVersion];
    std::memcpy(out.ei_pad, p + 7, 7);

    out.is_little_endian = (out.ei_data == kElfData2Lsb);

    if (out.ei_class != kElfClass64) {
        return make_error(ErrorCategory::Format, 3,
                          "not ELF64: e_ident[EI_CLASS]=" +
                          std::to_string(out.ei_class));
    }
    out.is_elf64 = true;

    const Elf64Ehdr* ehdr = reinterpret_cast<const Elf64Ehdr*>(p);

    out.e_type = ehdr->e_type;
    out.e_machine = ehdr->e_machine;
    out.e_version = ehdr->e_version;
    out.e_entry = ehdr->e_entry;
    out.e_phoff = ehdr->e_phoff;
    out.e_shoff = ehdr->e_shoff;
    out.e_flags = ehdr->e_flags;
    out.e_ehsize = ehdr->e_ehsize;
    out.e_phentsize = ehdr->e_phentsize;
    out.e_phnum = ehdr->e_phnum;
    out.e_shentsize = ehdr->e_shentsize;
    out.e_shnum = ehdr->e_shnum;
    out.e_shstrndx = ehdr->e_shstrndx;

    out.is_x86_64 = (out.e_machine == kEmX86_64);
    out.supports_x86_64 = out.is_x86_64;

    out.is_executable = (out.e_type == kEtExec);
    out.is_shared = (out.e_type == kEtDyn);
    out.has_entry_point = out.e_entry != 0;

    // Program headers
    if (out.e_phoff != 0 && out.e_phnum != 0) {
        if (data.size() < out.e_phoff +
                             static_cast<uint64_t>(out.e_phnum) *
                                 static_cast<uint64_t>(out.e_phentsize)) {
            return make_error(ErrorCategory::Format, 4,
                              "file too small for program headers");
        }
        const Elf64Phdr* phdr =
            reinterpret_cast<const Elf64Phdr*>(p + out.e_phoff);
        out.program_headers.reserve(out.e_phnum);
        for (uint16_t i = 0; i < out.e_phnum; ++i) {
            ElfAnalysis::Phdr ph;
            ph.p_type = phdr[i].p_type;
            ph.p_flags = phdr[i].p_flags;
            ph.p_offset = phdr[i].p_offset;
            ph.p_vaddr = phdr[i].p_vaddr;
            ph.p_paddr = phdr[i].p_paddr;
            ph.p_filesz = phdr[i].p_filesz;
            ph.p_memsz = phdr[i].p_memsz;
            ph.p_align = phdr[i].p_align;
            out.program_headers.push_back(ph);

            switch (ph.p_type) {
                case kPtLoad: ++out.pt_load_count; break;
                case kPtInterp: out.has_pt_interp = true; break;
                case kPtDynamic: out.has_pt_dynamic = true; break;
                case kPtTls: out.has_pt_tls = true; break;
                case kPtGnuStack: out.has_gnu_stack = true; break;
                case kPtGnuRelro: out.has_gnu_relro = true; break;
                default: break;
            }
        }
    }

    out.is_dynamic = out.has_pt_interp || out.has_pt_dynamic;

    // Section headers
    if (out.e_shoff != 0 && out.e_shnum != 0) {
        if (data.size() < out.e_shoff +
                             static_cast<uint64_t>(out.e_shnum) *
                                 static_cast<uint64_t>(out.e_shentsize)) {
            return make_error(ErrorCategory::Format, 5,
                              "file too small for section headers");
        }
        const Elf64Shdr* shdr =
            reinterpret_cast<const Elf64Shdr*>(p + out.e_shoff);
        out.section_headers.reserve(out.e_shnum);
        for (uint16_t i = 0; i < out.e_shnum; ++i) {
            ElfAnalysis::Shdr sh;
            sh.sh_name = shdr[i].sh_name;
            sh.sh_type = shdr[i].sh_type;
            sh.sh_flags = shdr[i].sh_flags;
            sh.sh_addr = shdr[i].sh_addr;
            sh.sh_offset = shdr[i].sh_offset;
            sh.sh_size = shdr[i].sh_size;
            sh.sh_link = shdr[i].sh_link;
            sh.sh_info = shdr[i].sh_info;
            sh.sh_addralign = shdr[i].sh_addralign;
            sh.sh_entsize = shdr[i].sh_entsize;
            out.section_headers.push_back(sh);
        }
    }

    nexapack::nxp_log(nexapack::LogLevel::Debug, "ELF64 analysis: type=" + std::to_string(out.e_type) +
                       " machine=" + std::to_string(out.e_machine) +
                       " phnum=" + std::to_string(out.e_phnum) +
                       " entry=0x" + std::to_string(out.e_entry));
    return ok_error();
}

} // namespace elf
} // namespace nexapack

