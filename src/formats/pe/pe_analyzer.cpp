#include "formats/pe/pe_analyzer.hpp"
#include "core/error.hpp"
#include "core/logging.hpp"

#include <cstring>
#include <string>

namespace nexapack {
namespace pe {

namespace {

// IMAGE_DOS_HEADER
#pragma pack(push, 1)
struct DosHeader {
    char e_magic[2];      // "MZ"
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;
};
static_assert(sizeof(DosHeader) == 64, "DosHeader must be 64 bytes");

// IMAGE_FILE_HEADER
struct FileHeader {
    uint16_t machine;
    uint16_t number_of_sections;
    uint32_t time_date_stamp;
    uint32_t pointer_to_symbol_table;
    uint32_t number_of_symbols;
    uint16_t size_of_optional_header;
    uint16_t characteristics;
};
static_assert(sizeof(FileHeader) == 20, "FileHeader must be 20 bytes");

// IMAGE_OPTIONAL_HEADER64 (PE32+)
struct OptionalHeader64 {
    uint16_t magic;
    uint8_t major_linker_version;
    uint8_t minor_linker_version;
    uint32_t size_of_code;
    uint32_t size_of_initialized_data;
    uint32_t size_of_uninitialized_data;
    uint32_t address_of_entry_point;
    uint32_t base_of_code;
    uint64_t image_base;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t major_os_version;
    uint16_t minor_os_version;
    uint16_t major_image_version;
    uint16_t minor_image_version;
    uint16_t major_subsystem_version;
    uint16_t minor_subsystem_version;
    uint32_t win32_version_value;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t checksum;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    uint64_t size_of_stack_reserve;
    uint64_t size_of_stack_commit;
    uint64_t size_of_heap_reserve;
    uint64_t size_of_heap_commit;
    uint32_t loader_flags;
    uint32_t number_of_rva_and_sizes;
};
static_assert(sizeof(OptionalHeader64) == 112, "OptionalHeader64 must be 112 bytes");

// IMAGE_DATA_DIRECTORY
struct DataDirectory {
    uint32_t virtual_address;
    uint32_t size;
};
static_assert(sizeof(DataDirectory) == 8, "DataDirectory must be 8 bytes");

// IMAGE_SECTION_HEADER
struct SectionHeader {
    char name[8];
    uint32_t virtual_size;
    uint32_t virtual_address;
    uint32_t size_of_raw_data;
    uint32_t pointer_to_raw_data;
    uint32_t pointer_to_relocations;
    uint32_t pointer_to_linenumbers;
    uint16_t number_of_relocations;
    uint16_t number_of_linenumbers;
    uint32_t characteristics;
};
static_assert(sizeof(SectionHeader) == 40, "SectionHeader must be 40 bytes");
#pragma pack(pop)

// Machine constants
constexpr uint16_t kMachineAmd64 = 0x8664;
constexpr uint16_t kMachineI386 = 0x014c;

// Optional header magic
constexpr uint16_t kOptMagicPe32 = 0x010b;
constexpr uint16_t kOptMagicPe32Plus = 0x020b;

// Characteristics
constexpr uint16_t kCharacteristicsDll = 0x2000;
constexpr uint16_t kCharacteristicsExe = 0x0002;

// Subsystem
constexpr uint16_t kSubsystemNative = 1;
constexpr uint16_t kSubsystemWindowsGui = 2;
constexpr uint16_t kSubsystemWindowsCui = 3;
constexpr uint16_t kSubsystemEfiApplication = 10;

// Data directory indices
constexpr uint32_t kDirExport = 0;
constexpr uint32_t kDirImport = 1;
constexpr uint32_t kDirResource = 2;
constexpr uint32_t kDirException = 3;
constexpr uint32_t kDirCertificate = 4;
constexpr uint32_t kDirBaseRelocation = 5;
constexpr uint32_t kDirDebug = 6;
constexpr uint32_t kDirArchitecture = 7;
constexpr uint32_t kDirGlobalPtr = 8;
constexpr uint32_t kDirTls = 9;
constexpr uint32_t kDirLoadConfig = 10;
constexpr uint32_t kDirBoundImport = 11;
constexpr uint32_t kDirIat = 12;
constexpr uint32_t kDirDelayImport = 13;
constexpr uint32_t kDirClrRuntimeHeader = 14;

} // namespace

Error analyze_pe(std::string_view data, PeAnalysis& out) {
    out = PeAnalysis{};

    if (data.size() < sizeof(DosHeader)) {
        return make_error(ErrorCategory::Format, 1,
                          "file too small for DOS header: " +
                          std::to_string(data.size()) + " bytes");
    }

    const uint8_t* p = reinterpret_cast<const uint8_t*>(data.data());

    // DOS header
    const DosHeader* dos = reinterpret_cast<const DosHeader*>(p);
    out.e_magic = static_cast<uint16_t>(dos->e_magic[0]) |
                  (static_cast<uint16_t>(dos->e_magic[1]) << 8);
    if (out.e_magic != 0x5A4D) { // "MZ"
        return make_error(ErrorCategory::Format, 2,
                          "not a PE file: missing MZ signature");
    }
    out.e_lfanew = dos->e_lfanew;

    // NT headers offset must be within file
    if (out.e_lfanew > data.size() - 4) {
        return make_error(ErrorCategory::Format, 3,
                          "e_lfanew points beyond end of file");
    }

    // PE signature
    uint32_t sig = 0;
    std::memcpy(&sig, p + out.e_lfanew, 4);
    out.signature = sig;
    if (sig != 0x00004550) { // "PE\0\0"
        return make_error(ErrorCategory::Format, 4,
                          "not a PE file: missing PE signature");
    }

    out.is_pe = true;

    const uint8_t* nt = p + out.e_lfanew + 4;

    // File header
    if (data.size() < out.e_lfanew + 4 + sizeof(FileHeader)) {
        return make_error(ErrorCategory::Format, 5,
                          "file too small for COFF file header");
    }
    const FileHeader* fh = reinterpret_cast<const FileHeader*>(nt);
    out.machine = fh->machine;
    out.number_of_sections = fh->number_of_sections;
    out.time_date_stamp = fh->time_date_stamp;
    out.size_of_optional_header = fh->size_of_optional_header;
    out.characteristics = fh->characteristics;

    out.is_dll = (out.characteristics & kCharacteristicsDll) != 0;
    out.is_exe = (out.characteristics & kCharacteristicsExe) != 0 || !out.is_dll;

    // Optional header
    const uint8_t* opt = nt + sizeof(FileHeader);
    if (data.size() < out.e_lfanew + 4 + sizeof(FileHeader) +
                         out.size_of_optional_header) {
        return make_error(ErrorCategory::Format, 6,
                          "file too small for optional header");
    }
    if (out.size_of_optional_header < sizeof(OptionalHeader64)) {
        return make_error(ErrorCategory::Format, 7,
                          "optional header too small for PE32+");
    }

    const OptionalHeader64* oh = reinterpret_cast<const OptionalHeader64*>(opt);
    out.magic = oh->magic;

    // PE32+ only
    if (out.magic != kOptMagicPe32Plus) {
        return make_error(ErrorCategory::Format, 8,
                          "not PE32+: optional header magic 0x" +
                          std::to_string(out.magic));
    }
    out.is_pe32_plus = true;
    out.supports_x64 = (out.machine == kMachineAmd64);

    out.major_linker_version = oh->major_linker_version;
    out.minor_linker_version = oh->minor_linker_version;
    out.size_of_code = oh->size_of_code;
    out.size_of_initialized_data = oh->size_of_initialized_data;
    out.size_of_uninitialized_data = oh->size_of_uninitialized_data;
    out.address_of_entry_point = oh->address_of_entry_point;
    out.base_of_code = oh->base_of_code;
    out.image_base = oh->image_base;
    out.section_alignment = oh->section_alignment;
    out.file_alignment = oh->file_alignment;
    out.major_os_version = oh->major_os_version;
    out.minor_os_version = oh->minor_os_version;
    out.major_image_version = oh->major_image_version;
    out.minor_image_version = oh->minor_image_version;
    out.major_subsystem_version = oh->major_subsystem_version;
    out.minor_subsystem_version = oh->minor_subsystem_version;
    out.size_of_image = oh->size_of_image;
    out.size_of_headers = oh->size_of_headers;
    out.checksum = oh->checksum;
    out.subsystem = oh->subsystem;
    out.dll_characteristics = oh->dll_characteristics;
    out.size_of_stack_reserve = oh->size_of_stack_reserve;
    out.size_of_stack_commit = oh->size_of_stack_commit;
    out.size_of_heap_reserve = oh->size_of_heap_reserve;
    out.size_of_heap_commit = oh->size_of_heap_commit;
    out.loader_flags = oh->loader_flags;
    out.number_of_rva_and_sizes = oh->number_of_rva_and_sizes;

    out.has_entry_point = out.address_of_entry_point != 0;

    // Data directories
    const uint8_t* dirs = opt + sizeof(OptionalHeader64);
    uint32_t dir_count =
        out.number_of_rva_and_sizes < 16 ? out.number_of_rva_and_sizes : 16;

    auto read_dir = [&](uint32_t index, PeAnalysis::DataDirectory& dd) {
        if (index < dir_count) {
            const auto* d = reinterpret_cast<const PeAnalysis::DataDirectory*>(
                dirs + index * sizeof(PeAnalysis::DataDirectory));
            dd.virtual_address = d->virtual_address;
            dd.size = d->size;
        }
    };

    read_dir(kDirExport, out.export_table);
    read_dir(kDirImport, out.import_table);
    read_dir(kDirResource, out.resource_table);
    read_dir(kDirException, out.exception_table);
    read_dir(kDirCertificate, out.certificate_table);
    read_dir(kDirBaseRelocation, out.base_relocation_table);
    read_dir(kDirDebug, out.debug);
    read_dir(kDirArchitecture, out.architecture);
    read_dir(kDirGlobalPtr, out.global_ptr);
    read_dir(kDirTls, out.tls_table);
    read_dir(kDirLoadConfig, out.load_config_table);
    read_dir(kDirBoundImport, out.bound_import);
    read_dir(kDirIat, out.iat);
    read_dir(kDirDelayImport, out.delay_import_descriptor);
    read_dir(kDirClrRuntimeHeader, out.clr_runtime_header);

    // Sections
    const uint8_t* sec = dirs + dir_count * sizeof(DataDirectory);
    if (data.size() < out.e_lfanew + 4 + sizeof(FileHeader) +
                         out.size_of_optional_header +
                         out.number_of_sections * sizeof(SectionHeader)) {
        return make_error(ErrorCategory::Format, 9,
                          "file too small for section table");
    }

    out.sections.reserve(out.number_of_sections);
    for (uint16_t i = 0; i < out.number_of_sections; ++i) {
        const SectionHeader* sh = reinterpret_cast<const SectionHeader*>(
            sec + i * sizeof(SectionHeader));
        PeAnalysis::Section s;
        s.name.assign(sh->name, 8);
        // Trim at null
        if (auto n = s.name.find('\0'); n != std::string::npos) {
            s.name.resize(n);
        }
        s.virtual_size = sh->virtual_size;
        s.virtual_address = sh->virtual_address;
        s.size_of_raw_data = sh->size_of_raw_data;
        s.pointer_to_raw_data = sh->pointer_to_raw_data;
        s.pointer_to_relocations = sh->pointer_to_relocations;
        s.pointer_to_linenumbers = sh->pointer_to_linenumbers;
        s.number_of_relocations = sh->number_of_relocations;
        s.number_of_linenumbers = sh->number_of_linenumbers;
        s.characteristics = sh->characteristics;
        out.sections.push_back(std::move(s));
    }

    // Summary counts (estimates from directory presence)
    out.import_descriptor_count =
        out.import_table.size != 0 ? 1 : 0;
    out.export_name_count = out.export_table.size != 0 ? 1 : 0;
    out.base_relocation_count =
        out.base_relocation_table.size != 0 ? 1 : 0;

    // Compatibility flags
    out.has_relocations = out.base_relocation_table.size != 0;
    out.has_tls = out.tls_table.size != 0;
    out.has_exception_data = out.exception_table.size != 0;
    out.has_debug_info = out.debug.size != 0;
    out.has_authenticode = out.certificate_table.size != 0;

    nexapack::nxp_log(nexapack::LogLevel::Debug, "PE32+ analysis: machine=0x" +
                       std::to_string(out.machine) +
                       " sections=" + std::to_string(out.number_of_sections) +
                       " entry=0x" +
                       std::to_string(out.address_of_entry_point) +
                       " image_base=0x" + std::to_string(out.image_base));
    return ok_error();
}

} // namespace pe
} // namespace nexapack

