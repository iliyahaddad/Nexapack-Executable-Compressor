#include "core/analyzer/analyzer.hpp"
#include "core/logging.hpp"

#include <cstring>

namespace nexapack {
namespace analyzer {

namespace {

constexpr char kMzMagic[2] = {'M', 'Z'};
constexpr char kElfMagic[4] = {0x7f, 'E', 'L', 'F'};

std::string format_name(ExecutableFormat f) {
    switch (f) {
        case ExecutableFormat::PE32Plus: return "PE32+ (Windows x64)";
        case ExecutableFormat::ELF64: return "ELF64 (Linux x86-64)";
        default: return "Unknown";
    }
}

std::string architecture_name(ExecutableArchitecture a) {
    switch (a) {
        case ExecutableArchitecture::X64: return "x86-64";
        case ExecutableArchitecture::X86: return "x86";
        default: return "Unknown";
    }
}

std::string os_name(ExecutableOs o) {
    switch (o) {
        case ExecutableOs::Windows: return "Windows";
        case ExecutableOs::Linux: return "Linux";
        default: return "Unknown";
    }
}

std::string type_name(ExecutableType t) {
    switch (t) {
        case ExecutableType::Exe: return "Executable (EXE)";
        case ExecutableType::Dll: return "Dynamic-link library (DLL)";
        case ExecutableType::So: return "Shared object (.so)";
        case ExecutableType::PIE: return "Position-independent executable (PIE)";
        default: return "Unknown";
    }
}

std::string compatibility_name(PackCompatibility c) {
    switch (c) {
        case PackCompatibility::Unsupported: return "Unsupported";
        case PackCompatibility::Recognized: return "Recognized (magic only)";
        case PackCompatibility::Parsed: return "Parsed (structure valid)";
        case PackCompatibility::Analyzable: return "Analyzable (metadata extracted)";
        case PackCompatibility::Packable: return "Packable (pipeline implemented)";
        case PackCompatibility::Executable: return "Executable (packed run verified)";
        default: return "Unknown";
    }
}

} // namespace

Error analyze_executable(std::string_view data, CompatibilityReport& out) {
    out = CompatibilityReport{};

    if (data.size() < 4) {
        return make_error(ErrorCategory::Format, 1,
                          "file too small to detect format: " +
                          std::to_string(data.size()) + " bytes");
    }

    const uint8_t* p = reinterpret_cast<const uint8_t*>(data.data());

    // PE detection: MZ signature
    if (p[0] == kMzMagic[0] && p[1] == kMzMagic[1]) {
        Error err = pe::analyze_pe(data, out.pe);
        if (!err.ok()) {
            // Recognized as PE by MZ but structure invalid
            out.format = ExecutableFormat::PE32Plus;
            out.architecture = ExecutableArchitecture::X64;
            out.os = ExecutableOs::Windows;
            out.format_name = format_name(out.format);
            out.architecture_name = architecture_name(out.architecture);
            out.os_name = os_name(out.os);
            out.compatibility = PackCompatibility::Recognized;
            out.compatibility_name = compatibility_name(out.compatibility);
            out.packable = false;
            out.executable = false;
            out.warnings.push_back("PE signature present but structure invalid: " +
                                   std::string(err.message()));
            return err;
        }

        out.format = ExecutableFormat::PE32Plus;
        out.os = ExecutableOs::Windows;
        out.format_name = format_name(out.format);
        out.os_name = os_name(out.os);

        if (out.pe.supports_x64) {
            out.architecture = ExecutableArchitecture::X64;
        } else {
            out.architecture = ExecutableArchitecture::X86;
        }
        out.architecture_name = architecture_name(out.architecture);

        if (out.pe.is_dll) {
            out.type = ExecutableType::Dll;
        } else {
            out.type = ExecutableType::Exe;
        }
        out.type_name = type_name(out.type);

        for (const auto& s : out.pe.sections) {
            out.sections.push_back(s.name);
        }

// Phase 4/6: PE32+ x64 EXE is packable (Runtime implemented and verified).
        // Store, ZSTD, LZ4, and LZMA codecs pass round-trip pack/unpack/execute.
        // DLLs are packable with stub_dll.dll (Phase 6).
        out.compatibility = PackCompatibility::Packable;
        out.compatibility_name = compatibility_name(out.compatibility);
        out.packable = true;
        out.executable = !out.pe.is_dll;

        out.notes.push_back("PE32+ x64 structure parsed successfully.");
        out.notes.push_back("Packing pipeline implemented (Phase 4).");
        out.notes.push_back("Store, ZSTD, and LZ4 codecs verified end-to-end.");

        if (out.pe.is_dll) {
            out.notes.push_back(
                "DLL detected; DLL Runtime support available via stub_dll.dll (Phase 6).");
        }

        if (out.pe.has_authenticode) {
            out.warnings.push_back(
                "Authenticode signature directory present; packing would "
                "invalidate the original signature.");
        }
        if (out.pe.is_dll) {
            out.notes.push_back(
                "DLL detected; DLL support is a separate Phase 6 milestone.");
        }
        return ok_error();
    }

    // ELF detection: \x7fELF
    if (p[0] == kElfMagic[0] && p[1] == kElfMagic[1] &&
        p[2] == kElfMagic[2] && p[3] == kElfMagic[3]) {
        Error err = elf::analyze_elf(data, out.elf);
        if (!err.ok()) {
            out.format = ExecutableFormat::ELF64;
            out.architecture = ExecutableArchitecture::X64;
            out.os = ExecutableOs::Linux;
            out.format_name = format_name(out.format);
            out.architecture_name = architecture_name(out.architecture);
            out.os_name = os_name(out.os);
            out.compatibility = PackCompatibility::Recognized;
            out.compatibility_name = compatibility_name(out.compatibility);
            out.packable = false;
            out.executable = false;
            out.warnings.push_back("ELF magic present but structure invalid: " +
                                   std::string(err.message()));
            return err;
        }

        out.format = ExecutableFormat::ELF64;
        out.os = ExecutableOs::Linux;
        out.format_name = format_name(out.format);
        out.os_name = os_name(out.os);

        if (out.elf.supports_x86_64) {
            out.architecture = ExecutableArchitecture::X64;
        } else {
            out.architecture = ExecutableArchitecture::Unknown;
        }
        out.architecture_name = architecture_name(out.architecture);

        if (out.elf.is_executable) {
            out.type = ExecutableType::Exe;
        } else if (out.elf.is_pie) {
            out.type = ExecutableType::PIE;
        } else if (out.elf.is_shared) {
            out.type = ExecutableType::So;
        } else {
            out.type = ExecutableType::Unknown;
        }
        out.type_name = type_name(out.type);

        for (size_t si = 0; si < out.elf.section_headers.size(); ++si) {
            // raw index; name unresolved without string table
            out.sections.push_back("section[" + std::to_string(si) + "]");
        }

        out.compatibility = PackCompatibility::Analyzable;
        out.compatibility_name = compatibility_name(out.compatibility);
        out.packable = false;
        out.executable = false;

        out.notes.push_back("ELF64 x86-64 structure parsed successfully.");
        out.notes.push_back("Packing pipeline not yet implemented (Phase 5).");
        out.notes.push_back("Do not mark as packable based on parse alone.");

        if (out.elf.is_dynamic) {
            out.notes.push_back(
                "Dynamic executable; dynamic linker handling is Phase 5 scope.");
        }
        if (out.elf.has_pt_tls) {
            out.notes.push_back("TLS segment present.");
        }
        return ok_error();
    }

    // Unknown format
    out.format = ExecutableFormat::Unknown;
    out.architecture = ExecutableArchitecture::Unknown;
    out.os = ExecutableOs::Unknown;
    out.type = ExecutableType::Unknown;
    out.format_name = format_name(out.format);
    out.architecture_name = architecture_name(out.architecture);
    out.os_name = os_name(out.os);
    out.type_name = type_name(out.type);
    out.compatibility = PackCompatibility::Unsupported;
    out.compatibility_name = compatibility_name(out.compatibility);
    out.packable = false;
    out.executable = false;
    out.notes.push_back("File format not recognized by NexaPack.");
    return ok_error();
}

std::string summarize(const CompatibilityReport& report) {
    std::string s;
    s += report.format_name + " | ";
    s += report.architecture_name + " | ";
    s += report.os_name + " | ";
    s += report.type_name + " | ";
    s += report.compatibility_name;
    s += " | packable=";
    s += report.packable ? "true" : "false";
    s += " | executable=";
    s += report.executable ? "true" : "false";
    return s;
}

std::string to_json(const CompatibilityReport& report) {
    std::string s = "{";
    s += "\"input\":\"" + report.input_path + "\",";
    s += "\"format\":\"" + report.format_name + "\",";
    s += "\"architecture\":\"" + report.architecture_name + "\",";
    s += "\"os\":\"" + report.os_name + "\",";
    s += "\"type\":\"" + report.type_name + "\",";
    s += "\"compatibility\":\"" + report.compatibility_name + "\",";
    s += "\"packable\":" + std::string(report.packable ? "true" : "false") + ",";
    s += "\"executable\":" + std::string(report.executable ? "true" : "false") + ",";
    s += "\"sections\":[";
    for (size_t i = 0; i < report.sections.size(); ++i) {
        if (i) s += ",";
        s += std::string("\"") + report.sections[i] + "\"";
    }
    s += "],";
    s += "\"notes\":[";
    for (size_t i = 0; i < report.notes.size(); ++i) {
        if (i) s += ",";
        s += std::string("\"") + report.notes[i] + "\"";
    }
    s += "],";
    s += "\"warnings\":[";
    for (size_t i = 0; i < report.warnings.size(); ++i) {
        if (i) s += ",";
        s += std::string("\"") + report.warnings[i] + "\"";
    }
    s += "]";
    s += "}";
    return s;
}

} // namespace analyzer
} // namespace nexapack

