#ifndef NEXAPACK_CORE_ANALYZER_ANALYZER_HPP
#define NEXAPACK_CORE_ANALYZER_ANALYZER_HPP

#include "core/error.hpp"
#include "core/metadata.hpp"
#include "formats/elf/elf_analyzer.hpp"
#include "formats/pe/pe_analyzer.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace nexapack {
namespace analyzer {

// Overall executable format classification.
enum class ExecutableFormat : uint32_t {
    Unknown = 0,
    PE32Plus = 1,   // Windows PE32+ (x64)
    ELF64 = 2,      // Linux ELF64 (x86-64)
};

// Architecture classification.
enum class ExecutableArchitecture : uint32_t {
    Unknown = 0,
    X64 = 1,
    X86 = 2,
};

// Operating-system target classification.
enum class ExecutableOs : uint32_t {
    Unknown = 0,
    Windows = 1,
    Linux = 2,
};

// Executable type classification.
enum class ExecutableType : uint32_t {
    Unknown = 0,
    Exe = 1,   // standalone executable
    Dll = 2,   // Windows DLL
    So = 3,    // Linux shared object
    PIE = 4,   // position-independent executable
};

// Compatibility level for NexaPack packing.
enum class PackCompatibility : uint32_t {
    Unknown = 0,
    Unsupported = 1,   // format not supported at all
    Recognized = 2,    // magic bytes recognized, structure parsed
    Parsed = 3,        // full structural analysis succeeded
    Analyzable = 4,    // all metadata extracted
    Packable = 5,      // pack pipeline implemented for this profile
    Executable = 6,    // packed file verified to execute
};

// Full compatibility report for a single executable.
struct CompatibilityReport {
    std::string input_path;
    ExecutableFormat format = ExecutableFormat::Unknown;
    ExecutableArchitecture architecture = ExecutableArchitecture::Unknown;
    ExecutableOs os = ExecutableOs::Unknown;
    ExecutableType type = ExecutableType::Unknown;
    PackCompatibility compatibility = PackCompatibility::Unknown;

    std::string format_name;
    std::string architecture_name;
    std::string os_name;
    std::string type_name;
    std::string compatibility_name;

    // Raw analysis results
    pe::PeAnalysis pe;
    elf::ElfAnalysis elf;

    // Notable sections / segments
    std::vector<std::string> sections;

    // Warnings / info messages
    std::vector<std::string> notes;
    std::vector<std::string> warnings;

    // Whether NexaPack claims to support packing this file.
    bool packable = false;
    bool executable = false;
};

// Detect format from magic bytes and dispatch to the appropriate analyzer.
Error analyze_executable(std::string_view data, CompatibilityReport& out);

// Produce a human-readable one-line summary.
std::string summarize(const CompatibilityReport& report);

// Produce JSON output.
std::string to_json(const CompatibilityReport& report);

} // namespace analyzer
} // namespace nexapack

#endif // NEXAPACK_CORE_ANALYZER_ANALYZER_HPP

