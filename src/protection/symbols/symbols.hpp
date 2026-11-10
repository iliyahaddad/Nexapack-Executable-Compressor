#ifndef NEXAPACK_PROTECTION_SYMBOLS_SYMBOLS_HPP
#define NEXAPACK_PROTECTION_SYMBOLS_SYMBOLS_HPP

#include "core/error.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace nexapack {
namespace nexaprotect {
namespace symbols {

// Symbol-handling policy for protection.
enum class SymbolPolicy {
    PreserveAll,    // Keep all symbols (no stripping)
    StripDebug,     // Strip debug symbols only
    StripNonRuntime, // Strip non-essential symbols, preserve runtime metadata
    StripAllEligible, // Strip all eligible symbols
};

// Result of symbol processing.
struct SymbolResult {
    std::vector<uint8_t> processed_data;
    uint64_t symbols_removed = 0;
    uint64_t bytes_saved = 0;
    bool runtime_metadata_preserved = false;
    Error error;
};

// Apply symbol handling policy to an executable buffer.
// Only strips symbols that are safe to remove; required runtime metadata
// (relocations, TLS, exception data, dynamic symbols for shared libs) is
// always preserved.
Error process_symbols(std::string_view input,
                      SymbolPolicy policy,
                      SymbolResult& out);

} // namespace symbols
} // namespace nexaprotect
} // namespace nexapack

#endif // NEXAPACK_PROTECTION_SYMBOLS_SYMBOLS_HPP

