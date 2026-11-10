#ifndef NEXAPACK_PROTECTION_MBA_MBA_HPP
#define NEXAPACK_PROTECTION_MBA_MBA_HPP

#include "core/error.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace nexapack {
namespace nexaprotect {
namespace mba {

// MBA transformation intensity level.
enum class MBAIntensity {
    Low = 1,    // Simple substitutions
    Medium = 2, // Multiple nested substitutions
    High = 3,   // Complex nested substitutions with verification
};

// Result of MBA transformation.
struct MBAResult {
    std::vector<uint8_t> transformed_data;
    uint32_t transformations_applied = 0;
    MBAIntensity intensity = MBAIntensity::Low;
    bool semantically_equivalent = true; // must always be true
    Error error;
};

// Apply Mixed Boolean Arithmetic transformations to eligible code regions.
// All transformations are semantically equivalent and validated for
// correctness. MBA is an optional optimization pass, not a security boundary.
Error apply_mba(std::string_view input,
                MBAIntensity intensity,
                MBAResult& out);

} // namespace mba
} // namespace nexaprotect
} // namespace nexapack

#endif // NEXAPACK_PROTECTION_MBA_MBA_HPP

