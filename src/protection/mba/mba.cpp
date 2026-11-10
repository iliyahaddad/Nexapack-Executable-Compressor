#include "protection/mba/mba.hpp"
#include "core/error.hpp"
#include "core/logging.hpp"

#include <algorithm>
#include <cstring>

namespace nexapack {
namespace nexaprotect {
namespace mba {

Error apply_mba(std::string_view input,
                MBAIntensity intensity,
                MBAResult& out) {
    out = MBAResult{};
    out.intensity = intensity;
    out.semantically_equivalent = true;

    if (input.empty()) {
        return make_error(ErrorCategory::InvalidArgument, 1,
                          "empty input buffer");
    }

    const uint8_t* data = reinterpret_cast<const uint8_t*>(input.data());
    size_t size = input.size();

    if (size < 64 || data[0] != 'M' || data[1] != 'Z') {
        out.transformed_data.assign(input.begin(), input.end());
        return ok_error();
    }

    uint32_t e_lfanew = 0;
    std::memcpy(&e_lfanew, data + 60, 4);
    if (e_lfanew > size - 4 ||
        std::memcmp(data + e_lfanew, "PE\0\0", 4) != 0) {
        out.transformed_data.assign(input.begin(), input.end());
        return ok_error();
    }

    out.transformed_data.assign(input.begin(), input.end());

    // Safe default for Phase 8: MBA transformations are marked as available
    // but not actually applied. Incorrect MBA can change program semantics.
    // Semantic equivalence validation is required before any transformation
    // is applied to real code.
    nexapack::nxp_log(nexapack::LogLevel::Debug, "mba: intensity applied (no-op transformation in Phase 8)");

    return ok_error();
}

} // namespace mba
} // namespace nexaprotect
} // namespace nexapack


