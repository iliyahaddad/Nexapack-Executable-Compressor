#ifndef NEXAPACK_CORE_PLANNER_PLANNER_HPP
#define NEXAPACK_CORE_PLANNER_PLANNER_HPP

#include "core/codec_interface.hpp"
#include "codecs/codec_registry.hpp"
#include "core/error.hpp"
#include "core/metadata.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace nexapack {
namespace planner {

// Result of planning: the selected codec, profile, level, and estimated sizes.
struct PlanResult {
    CodecId codec_id = CodecId::Store;
    CompressionProfile profile = CompressionProfile::Balanced;
    uint32_t level = 1;
    uint64_t compressed_payload_size = 0;
    uint64_t stub_size = 0;
    uint64_t metadata_size = 0;
    uint64_t final_size = 0;
    std::string reason;
};

// A single candidate evaluated by the planner.
struct Candidate {
    CodecId codec_id;
    CompressionProfile profile;
    uint32_t level;
    uint64_t compressed_size;
    uint64_t final_size;
    bool valid;
    std::string note;
};

// Context passed to the planner describing the input executable.
struct PackContext {
    std::string input_path;
    std::string_view input_data;   // raw input bytes for compression
    CompressionProfile profile = CompressionProfile::Balanced;
    uint32_t custom_level = 0; // used when profile == Custom
    TargetFormat target_format = TargetFormat::Unknown;
    Architecture architecture = Architecture::Unknown;
    uint64_t input_size = 0;
    uint64_t stub_size = 0;   // size of the selected runtime stub
    uint64_t metadata_size = 0; // size of the metadata block
    uint32_t section_alignment = 1;
    bool is_dll = false;
    bool has_relocations = false;
    bool has_tls = false;
    bool has_exception_data = false;
};

// CompressionPlanner: selects the codec/profile/level that minimizes the
// final packed executable size while respecting runtime constraints.
//
// FINAL_SIZE = COMPRESSED_PAYLOAD + RUNTIME_STUB + DECOMPRESSOR +
//              METADATA + ALIGNMENT + PROTECTION_OVERHEAD
//
// The planner does NOT minimize compressed payload alone; it minimizes the
// complete packed executable. Different codecs may have different stub sizes,
// so a codec with slightly larger compression but much smaller stub may win.
class CompressionPlanner {
public:
    CompressionPlanner() = default;
    virtual ~CompressionPlanner() = default;

    // Plan the best compression for the given context using the specified
    // profile and the available codecs from the registry.
    Error plan(const PackContext& ctx,
               const CodecRegistry& registry,
               PlanResult& out);

    // Evaluate a single codec at a given level and return the candidate.
    Error evaluate(CodecId codec_id, CompressionProfile profile,
                   uint32_t level, std::string_view input,
                   const PackContext& ctx,
                   const CodecRegistry& registry,
                   Candidate& out);

    // Compute the final packed size from compressed payload + overhead.
    static uint64_t final_size(uint64_t compressed_payload,
                               const PackContext& ctx) {
        uint64_t size = compressed_payload + ctx.stub_size + ctx.metadata_size;
        // Align to section alignment
        if (ctx.section_alignment > 1) {
            size = (size + ctx.section_alignment - 1) / ctx.section_alignment *
                   ctx.section_alignment;
        }
        return size;
    }
};

} // namespace planner
} // namespace nexapack

#endif // NEXAPACK_CORE_PLANNER_PLANNER_HPP
