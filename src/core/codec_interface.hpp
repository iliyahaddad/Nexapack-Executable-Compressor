#ifndef NEXAPACK_CORE_CODEC_INTERFACE_HPP
#define NEXAPACK_CORE_CODEC_INTERFACE_HPP

#include "core/error.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace nexapack {

// Compression profile selected by the adaptive planner / user.
enum class CompressionProfile : uint32_t {
    Fast = 1,
    Balanced = 2,
    Maximum = 3,
    Auto = 4,
    Custom = 5,
};

// Capabilities reported by a codec.
struct CodecCapabilities {
    bool supports_compression = false;
    bool supports_decompression = false;
    uint64_t min_decoder_memory_bytes = 0;
    uint64_t recommended_decoder_memory_bytes = 0;
    uint64_t dictionary_size_bytes = 0;
    uint32_t min_level = 1;
    uint32_t max_level = 22;
};

// Result of an encode operation.
struct EncodeResult {
    std::vector<uint8_t> compressed;
    uint64_t original_size = 0;
    uint64_t compressed_size = 0;
    uint64_t encode_time_us = 0;
    Error error;
};

// Result of a decode operation.
struct DecodeResult {
    std::vector<uint8_t> decompressed;
    uint64_t decompressed_size = 0;
    uint64_t decode_time_us = 0;
    Error error;
};

// Every NexaPack codec implements this interface. The matching Runtime decoder
// must exist independently and pass round-trip, corruption, truncation, and
// boundary tests. A codec that only wraps another codec is forbidden.
class Codec {
public:
    virtual ~Codec() = default;

    // Unique codec identifier (e.g. "store", "zstd", "lz4").
    [[nodiscard]] virtual std::string_view id() const noexcept = 0;

    // Human-readable name and version of the actual implementation.
    [[nodiscard]] virtual std::string name() const noexcept = 0;
    [[nodiscard]] virtual std::string version() const noexcept = 0;

    [[nodiscard]] virtual CodecCapabilities capabilities() const noexcept = 0;

    // Estimate the compressed output size for an input of the given size.
    [[nodiscard]] virtual uint64_t estimate_compressed_size(uint64_t input_size) const noexcept = 0;

// Compress input -> output. Returns an error on failure.
    [[nodiscard]] virtual EncodeResult compress(std::string_view input,
                                                CompressionProfile profile,
                                                uint32_t level) const = 0;

    // Decompress input -> output. Returns an error on failure or truncated data.
    [[nodiscard]] virtual DecodeResult decompress(std::string_view input,
                                                  uint64_t expected_output_size) const = 0;

    // Validate that a compressed buffer is well-formed (header + framing).
    [[nodiscard]] virtual bool validate(std::string_view input) const noexcept = 0;
};

using CodecPtr = std::unique_ptr<Codec>;

} // namespace nexapack

#endif // NEXAPACK_CORE_CODEC_INTERFACE_HPP

