#ifndef NEXAPACK_CODECS_LZ4_LZ4_CODEC_HPP
#define NEXAPACK_CODECS_LZ4_LZ4_CODEC_HPP

#include "core/codec_interface.hpp"

#include <lz4.h>

namespace nexapack {

// LZ4 codec wrapping the official lz4-dev implementation.
// Real encoder + real decoder using the LZ4 block API (LZ4_compress_default /
// LZ4_decompress_safe). Not an alias for any other codec.
class Lz4Codec : public Codec {
public:
    Lz4Codec() = default;

    [[nodiscard]] std::string_view id() const noexcept override { return "lz4"; }
    [[nodiscard]] std::string name() const noexcept override { return "LZ4"; }
    [[nodiscard]] std::string version() const noexcept override { return LZ4_VERSION_STRING; }

    [[nodiscard]] CodecCapabilities capabilities() const noexcept override;

    [[nodiscard]] uint64_t estimate_compressed_size(uint64_t input_size) const noexcept override;

    [[nodiscard]] EncodeResult compress(std::string_view input,
                                        CompressionProfile profile,
                                        uint32_t level) const override;

    [[nodiscard]] DecodeResult decompress(std::string_view input,
                                          uint64_t expected_output_size) const override;

    [[nodiscard]] bool validate(std::string_view input) const noexcept override;
};

} // namespace nexapack

#endif // NEXAPACK_CODECS_LZ4_LZ4_CODEC_HPP

