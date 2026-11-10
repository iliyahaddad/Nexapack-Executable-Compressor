#ifndef NEXAPACK_CODECS_ZSTD_ZSTD_CODEC_HPP
#define NEXAPACK_CODECS_ZSTD_ZSTD_CODEC_HPP

#include "core/codec_interface.hpp"

#include <zstd.h>

namespace nexapack {

// Zstandard codec wrapping the official zstd-dev implementation.
// Real encoder + real decoder. Not an alias for any other codec.
class ZstdCodec : public Codec {
public:
    ZstdCodec() = default;

    [[nodiscard]] std::string_view id() const noexcept override { return "zstd"; }
    [[nodiscard]] std::string name() const noexcept override { return "Zstandard"; }
    [[nodiscard]] std::string version() const noexcept override { return ZSTD_VERSION_STRING; }

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

#endif // NEXAPACK_CODECS_ZSTD_ZSTD_CODEC_HPP

