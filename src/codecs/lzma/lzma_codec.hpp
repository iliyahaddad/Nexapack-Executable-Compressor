#ifndef NEXAPACK_CODECS_LZMA_LZMA_CODEC_HPP
#define NEXAPACK_CODECS_LZMA_LZMA_CODEC_HPP

#include "core/codec_interface.hpp"

namespace nexapack {

// LZMA codec wrapping the official 7-Zip LZMA SDK (lzma2605).
// Real encoder + real decoder using LzmaEnc / LzmaDec API.
// Not an alias for any other codec.
class LzmaCodec : public Codec {
public:
    LzmaCodec() = default;

    [[nodiscard]] std::string_view id() const noexcept override { return "lzma"; }
    [[nodiscard]] std::string name() const noexcept override { return "LZMA"; }
    [[nodiscard]] std::string version() const noexcept override { return "LZMA SDK 16.06 (2605)"; }

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

#endif // NEXAPACK_CODECS_LZMA_LZMA_CODEC_HPP
