#ifndef NEXAPACK_CODECS_APULTRA_APULTRA_CODEC_HPP
#define NEXAPACK_CODECS_APULTRA_APULTRA_CODEC_HPP

#include "core/codec_interface.hpp"

namespace nexapack {

// Apultra codec wrapping the Apultra library (Emmanuel Marty).
// Real encoder + real decoder using apultra_compress / apultra_decompress.
// Not an alias for any other codec.
class ApultraCodec : public Codec {
public:
    ApultraCodec() = default;

    [[nodiscard]] std::string_view id() const noexcept override { return "apultra"; }
    [[nodiscard]] std::string name() const noexcept override { return "Apultra"; }
    [[nodiscard]] std::string version() const noexcept override { return "Apultra (zX0-based)"; }

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

#endif // NEXAPACK_CODECS_APULTRA_APULTRA_CODEC_HPP
