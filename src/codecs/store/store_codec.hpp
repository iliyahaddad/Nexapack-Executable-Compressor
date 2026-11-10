#ifndef NEXAPACK_CODECS_STORE_STORE_CODEC_HPP
#define NEXAPACK_CODECS_STORE_STORE_CODEC_HPP

#include "core/codec_interface.hpp"

namespace nexapack {

// Store codec: no compression. Pass-through with framing overhead zero.
// Always available, always round-trips byte-for-byte. Serves as the mandatory
// no-compression fallback and as a sanity reference for the adaptive planner.
class StoreCodec : public Codec {
public:
    StoreCodec() = default;

    [[nodiscard]] std::string_view id() const noexcept override { return "store"; }
    [[nodiscard]] std::string name() const noexcept override { return "Store"; }
    [[nodiscard]] std::string version() const noexcept override { return "1.0.0"; }

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

#endif // NEXAPACK_CODECS_STORE_STORE_CODEC_HPP

