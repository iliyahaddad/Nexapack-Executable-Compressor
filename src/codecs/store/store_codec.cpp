#include "codecs/store/store_codec.hpp"
#include "core/logging.hpp"

#include <chrono>
#include <cstring>

namespace nexapack {

CodecCapabilities StoreCodec::capabilities() const noexcept {
    CodecCapabilities cap;
    cap.supports_compression = true;
    cap.supports_decompression = true;
    cap.min_decoder_memory_bytes = 0;
    cap.recommended_decoder_memory_bytes = 0;
    cap.dictionary_size_bytes = 0;
    cap.min_level = 1;
    cap.max_level = 1;
    return cap;
}

uint64_t StoreCodec::estimate_compressed_size(uint64_t input_size) const noexcept {
    return input_size; // no compression, no overhead
}

EncodeResult StoreCodec::compress(std::string_view input, CompressionProfile, uint32_t) const {
    EncodeResult result;
    auto start = std::chrono::high_resolution_clock::now();

    result.compressed.assign(input.begin(), input.end());
    result.original_size = input.size();
    result.compressed_size = input.size();

    auto end = std::chrono::high_resolution_clock::now();
    result.encode_time_us =
        std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    nexapack::nxp_log(nexapack::LogLevel::Debug, "store: compressed " + std::to_string(input.size()) + " bytes (pass-through)");
    return result;
}

DecodeResult StoreCodec::decompress(std::string_view input, uint64_t expected_output_size) const {
    DecodeResult result;
    auto start = std::chrono::high_resolution_clock::now();

    if (input.size() != expected_output_size && expected_output_size != 0) {
        result.error = make_error(ErrorCategory::Codec, 1,
                                  "store: size mismatch expected=" +
                                      std::to_string(expected_output_size) +
                                      " got=" + std::to_string(input.size()));
        return result;
    }

    result.decompressed.assign(input.begin(), input.end());
    result.decompressed_size = input.size();

    auto end = std::chrono::high_resolution_clock::now();
    result.decode_time_us =
        std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    nexapack::nxp_log(nexapack::LogLevel::Debug, "store: decompressed " + std::to_string(input.size()) + " bytes (pass-through)");
    return result;
}

bool StoreCodec::validate(std::string_view /*input*/) const noexcept {
    return true; // store is always valid
}

} // namespace nexapack


