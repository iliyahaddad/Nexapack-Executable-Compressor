#include "codecs/lz4/lz4_codec.hpp"
#include "core/error.hpp"
#include "core/logging.hpp"

#include <chrono>
#include <cstring>

namespace nexapack {

CodecCapabilities Lz4Codec::capabilities() const noexcept {
    CodecCapabilities cap;
    cap.supports_compression = true;
    cap.supports_decompression = true;
    cap.min_decoder_memory_bytes = 64 * 1024;
    cap.recommended_decoder_memory_bytes = 4 * 1024 * 1024;
    cap.dictionary_size_bytes = 0;
    cap.min_level = 1;
    cap.max_level = 16; // LZ4 HC acceleration levels map roughly 1..16
    return cap;
}

uint64_t Lz4Codec::estimate_compressed_size(uint64_t input_size) const noexcept {
    return static_cast<uint64_t>(LZ4_compressBound(static_cast<int>(input_size)));
}

EncodeResult Lz4Codec::compress(std::string_view input, CompressionProfile /*profile*/, uint32_t level) const {
    EncodeResult result;
    auto start = std::chrono::high_resolution_clock::now();

    if (level < 1) level = 1;
    if (level > 16) level = 16;

    int max_size = LZ4_compressBound(static_cast<int>(input.size()));
    result.compressed.resize(static_cast<size_t>(max_size));

    int rc = LZ4_compress_default(input.data(),
                                  reinterpret_cast<char*>(result.compressed.data()),
                                  static_cast<int>(input.size()),
                                  static_cast<int>(result.compressed.size()));
    if (rc <= 0) {
        auto end = std::chrono::high_resolution_clock::now();
        result.encode_time_us =
            std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        result.error = make_error(ErrorCategory::Codec, 1, "lz4 compress failed");
        return result;
    }

    result.compressed.resize(static_cast<size_t>(rc));
    result.original_size = input.size();
    result.compressed_size = static_cast<uint64_t>(rc);

    auto end = std::chrono::high_resolution_clock::now();
    result.encode_time_us =
        std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    nexapack::nxp_log(nexapack::LogLevel::Debug, "lz4: level " + std::to_string(level) + " compressed " +
                       std::to_string(input.size()) + " -> " + std::to_string(rc) + " bytes");
    return result;
}

DecodeResult Lz4Codec::decompress(std::string_view input, uint64_t expected_output_size) const {
    DecodeResult result;
    auto start = std::chrono::high_resolution_clock::now();

    uint64_t out_size = (expected_output_size != 0) ? expected_output_size
                                                    : static_cast<uint64_t>(input.size() * 4);
    result.decompressed.resize(out_size);

    int rc = LZ4_decompress_safe(input.data(),
                                 reinterpret_cast<char*>(result.decompressed.data()),
                                 static_cast<int>(input.size()),
                                 static_cast<int>(result.decompressed.size()));
    if (rc < 0) {
        auto end = std::chrono::high_resolution_clock::now();
        result.decode_time_us =
            std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        result.error = make_error(ErrorCategory::Codec, 2,
                                  "lz4 decompress failed: error code " + std::to_string(rc));
        return result;
    }

    result.decompressed.resize(static_cast<size_t>(rc));
    result.decompressed_size = static_cast<uint64_t>(rc);

    auto end = std::chrono::high_resolution_clock::now();
    result.decode_time_us =
        std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    nexapack::nxp_log(nexapack::LogLevel::Debug, "lz4: decompressed " + std::to_string(input.size()) + " -> " +
                       std::to_string(rc) + " bytes");
    return result;
}

bool Lz4Codec::validate(std::string_view input) const noexcept {
    // LZ4 block frames have no magic; validate by attempting a size query.
    // LZ4_decompress_safe requires a known output size, so a non-empty input
    // is treated as potentially valid; the decoder is the real validator.
    return !input.empty();
}

} // namespace nexapack


