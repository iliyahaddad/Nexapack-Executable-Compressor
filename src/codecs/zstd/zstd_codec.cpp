#include "codecs/zstd/zstd_codec.hpp"
#include "core/error.hpp"
#include "core/logging.hpp"

#include <chrono>
#include <cstring>

namespace nexapack {

CodecCapabilities ZstdCodec::capabilities() const noexcept {
    CodecCapabilities cap;
    cap.supports_compression = true;
    cap.supports_decompression = true;
    cap.min_decoder_memory_bytes = 128 * 1024;
    cap.recommended_decoder_memory_bytes = 8 * 1024 * 1024;
    cap.dictionary_size_bytes = 0;
    cap.min_level = 1;
    cap.max_level = ZSTD_maxCLevel();
    return cap;
}

uint64_t ZstdCodec::estimate_compressed_size(uint64_t input_size) const noexcept {
    return ZSTD_compressBound(input_size);
}

EncodeResult ZstdCodec::compress(std::string_view input, CompressionProfile profile, uint32_t level) const {
    EncodeResult result;
    auto start = std::chrono::high_resolution_clock::now();

    if (level < 1) level = 1;
    if (static_cast<int>(level) > ZSTD_maxCLevel()) level = ZSTD_maxCLevel();

    size_t bound = ZSTD_compressBound(input.size());
    result.compressed.resize(bound);

    size_t rc = ZSTD_compress(result.compressed.data(), bound,
                              input.data(), input.size(), level);
    if (ZSTD_isError(rc)) {
        auto end = std::chrono::high_resolution_clock::now();
        result.encode_time_us =
            std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        result.error = make_error(ErrorCategory::Codec, 1,
                                  "zstd compress failed: " +
                                      std::string(ZSTD_getErrorName(rc)));
        return result;
    }

    result.compressed.resize(rc);
    result.original_size = input.size();
    result.compressed_size = rc;

    auto end = std::chrono::high_resolution_clock::now();
    result.encode_time_us =
        std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    nexapack::nxp_log(nexapack::LogLevel::Debug, "zstd: level " + std::to_string(level) + " compressed " +
                       std::to_string(input.size()) + " -> " + std::to_string(rc) + " bytes");
    return result;
}

DecodeResult ZstdCodec::decompress(std::string_view input, uint64_t expected_output_size) const {
    DecodeResult result;
    auto start = std::chrono::high_resolution_clock::now();

    // Determine the decompressed size from the frame header.
    long long content_size = ZSTD_getFrameContentSize(input.data(), input.size());
    if (content_size < 0) {
        auto end = std::chrono::high_resolution_clock::now();
        result.decode_time_us =
            std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        result.error = make_error(ErrorCategory::Codec, 2,
                                  "zstd: unable to determine frame content size");
        return result;
    }

    uint64_t out_size = (expected_output_size != 0) ? expected_output_size
                                                    : static_cast<uint64_t>(content_size);
    result.decompressed.resize(out_size);

    size_t rc = ZSTD_decompress(result.decompressed.data(), out_size,
                                input.data(), input.size());
    if (ZSTD_isError(rc)) {
        auto end = std::chrono::high_resolution_clock::now();
        result.decode_time_us =
            std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        result.error = make_error(ErrorCategory::Codec, 3,
                                  "zstd decompress failed: " +
                                      std::string(ZSTD_getErrorName(rc)));
        return result;
    }

    result.decompressed.resize(rc);
    result.decompressed_size = rc;

    auto end = std::chrono::high_resolution_clock::now();
    result.decode_time_us =
        std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    nexapack::nxp_log(nexapack::LogLevel::Debug, "zstd: decompressed " + std::to_string(input.size()) + " -> " +
                       std::to_string(rc) + " bytes");
    return result;
}

bool ZstdCodec::validate(std::string_view input) const noexcept {
    return ZSTD_getFrameContentSize(input.data(), input.size()) >= 0;
}

} // namespace nexapack


