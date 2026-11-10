#include "codecs/apultra/apultra_codec.hpp"
#include "core/error.hpp"
#include "core/logging.hpp"

#include <chrono>
#include <cstring>

#include "shrink.h"
#include "expand.h"

namespace nexapack {

CodecCapabilities ApultraCodec::capabilities() const noexcept {
    CodecCapabilities cap;
    cap.supports_compression = true;
    cap.supports_decompression = true;
    cap.min_decoder_memory_bytes = 64 * 1024;
    cap.recommended_decoder_memory_bytes = 16 * 1024 * 1024;
    cap.dictionary_size_bytes = 1 << 20;
    cap.min_level = 1;
    cap.max_level = 9;
    return cap;
}

uint64_t ApultraCodec::estimate_compressed_size(uint64_t input_size) const noexcept {
    return input_size + input_size / 100 + 64;
}

EncodeResult ApultraCodec::compress(std::string_view input, CompressionProfile profile,
                                    uint32_t level) const {
    EncodeResult result;
    auto start = std::chrono::high_resolution_clock::now();

    if (level > 9) level = 9;
    if (level < 1) level = 1;

    size_t max_out = apultra_get_max_compressed_size(input.size());
    std::vector<uint8_t> out_buf(max_out);

    size_t out_size = apultra_compress(reinterpret_cast<const unsigned char*>(input.data()),
                                       out_buf.data(),
                                       input.size(),
                                       max_out,
                                       0,
                                       0,
                                       0,
                                       nullptr,
                                       nullptr);

    if (out_size == static_cast<size_t>(-1)) {
        auto end = std::chrono::high_resolution_clock::now();
        result.encode_time_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        result.error = make_error(ErrorCategory::Codec, 1, "apultra: compress failed");
        return result;
    }

    result.compressed.assign(out_buf.begin(), out_buf.begin() + out_size);
    result.original_size = input.size();
    result.compressed_size = result.compressed.size();

    auto end = std::chrono::high_resolution_clock::now();
    result.encode_time_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    nexapack::nxp_log(nexapack::LogLevel::Debug, "apultra: level " + std::to_string(level) + " compressed " +
                   std::to_string(input.size()) + " -> " + std::to_string(result.compressed_size) + " bytes");
    return result;
}

DecodeResult ApultraCodec::decompress(std::string_view input, uint64_t expected_output_size) const {
    DecodeResult result;
    auto start = std::chrono::high_resolution_clock::now();

    if (input.size() == 0) {
        auto end = std::chrono::high_resolution_clock::now();
        result.decode_time_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        result.error = make_error(ErrorCategory::Codec, 1, "apultra: input too small");
        return result;
    }

    size_t max_out = apultra_get_max_decompressed_size(reinterpret_cast<const unsigned char*>(input.data()),
                                                       input.size(),
                                                       0);
    if (max_out == static_cast<size_t>(-1)) {
        auto end = std::chrono::high_resolution_clock::now();
        result.decode_time_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        result.error = make_error(ErrorCategory::Codec, 2, "apultra: cannot determine decompressed size");
        return result;
    }

    size_t out_buf_size = static_cast<size_t>(expected_output_size > max_out ? expected_output_size : max_out);
    std::vector<uint8_t> out_buf(out_buf_size);

    size_t out_size = apultra_decompress(reinterpret_cast<const unsigned char*>(input.data()),
                                         out_buf.data(),
                                         input.size(),
                                         out_buf_size,
                                         0,
                                         0);

    if (out_size == static_cast<size_t>(-1)) {
        auto end = std::chrono::high_resolution_clock::now();
        result.decode_time_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        result.error = make_error(ErrorCategory::Codec, 3, "apultra: decompress failed");
        return result;
    }

    result.decompressed.assign(out_buf.begin(), out_buf.begin() + out_size);
    result.decompressed_size = out_size;

    auto end = std::chrono::high_resolution_clock::now();
    result.decode_time_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    nexapack::nxp_log(nexapack::LogLevel::Debug, "apultra: decompressed " + std::to_string(input.size()) + " -> " +
                   std::to_string(out_size) + " bytes");
    return result;
}

bool ApultraCodec::validate(std::string_view input) const noexcept {
    if (input.size() == 0) return false;
    size_t max_out = apultra_get_max_decompressed_size(reinterpret_cast<const unsigned char*>(input.data()),
                                                       input.size(),
                                                       0);
    return max_out != static_cast<size_t>(-1);
}

} // namespace nexapack
