#include "codecs/lzma/lzma_codec.hpp"
#include "core/error.hpp"
#include "core/logging.hpp"

#include <chrono>
#include <cstdlib>
#include <cstring>

#include "7zTypes.h"
#include "LzmaDec.h"
#include "LzmaEnc.h"

namespace nexapack {

// Simple malloc/free allocator for LZMA SDK (no VirtualAlloc dependency).
static void* SzAlloc(ISzAllocPtr p, size_t size) { return std::malloc(size); }
static void SzFree(ISzAllocPtr p, void* address) { std::free(address); }
static const ISzAlloc g_Alloc = { SzAlloc, SzFree };

CodecCapabilities LzmaCodec::capabilities() const noexcept {
    CodecCapabilities cap;
    cap.supports_compression = true;
    cap.supports_decompression = true;
    cap.min_decoder_memory_bytes = 16 * 1024;
    cap.recommended_decoder_memory_bytes = 16 * 1024 * 1024;
    cap.dictionary_size_bytes = 8 * 1024 * 1024;
    cap.min_level = 0;
    cap.max_level = 9;
    return cap;
}

uint64_t LzmaCodec::estimate_compressed_size(uint64_t input_size) const noexcept {
    return input_size + input_size / 100 + 64;
}

EncodeResult LzmaCodec::compress(std::string_view input, CompressionProfile profile,
                                 uint32_t level) const {
    EncodeResult result;
    auto start = std::chrono::high_resolution_clock::now();

    if (level > 9) level = 9;
    if (level < 0) level = 0;

    CLzmaEncHandle enc = LzmaEnc_Create(&g_Alloc);
    if (!enc) {
        auto end = std::chrono::high_resolution_clock::now();
        result.encode_time_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        result.error = make_error(ErrorCategory::Codec, 1, "lzma: encoder create failed");
        return result;
    }

    CLzmaEncProps props;
    LzmaEncProps_Init(&props);
    props.level = static_cast<Int32>(level);
    props.dictSize = 1 << 23;
    props.mc = 32;
    props.writeEndMark = 0;

    SRes res = LzmaEnc_SetProps(enc, &props);
    if (res != SZ_OK) {
        LzmaEnc_Destroy(enc, &g_Alloc, &g_Alloc);
        auto end = std::chrono::high_resolution_clock::now();
        result.encode_time_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        result.error = make_error(ErrorCategory::Codec, 2, "lzma: set props failed");
        return result;
    }

    Byte props_buf[LZMA_PROPS_SIZE];
    SizeT props_size = LZMA_PROPS_SIZE;
    res = LzmaEnc_WriteProperties(enc, props_buf, &props_size);
    if (res != SZ_OK) {
        LzmaEnc_Destroy(enc, &g_Alloc, &g_Alloc);
        auto end = std::chrono::high_resolution_clock::now();
        result.encode_time_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        result.error = make_error(ErrorCategory::Codec, 3, "lzma: write props failed");
        return result;
    }

    result.compressed.insert(result.compressed.end(), props_buf, props_buf + props_size);

    SizeT out_buf_size = static_cast<SizeT>(input.size() + input.size() / 100 + 64 + 16);
    std::vector<uint8_t> out_buf(out_buf_size);
    SizeT out_size = out_buf_size;

    res = LzmaEnc_MemEncode(enc, out_buf.data(), &out_size,
                            reinterpret_cast<const Byte*>(input.data()),
                            static_cast<SizeT>(input.size()),
                            0, nullptr, &g_Alloc, &g_Alloc);
    if (res != SZ_OK) {
        LzmaEnc_Destroy(enc, &g_Alloc, &g_Alloc);
        auto end = std::chrono::high_resolution_clock::now();
        result.encode_time_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        result.error = make_error(ErrorCategory::Codec, 4, "lzma: encode failed");
        return result;
    }

    result.compressed.insert(result.compressed.end(), out_buf.begin(), out_buf.begin() + out_size);
    result.original_size = input.size();
    result.compressed_size = result.compressed.size();

    LzmaEnc_Destroy(enc, &g_Alloc, &g_Alloc);

    auto end = std::chrono::high_resolution_clock::now();
    result.encode_time_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    nexapack::nxp_log(nexapack::LogLevel::Debug, "lzma: level " + std::to_string(level) + " compressed " +
                   std::to_string(input.size()) + " -> " + std::to_string(result.compressed_size) + " bytes");
    return result;
}

DecodeResult LzmaCodec::decompress(std::string_view input, uint64_t expected_output_size) const {
    DecodeResult result;
    auto start = std::chrono::high_resolution_clock::now();

    if (input.size() < LZMA_PROPS_SIZE) {
        auto end = std::chrono::high_resolution_clock::now();
        result.decode_time_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        result.error = make_error(ErrorCategory::Codec, 1, "lzma: input too small for properties");
        return result;
    }

    CLzmaProps props;
    SRes res = LzmaProps_Decode(&props,
                                reinterpret_cast<const Byte*>(input.data()),
                                LZMA_PROPS_SIZE);
    if (res != SZ_OK) {
        auto end = std::chrono::high_resolution_clock::now();
        result.decode_time_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        result.error = make_error(ErrorCategory::Codec, 2, "lzma: decode props failed");
        return result;
    }

    CLzmaDec dec;
    LzmaDec_Construct(&dec);
    res = LzmaDec_Allocate(&dec, reinterpret_cast<const Byte*>(input.data()),
                           LZMA_PROPS_SIZE, &g_Alloc);
    if (res != SZ_OK) {
        auto end = std::chrono::high_resolution_clock::now();
        result.decode_time_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        result.error = make_error(ErrorCategory::Codec, 3, "lzma: decoder allocate failed");
        return result;
    }

    LzmaDec_Init(&dec);

    SizeT out_size = static_cast<SizeT>(expected_output_size);
    std::vector<uint8_t> out_buf(out_size);

    const Byte* src = reinterpret_cast<const Byte*>(input.data()) + LZMA_PROPS_SIZE;
    SizeT src_size = static_cast<SizeT>(input.size()) - LZMA_PROPS_SIZE;

    ELzmaStatus status;
    res = LzmaDec_DecodeToBuf(&dec,
                              out_buf.data(), &out_size,
                              src, &src_size,
                              LZMA_FINISH_ANY, &status);

    bool ok = (res == SZ_OK);
    if (!ok) {
        LzmaDec_Free(&dec, &g_Alloc);
        auto end = std::chrono::high_resolution_clock::now();
        result.decode_time_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        result.error = make_error(ErrorCategory::Codec, 4, "lzma: decompress failed");
        return result;
    }

    LzmaDec_Free(&dec, &g_Alloc);

    result.decompressed.assign(out_buf.begin(), out_buf.begin() + out_size);
    result.decompressed_size = out_size;

    auto end = std::chrono::high_resolution_clock::now();
    result.decode_time_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    nexapack::nxp_log(nexapack::LogLevel::Debug, "lzma: decompressed " + std::to_string(input.size()) + " -> " +
                   std::to_string(out_size) + " bytes");
    return result;
}

bool LzmaCodec::validate(std::string_view input) const noexcept {
    if (input.size() < LZMA_PROPS_SIZE) return false;
    CLzmaProps props;
    return LzmaProps_Decode(&props,
                            reinterpret_cast<const Byte*>(input.data()),
                            LZMA_PROPS_SIZE) == SZ_OK;
}

} // namespace nexapack
