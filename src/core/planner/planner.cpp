#include "core/planner/planner.hpp"
#include "core/codec_interface.hpp"
#include "core/error.hpp"
#include "core/logging.hpp"

#include <algorithm>
#include <string>

namespace nexapack {
namespace planner {

namespace {

constexpr uint32_t kMaxCandidates = 8;

const char* codec_id_to_name(CodecId id) {
    switch (id) {
        case CodecId::Store: return "store";
        case CodecId::ZSTD: return "zstd";
        case CodecId::LZ4: return "lz4";
        case CodecId::LZMA: return "lzma";
        default: return "unknown";
    }
}

CodecId codec_id_from_name(std::string_view name) {
    if (name == "store") return CodecId::Store;
    if (name == "zstd") return CodecId::ZSTD;
    if (name == "lz4") return CodecId::LZ4;
    if (name == "lzma") return CodecId::LZMA;
    return CodecId::Unknown;
}

} // namespace

Error CompressionPlanner::evaluate(CodecId codec_id, CompressionProfile profile,
                                   uint32_t level, std::string_view input,
                                   const PackContext& /*ctx*/,
                                   const CodecRegistry& registry,
                                   Candidate& out) {
    out = Candidate{};
    out.codec_id = codec_id;
    out.profile = profile;
    out.level = level;

    Codec* codec = registry.find(codec_id_to_name(codec_id));
    if (!codec) {
        out.valid = false;
        out.note = "codec not found in registry";
        return ok_error();
    }

    CodecCapabilities cap = codec->capabilities();
    if (!cap.supports_compression || !cap.supports_decompression) {
        out.valid = false;
        out.note = "codec lacks compression or decompression";
        return ok_error();
    }
    if (level < cap.min_level || level > cap.max_level) {
        out.valid = false;
        out.note = "level out of codec range";
        return ok_error();
    }

    // Actually compress to get real compressed size (not just estimate).
    EncodeResult enc = codec->compress(input, profile, level);
    if (!enc.error.ok()) {
        out.valid = false;
        out.note = "compression failed: " + enc.error.message();
        return ok_error();
    }

    // Verify round-trip decompression.
    DecodeResult dec = codec->decompress(
        std::string_view(reinterpret_cast<const char*>(enc.compressed.data()),
                         enc.compressed.size()),
        input.size());
    if (!dec.error.ok() || dec.decompressed_size != input.size()) {
        out.valid = false;
        out.note = "round-trip verification failed";
        return ok_error();
    }

    out.compressed_size = enc.compressed_size;
    out.valid = true;
    out.note = "real";
    return ok_error();
}

Error CompressionPlanner::plan(const PackContext& ctx,
                               const CodecRegistry& registry,
                               PlanResult& out) {
    out = PlanResult{};

    if (ctx.input_data.empty()) {
        return make_error(ErrorCategory::Codec, 1,
                          "no input data provided to planner");
    }

    // Collect all real compress+decompress codecs from registry.
    std::vector<CodecId> candidate_codecs;
    for (size_t i = 0; i < registry.count(); ++i) {
        const Codec* c = registry.at(i);
        CodecCapabilities cap = c->capabilities();
        if (cap.supports_compression && cap.supports_decompression) {
            candidate_codecs.push_back(codec_id_from_name(c->id()));
        }
    }

    if (candidate_codecs.empty()) {
        return make_error(ErrorCategory::Codec, 2,
                          "no compressible codecs available in registry");
    }

    // Build per-codec level lists respecting each codec's max level.
    auto levels_for_codec = [&](CodecId cid) -> std::vector<uint32_t> {
        Codec* codec = registry.find(codec_id_to_name(cid));
        if (!codec) return {1u};
        CodecCapabilities cap = codec->capabilities();
        uint32_t max_lvl = cap.max_level;
        std::vector<uint32_t> lvls;
        switch (ctx.profile) {
            case CompressionProfile::Fast:
                lvls = { std::min(1u, max_lvl) };
                break;
            case CompressionProfile::Balanced:
                for (uint32_t l : {3u, 6u}) {
                    if (l <= max_lvl) lvls.push_back(l);
                }
                if (lvls.empty()) lvls.push_back(std::min(1u, max_lvl));
                break;
            case CompressionProfile::Maximum:
                for (uint32_t l : {1u, 3u, 6u, 9u, 12u}) {
                    if (l <= max_lvl) lvls.push_back(l);
                }
                if (lvls.empty()) lvls.push_back(std::min(1u, max_lvl));
                break;
            case CompressionProfile::Auto: {
                // Adaptive: small files favor LZ4/Store, large compressible favor ZSTD/LZMA.
                bool small_file = ctx.input_size <= 64 * 1024;
                for (uint32_t l : {1u, 3u, 6u, 9u}) {
                    if (l <= max_lvl) lvls.push_back(l);
                }
                if (small_file && cid == CodecId::LZMA) {
                    // LZMA rarely wins on small files; skip it in Auto.
                    lvls.clear();
                }
                if (lvls.empty()) lvls.push_back(std::min(1u, max_lvl));
                break;
            }
            case CompressionProfile::Custom:
                lvls = { ctx.custom_level != 0 ? ctx.custom_level : 6u };
                if (lvls[0] > max_lvl) lvls[0] = max_lvl;
                break;
        }
        return lvls;
    };

    std::vector<Candidate> screened;
    screened.reserve(candidate_codecs.size() * 4);

    for (CodecId cid : candidate_codecs) {
        std::vector<uint32_t> lvls = levels_for_codec(cid);
        for (uint32_t lvl : lvls) {
            CompressionProfile use_profile = ctx.profile;
            if (use_profile == CompressionProfile::Auto) {
                use_profile = CompressionProfile::Balanced;
            }
            Candidate cand;
            Error err = evaluate(cid, use_profile, lvl,
                                 ctx.input_data, ctx, registry, cand);
            if (!err.ok() || !cand.valid) continue;
            screened.push_back(cand);
            if (screened.size() >= kMaxCandidates) break;
        }
        if (screened.size() >= kMaxCandidates) break;
    }

    if (screened.empty()) {
        return make_error(ErrorCategory::Codec, 3,
                          "no valid compression candidates");
    }

    // Select candidate that minimizes FINAL_SIZE (not just compressed payload).
    Candidate best = screened[0];
    for (const Candidate& c : screened) {
        uint64_t c_final = CompressionPlanner::final_size(c.compressed_size, ctx);
        uint64_t b_final = CompressionPlanner::final_size(best.compressed_size, ctx);
        if (c_final < b_final) {
            best = c;
        }
    }

    out.codec_id = best.codec_id;
    out.profile = best.profile;
    out.level = best.level;
    out.compressed_payload_size = best.compressed_size;
    out.stub_size = ctx.stub_size;
    out.metadata_size = ctx.metadata_size;
    out.final_size = CompressionPlanner::final_size(
        out.compressed_payload_size, ctx);
    out.reason = "adaptive selection: smallest final size among " +
                 std::to_string(screened.size()) + " real candidates";

    nexapack::nxp_log(nexapack::LogLevel::Debug, "planner: codec=" +
                       std::to_string(static_cast<uint32_t>(out.codec_id)) +
                       " level=" + std::to_string(out.level) +
                       " compressed=" +
                       std::to_string(out.compressed_payload_size) +
                       " final_size=" + std::to_string(out.final_size) +
                       " candidates=" + std::to_string(screened.size()));
    return ok_error();
}

} // namespace planner
} // namespace nexapack
