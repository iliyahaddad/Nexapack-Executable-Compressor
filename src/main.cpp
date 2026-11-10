#include "cli/cli.hpp"
#include "codecs/codec_registry.hpp"
#include "core/codec_interface.hpp"
#include "core/analyzer/analyzer.hpp"
#include "core/error.hpp"
#include "core/logging.hpp"
#include "core/metadata.hpp"
#include "core/planner/planner.hpp"
#include "protection/nexaprotect/nexaprotect.hpp"

#include <chrono>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

namespace nexapack {

using ExecutableFormat = analyzer::ExecutableFormat;
using Architecture = nexapack::Architecture;
using ExecutableType = analyzer::ExecutableType;
using CompressionProfile = nexapack::CompressionProfile;
using CompressionPlanner = nexapack::planner::CompressionPlanner;
using PlanResult = nexapack::planner::PlanResult;
using PackContext = nexapack::planner::PackContext;
using ProtectionProfile = nexaprotect::ProtectionProfile;

namespace {

std::vector<uint8_t> read_file(const std::string& path, Error& err) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        err = make_error(ErrorCategory::Io, 1, "cannot open input file: " + path);
        return {};
    }
    std::vector<uint8_t> buf((std::istreambuf_iterator<char>(in)),
                             std::istreambuf_iterator<char>());
    return buf;
}

bool write_file(const std::string& path, std::string_view data, Error& err) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        err = make_error(ErrorCategory::Io, 2, "cannot open output file: " + path);
        return false;
    }
    out.write(data.data(), static_cast<std::streamsize>(data.size()));
    if (!out) {
        err = make_error(ErrorCategory::Io, 3, "failed writing output file: " + path);
        return false;
    }
    return true;
}

bool file_exists(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    return in.good();
}

std::string json_escape(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: out += c;
        }
    }
    return out;
}

std::string plan_profile_name(CompressionProfile p) {
    switch (p) {
        case CompressionProfile::Fast: return "fast";
        case CompressionProfile::Balanced: return "balanced";
        case CompressionProfile::Maximum: return "maximum";
        case CompressionProfile::Auto: return "auto";
        case CompressionProfile::Custom: return "custom";
    }
    return "unknown";
}

std::string protection_profile_name(ProtectionProfile p) {
    switch (p) {
        case ProtectionProfile::None: return "none";
        case ProtectionProfile::Basic: return "basic";
        case ProtectionProfile::Standard: return "standard";
        case ProtectionProfile::Advanced: return "advanced";
        case ProtectionProfile::Maximum: return "maximum";
    }
    return "unknown";
}

std::string resolve_stub_path(const std::string& stub_name) {
    // Stub must be alongside nexapack executable
    return stub_name;
}

} // namespace

int run(int argc, char* argv[]) {
    Cli cli;
    Error err = cli.parse(argc, argv);
    if (!err.ok()) {
        if (cli.command() != Cli::Command::Help) {
            std::cerr << "nexapack: error: " << err.message() << "\n";
        }
        return 1;
    }

    Logger::instance().set_level(cli.common().verbose ? LogLevel::Debug : LogLevel::Info);

    switch (cli.command()) {
        case Cli::Command::Help:
            std::cout << R"(NexaPack v0.1.0 - Independent executable packer
Usage: nexapack <command> [options]

Commands:
  pack <input> -o <output>   Pack an executable
  unpack <input> -o <output> Unpack a NexaPack file
  inspect <input>            Inspect an executable
  verify <input>             Verify a NexaPack file
  benchmark <input>          Benchmark a file
  batch <input>              Batch pack files
  codecs                     List available codecs
  profiles                   List compression profiles
  version                    Show version
  help                       Show this help

Pack options:
  --profile fast|balanced|maximum|auto|custom
  --codec store|zstd|lz4|lzma|apultra|auto
  --level <N> --best --force --verbose --json
  --protection none|basic|standard|advanced|maximum

Verify options:
  --verbose --json

Benchmark options:
  --verbose --json

Batch options:
  --profile fast|balanced|maximum|auto|custom
  --codec store|zstd|lz4|lzma|apultra|auto
  --protection none|basic|standard|advanced|maximum
  --force --verbose --json
)";
            return 0;
        case Cli::Command::Version:
            std::cout << "nexapack 0.1.0\n";
            return 0;
        case Cli::Command::Pack: {
            const auto& po = cli.pack_options();
            Error e;

            auto input = read_file(po.input, e);
            if (!e.ok()) {
                std::cerr << "nexapack: error: " << e.message() << "\n";
                return 1;
            }

            if (!po.force && !po.output.empty() && file_exists(po.output)) {
                std::cerr << "nexapack: error: output already exists: " << po.output
                          << " (use --force to overwrite)\n";
                return 1;
            }

            std::string out_path = po.output.empty()
                                       ? (po.input + ".nxp")
                                       : po.output;

            analyzer::CompatibilityReport report;
            report.input_path = po.input;
            err = analyzer::analyze_executable(
                std::string_view(reinterpret_cast<const char*>(input.data()),
                                 input.size()),
                report);
            if (!err.ok()) {
                std::cerr << "nexapack: error: cannot analyze input: "
                          << err.message() << "\n";
                return 1;
            }

            PackMetadata meta;
            meta.original_file_size = input.size();

            std::string stub_path;
            if (report.format == ExecutableFormat::PE32Plus) {
                meta.target_format = TargetFormat::PE32Plus;
                meta.architecture = Architecture::X64;
                if (report.type == ExecutableType::Dll) {
                    stub_path = resolve_stub_path("stub_dll.dll");
                } else {
                    stub_path = resolve_stub_path("stub.exe");
                }
            } else if (report.format == ExecutableFormat::ELF64) {
                meta.target_format = TargetFormat::ELF64;
                meta.architecture = Architecture::X64;
                stub_path = resolve_stub_path("stub");
            } else {
                std::cerr << "nexapack: error: unsupported input format for packing: "
                          << report.format_name << "\n";
                return 1;
            }

            if (stub_path.empty()) {
                std::cerr << "nexapack: error: runtime stub not found. "
                          << "Deploy stub binaries alongside nexapack.\n";
                return 1;
            }

            std::vector<uint8_t> stub = read_file(stub_path, e);
            if (!e.ok()) {
                std::cerr << "nexapack: error: cannot load runtime stub: "
                          << e.message() << "\n";
                return 1;
            }

            PackContext pctx;
            pctx.input_path = po.input;
            pctx.input_data =
                std::string_view(reinterpret_cast<const char*>(input.data()),
                                 input.size());
            pctx.profile = po.profile;
            pctx.target_format = meta.target_format;
            pctx.architecture = Architecture::X64;
            pctx.input_size = input.size();
            pctx.stub_size = stub.size();
            pctx.metadata_size = sizeof(NxMetadataHeader);
            pctx.section_alignment = 16;
            pctx.is_dll = (report.type == ExecutableType::Dll);
            pctx.has_relocations = report.pe.has_relocations;
            pctx.has_tls = report.pe.has_tls;
            pctx.has_exception_data = report.pe.has_exception_data;

            CodecRegistry registry;
            planner::CompressionPlanner planner;
            planner::PlanResult plan;
            err = planner.plan(pctx, registry, plan);
            if (!err.ok()) {
                std::cerr << "nexapack: error: compression planning failed: "
                          << err.message() << "\n";
                return 1;
            }

            Codec* codec = nullptr;
            if (po.codec_id != "auto") {
                for (size_t ci = 0; ci < registry.count(); ++ci) {
                    const Codec* c = registry.at(ci);
                    if (c->id() == po.codec_id) {
                        codec = const_cast<Codec*>(c);
                        break;
                    }
                }
                if (!codec) {
                    std::cerr << "nexapack: error: codec not found: "
                              << po.codec_id << "\n";
                    return 1;
                }
            } else {
                for (size_t ci = 0; ci < registry.count(); ++ci) {
                    const Codec* c = registry.at(ci);
                    if (c->id() == "store") codec = const_cast<Codec*>(c);
                    else if (c->id() == "zstd") codec = const_cast<Codec*>(c);
                    else if (c->id() == "lz4") codec = const_cast<Codec*>(c);
                    else if (c->id() == "lzma") codec = const_cast<Codec*>(c);
                    else if (c->id() == "apultra") codec = const_cast<Codec*>(c);
                }
                if (!codec) {
                    std::cerr << "nexapack: error: planned codec not found: "
                              << static_cast<uint32_t>(plan.codec_id) << "\n";
                    return 1;
                }
            }

            EncodeResult enc = codec->compress(
                std::string_view(reinterpret_cast<const char*>(input.data()),
                                 input.size()),
                po.profile, po.level);
            if (!enc.error.ok()) {
                std::cerr << "nexapack: error: compression failed: "
                          << enc.error.message() << "\n";
                return 1;
            }

            nexaprotect::ProtectionConfig pconfig;
            if (po.protection == "none") {
                pconfig.profile = nexaprotect::ProtectionProfile::None;
            } else if (po.protection == "basic") {
                pconfig.profile = nexaprotect::ProtectionProfile::Basic;
            } else if (po.protection == "standard") {
                pconfig.profile = nexaprotect::ProtectionProfile::Standard;
            } else if (po.protection == "advanced") {
                pconfig.profile = nexaprotect::ProtectionProfile::Advanced;
            } else if (po.protection == "maximum") {
                pconfig.profile = nexaprotect::ProtectionProfile::Maximum;
            } else {
                std::cerr << "nexapack: error: unknown protection profile: "
                          << po.protection << "\n";
                return 1;
            }

            std::vector<uint8_t> protected_payload = enc.compressed;
            std::vector<uint8_t> protection_meta;
            if (pconfig.profile != nexaprotect::ProtectionProfile::None) {
                nexaprotect::ProtectionResult pres;
                Error perr = nexaprotect::apply_protection(
                    std::string_view(reinterpret_cast<const char*>(enc.compressed.data()),
                                     enc.compressed.size()),
                    pconfig, pres);
                if (!perr.ok()) {
                    std::cerr << "nexapack: error: protection failed: "
                              << perr.message() << "\n";
                    return 1;
                }
                if (!pres.protected_data.empty()) {
                    protected_payload = std::move(pres.protected_data);
                }
                protection_meta = std::move(pres.protection_meta);
                meta.encrypted_sections = std::move(pres.encrypted_sections);
            }

            CodecId actual_codec_id = CodecId::Store;
            if (codec->id() == "zstd") actual_codec_id = CodecId::ZSTD;
            else if (codec->id() == "lz4") actual_codec_id = CodecId::LZ4;
            else if (codec->id() == "lzma") actual_codec_id = CodecId::LZMA;
            else if (codec->id() == "apultra") actual_codec_id = CodecId::ApUltra;

            meta.compression_settings =
                (static_cast<uint32_t>(po.profile) << 16) | po.level;
            meta.codec_id = actual_codec_id;
            meta.payload_size = protected_payload.size();
            meta.stub_size = stub.size();
            meta.metadata_offset = stub.size();
            meta.metadata_size = sizeof(NxMetadataHeader) + sizeof(uint32_t);
            meta.payload_offset = stub.size() + meta.metadata_size;

            auto meta_buf = serialize_metadata(meta);
            meta.metadata_size = meta_buf.size();
            meta.payload_offset = stub.size() + meta.metadata_size;

            // Set integrity metadata offset/size for verify command.
            // integrity_meta is stored right after the protected payload.
            // integrity_offset and integrity_size are fixed fields in the
            // 108-byte NxMetadataHeader, so metadata_size does not change.
            if (!protection_meta.empty()) {
                meta.integrity_offset = meta.payload_offset + meta.payload_size;
                meta.integrity_size = protection_meta.size();
            }

            // Final serialize with integrity metadata offsets included.
            meta_buf = serialize_metadata(meta);
            meta.metadata_size = meta_buf.size();
            meta.payload_offset = stub.size() + meta.metadata_size;

            // Recompute integrity_offset with final payload_offset.
            if (!protection_meta.empty()) {
                meta.integrity_offset = meta.payload_offset + meta.payload_size;
            }

            uint8_t footer[8];
            for (int i = 0; i < 8; i++)
                footer[i] = static_cast<uint8_t>((meta.metadata_offset >> (8 * i)) & 0xFF);

            std::vector<uint8_t> packed;
            packed.reserve(stub.size() + meta_buf.size() + protected_payload.size() +
                           protection_meta.size() + 8);
            packed.insert(packed.end(), stub.begin(), stub.end());
            packed.insert(packed.end(), meta_buf.begin(), meta_buf.end());
            packed.insert(packed.end(), protected_payload.begin(),
                          protected_payload.end());
            packed.insert(packed.end(), protection_meta.begin(),
                          protection_meta.end());
            packed.insert(packed.end(), footer, footer + 8);

            if (!write_file(out_path,
                            std::string_view(reinterpret_cast<const char*>(packed.data()),
                                             packed.size()),
                            e)) {
                std::cerr << "nexapack: error: " << e.message() << "\n";
                return 1;
            }

            if (po.json) {
                std::cout << "{ \"input\": \"" << json_escape(po.input)
                          << "\", \"output\": \"" << json_escape(out_path)
                          << "\", \"codec\": \"" << codec->id()
                          << "\", \"format\": \"" << report.format_name
                          << "\", \"profile\": \"" << plan_profile_name(po.profile)
                          << "\", \"level\": " << po.level
                          << ", \"protection\": \"" << po.protection
                          << "\", \"original_size\": " << input.size()
                          << ", \"packed_size\": " << packed.size()
                          << ", \"planned_final_size\": " << plan.final_size
                          << " }\n";
            } else {
                std::cout << "Packed " << po.input << " -> " << out_path << "\n"
                          << "  format: " << report.format_name << "\n"
                          << "  codec:  " << codec->id() << " v" << codec->version() << "\n"
                          << "  profile: " << plan_profile_name(po.profile)
                          << " level=" << po.level << "\n"
                          << "  protection: " << po.protection << "\n"
                          << "  original: " << input.size() << " bytes\n"
                          << "  packed:   " << packed.size() << " bytes\n"
                          << "  planned final size: " << plan.final_size << " bytes\n";
            }
            return 0;
        }
        case Cli::Command::Unpack: {
            const auto& uo = cli.unpack_options();
            Error e;

            auto packed = read_file(uo.input, e);
            if (!e.ok()) {
                std::cerr << "nexapack: error: " << e.message() << "\n";
                return 1;
            }

            if (packed.size() < sizeof(NxMetadataHeader) + 8) {
                std::cerr << "nexapack: error: file too small for metadata + footer\n";
                return 1;
            }

            uint64_t meta_offset = 0;
            for (int i = 0; i < 8; i++)
                meta_offset |= ((uint64_t)packed[packed.size() - 8 + i]) << (8 * i);
            if (meta_offset + sizeof(NxMetadataHeader) > packed.size()) {
                std::cerr << "nexapack: error: metadata offset out of range\n";
                return 1;
            }

            PackMetadata meta;
            size_t meta_avail = packed.size() - meta_offset - 8;
            Error err = deserialize_metadata(
                std::string_view(reinterpret_cast<const char*>(packed.data() + meta_offset),
                                 meta_avail),
                meta);
            if (!err.ok()) {
                std::cerr << "nexapack: error: invalid metadata: " << err.message() << "\n";
                return 1;
            }

            if (meta.payload_offset >= packed.size()) {
                std::cerr << "nexapack: error: payload offset out of range\n";
                return 1;
            }
            if (meta.payload_size > packed.size() - meta.payload_offset) {
                std::cerr << "nexapack: error: payload size out of range\n";
                return 1;
            }

            CodecRegistry registry;
            Codec* codec = nullptr;
            if (meta.codec_id == CodecId::ZSTD) codec = registry.find("zstd");
            else if (meta.codec_id == CodecId::LZ4) codec = registry.find("lz4");
            else if (meta.codec_id == CodecId::Store) codec = registry.find("store");
            else if (meta.codec_id == CodecId::LZMA) codec = registry.find("lzma");
            else if (meta.codec_id == CodecId::ApUltra) codec = registry.find("apultra");
            if (!codec) {
                std::cerr << "nexapack: error: codec not available: "
                          << static_cast<uint32_t>(meta.codec_id) << "\n";
                return 1;
            }

            std::string_view payload(
                reinterpret_cast<const char*>(packed.data() + meta.payload_offset),
                meta.payload_size);

            DecodeResult dec = codec->decompress(payload, meta.original_file_size);
            if (!dec.error.ok()) {
                std::cerr << "nexapack: error: decompression failed: "
                          << dec.error.message() << "\n";
                return 1;
            }
            if (dec.decompressed_size != meta.original_file_size) {
                std::cerr << "nexapack: error: size mismatch: expected "
                          << meta.original_file_size << " got "
                          << dec.decompressed_size << "\n";
                return 1;
            }

            std::string out_path = uo.output.empty()
                                       ? (uo.input + ".orig")
                                       : uo.output;
            if (!uo.force && file_exists(out_path)) {
                std::cerr << "nexapack: error: output already exists: " << out_path
                          << " (use --force to overwrite)\n";
                return 1;
            }

            if (!write_file(out_path,
                            std::string_view(
                                reinterpret_cast<const char*>(dec.decompressed.data()),
                                dec.decompressed.size()),
                            e)) {
                std::cerr << "nexapack: error: " << e.message() << "\n";
                return 1;
            }

            if (uo.json) {
                std::cout << "{ \"input\": \"" << json_escape(uo.input)
                          << "\", \"output\": \"" << json_escape(out_path)
                          << "\", \"codec\": \"" << codec->id()
                          << "\", \"original_size\": " << meta.original_file_size
                          << ", \"unpacked_size\": " << dec.decompressed_size
                          << " }\n";
            } else {
                std::cout << "Unpacked " << uo.input << " -> " << out_path << "\n"
                          << "  codec: " << codec->id() << " v" << codec->version()
                          << "\n"
                          << "  original: " << meta.original_file_size << " bytes\n"
                          << "  unpacked: " << dec.decompressed_size << " bytes\n";
            }
            return 0;
        }
        case Cli::Command::Inspect: {
            const auto& io = cli.inspect_options();
            Error e;

            auto input = read_file(io.input, e);
            if (!e.ok()) {
                std::cerr << "nexapack: error: " << e.message() << "\n";
                return 1;
            }

            analyzer::CompatibilityReport report;
            report.input_path = io.input;
            err = analyzer::analyze_executable(
                std::string_view(reinterpret_cast<const char*>(input.data()),
                                 input.size()),
                report);
            if (!err.ok()) {
                std::cerr << "nexapack: error: cannot analyze input: "
                          << err.message() << "\n";
                return 1;
            }

            if (io.json) {
                std::cout << analyzer::to_json(report) << "\n";
            } else {
                std::cout << "nexapack inspect: " << io.input << "\n";
                std::cout << "  format:       " << report.format_name << "\n";
                std::cout << "  architecture: " << report.architecture_name << "\n";
                std::cout << "  os:           " << report.os_name << "\n";
                std::cout << "  type:         " << report.type_name << "\n";
                std::cout << "  compatibility:" << report.compatibility_name << "\n";
                std::cout << "  packable:     " << (report.packable ? "true" : "false")
                          << "\n";
                std::cout << "  executable:   " << (report.executable ? "true" : "false")
                          << "\n";
                if (!report.sections.empty()) {
                    std::cout << "  sections:";
                    for (const auto& s : report.sections) {
                        std::cout << " " << s;
                    }
                    std::cout << "\n";
                }
                if (!report.notes.empty()) {
                    std::cout << "  notes:";
                    for (const auto& n : report.notes) {
                        std::cout << " " << n;
                    }
                    std::cout << "\n";
                }
                if (!report.warnings.empty()) {
                    std::cout << "  warnings:";
                    for (const auto& w : report.warnings) {
                        std::cout << " " << w;
                    }
                    std::cout << "\n";
                }
            }
            return 0;
        }
        case Cli::Command::Verify: {
            const auto& vo = cli.verify_options();
            Error e;

            auto packed = read_file(vo.input, e);
            if (!e.ok()) {
                std::cerr << "nexapack: error: " << e.message() << "\n";
                return 1;
            }

            if (packed.size() < sizeof(NxMetadataHeader) + 8) {
                std::cerr << "nexapack: error: file too small for metadata + footer\n";
                return 1;
            }

            uint64_t meta_offset = 0;
            for (int i = 0; i < 8; i++)
                meta_offset |= ((uint64_t)packed[packed.size() - 8 + i]) << (8 * i);
            if (meta_offset + sizeof(NxMetadataHeader) > packed.size()) {
                std::cerr << "nexapack: error: metadata offset out of range\n";
                return 1;
            }

            PackMetadata meta;
            Error err = deserialize_metadata(
                std::string_view(reinterpret_cast<const char*>(packed.data() + meta_offset),
                                 sizeof(NxMetadataHeader)),
                meta);
            if (!err.ok()) {
                std::cerr << "nexapack: error: invalid metadata: " << err.message() << "\n";
                return 1;
            }

            bool tampered = false;
            if (meta.integrity_offset != 0 && meta.integrity_size > 0 &&
                meta.integrity_offset + meta.integrity_size <= packed.size()) {
                std::string_view integrity_meta(
                    reinterpret_cast<const char*>(packed.data() + meta.integrity_offset),
                    meta.integrity_size);
                // Verify integrity over the protected payload section.
                std::string_view payload_section(
                    reinterpret_cast<const char*>(packed.data() + meta.payload_offset),
                    meta.payload_size);
                Error verify_err = nexaprotect::verify_protection(
                    payload_section, integrity_meta, tampered);
                if (!verify_err.ok()) {
                    std::cerr << "nexapack: error: integrity verification failed: "
                              << verify_err.message() << "\n";
                    return 1;
                }
            }

            if (vo.json) {
                std::cout << "{ \"input\": \"" << json_escape(vo.input)
                          << "\", \"valid\": true"
                          << ", \"tampered\": " << (tampered ? "true" : "false")
                          << ", \"codec\": " << static_cast<uint32_t>(meta.codec_id)
                          << ", \"original_size\": " << meta.original_file_size
                          << ", \"packed_size\": " << packed.size()
                          << " }\n";
            } else {
                std::cout << "Verified: " << vo.input << "\n";
                std::cout << "  codec:      " << static_cast<uint32_t>(meta.codec_id) << "\n";
                std::cout << "  original:   " << meta.original_file_size << " bytes\n";
                std::cout << "  packed:     " << packed.size() << " bytes\n";
                std::cout << "  tampered:   " << (tampered ? "YES" : "NO") << "\n";
                if (tampered) {
                    std::cerr << "nexapack: warning: file has been tampered with!\n";
                    return 1;
                }
            }
            return 0;
        }
        case Cli::Command::Benchmark: {
            const auto& bo = cli.benchmark_options();
            Error e;

            auto input = read_file(bo.input, e);
            if (!e.ok()) {
                std::cerr << "nexapack: error: " << e.message() << "\n";
                return 1;
            }

            analyzer::CompatibilityReport report;
            report.input_path = bo.input;
            err = analyzer::analyze_executable(
                std::string_view(reinterpret_cast<const char*>(input.data()),
                                 input.size()),
                report);
            if (!err.ok()) {
                std::cerr << "nexapack: error: cannot analyze input: "
                          << err.message() << "\n";
                return 1;
            }

            CodecRegistry registry;

            if (bo.json) {
                std::cout << "{\n";
                std::cout << "  \"input\": \"" << json_escape(bo.input) << "\",\n";
                std::cout << "  \"format\": \"" << report.format_name << "\",\n";
                std::cout << "  \"architecture\": \"" << report.architecture_name << "\",\n";
                std::cout << "  \"original_size\": " << input.size() << ",\n";
                std::cout << "  \"codecs\": [\n";

                bool first = true;
                for (size_t ci = 0; ci < registry.count(); ci++) {
                    const Codec* codec = registry.at(ci);
                    CodecCapabilities cap = codec->capabilities();
                    if (!cap.supports_compression || !cap.supports_decompression)
                        continue;

                    // Test levels 1, 3, 6, 9 bounded by max_level
                    std::vector<uint32_t> levels;
                    for (uint32_t l : {1u, 3u, 6u, 9u}) {
                        if (l <= cap.max_level) levels.push_back(l);
                    }
                    if (levels.empty()) levels.push_back(std::min(1u, cap.max_level));

                    for (uint32_t lvl : levels) {
                        auto t0 = std::chrono::high_resolution_clock::now();
                        EncodeResult enc = codec->compress(
                            std::string_view(reinterpret_cast<const char*>(input.data()),
                                             input.size()),
                            CompressionProfile::Balanced, lvl);
                        auto t1 = std::chrono::high_resolution_clock::now();
                        double compress_ms =
                            std::chrono::duration<double, std::milli>(t1 - t0).count();

                        if (!enc.error.ok()) continue;

                        auto t2 = std::chrono::high_resolution_clock::now();
                        DecodeResult dec = codec->decompress(
                            std::string_view(reinterpret_cast<const char*>(enc.compressed.data()),
                                             enc.compressed_size),
                            input.size());
                        auto t3 = std::chrono::high_resolution_clock::now();
                        double decompress_ms =
                            std::chrono::duration<double, std::milli>(t3 - t2).count();

                        if (!dec.error.ok() || dec.decompressed_size != input.size())
                            continue;

                        uint64_t stub_size = 0;
                        // Try to find stub size from build directory
                        {
                            std::string stub_path = resolve_stub_path("stub.exe");
                            auto stub_data = read_file(stub_path, e);
                            if (e.ok()) stub_size = stub_data.size();
                        }

                        uint64_t metadata_size = sizeof(NxMetadataHeader) + sizeof(uint32_t);
                        uint64_t final_size =
                            enc.compressed_size + stub_size + metadata_size;

                        double ratio = (double)input.size() / (double)final_size;

                        if (!first) std::cout << ",\n";
                        first = false;
                        std::cout << "    {\n";
                        std::cout << "      \"codec\": \"" << codec->id() << "\",\n";
                        std::cout << "      \"version\": \"" << codec->version() << "\",\n";
                        std::cout << "      \"level\": " << lvl << ",\n";
                        std::cout << "      \"compressed_size\": " << enc.compressed_size << ",\n";
                        std::cout << "      \"stub_size\": " << stub_size << ",\n";
                        std::cout << "      \"metadata_size\": " << metadata_size << ",\n";
                        std::cout << "      \"final_size\": " << final_size << ",\n";
                        std::cout << "      \"compression_ratio\": " << ratio << ",\n";
                        std::cout << "      \"compress_ms\": " << compress_ms << ",\n";
                        std::cout << "      \"decompress_ms\": " << decompress_ms << "\n";
                        std::cout << "    }";
                    }
                }

                std::cout << "\n  ],\n";
                std::cout << "  \"upx_available\": false,\n";
                std::cout << "  \"timestamp\": \"" << __DATE__ << " " << __TIME__ << "\"\n";
                std::cout << "}\n";
            } else {
                std::cout << "=== NexaPack Benchmark Report ===\n";
                std::cout << "Input:    " << bo.input << "\n";
                std::cout << "Format:   " << report.format_name << "\n";
                std::cout << "Arch:     " << report.architecture_name << "\n";
                std::cout << "Original: " << input.size() << " bytes\n";
                std::cout << "\n";

                // Find stub size
                uint64_t stub_size = 0;
                {
                    std::string stub_path = resolve_stub_path("stub.exe");
                    auto stub_data = read_file(stub_path, e);
                    if (e.ok()) stub_size = stub_data.size();
                }
                uint64_t metadata_size = sizeof(NxMetadataHeader) + sizeof(uint32_t);

                std::cout << "Codec comparison (profile=Balanced):\n";
                std::cout << "--------------------------------------------------------------\n";
                std::cout << std::left << std::setw(12) << "Codec"
                          << std::setw(8) << "Level"
                          << std::setw(14) << "Compressed"
                          << std::setw(10) << "Stub"
                          << std::setw(14) << "Final Size"
                          << std::setw(10) << "Ratio"
                          << std::setw(12) << "Comp ms"
                          << "Decomp ms\n";
                std::cout << "--------------------------------------------------------------\n";

                uint64_t best_final = UINT64_MAX;
                std::string best_codec_name;
                uint32_t best_level = 0;

                for (size_t ci = 0; ci < registry.count(); ci++) {
                    const Codec* codec = registry.at(ci);
                    CodecCapabilities cap = codec->capabilities();
                    if (!cap.supports_compression || !cap.supports_decompression)
                        continue;

                    std::vector<uint32_t> levels;
                    for (uint32_t l : {1u, 3u, 6u, 9u}) {
                        if (l <= cap.max_level) levels.push_back(l);
                    }
                    if (levels.empty()) levels.push_back(std::min(1u, cap.max_level));

                    for (uint32_t lvl : levels) {
                        auto t0 = std::chrono::high_resolution_clock::now();
                        EncodeResult enc = codec->compress(
                            std::string_view(reinterpret_cast<const char*>(input.data()),
                                             input.size()),
                            CompressionProfile::Balanced, lvl);
                        auto t1 = std::chrono::high_resolution_clock::now();
                        double compress_ms =
                            std::chrono::duration<double, std::milli>(t1 - t0).count();

                        if (!enc.error.ok()) continue;

                        auto t2 = std::chrono::high_resolution_clock::now();
                        DecodeResult dec = codec->decompress(
                            std::string_view(reinterpret_cast<const char*>(enc.compressed.data()),
                                             enc.compressed_size),
                            input.size());
                        auto t3 = std::chrono::high_resolution_clock::now();
                        double decompress_ms =
                            std::chrono::duration<double, std::milli>(t3 - t2).count();

                        if (!dec.error.ok() || dec.decompressed_size != input.size())
                            continue;

                        uint64_t final_size =
                            enc.compressed_size + stub_size + metadata_size;
                        double ratio = (double)input.size() / (double)final_size;

                        std::cout << std::left << std::setw(12) << codec->id()
                                  << std::setw(8) << lvl
                                  << std::setw(14) << enc.compressed_size
                                  << std::setw(10) << stub_size
                                  << std::setw(14) << final_size
                                  << std::setw(10) << std::fixed << std::setprecision(3) << ratio
                                  << std::setw(12) << std::fixed << std::setprecision(2) << compress_ms
                                  << std::fixed << std::setprecision(2) << decompress_ms << "\n";

                        if (final_size < best_final) {
                            best_final = final_size;
                            best_codec_name = codec->id();
                            best_level = lvl;
                        }
                    }
                }

                std::cout << "--------------------------------------------------------------\n";
                if (!best_codec_name.empty()) {
                    std::cout << "Best codec:  " << best_codec_name
                              << " level=" << best_level << "\n";
                    std::cout << "Best size:   " << best_final << " bytes\n";
                    double best_ratio = (double)input.size() / (double)best_final;
                    std::cout << "Best ratio:  " << std::fixed << std::setprecision(3)
                              << best_ratio << "x\n";
                }
                std::cout << "\n";
                std::cout << "Note: Final size = compressed payload + runtime stub + metadata.\n";
                std::cout << "      No temporary executable extraction is used.\n";
            }
            return 0;
        }
        case Cli::Command::Compare: {
            // Compare is an alias for Benchmark - compare algorithms
            const auto& bo = cli.compare_options();
            Error e;

            auto input = read_file(bo.input, e);
            if (!e.ok()) {
                std::cerr << "nexapack: error: " << e.message() << "\n";
                return 1;
            }

            analyzer::CompatibilityReport report;
            report.input_path = bo.input;
            err = analyzer::analyze_executable(
                std::string_view(reinterpret_cast<const char*>(input.data()),
                                 input.size()),
                report);
            if (!err.ok()) {
                std::cerr << "nexapack: error: cannot analyze input: "
                          << err.message() << "\n";
                return 1;
            }

            CodecRegistry registry;

            if (bo.json) {
                std::cout << "{\n";
                std::cout << "  \"input\": \"" << json_escape(bo.input) << "\",\n";
                std::cout << "  \"format\": \"" << report.format_name << "\",\n";
                std::cout << "  \"architecture\": \"" << report.architecture_name << "\",\n";
                std::cout << "  \"original_size\": " << input.size() << ",\n";
                std::cout << "  \"codecs\": [\n";

                bool first = true;
                for (size_t ci = 0; ci < registry.count(); ci++) {
                    const Codec* codec = registry.at(ci);
                    CodecCapabilities cap = codec->capabilities();
                    if (!cap.supports_compression || !cap.supports_decompression)
                        continue;

                    std::vector<uint32_t> levels;
                    for (uint32_t l : {1u, 3u, 6u, 9u}) {
                        if (l <= cap.max_level) levels.push_back(l);
                    }
                    if (levels.empty()) levels.push_back(std::min(1u, cap.max_level));

                    for (uint32_t lvl : levels) {
                        auto t0 = std::chrono::high_resolution_clock::now();
                        EncodeResult enc = codec->compress(
                            std::string_view(reinterpret_cast<const char*>(input.data()),
                                             input.size()),
                            CompressionProfile::Balanced, lvl);
                        auto t1 = std::chrono::high_resolution_clock::now();
                        double compress_ms =
                            std::chrono::duration<double, std::milli>(t1 - t0).count();

                        if (!enc.error.ok()) continue;

                        auto t2 = std::chrono::high_resolution_clock::now();
                        DecodeResult dec = codec->decompress(
                            std::string_view(reinterpret_cast<const char*>(enc.compressed.data()),
                                             enc.compressed_size),
                            input.size());
                        auto t3 = std::chrono::high_resolution_clock::now();
                        double decompress_ms =
                            std::chrono::duration<double, std::milli>(t3 - t2).count();

                        if (!dec.error.ok() || dec.decompressed_size != input.size())
                            continue;

                        uint64_t stub_size = 0;
                        {
                            std::string stub_path = resolve_stub_path("stub.exe");
                            auto stub_data = read_file(stub_path, e);
                            if (e.ok()) stub_size = stub_data.size();
                        }

                        uint64_t metadata_size = sizeof(NxMetadataHeader) + sizeof(uint32_t);
                        uint64_t final_size =
                            enc.compressed_size + stub_size + metadata_size;

                        double ratio = (double)input.size() / (double)final_size;

                        if (!first) std::cout << ",\n";
                        first = false;
                        std::cout << "    {\n";
                        std::cout << "      \"codec\": \"" << codec->id() << "\",\n";
                        std::cout << "      \"version\": \"" << codec->version() << "\",\n";
                        std::cout << "      \"level\": " << lvl << ",\n";
                        std::cout << "      \"compressed_size\": " << enc.compressed_size << ",\n";
                        std::cout << "      \"stub_size\": " << stub_size << ",\n";
                        std::cout << "      \"metadata_size\": " << metadata_size << ",\n";
                        std::cout << "      \"final_size\": " << final_size << ",\n";
                        std::cout << "      \"compression_ratio\": " << ratio << ",\n";
                        std::cout << "      \"compress_ms\": " << compress_ms << ",\n";
                        std::cout << "      \"decompress_ms\": " << decompress_ms << "\n";
                        std::cout << "    }";
                    }
                }

                std::cout << "\n  ],\n";
                std::cout << "  \"upx_available\": false,\n";
                std::cout << "  \"timestamp\": \"" << __DATE__ << " " << __TIME__ << "\"\n";
                std::cout << "}\n";
            } else {
                std::cout << "=== NexaPack Compare Report ===\n";
                std::cout << "Input:    " << bo.input << "\n";
                std::cout << "Format:   " << report.format_name << "\n";
                std::cout << "Arch:     " << report.architecture_name << "\n";
                std::cout << "Original: " << input.size() << " bytes\n";
                std::cout << "\n";

                uint64_t stub_size = 0;
                {
                    std::string stub_path = resolve_stub_path("stub.exe");
                    auto stub_data = read_file(stub_path, e);
                    if (e.ok()) stub_size = stub_data.size();
                }
                uint64_t metadata_size = sizeof(NxMetadataHeader) + sizeof(uint32_t);

                std::cout << "Codec comparison (profile=Balanced):\n";
                std::cout << "--------------------------------------------------------------\n";
                std::cout << std::left << std::setw(12) << "Codec"
                          << std::setw(8) << "Level"
                          << std::setw(14) << "Compressed"
                          << std::setw(10) << "Stub"
                          << std::setw(14) << "Final Size"
                          << std::setw(10) << "Ratio"
                          << std::setw(12) << "Comp ms"
                          << "Decomp ms\n";
                std::cout << "--------------------------------------------------------------\n";

                uint64_t best_final = UINT64_MAX;
                std::string best_codec_name;
                uint32_t best_level = 0;

                for (size_t ci = 0; ci < registry.count(); ci++) {
                    const Codec* codec = registry.at(ci);
                    CodecCapabilities cap = codec->capabilities();
                    if (!cap.supports_compression || !cap.supports_decompression)
                        continue;

                    std::vector<uint32_t> levels;
                    for (uint32_t l : {1u, 3u, 6u, 9u}) {
                        if (l <= cap.max_level) levels.push_back(l);
                    }
                    if (levels.empty()) levels.push_back(std::min(1u, cap.max_level));

                    for (uint32_t lvl : levels) {
                        auto t0 = std::chrono::high_resolution_clock::now();
                        EncodeResult enc = codec->compress(
                            std::string_view(reinterpret_cast<const char*>(input.data()),
                                             input.size()),
                            CompressionProfile::Balanced, lvl);
                        auto t1 = std::chrono::high_resolution_clock::now();
                        double compress_ms =
                            std::chrono::duration<double, std::milli>(t1 - t0).count();

                        if (!enc.error.ok()) continue;

                        auto t2 = std::chrono::high_resolution_clock::now();
                        DecodeResult dec = codec->decompress(
                            std::string_view(reinterpret_cast<const char*>(enc.compressed.data()),
                                             enc.compressed_size),
                            input.size());
                        auto t3 = std::chrono::high_resolution_clock::now();
                        double decompress_ms =
                            std::chrono::duration<double, std::milli>(t3 - t2).count();

                        if (!dec.error.ok() || dec.decompressed_size != input.size())
                            continue;

                        uint64_t final_size =
                            enc.compressed_size + stub_size + metadata_size;
                        double ratio = (double)input.size() / (double)final_size;

                        std::cout << std::left << std::setw(12) << codec->id()
                                  << std::setw(8) << lvl
                                  << std::setw(14) << enc.compressed_size
                                  << std::setw(10) << stub_size
                                  << std::setw(14) << final_size
                                  << std::setw(10) << std::fixed << std::setprecision(3) << ratio
                                  << std::setw(12) << std::fixed << std::setprecision(2) << compress_ms
                                  << std::fixed << std::setprecision(2) << decompress_ms << "\n";

                        if (final_size < best_final) {
                            best_final = final_size;
                            best_codec_name = codec->id();
                            best_level = lvl;
                        }
                    }
                }

                std::cout << "--------------------------------------------------------------\n";
                if (!best_codec_name.empty()) {
                    std::cout << "Best codec:  " << best_codec_name
                              << " level=" << best_level << "\n";
                    std::cout << "Best size:   " << best_final << " bytes\n";
                    double best_ratio = (double)input.size() / (double)best_final;
                    std::cout << "Best ratio:  " << std::fixed << std::setprecision(3)
                              << best_ratio << "x\n";
                }
                std::cout << "\n";
                std::cout << "Note: Final size = compressed payload + runtime stub + metadata.\n";
                std::cout << "      No temporary executable extraction is used.\n";
            }
            return 0;
        }
        case Cli::Command::Batch: {
            const auto& bo = cli.batch_options();
            Error e;

            // Batch processes a directory of executables
            std::filesystem::path dir_path(bo.input);
            if (!std::filesystem::exists(dir_path) || !std::filesystem::is_directory(dir_path)) {
                std::cerr << "nexapack: error: directory not found: " << bo.input << "\n";
                return 1;
            }

            std::vector<std::filesystem::path> files;
            for (const auto& entry : std::filesystem::directory_iterator(dir_path)) {
                if (entry.is_regular_file()) {
                    std::string ext = entry.path().extension().string();
                    if (ext == ".exe" || ext == ".dll") {
                        files.push_back(entry.path());
                    }
                }
            }

            std::sort(files.begin(), files.end());

            if (files.empty()) {
                std::cout << "No executables found in: " << bo.input << "\n";
                return 0;
            }

            std::cout << "Batch processing " << files.size() << " file(s) from: " << bo.input << "\n";
            std::cout << "Profile: " << bo.profile << "  Codec: " << bo.codec_id << "  Protection: " << bo.protection << "\n\n";

            int success_count = 0;
            int fail_count = 0;

            for (const auto& input_path : files) {
                std::string input_str = input_path.string();
                std::string output_str = input_str + ".nxp";

                auto input_data = read_file(input_str, e);
                if (!e.ok()) {
                    std::cerr << "  FAIL: " << input_path.filename().string() << " - " << e.message() << "\n";
                    fail_count++;
                    continue;
                }

                analyzer::CompatibilityReport report;
                report.input_path = input_str;
                err = analyzer::analyze_executable(
                    std::string_view(reinterpret_cast<const char*>(input_data.data()),
                                     input_data.size()),
                    report);
                if (!err.ok()) {
                    std::cerr << "  FAIL: " << input_path.filename().string() << " - " << err.message() << "\n";
                    fail_count++;
                    continue;
                }

                PackMetadata meta;
                meta.original_file_size = input_data.size();
                meta.target_format = TargetFormat::PE32Plus;
                meta.architecture = Architecture::X64;

                std::string stubName = (report.type == analyzer::ExecutableType::Dll) ? "stub_dll.dll" : "stub.exe";
                std::string stub_path = resolve_stub_path(stubName);
                if (stub_path.empty()) {
                    std::cerr << "  FAIL: " << input_path.filename().string() << " - runtime stub not found\n";
                    fail_count++;
                    continue;
                }

                auto stub_data = read_file(stub_path, e);
                if (!e.ok()) {
                    std::cerr << "  FAIL: " << input_path.filename().string() << " - " << e.message() << "\n";
                    fail_count++;
                    continue;
                }

                PackContext pctx;
                pctx.input_path = input_str;
                pctx.input_data = std::string_view(reinterpret_cast<const char*>(input_data.data()), input_data.size());
                pctx.profile = CompressionProfile::Balanced;
                pctx.target_format = meta.target_format;
                pctx.architecture = Architecture::X64;
                pctx.input_size = input_data.size();
                pctx.stub_size = stub_data.size();
                pctx.metadata_size = sizeof(NxMetadataHeader);
                pctx.section_alignment = 16;
                pctx.is_dll = (report.type == analyzer::ExecutableType::Dll);
                pctx.has_relocations = report.pe.has_relocations;
                pctx.has_tls = report.pe.has_tls;
                pctx.has_exception_data = report.pe.has_exception_data;

                CodecRegistry registry;
                planner::CompressionPlanner planner;
                planner::PlanResult plan;
                err = planner.plan(pctx, registry, plan);
                if (!err.ok()) {
                    std::cerr << "  FAIL: " << input_path.filename().string() << " - " << err.message() << "\n";
                    fail_count++;
                    continue;
                }

                Codec* codec_ptr = nullptr;
                if (bo.codec_id != "auto") {
                    for (size_t ci = 0; ci < registry.count(); ++ci) {
                        const Codec* c = registry.at(ci);
                        if (c->id() == bo.codec_id) {
                            codec_ptr = const_cast<Codec*>(c);
                            break;
                        }
                    }
                } else {
                    codec_ptr = const_cast<Codec*>(registry.at(0));
                    for (size_t ci = 0; ci < registry.count(); ++ci) {
                        const Codec* c = registry.at(ci);
                        if (c->id() == "zstd") { codec_ptr = const_cast<Codec*>(c); break; }
                        else if (c->id() == "lz4") { codec_ptr = const_cast<Codec*>(c); break; }
                        else if (c->id() == "lzma") { codec_ptr = const_cast<Codec*>(c); break; }
                    }
                }

                if (!codec_ptr) {
                    std::cerr << "  FAIL: " << input_path.filename().string() << " - codec not found\n";
                    fail_count++;
                    continue;
                }

                CompressionProfile prof;
                if (bo.profile == "fast") prof = CompressionProfile::Fast;
                else if (bo.profile == "balanced") prof = CompressionProfile::Balanced;
                else if (bo.profile == "maximum") prof = CompressionProfile::Maximum;
                else if (bo.profile == "auto") prof = CompressionProfile::Auto;
                else prof = CompressionProfile::Custom;

                EncodeResult enc = codec_ptr->compress(
                    std::string_view(reinterpret_cast<const char*>(input_data.data()), input_data.size()),
                    prof, bo.level);
                if (!enc.error.ok()) {
                    std::cerr << "  FAIL: " << input_path.filename().string() << " - compression failed: " << enc.error.message() << "\n";
                    fail_count++;
                    continue;
                }

                ProtectionProfile pprofile;
                if (bo.protection == "basic") pprofile = ProtectionProfile::Basic;
                else if (bo.protection == "standard") pprofile = ProtectionProfile::Standard;
                else if (bo.protection == "advanced") pprofile = ProtectionProfile::Advanced;
                else if (bo.protection == "maximum") pprofile = ProtectionProfile::Maximum;
                else pprofile = ProtectionProfile::None;

                std::vector<uint8_t> protected_payload = enc.compressed;
                std::vector<uint8_t> protection_meta;
                if (pprofile != ProtectionProfile::None) {
                    nexaprotect::ProtectionConfig pconfig;
                    pconfig.profile = pprofile;
                    nexaprotect::ProtectionResult pres;
                    Error perr = nexaprotect::apply_protection(
                        std::string_view(reinterpret_cast<const char*>(enc.compressed.data()),
                                         enc.compressed.size()),
                        pconfig, pres);
                    if (!perr.ok()) {
                        std::cerr << "  FAIL: " << input_path.filename().string() << " - protection failed: " << perr.message() << "\n";
                        fail_count++;
                        continue;
                    }
                    if (!pres.protected_data.empty()) {
                        protected_payload = std::move(pres.protected_data);
                    }
                    protection_meta = std::move(pres.protection_meta);
                    meta.encrypted_sections = std::move(pres.encrypted_sections);
                }

                CodecId actual_codec_id = CodecId::Store;
                if (codec_ptr->id() == "zstd") actual_codec_id = CodecId::ZSTD;
                else if (codec_ptr->id() == "lz4") actual_codec_id = CodecId::LZ4;
                else if (codec_ptr->id() == "lzma") actual_codec_id = CodecId::LZMA;
                else if (codec_ptr->id() == "apultra") actual_codec_id = CodecId::ApUltra;

                meta.compression_settings = (static_cast<uint32_t>(prof) << 16) | bo.level;
                meta.codec_id = actual_codec_id;
                meta.payload_size = protected_payload.size();
                meta.stub_size = stub_data.size();
                meta.metadata_offset = stub_data.size();
                meta.metadata_size = sizeof(NxMetadataHeader) + sizeof(uint32_t);
                meta.payload_offset = stub_data.size() + meta.metadata_size;

                auto meta_buf = serialize_metadata(meta);
                meta.metadata_size = meta_buf.size();
                meta.payload_offset = stub_data.size() + meta.metadata_size;

                if (!protection_meta.empty()) {
                    meta.integrity_offset = meta.payload_offset + meta.payload_size;
                    meta.integrity_size = protection_meta.size();
                }

                meta_buf = serialize_metadata(meta);
                meta.metadata_size = meta_buf.size();
                meta.payload_offset = stub_data.size() + meta.metadata_size;

                if (!protection_meta.empty()) {
                    meta.integrity_offset = meta.payload_offset + meta.payload_size;
                }

                uint8_t footer[8];
                for (int i = 0; i < 8; i++)
                    footer[i] = static_cast<uint8_t>((meta.metadata_offset >> (8 * i)) & 0xFF);

                std::vector<uint8_t> packed;
                packed.reserve(stub_data.size() + meta_buf.size() + protected_payload.size() +
                               protection_meta.size() + 8);
                packed.insert(packed.end(), stub_data.begin(), stub_data.end());
                packed.insert(packed.end(), meta_buf.begin(), meta_buf.end());
                packed.insert(packed.end(), protected_payload.begin(), protected_payload.end());
                packed.insert(packed.end(), protection_meta.begin(), protection_meta.end());
                packed.insert(packed.end(), footer, footer + 8);

                if (!write_file(output_str,
                                std::string_view(reinterpret_cast<const char*>(packed.data()),
                                                 packed.size()),
                                e)) {
                    std::cerr << "  FAIL: " << input_path.filename().string() << " - " << e.message() << "\n";
                    fail_count++;
                    continue;
                }

                std::cout << "  OK: " << input_path.filename().string()
                          << " -> " << packed.size() << " bytes\n";
                success_count++;
            }

            std::cout << "\nBatch complete: " << success_count << " succeeded, " << fail_count << " failed\n";

            if (bo.json) {
                std::cout << "{ \"input\": \"" << json_escape(bo.input)
                          << "\", \"batch\": true, \"profile\": \"" << bo.profile
                          << "\", \"codec\": \"" << bo.codec_id
                          << "\", \"protection\": \"" << bo.protection
                          << "\", \"success\": " << success_count
                          << ", \"failed\": " << fail_count << " }\n";
            }

            return fail_count > 0 ? 1 : 0;
        }
        case Cli::Command::Codecs: {
            CodecRegistry registry;
            if (cli.codecs_options().json) {
                std::cout << "{ \"codecs\": [";
                bool first = true;
                for (size_t i = 0; i < registry.count(); ++i) {
                    if (!first) std::cout << ", ";
                    first = false;
                    const Codec* c = registry.at(i);
                    std::cout << "{ \"id\": \"" << c->id()
                              << "\", \"name\": \"" << c->name()
                              << "\", \"version\": \"" << c->version() << "\" }";
                }
                std::cout << "] }\n";
            } else {
                std::cout << "Available codecs:\n";
                for (size_t i = 0; i < registry.count(); ++i) {
                    Codec* c = registry.at(i);
                    std::cout << "  " << c->id() << " - " << c->name()
                              << " v" << c->version() << "\n";
                }
            }
            return 0;
        }
        case Cli::Command::Profiles: {
            if (cli.profiles_options().json) {
                std::cout << "{ \"profiles\": [";
                bool first = true;
                static const std::string profiles[] = {"fast", "balanced", "maximum", "auto", "custom"};
                for (const auto& p : profiles) {
                    if (!first) std::cout << ", ";
                    first = false;
                    std::cout << "\"" << p << "\"";
                }
                std::cout << "] }\n";
            } else {
                std::cout << "Compression profiles:\n";
                std::cout << "  fast      - Fast compression, lower ratio\n";
                std::cout << "  balanced  - Balanced compression and speed (default)\n";
                std::cout << "  maximum   - Maximum compression, slower\n";
                std::cout << "  auto      - Automatic selection based on input analysis\n";
                std::cout << "  custom    - Custom configuration\n";
            }
            return 0;
        }
        default:
            std::cerr << "nexapack: command not yet implemented ("
                      << static_cast<int>(cli.command()) << ")\n";
            return 1;
    }
}

} // namespace nexapack

int main(int argc, char* argv[]) {
    return nexapack::run(argc, argv);
}