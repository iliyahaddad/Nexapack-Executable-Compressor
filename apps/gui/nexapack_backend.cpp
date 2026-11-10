#include "nexapack_backend.hpp"

#include <QCoreApplication>
#include <QFileInfo>
#include <QDir>
#include <QStandardPaths>
#include <QDateTime>

#include <core/error.hpp>
#include <core/logging.hpp>
#include <core/metadata.hpp>
#include <core/codec_interface.hpp>
#include <codecs/codec_registry.hpp>
#include <core/analyzer/analyzer.hpp>
#include <core/planner/planner.hpp>
#include <protection/nexaprotect/nexaprotect.hpp>

#include <fstream>
#include <sstream>
#include <climits>

namespace nexapack {

using planner::PackContext;
using planner::PlanResult;
using nexaprotect::ProtectionProfile;

static std::vector<uint8_t> read_file_bytes(const QString& path, Error& err) {
    std::ifstream file(path.toStdString(), std::ios::binary);
    if (!file) {
        err = make_error(ErrorCategory::Io, 1, "cannot open file: " + path.toStdString());
        return {};
    }
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(file)),
                                 std::istreambuf_iterator<char>());
}

static bool write_file_bytes(const QString& path, const std::vector<uint8_t>& data, Error& err) {
    std::ofstream out(path.toStdString(), std::ios::binary | std::ios::trunc);
    if (!out) {
        err = make_error(ErrorCategory::Io, 2, "cannot write file: " + path.toStdString());
        return false;
    }
    out.write(reinterpret_cast<const char*>(data.data()),
              static_cast<std::streamsize>(data.size()));
    return out.good();
}

static std::string resolve_stub_path(const QString& stub_name) {
    QDir appDir(QCoreApplication::applicationDirPath());
    QStringList searchPaths = {
        appDir.filePath(stub_name),
        QStandardPaths::writableLocation(QStandardPaths::AppDataLocation) + "/" + stub_name,
        stub_name
    };
    for (const QString& sp : searchPaths) {
        QFileInfo fi(sp);
        if (fi.exists() && fi.isFile()) {
            return sp.toStdString();
        }
    }
    return "";
}

NexaPackBackend::NexaPackBackend(QObject* parent)
    : QObject(parent)
    , m_version("1.0.0")
    , m_isBusy(false)
    , m_currentStatus("Ready")
{
    CodecRegistry registry;
    for (size_t i = 0; i < registry.count(); ++i) {
        const Codec* c = registry.at(i);
        m_codecs << QString::fromStdString(std::string(c->id()));
    }

    m_profiles << "fast" << "balanced" << "maximum" << "auto" << "custom";
    m_protectionProfiles << "none" << "basic" << "standard" << "advanced" << "maximum";
}

QString NexaPackBackend::version() const {
    return m_version;
}

QStringList NexaPackBackend::codecs() const {
    return m_codecs;
}

QStringList NexaPackBackend::profiles() const {
    return m_profiles;
}

QStringList NexaPackBackend::protectionProfiles() const {
    return m_protectionProfiles;
}

bool NexaPackBackend::isBusy() const {
    return m_isBusy;
}

QString NexaPackBackend::currentStatus() const {
    return m_currentStatus;
}

void NexaPackBackend::setBusy(bool busy) {
    if (m_isBusy != busy) {
        m_isBusy = busy;
        emit isBusyChanged();
    }
}

void NexaPackBackend::setStatus(const QString& status) {
    if (m_currentStatus != status) {
        m_currentStatus = status;
        emit currentStatusChanged();
    }
}

QVariantMap NexaPackBackend::analyzeExecutable(const QString& filePath) {
    QVariantMap result;
    result["success"] = false;

    QFileInfo fileInfo(filePath);
    if (!fileInfo.exists() || !fileInfo.isFile()) {
        result["error"] = "File not found";
        return result;
    }

    Error err;
    auto data = read_file_bytes(filePath, err);
    if (!err.ok()) {
        result["error"] = QString::fromStdString(std::string(err.message()));
        return result;
    }

    analyzer::CompatibilityReport report;
    report.input_path = filePath.toStdString();
    err = analyzer::analyze_executable(
        std::string_view(reinterpret_cast<const char*>(data.data()), data.size()),
        report);

    if (!err.ok()) {
        result["error"] = QString::fromStdString(std::string(err.message()));
        return result;
    }

    result["success"] = true;
    result["format"] = QString::fromStdString(std::string(report.format_name));
    result["architecture"] = QString::fromStdString(std::string(report.architecture_name));
    result["packable"] = report.packable;
    result["executable"] = report.executable;
    result["compatibility"] = QString::fromStdString(std::string(report.compatibility_name));
    result["size"] = (qint64)data.size();

    QStringList notes;
    for (const auto& note : report.notes) {
        notes << QString::fromStdString(std::string(note));
    }
    result["notes"] = notes;

    return result;
}

QVariantMap NexaPackBackend::packExecutable(const QString& inputPath,
                                             const QString& outputPath,
                                             const QString& codec,
                                             const QString& profile,
                                             const QString& protectionProfile,
                                             uint32_t level) {
    QVariantMap result;
    result["success"] = false;

    setBusy(true);
    setStatus("Analyzing input...");

    QFileInfo inputInfo(inputPath);
    if (!inputInfo.exists()) {
        setBusy(false);
        setStatus("Error: input file not found");
        result["error"] = "Input file not found";
        return result;
    }

    Error err;
    auto input_data = read_file_bytes(inputPath, err);
    if (!err.ok()) {
        setBusy(false);
        setStatus("Error: cannot read input file");
        result["error"] = QString::fromStdString(std::string(err.message()));
        return result;
    }

    analyzer::CompatibilityReport report;
    report.input_path = inputPath.toStdString();
    err = analyzer::analyze_executable(
        std::string_view(reinterpret_cast<const char*>(input_data.data()),
                         input_data.size()),
        report);
    if (!err.ok()) {
        setBusy(false);
        setStatus("Error: cannot analyze input");
        result["error"] = QString::fromStdString(std::string(err.message()));
        return result;
    }

    if (report.format != analyzer::ExecutableFormat::PE32Plus) {
        setBusy(false);
        setStatus("Error: only PE32+ supported for now");
        result["error"] = "Only PE32+ format supported for packing";
        return result;
    }

    PackMetadata meta;
    meta.original_file_size = input_data.size();
    meta.target_format = TargetFormat::PE32Plus;
    meta.architecture = Architecture::X64;

    QString stubName = (report.type == analyzer::ExecutableType::Dll) ? "stub_dll.dll" : "stub.exe";
    std::string stub_path = resolve_stub_path(stubName);
    if (stub_path.empty()) {
        setBusy(false);
        setStatus("Error: runtime stub not found");
        result["error"] = "Runtime stub not found: " + stubName;
        return result;
    }

    auto stub = read_file_bytes(QString::fromStdString(std::string(stub_path)), err);
    if (!err.ok()) {
        setBusy(false);
        setStatus("Error: cannot load runtime stub");
        result["error"] = QString::fromStdString(std::string(err.message()));
        return result;
    }

    PackContext pctx;
    pctx.input_path = inputPath.toStdString();
    pctx.input_data = std::string_view(reinterpret_cast<const char*>(input_data.data()), input_data.size());
    pctx.profile = CompressionProfile::Balanced;
    pctx.target_format = meta.target_format;
    pctx.architecture = Architecture::X64;
    pctx.input_size = input_data.size();
    pctx.stub_size = stub.size();
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
        setBusy(false);
        setStatus("Error: planning failed");
        result["error"] = QString::fromStdString(std::string(err.message()));
        return result;
    }

    emit packingProgress(10);

    Codec* codec_ptr = nullptr;
    if (codec != "auto") {
        for (size_t ci = 0; ci < registry.count(); ++ci) {
            const Codec* c = registry.at(ci);
            if (c->id() == codec.toStdString()) {
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
        setBusy(false);
        setStatus("Error: codec not found");
        result["error"] = "Codec not found: " + codec;
        return result;
    }

    CompressionProfile prof;
    if (profile == "fast") prof = CompressionProfile::Fast;
    else if (profile == "balanced") prof = CompressionProfile::Balanced;
    else if (profile == "maximum") prof = CompressionProfile::Maximum;
    else if (profile == "auto") prof = CompressionProfile::Auto;
    else prof = CompressionProfile::Custom;

    setStatus("Compressing...");
    EncodeResult enc = codec_ptr->compress(
        std::string_view(reinterpret_cast<const char*>(input_data.data()), input_data.size()),
        prof, level);
    if (!enc.error.ok()) {
        setBusy(false);
        setStatus("Error: compression failed");
        result["error"] = QString::fromStdString(std::string(enc.error.message()));
        return result;
    }

    emit packingProgress(40);

    ProtectionProfile pprofile;
    if (protectionProfile == "basic") pprofile = ProtectionProfile::Basic;
    else if (protectionProfile == "standard") pprofile = ProtectionProfile::Standard;
    else if (protectionProfile == "advanced") pprofile = ProtectionProfile::Advanced;
    else if (protectionProfile == "maximum") pprofile = ProtectionProfile::Maximum;
    else pprofile = ProtectionProfile::None;

    std::vector<uint8_t> protected_payload = enc.compressed;
    std::vector<uint8_t> protection_meta;
    if (pprofile != ProtectionProfile::None) {
        setStatus("Applying protection...");
        nexaprotect::ProtectionConfig pconfig;
        pconfig.profile = pprofile;
        nexaprotect::ProtectionResult pres;
        Error perr = nexaprotect::apply_protection(
            std::string_view(reinterpret_cast<const char*>(enc.compressed.data()),
                             enc.compressed.size()),
            pconfig, pres);
        if (!perr.ok()) {
            setBusy(false);
            setStatus("Error: protection failed");
            result["error"] = QString::fromStdString(std::string(perr.message()));
            return result;
        }
        if (!pres.protected_data.empty()) {
            protected_payload = std::move(pres.protected_data);
        }
        protection_meta = std::move(pres.protection_meta);
        meta.encrypted_sections = std::move(pres.encrypted_sections);
    }

    emit packingProgress(60);

    CodecId actual_codec_id = CodecId::Store;
    if (codec_ptr->id() == "zstd") actual_codec_id = CodecId::ZSTD;
    else if (codec_ptr->id() == "lz4") actual_codec_id = CodecId::LZ4;
    else if (codec_ptr->id() == "lzma") actual_codec_id = CodecId::LZMA;
    else if (codec_ptr->id() == "apultra") actual_codec_id = CodecId::ApUltra;

    meta.compression_settings = (static_cast<uint32_t>(prof) << 16) | level;
    meta.codec_id = actual_codec_id;
    meta.payload_size = protected_payload.size();
    meta.stub_size = stub.size();
    meta.metadata_offset = stub.size();
    meta.metadata_size = sizeof(NxMetadataHeader) + sizeof(uint32_t);
    meta.payload_offset = stub.size() + meta.metadata_size;

    auto meta_buf = serialize_metadata(meta);
    meta.metadata_size = meta_buf.size();
    meta.payload_offset = stub.size() + meta.metadata_size;

    if (!protection_meta.empty()) {
        meta.integrity_offset = meta.payload_offset + meta.payload_size;
    }

    meta_buf = serialize_metadata(meta);
    meta.metadata_size = meta_buf.size();
    meta.payload_offset = stub.size() + meta.metadata_size;

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
    packed.insert(packed.end(), protected_payload.begin(), protected_payload.end());
    packed.insert(packed.end(), protection_meta.begin(), protection_meta.end());
    packed.insert(packed.end(), footer, footer + 8);

    setStatus("Writing output...");
    if (!write_file_bytes(outputPath, packed, err)) {
        setBusy(false);
        setStatus("Error: cannot write output file");
        result["error"] = QString::fromStdString(std::string(err.message()));
        return result;
    }

    emit packingProgress(100);
    setBusy(false);
    setStatus("Packing complete");

    result["success"] = true;
    result["outputPath"] = outputPath;
    result["originalSize"] = (qint64)input_data.size();
    result["packedSize"] = (qint64)packed.size();
    result["codec"] = codec;
    result["profile"] = profile;
    result["protectionProfile"] = protectionProfile;

    emit packingFinished(true, "Packing completed successfully");
    return result;
}

QVariantMap NexaPackBackend::unpackExecutable(const QString& inputPath,
                                               const QString& outputPath) {
    QVariantMap result;
    result["success"] = false;

    setBusy(true);
    setStatus("Reading packed file...");

    Error err;
    auto packed = read_file_bytes(inputPath, err);
    if (!err.ok()) {
        setBusy(false);
        setStatus("Error: cannot read packed file");
        result["error"] = QString::fromStdString(std::string(err.message()));
        return result;
    }

    size_t meta_offset = packed.size();
    for (size_t i = packed.size(); i > 8; i--) {
        if (packed[i - 1] == 0x00 && packed[i - 2] == 0x00) {
            meta_offset = i - 8;
            break;
        }
    }

    PackMetadata meta;
    err = deserialize_metadata(
        std::string_view(reinterpret_cast<const char*>(packed.data() + meta_offset),
                         sizeof(NxMetadataHeader)),
        meta);
    if (!err.ok()) {
        setBusy(false);
        setStatus("Error: invalid metadata");
        result["error"] = QString::fromStdString(std::string(err.message()));
        return result;
    }

    setStatus("Decompressing payload...");

    CodecRegistry registry;
    Codec* codec = nullptr;
    if (meta.codec_id == CodecId::ZSTD) codec = registry.find("zstd");
    else if (meta.codec_id == CodecId::LZ4) codec = registry.find("lz4");
    else if (meta.codec_id == CodecId::Store) codec = registry.find("store");
    else if (meta.codec_id == CodecId::LZMA) codec = registry.find("lzma");

    if (!codec) {
        setBusy(false);
        setStatus("Error: codec not available");
        result["error"] = "Codec not available: " + QString::number(static_cast<uint32_t>(meta.codec_id));
        return result;
    }

    std::string_view payload(
        reinterpret_cast<const char*>(packed.data() + meta.payload_offset),
        meta.payload_size);
    DecodeResult dec = codec->decompress(payload, meta.original_file_size);
    if (!dec.error.ok()) {
        setBusy(false);
        setStatus("Error: decompression failed");
        result["error"] = QString::fromStdString(std::string(dec.error.message()));
        return result;
    }

    emit packingProgress(80);

    if (!write_file_bytes(outputPath,
                          std::vector<uint8_t>(dec.decompressed.begin(), dec.decompressed.end()),
                          err)) {
        setBusy(false);
        setStatus("Error: cannot write output file");
        result["error"] = QString::fromStdString(std::string(err.message()));
        return result;
    }

    setBusy(false);
    setStatus("Unpacking complete");

    result["success"] = true;
    result["outputPath"] = outputPath;
    result["originalSize"] = (qint64)meta.original_file_size;

    emit unpackingFinished(true, "Unpacking completed successfully");
    return result;
}

QVariantMap NexaPackBackend::verifyExecutable(const QString& filePath) {
    QVariantMap result;
    result["success"] = false;

    QFileInfo fileInfo(filePath);
    if (!fileInfo.exists() || !fileInfo.isFile()) {
        result["error"] = "File not found";
        return result;
    }

    Error err;
    auto packed = read_file_bytes(filePath, err);
    if (!err.ok()) {
        result["error"] = QString::fromStdString(std::string(err.message()));
        return result;
    }

    size_t meta_offset = packed.size();
    for (size_t i = packed.size(); i > 8; i--) {
        if (packed[i - 1] == 0x00 && packed[i - 2] == 0x00) {
            meta_offset = i - 8;
            break;
        }
    }

    PackMetadata meta;
    err = deserialize_metadata(
        std::string_view(reinterpret_cast<const char*>(packed.data() + meta_offset),
                         sizeof(NxMetadataHeader)),
        meta);
    if (!err.ok()) {
        result["error"] = QString::fromStdString(std::string(err.message()));
        return result;
    }

    bool tampered = false;
    if (meta.integrity_offset != 0 && meta.integrity_size > 0 &&
        meta.integrity_offset + meta.integrity_size <= packed.size()) {
        std::string_view integrity_meta(
            reinterpret_cast<const char*>(packed.data() + meta.integrity_offset),
            meta.integrity_size);
        Error verify_err = nexaprotect::verify_protection(
            std::string_view(reinterpret_cast<const char*>(packed.data() + meta.payload_offset),
                             meta.payload_size),
            integrity_meta, tampered);
        if (!verify_err.ok()) {
            result["error"] = QString::fromStdString(std::string(verify_err.message()));
            return result;
        }
    }

    result["success"] = true;
    result["codec"] = static_cast<int>(meta.codec_id);
    result["originalSize"] = (qint64)meta.original_file_size;
    result["packedSize"] = (qint64)packed.size();
    result["tampered"] = tampered;

    return result;
}

QVariantMap NexaPackBackend::benchmarkExecutable(const QString& filePath) {
    QVariantMap result;
    result["success"] = false;

    QFileInfo fileInfo(filePath);
    if (!fileInfo.exists() || !fileInfo.isFile()) {
        result["error"] = "File not found";
        return result;
    }

    Error err;
    auto input = read_file_bytes(filePath, err);
    if (!err.ok()) {
        result["error"] = QString::fromStdString(std::string(err.message()));
        return result;
    }

    analyzer::CompatibilityReport report;
    report.input_path = filePath.toStdString();
    err = analyzer::analyze_executable(
        std::string_view(reinterpret_cast<const char*>(input.data()), input.size()),
        report);

    if (!err.ok()) {
        result["error"] = QString::fromStdString(std::string(err.message()));
        return result;
    }

    result["success"] = true;
    result["format"] = QString::fromStdString(std::string(report.format_name));
    result["architecture"] = QString::fromStdString(std::string(report.architecture_name));
    result["originalSize"] = (qint64)input.size();

    CodecRegistry registry;
    uint64_t stub_size = 0;
    {
        std::string stub_path = resolve_stub_path("stub.exe");
        if (!stub_path.empty()) {
            auto stub_data = read_file_bytes(QString::fromStdString(std::string(stub_path)), err);
            stub_size = stub_data.size();
        }
    }

    QVariantList codecResults;
    uint64_t best_final = ULLONG_MAX;
    QString best_codec;
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
            auto t0 = QDateTime::currentMSecsSinceEpoch();
            EncodeResult enc = codec->compress(
                std::string_view(reinterpret_cast<const char*>(input.data()), input.size()),
                CompressionProfile::Balanced, lvl);
            auto t1 = QDateTime::currentMSecsSinceEpoch();

            if (!enc.error.ok()) continue;

            auto t2 = QDateTime::currentMSecsSinceEpoch();
            DecodeResult dec = codec->decompress(
                std::string_view(reinterpret_cast<const char*>(enc.compressed.data()),
                                 enc.compressed_size),
                input.size());
            auto t3 = QDateTime::currentMSecsSinceEpoch();

            if (!dec.error.ok() || dec.decompressed_size != input.size())
                continue;

            uint64_t metadata_size = sizeof(NxMetadataHeader) + sizeof(uint32_t);
            uint64_t final_size = enc.compressed_size + stub_size + metadata_size;
            double ratio = (double)input.size() / (double)final_size;

            QVariantMap entry;
            entry["codec"] = QString::fromStdString(std::string(codec->id()));
            entry["version"] = QString::fromStdString(codec->version());
            entry["level"] = (qint32)lvl;
            entry["compressedSize"] = (qint64)enc.compressed_size;
            entry["stubSize"] = (qint64)stub_size;
            entry["metadataSize"] = (qint64)metadata_size;
            entry["finalSize"] = (qint64)final_size;
            entry["ratio"] = ratio;
            entry["compressMs"] = (double)(t1 - t0);
            entry["decompressMs"] = (double)(t3 - t2);
            codecResults.append(entry);

            if (final_size < best_final) {
                best_final = final_size;
                best_codec = QString::fromStdString(std::string(codec->id()));
                best_level = lvl;
            }
        }
    }

    result["codecResults"] = codecResults;
    result["bestCodec"] = best_codec;
    result["bestLevel"] = (qint32)best_level;
    result["bestSize"] = (qint64)best_final;

    return result;
}

QVariantList NexaPackBackend::listCodecs() {
    QVariantList list;
    CodecRegistry registry;
    for (size_t i = 0; i < registry.count(); ++i) {
        const Codec* c = registry.at(i);
        QVariantMap entry;
        entry["id"] = QString::fromStdString(std::string(c->id()));
        entry["name"] = QString::fromStdString(std::string(c->name()));
        entry["version"] = QString::fromStdString(std::string(c->version()));
        CodecCapabilities cap = c->capabilities();
        entry["supportsCompression"] = cap.supports_compression;
        entry["supportsDecompression"] = cap.supports_decompression;
        entry["minLevel"] = (qint32)cap.min_level;
        entry["maxLevel"] = (qint32)cap.max_level;
        list.append(entry);
    }
    return list;
}

} // namespace nexapack
