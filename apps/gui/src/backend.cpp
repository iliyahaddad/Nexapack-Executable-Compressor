#include "backend.hpp"

#include <QCoreApplication>
#include <QGuiApplication>
#include <QStandardPaths>

#include <algorithm>

namespace nexapack {

Backend::Backend(QObject* parent)
    : QObject(parent) {
    registry_ = std::make_unique<CodecRegistry>();
}

Backend::~Backend() = default;

QString Backend::version() const {
    return QString("0.1.0");
}

QVariantMap Backend::codecs() const {
    QVariantMap result;
    QVariantList list;
    for (size_t i = 0; i < registry_->count(); ++i) {
        const Codec* c = registry_->at(i);
        QVariantMap entry;
        entry["id"] = QString::fromStdString(c->id());
        entry["name"] = QString::fromStdString(c->name());
        entry["version"] = QString::fromStdString(c->version());
        list.append(entry);
    }
    result["codecs"] = list;
    return result;
}

QStringList Backend::profiles() const {
    return {"fast", "balanced", "maximum", "auto", "custom"};
}

QString Backend::platform() const {
#ifdef Q_OS_WIN
    return "Windows";
#elif defined(Q_OS_LINUX)
    return "Linux";
#else
    return "Unknown";
#endif
}

// Resolve the path to a runtime stub deployed alongside the packer executable.
QString resolve_stub_path(const QString& stub_name) {
    QString dir = QCoreApplication::applicationDirPath();
    if (dir.isEmpty()) return QString();
    QString path = dir + "/" + stub_name;
    QFileInfo info(path);
    if (info.exists() && info.isFile()) return path;
    return QString();
}

QVariantMap Backend::inspectFile(const QString& path) {
    QVariantMap result;
    result["success"] = false;

    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        result["error"] = "Cannot open file: " + path;
        return result;
    }
    QByteArray data = file.readAll();
    file.close();

    analyzer::CompatibilityReport report;
    report.input_path = path.toStdString();
    Error err = analyzer::analyze_executable(
        std::string_view(reinterpret_cast<const char*>(data.constData()),
                         data.size()),
        report);
    if (!err.ok()) {
        result["error"] = QString::fromStdString(err.message());
        return result;
    }

    result["success"] = true;
    result["format"] = QString::fromStdString(report.format_name);
    result["architecture"] = QString::fromStdString(report.architecture_name);
    result["os"] = QString::fromStdString(report.os_name);
    result["type"] = QString::fromStdString(report.type_name);
    result["compatibility"] = QString::fromStdString(report.compatibility_name);
    result["packable"] = report.packable;
    result["executable"] = report.executable;

    QVariantList sections;
    for (const auto& s : report.sections) {
        sections.append(QString::fromStdString(s));
    }
    result["sections"] = sections;

    QVariantList notes;
    for (const auto& n : report.notes) {
        notes.append(QString::fromStdString(n));
    }
    result["notes"] = notes;

    QVariantList warnings;
    for (const auto& w : report.warnings) {
        warnings.append(QString::fromStdString(w));
    }
    result["warnings"] = warnings;

    return result;
}

QVariantMap Backend::packFile(const QString& input,
                              const QString& output,
                              const QString& profile,
                              const QString& codec,
                              const QString& protection) {
    QVariantMap result;
    result["success"] = false;

    // Convert profile string to enum
    CompressionProfile prof = CompressionProfile::Balanced;
    if (profile == "fast") prof = CompressionProfile::Fast;
    else if (profile == "balanced") prof = CompressionProfile::Balanced;
    else if (profile == "maximum") prof = CompressionProfile::Maximum;
    else if (profile == "auto") prof = CompressionProfile::Auto;
    else if (profile == "custom") prof = CompressionProfile::Custom;

    // Read input
    QFile inFile(input);
    if (!inFile.open(QIODevice::ReadOnly)) {
        result["error"] = "Cannot open input: " + input;
        return result;
    }
    QByteArray inData = inFile.readAll();
    inFile.close();

    // Analyze
    analyzer::CompatibilityReport report;
    report.input_path = input.toStdString();
    Error err = analyzer::analyze_executable(
        std::string_view(reinterpret_cast<const char*>(inData.constData()),
                         inData.size()),
        report);
    if (!err.ok()) {
        result["error"] = "Analysis failed: " + QString::fromStdString(err.message());
        return result;
    }

    // Select codec
    Codec* selectedCodec = nullptr;
    for (size_t i = 0; i < registry_->count(); ++i) {
        Codec* c = registry_->at(i);
        if (c->id() == codec.toStdString()) {
            selectedCodec = c;
            break;
        }
    }
    if (!selectedCodec) {
        selectedCodec = registry_->find("zstd");
        if (!selectedCodec) selectedCodec = registry_->find("store");
    }

    // Compress
    EncodeResult enc = selectedCodec->compress(
        std::string_view(reinterpret_cast<const char*>(inData.constData()),
                         inData.size()),
        prof, 3);
    if (!enc.error.ok()) {
        result["error"] = "Compression failed: " + QString::fromStdString(enc.error.message());
        return result;
    }

    // Build metadata
    PackMetadata meta;
    meta.target_format = report.format == ExecutableFormat::PE32Plus
                             ? TargetFormat::PE32Plus
                             : TargetFormat::ELF64;
    meta.architecture = Architecture::X64;
    meta.codec_id = (selectedCodec->id() == "zstd")   ? CodecId::ZSTD
                    : (selectedCodec->id() == "lz4")  ? CodecId::LZ4
                                                      : CodecId::Store;
    meta.compression_settings = (static_cast<uint32_t>(prof) << 16) | 3;
    meta.original_file_size = inData.size();
    meta.payload_size = enc.compressed_size;

    // Determine stub
    QString stubPath;
    if (report.format == ExecutableFormat::PE32Plus) {
        meta.architecture = Architecture::X64;
        if (report.type == ExecutableType::Dll) {
            stubPath = resolve_stub_path("stub_dll.dll");
        } else {
            stubPath = resolve_stub_path("stub.exe");
        }
    } else if (report.format == ExecutableFormat::ELF64) {
        meta.architecture = Architecture::X64;
        stubPath = resolve_stub_path("stub");
    } else {
        result["error"] = "Unsupported input format for packing: " +
                          QString::fromStdString(report.format_name);
        return result;
    }

    if (stubPath.isEmpty()) {
        result["error"] = "Runtime stub not found. Deploy stub binaries alongside nexapack.";
        return result;
    }

    QFile stubFile(stubPath);
    if (!stubFile.open(QIODevice::ReadOnly)) {
        result["error"] = "Cannot load runtime stub: " + stubPath;
        return result;
    }
    QByteArray stubData = stubFile.readAll();
    stubFile.close();

    meta.stub_size = stubData.size();
    meta.metadata_size = sizeof(NxMetadataHeader);
    meta.metadata_offset = meta.stub_size;
    meta.payload_offset = meta.metadata_offset + meta.metadata_size;

    auto metaBuf = serialize_metadata(meta);
    meta.metadata_offset = meta.stub_size;

    uint8_t footer[8];
    for (int i = 0; i < 8; i++)
        footer[i] = static_cast<uint8_t>((meta.metadata_offset >> (8 * i)) & 0xFF);

    std::vector<uint8_t> packed;
    packed.reserve(stubData.size() + metaBuf.size() +
                   enc.compressed.size() + 8);
    packed.insert(packed.end(), stubData.begin(), stubData.end());
    packed.insert(packed.end(), metaBuf.begin(), metaBuf.end());
    packed.insert(packed.end(), enc.compressed.begin(), enc.compressed.end());
    packed.insert(packed.end(), footer, footer + 8);

    QFile outFile(output);
    if (!outFile.open(QIODevice::WriteOnly)) {
        result["error"] = "Cannot write output: " + output;
        return result;
    }
    outFile.write(reinterpret_cast<const char*>(packed.data()),
                  static_cast<qint64>(packed.size()));
    outFile.close();

    result["success"] = true;
    result["input"] = input;
    result["output"] = output;
    result["codec"] = QString::fromStdString(selectedCodec->id());
    result["format"] = QString::fromStdString(report.format_name);
    result["original_size"] = (qint64)inData.size();
    result["packed_size"] = (qint64)packed.size();
    result["planned_final_size"] = (qint64)metaBuf.size() + stubData.size() +
                                   enc.compressed.size() + 8;

    emit operationFinished("pack", true, "Packing completed successfully");
    return result;
}

QVariantMap Backend::unpackFile(const QString& input,
                                const QString& output) {
    QVariantMap result;
    result["success"] = false;

    QFile inFile(input);
    if (!inFile.open(QIODevice::ReadOnly)) {
        result["error"] = "Cannot open input: " + input;
        return result;
    }
    QByteArray packed = inFile.readAll();
    inFile.close();

    if (packed.size() < sizeof(NxMetadataHeader) + 8) {
        result["error"] = "File too small for metadata + footer";
        return result;
    }

    // Footer: last 8 bytes = metadata_offset
    uint64_t metaOffset = 0;
    const uint8_t* data = reinterpret_cast<const uint8_t*>(packed.constData());
    for (int i = 0; i < 8; i++)
        metaOffset |= ((uint64_t)data[packed.size() - 8 + i]) << (8 * i);

    if (metaOffset + sizeof(NxMetadataHeader) > packed.size()) {
        result["error"] = "Metadata offset out of range";
        return result;
    }

    PackMetadata meta;
    Error err = deserialize_metadata(
        std::string_view(reinterpret_cast<const char*>(data + metaOffset),
                         sizeof(NxMetadataHeader)),
        meta);
    if (!err.ok()) {
        result["error"] = "Invalid metadata: " + QString::fromStdString(err.message());
        return result;
    }

    if (meta.payload_offset >= packed.size()) {
        result["error"] = "Payload offset out of range";
        return result;
    }
    if (meta.payload_size > packed.size() - meta.payload_offset) {
        result["error"] = "Payload size out of range";
        return result;
    }

    Codec* codec = nullptr;
    for (size_t i = 0; i < registry_->count(); ++i) {
        Codec* c = registry_->at(i);
        if ((c->id() == "zstd" && meta.codec_id == CodecId::ZSTD) ||
            (c->id() == "lz4" && meta.codec_id == CodecId::LZ4) ||
            (c->id() == "store" && meta.codec_id == CodecId::Store)) {
            codec = c;
            break;
        }
    }
    if (!codec) {
        result["error"] = "Codec not available for unpacking";
        return result;
    }

    std::string_view payload(
        reinterpret_cast<const char*>(data + meta.payload_offset),
        meta.payload_size);
    DecodeResult dec = codec->decompress(payload, meta.original_file_size);
    if (!dec.error.ok()) {
        result["error"] = "Decompression failed: " +
                          QString::fromStdString(dec.error.message());
        return result;
    }

    QFile outFile(output);
    if (!outFile.open(QIODevice::WriteOnly)) {
        result["error"] = "Cannot write output: " + output;
        return result;
    }
    outFile.write(reinterpret_cast<const char*>(dec.decompressed.data()),
                  static_cast<qint64>(dec.decompressed.size()));
    outFile.close();

    result["success"] = true;
    result["input"] = input;
    result["output"] = output;
    result["codec"] = QString::fromStdString(codec->id());
    result["original_size"] = (qint64)meta.original_file_size;
    result["unpacked_size"] = (qint64)dec.decompressed_size;

    emit operationFinished("unpack", true, "Unpacking completed successfully");
    return result;
}

} // namespace nexapack
