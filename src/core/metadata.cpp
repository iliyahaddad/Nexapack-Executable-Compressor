#include "core/metadata.hpp"
#include "core/error.hpp"
#include "core/logging.hpp"

#include <algorithm>
#include <cstring>

namespace nexapack {

namespace {

constexpr uint8_t kEndianTag = 0x01; // 1 = little-endian

void write_le16(std::vector<uint8_t>& buf, size_t& off, uint16_t v) {
    buf[off + 0] = static_cast<uint8_t>(v & 0xFF);
    buf[off + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
    off += 2;
}

void write_le32(std::vector<uint8_t>& buf, size_t& off, uint32_t v) {
    buf[off + 0] = static_cast<uint8_t>(v & 0xFF);
    buf[off + 1] = static_cast<uint8_t>((v >> 8) & 0xFF);
    buf[off + 2] = static_cast<uint8_t>((v >> 16) & 0xFF);
    buf[off + 3] = static_cast<uint8_t>((v >> 24) & 0xFF);
    off += 4;
}

void write_le64(std::vector<uint8_t>& buf, size_t& off, uint64_t v) {
    for (int i = 0; i < 8; i++) {
        buf[off + i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFF);
    }
    off += 8;
}

uint16_t read_le16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}

uint32_t read_le32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

uint64_t read_le64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v |= static_cast<uint64_t>(p[i]) << (8 * i);
    }
    return v;
}

} // namespace

std::vector<uint8_t> serialize_metadata(const PackMetadata& meta) {
    size_t total_size = sizeof(NxMetadataHeader) +
                        sizeof(uint32_t) + // num_encrypted_sections always written
                        meta.encrypted_sections.size() * sizeof(NxSectionEncryption);
    std::vector<uint8_t> buf(total_size);
    size_t off = 0;

    // Magic
    std::memcpy(buf.data() + off, kNxMagic.data(), 4);
    off += 4;

    write_le32(buf, off, kNxMetadataVersion);            // version
    write_le32(buf, off, 1);                             // runtime_abi_version
    write_le32(buf, off, static_cast<uint32_t>(meta.target_format));
    write_le32(buf, off, static_cast<uint32_t>(meta.architecture));
    write_le32(buf, off, static_cast<uint32_t>(meta.codec_id));
    write_le32(buf, off, meta.compression_settings);
    write_le64(buf, off, meta.original_file_size);
    write_le64(buf, off, meta.payload_size);
    write_le64(buf, off, meta.stub_size);
    write_le64(buf, off, meta.metadata_offset);
    write_le64(buf, off, meta.metadata_size);
    write_le64(buf, off, meta.payload_offset);
    write_le64(buf, off, meta.stub_offset);
    write_le64(buf, off, meta.integrity_offset);
    write_le64(buf, off, meta.integrity_size);
    write_le32(buf, off, meta.checksum);
    write_le32(buf, off, 0);                             // reserved
    write_le32(buf, off, meta.num_encrypted_sections);

    // Section encryption entries
    for (const auto& enc : meta.encrypted_sections) {
        write_le32(buf, off, enc.first);
        write_le64(buf, off, enc.second);
    }

    nexapack::nxp_log(nexapack::LogLevel::Debug, "serialized metadata block of " + std::to_string(buf.size()) + " bytes");
    return buf;
}

Error deserialize_metadata(std::string_view buffer, PackMetadata& out) {
    if (buffer.size() < sizeof(NxMetadataHeader)) {
        return make_error(ErrorCategory::Format, 1,
                          "metadata buffer too small: " + std::to_string(buffer.size()) +
                          " bytes, need " + std::to_string(sizeof(NxMetadataHeader)));
    }

    const uint8_t* p = reinterpret_cast<const uint8_t*>(buffer.data());

    if (std::memcmp(p, kNxMagic.data(), 4) != 0) {
        return make_error(ErrorCategory::Format, 2, "invalid NexaPack magic identifier");
    }

    uint32_t version = read_le32(p + 4);
    if (version != kNxMetadataVersion) {
        return make_error(ErrorCategory::Format, 3,
                          "unsupported metadata version " + std::to_string(version));
    }

    // runtime_abi_version at p + 8 (reserved for future ABI checks)
    out.target_format = static_cast<TargetFormat>(read_le32(p + 12));
    out.architecture = static_cast<Architecture>(read_le32(p + 16));
    out.codec_id = static_cast<CodecId>(read_le32(p + 20));
    out.compression_settings = read_le32(p + 24);
    out.original_file_size = read_le64(p + 28);
    out.payload_size = read_le64(p + 36);
    out.stub_size = read_le64(p + 44);
    out.metadata_offset = read_le64(p + 52);
    out.metadata_size = read_le64(p + 60);
    out.payload_offset = read_le64(p + 68);
    out.stub_offset = read_le64(p + 76);
    out.integrity_offset = read_le64(p + 84);
    out.integrity_size = read_le64(p + 92);
    out.checksum = read_le32(p + 100);

    // Read section encryption entries
    uint32_t num_encrypted = 0;
    if (buffer.size() >= sizeof(NxMetadataHeader) + sizeof(uint32_t)) {
        num_encrypted = read_le32(p + 108);
    }
    out.num_encrypted_sections = num_encrypted;
    size_t expected_size = sizeof(NxMetadataHeader) +
                           static_cast<size_t>(num_encrypted) * sizeof(NxSectionEncryption);
    if (buffer.size() < expected_size) {
        return make_error(ErrorCategory::Format, 4,
                          "metadata buffer too small: " + std::to_string(buffer.size()) +
                          " bytes, need " + std::to_string(expected_size));
    }

    const NxSectionEncryption* enc_entries =
        reinterpret_cast<const NxSectionEncryption*>(p + sizeof(NxMetadataHeader));
    for (uint32_t i = 0; i < num_encrypted; i++) {
        out.encrypted_sections.push_back({enc_entries[i].section_index, enc_entries[i].xor_key});
    }

    nexapack::nxp_log(nexapack::LogLevel::Debug, "deserialized metadata: codec=" +
                       std::to_string(static_cast<uint32_t>(out.codec_id)) +
                       " format=" + std::to_string(static_cast<uint32_t>(out.target_format)) +
                       " encrypted_sections=" + std::to_string(num_encrypted));
    return ok_error();
}

} // namespace nexapack
