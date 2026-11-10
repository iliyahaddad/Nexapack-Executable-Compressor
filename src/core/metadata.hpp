#ifndef NEXAPACK_CORE_METADATA_HPP
#define NEXAPACK_CORE_METADATA_HPP

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "core/error.hpp"

namespace nexapack {

// NexaPack on-disk metadata format. All multi-byte integer fields use explicit
// fixed-width types and little-endian encoding. This structure is the logical
// definition; serialization is performed field-by-field (see metadata.cpp) so
// that no compiler struct-packing assumption is ever relied upon.

#pragma pack(push, 1)
struct NxMetadataHeader {
    char     magic[4];                 // "NXP\0"
    uint32_t version;                  // metadata format version (2)
    uint32_t runtime_abi_version;      // Runtime ABI version
    uint32_t target_format;            // 1=PE32+, 2=ELF64
    uint32_t architecture;             // 1=x64, 2=x86
    uint32_t codec_id;                 // codec identifier
    uint32_t compression_settings;     // profile / level bitmask
    uint64_t original_file_size;       // size of the original executable
    uint64_t payload_size;             // compressed payload size in bytes
    uint64_t stub_size;                // runtime stub size in bytes
    uint64_t metadata_offset;          // file offset to this metadata block
    uint64_t metadata_size;            // size of this metadata block in bytes
    uint64_t payload_offset;           // file offset to compressed payload
    uint64_t stub_offset;              // file offset to runtime stub
    uint64_t integrity_offset;         // file offset to integrity block (0 if none)
    uint64_t integrity_size;           // size of integrity block (0 if none)
    uint32_t checksum;                 // CRC32 of original file (for verification)
    uint32_t reserved;
};
#pragma pack(pop)

static_assert(sizeof(NxMetadataHeader) == 108, "NxMetadataHeader must be 108 bytes");

// Section encryption metadata follows NxMetadataHeader:
#pragma pack(push, 1)
struct NxSectionEncryption {
    uint32_t section_index;   // index into section table (0-based)
    uint64_t xor_key;         // XOR key for this section
};
#pragma pack(pop)

static_assert(sizeof(NxSectionEncryption) == 12, "NxSectionEncryption must be 12 bytes");

enum class TargetFormat : uint32_t {
    Unknown = 0,
    PE32Plus = 1,
    ELF64 = 2,
};

enum class Architecture : uint32_t {
    Unknown = 0,
    X64 = 1,
    X86 = 2,
};

enum class CodecId : uint32_t {
    Unknown = 0,
    Store = 1,
    ZSTD = 2,
    LZ4 = 3,
    LZMA = 4,
    ApUltra = 5,
};

struct PackMetadata {
    TargetFormat target_format = TargetFormat::Unknown;
    Architecture architecture = Architecture::Unknown;
    CodecId codec_id = CodecId::Unknown;
    uint32_t compression_settings = 0;
    uint64_t original_file_size = 0;
    uint64_t payload_size = 0;
    uint64_t stub_size = 0;
    uint64_t metadata_offset = 0;
    uint64_t metadata_size = 0;
    uint64_t payload_offset = 0;
    uint64_t stub_offset = 0;
    uint64_t integrity_offset = 0;
    uint64_t integrity_size = 0;
    uint32_t checksum = 0;
    // Section encryption metadata
    uint32_t num_encrypted_sections = 0;
    std::vector<std::pair<uint32_t, uint64_t>> encrypted_sections; // (section_index, xor_key)
};

// Serialize PackMetadata into a byte buffer in little-endian order.
std::vector<uint8_t> serialize_metadata(const PackMetadata& meta);

// Deserialize PackMetadata from a little-endian byte buffer.
// Returns an error if the buffer is too small or the magic is invalid.
Error deserialize_metadata(std::string_view buffer, PackMetadata& out);

constexpr std::string_view kNxMagic = "NXP\0";
constexpr uint32_t kNxMetadataVersion = 2;

} // namespace nexapack

#endif // NEXAPACK_CORE_METADATA_HPP

