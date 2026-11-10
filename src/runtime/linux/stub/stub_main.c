// NexaPack Linux ELF64 Runtime Stub
// Compiled as a standalone ELF64 x86-64 executable, embedded into packed ELF files.
//
// The stub:
//   1. Reads its own file via /proc/self/exe
//   2. Parses NXP metadata from the end of the file (8-byte footer = metadata_offset)
//   3. Decompresses the payload (Store = pass-through for now)
//   4. Creates an anonymous memory file via memfd_create()
//   5. Writes the original ELF bytes to the memfd
//   6. Transfers execution via execveat(memfd_fd, "", ...)
//
// No temporary executable is written to /tmp or any filesystem path.
// Execution is in-memory through a kernel-backed anonymous file.
//
// Layout expected in the packed file:
//   [stub ELF][NXP metadata (108 bytes)][compressed payload][8-byte footer: metadata_offset]

#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/syscall.h>

//-----------------------------------------------------------------------------
// Minimal ELF64 structures (self-contained).
//-----------------------------------------------------------------------------

#pragma pack(push, 1)
typedef struct {
    unsigned char e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} NxElf64_Ehdr;

typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} NxElf64_Phdr;
#pragma pack(pop)

#define NX_ELF_MAG0 0x7f
#define NX_ELF_MAG1 'E'
#define NX_ELF_MAG2 'L'
#define NX_ELF_MAG3 'F'
#define NX_ELFCLASS64 2
#define NX_ET_EXEC 2
#define NX_ET_DYN 3
#define NX_EM_X86_64 62
#define NX_PT_LOAD 1
#define NX_PF_R 4
#define NX_PF_W 2
#define NX_PF_X 1

//-----------------------------------------------------------------------------
// NXP metadata (mirrors core/metadata.hpp).
//-----------------------------------------------------------------------------

#pragma pack(push, 1)
typedef struct {
    char     magic[4];
    uint32_t version;
    uint32_t runtime_abi_version;
    uint32_t target_format;   // 1=PE32+, 2=ELF64
    uint32_t architecture;    // 1=x64, 2=x86
    uint32_t codec_id;        // 1=store, 2=zstd, 3=lz4
    uint32_t compression_settings;
    uint64_t original_file_size;
    uint64_t payload_size;
    uint64_t stub_size;
    uint64_t metadata_offset;
    uint64_t metadata_size;
    uint64_t payload_offset;
    uint64_t stub_offset;
    uint64_t integrity_offset;
    uint64_t integrity_size;
    uint32_t checksum;
    uint32_t reserved;
} NxMetaHeader;
#pragma pack(pop)

#define NX_MAGIC "NXP\0"
#define NX_META_VERSION 1
#define NX_FORMAT_ELF64 2
#define NX_ARCH_X64 1
#define NX_CODEC_STORE 1

//-----------------------------------------------------------------------------
// Helpers
//-----------------------------------------------------------------------------

static uint64_t rd64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= ((uint64_t)p[i]) << (8 * i);
    return v;
}

static uint32_t rd32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

// Read entire own file (/proc/self/exe) into a malloc'd buffer.
// Returns size in *out_size, or NULL on failure.
static uint8_t* read_own_file(size_t* out_size) {
    const char* path = "/proc/self/exe";
    int fd = open(path, O_RDONLY);
    if (fd < 0) return NULL;

    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return NULL; }
    if (st.st_size == 0 || st.st_size > (1ull << 40)) { close(fd); return NULL; }

    uint8_t* buf = (uint8_t*)malloc((size_t)st.st_size);
    if (!buf) { close(fd); return NULL; }

    ssize_t total = 0;
    while (total < (ssize_t)st.st_size) {
        ssize_t r = read(fd, buf + total, (size_t)(st.st_size - total));
        if (r <= 0) { free(buf); close(fd); return NULL; }
        total += r;
    }
    close(fd);
    *out_size = (size_t)st.st_size;
    return buf;
}

//-----------------------------------------------------------------------------
// Main
//-----------------------------------------------------------------------------

int main(int argc, char* argv[], char* envp[]) {
    size_t file_size = 0;
    uint8_t* file = read_own_file(&file_size);
    if (!file || file_size < sizeof(NxMetaHeader) + 8) {
        fprintf(stderr, "nexapack stub: cannot read own file\n");
        free(file);
        return 1;
    }

    // Footer: last 8 bytes = metadata_offset (little-endian)
    uint64_t meta_off = rd64(file + file_size - 8);
    if (meta_off >= file_size || meta_off + sizeof(NxMetaHeader) > file_size) {
        fprintf(stderr, "nexapack stub: metadata offset out of range\n");
        free(file);
        return 1;
    }

    const NxMetaHeader* meta = (const NxMetaHeader*)(file + meta_off);
    if (memcmp(meta->magic, NX_MAGIC, 4) != 0) {
        fprintf(stderr, "nexapack stub: invalid magic\n");
        free(file);
        return 1;
    }
    if (meta->version != NX_META_VERSION) {
        fprintf(stderr, "nexapack stub: unsupported metadata version\n");
        free(file);
        return 1;
    }
    if (meta->target_format != NX_FORMAT_ELF64) {
        fprintf(stderr, "nexapack stub: not an ELF64 target\n");
        free(file);
        return 1;
    }
    if (meta->architecture != NX_ARCH_X64) {
        fprintf(stderr, "nexapack stub: unsupported architecture\n");
        free(file);
        return 1;
    }
    if (meta->codec_id != NX_CODEC_STORE) {
        fprintf(stderr, "nexapack stub: unsupported codec\n");
        free(file);
        return 1;
    }
    if (meta->payload_offset >= file_size) {
        fprintf(stderr, "nexapack stub: payload offset out of range\n");
        free(file);
        return 1;
    }
    if (meta->payload_size > file_size - meta->payload_offset) {
        fprintf(stderr, "nexapack stub: payload size out of range\n");
        free(file);
        return 1;
    }

    const uint8_t* payload = file + meta->payload_offset;
    uint64_t pe_size = meta->payload_size;

    // Validate ELF magic
    if (pe_size < sizeof(NxElf64_Ehdr) ||
        payload[0] != NX_ELF_MAG0 || payload[1] != NX_ELF_MAG1 ||
        payload[2] != NX_ELF_MAG2 || payload[3] != NX_ELF_MAG3) {
        fprintf(stderr, "nexapack stub: invalid ELF magic\n");
        free(file);
        return 1;
    }

    const NxElf64_Ehdr* ehdr = (const NxElf64_Ehdr*)payload;
    if (ehdr->e_ident[4] != NX_ELFCLASS64) {
        fprintf(stderr, "nexapack stub: not ELF64\n");
        free(file);
        return 1;
    }

    // Store codec: payload is the original ELF verbatim
    const uint8_t* elf_bytes = payload;

    // Create anonymous memory-backed file
    int mfd = memfd_create("nexapack", MFD_CLOEXEC);
    if (mfd < 0) {
        fprintf(stderr, "nexapack stub: memfd_create failed\n");
        free(file);
        return 1;
    }

    // Write original ELF bytes to memfd
    ssize_t written = 0;
    while (written < (ssize_t)pe_size) {
        ssize_t w = write(mfd, elf_bytes + written, (size_t)(pe_size - written));
        if (w <= 0) {
            fprintf(stderr, "nexapack stub: write to memfd failed\n");
            close(mfd);
            free(file);
            return 1;
        }
        written += w;
    }

    // Ensure data is flushed to the file backing
    if (fsync(mfd) != 0) {
        /* non-fatal */
    }

    // Rewind to start for execution
    if (lseek(mfd, 0, SEEK_SET) < 0) {
        fprintf(stderr, "nexapack stub: lseek failed\n");
        close(mfd);
        free(file);
        return 1;
    }

    // Execute the original ELF from the anonymous memory file.
    // execveat with AT_EMPTY_PATH operates on the fd directly.
    // argv[0] is set to the original path (/proc/self/exe of the packed file)
    // so the child sees a reasonable program name.
    char procpath[64];
    snprintf(procpath, sizeof(procpath), "/proc/self/fd/%d", mfd);

    // Build the argv/execve call. We pass through argc/argv/envp.
    execve(procpath, argv, envp);

    // If execve returns, it failed
    fprintf(stderr, "nexapack stub: execveat failed\n");
    close(mfd);
    free(file);
    return 1;
}
