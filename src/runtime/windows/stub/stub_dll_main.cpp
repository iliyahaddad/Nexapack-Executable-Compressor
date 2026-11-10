// NexaPack Windows PE Runtime Stub (DLL variant)
// Compiled as a standalone DLL, embedded into packed DLLs.
//
// The stub:
//   1. Reads its own packed file via GetModuleFileNameW(hinstDLL, ...)
//   2. Parses NXP metadata from the end of the file (8-byte footer = metadata_offset)
//   3. Decompresses the payload (Store / ZSTD / LZ4)
//   4. Reconstructs the original PE image in memory (VirtualAlloc)
//   5. Applies base relocations and resolves imports
//   6. Calls the original DLL's entry point (DllMain) with DLL_PROCESS_ATTACH
//
// No temporary executable is written to disk. Execution is in-memory.
//
// Layout expected in the packed file:
//   [stub DLL][NXP metadata (108 bytes)][compressed payload][8-byte footer: metadata_offset]
//
// Limitations:
//   - Export forwarding is not yet implemented. GetProcAddress on the packed
//     DLL handle will not resolve the original DLL's exports.
//   - Store, ZSTD, LZ4, and LZMA decompression are supported.

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <stdint.h>
#include <windows.h>
#include <cstdlib>

#include "zstd.h"
#include "lz4.h"
#include "LzmaDec.h"

// Simple malloc/free allocator for LZMA SDK in the stub.
static void* SzAllocStub(ISzAllocPtr p, size_t size) { return std::malloc(size); }
static void SzFreeStub(ISzAllocPtr p, void* address) { std::free(address); }
static const ISzAlloc g_Alloc = { SzAllocStub, SzFreeStub };

//-----------------------------------------------------------------------------
// Minimal PE structures (self-contained).
//-----------------------------------------------------------------------------

#pragma pack(push, 1)
typedef struct _NX_DOS_HEADER {
    char   e_magic[2];
    uint16_t e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc;
    uint16_t e_ss, e_sp, e_csum, e_ip, e_cs, e_lfarlc, e_ovno;
    uint16_t e_res[4], e_oemid, e_oeminfo, e_res2[10];
    uint32_t e_lfanew;
} NX_DOS_HEADER;

typedef struct _NX_FILE_HEADER {
    uint16_t Machine, NumberOfSections;
    uint32_t TimeDateStamp, PointerToSymbolTable, NumberOfSymbols;
    uint16_t SizeOfOptionalHeader, Characteristics;
} NX_FILE_HEADER;

typedef struct _NX_OPTIONAL_HEADER64 {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion, MinorLinkerVersion;
    uint32_t SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint, BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment, FileAlignment;
    uint16_t MajorOperatingSystemVersion, MinorOperatingSystemVersion;
    uint16_t MajorImageVersion, MinorImageVersion;
    uint16_t MajorSubsystemVersion, MinorSubsystemVersion;
    uint32_t Win32VersionValue, SizeOfImage, SizeOfHeaders, CheckSum;
    uint16_t Subsystem, DllCharacteristics;
    uint64_t SizeOfStackReserve, SizeOfStackCommit;
    uint64_t SizeOfHeapReserve, SizeOfHeapCommit;
    uint32_t LoaderFlags, NumberOfRvaAndSizes;
} NX_OPTIONAL_HEADER64;

typedef struct _NX_DATA_DIRECTORY { uint32_t VirtualAddress, Size; } NX_DATA_DIRECTORY;

typedef struct _NX_SECTION_HEADER {
    char Name[8];
    uint32_t VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData;
    uint32_t PointerToRelocations, PointerToLinenumbers;
    uint16_t NumberOfRelocations, NumberOfLinenumbers;
    uint32_t Characteristics;
} NX_SECTION_HEADER;

typedef struct _NX_IMPORT_DESCRIPTOR {
    uint32_t OriginalFirstThunk, TimeDateStamp, ForwarderChain, Name, FirstThunk;
} NX_IMPORT_DESCRIPTOR;

typedef struct _NX_BASE_RELOCATION { uint32_t VirtualAddress, SizeOfBlock; } NX_BASE_RELOCATION;

typedef struct _NX_EXPORT_DIRECTORY {
    uint32_t Characteristics;
    uint32_t TimeDateStamp;
    uint16_t MajorVersion;
    uint16_t MinorVersion;
    uint32_t Name;
    uint32_t Base;
    uint32_t NumberOfFunctions;
    uint32_t NumberOfNames;
    uint32_t AddressOfFunctions;
    uint32_t AddressOfNames;
    uint32_t AddressOfNameOrdinals;
} NX_EXPORT_DIRECTORY;

typedef struct _NX_SECTION_ENCRYPTION {
    uint32_t section_index;
    uint64_t xor_key;
} NX_SECTION_ENCRYPTION;
#pragma pack(pop)

#define NX_NT_SIGNATURE 0x00004550
#define NX_DIR_EXPORT 0
#define NX_DIR_IMPORT 1
#define NX_DIR_BASERELOC 5
#define NX_REL_DIR64 10
#define NX_REL_HIGHLOW 3

//-----------------------------------------------------------------------------
// NXP metadata (v2).
//-----------------------------------------------------------------------------

#pragma pack(push, 1)
typedef struct _NX_META_HEADER {
    char     magic[4];
    uint32_t version, runtime_abi_version, target_format, architecture, codec_id;
    uint32_t compression_settings;
    uint64_t original_file_size, payload_size, stub_size;
    uint64_t metadata_offset, metadata_size, payload_offset;
    uint64_t stub_offset, integrity_offset, integrity_size;
    uint32_t checksum, reserved;
    uint32_t num_encrypted_sections;
} NX_META_HEADER;
#pragma pack(pop)

#define NX_MAGIC "NXP\0"
#define NX_META_VERSION 2
#define NX_CODEC_STORE 1
#define NX_CODEC_ZSTD 2
#define NX_CODEC_LZ4 3
#define NX_CODEC_LZMA 4

//-----------------------------------------------------------------------------
// Global state for export forwarding.
// pe_buf_alloc is intentionally never freed — export lookups need it.
static uint8_t* g_dll_image_base = NULL;
static const uint8_t* g_dll_pe_buf = NULL;
static const NX_FILE_HEADER* g_dll_fh = NULL;
static const NX_SECTION_HEADER* g_dll_sec = NULL;
static uint8_t* g_dll_pe_buf_alloc = NULL;

// Forward declarations (defined later in this file).
static uint8_t* rva_to_ptr(uint8_t* image_base, const NX_FILE_HEADER* fh,
                           const NX_SECTION_HEADER* sec, uint32_t rva);
static int nx_memcmp(const void* s1, const void* s2, size_t n);

// Resolve an exported function by name from the reconstructed PE image.
static FARPROC dll_get_proc_address(const char* name) {
    if (!g_dll_image_base || !g_dll_pe_buf || !g_dll_fh || !g_dll_sec) {
        return NULL;
    }

    const NX_DOS_HEADER* dos = (const NX_DOS_HEADER*)g_dll_pe_buf;
    const uint8_t* nt = g_dll_pe_buf + dos->e_lfanew;
    const NX_OPTIONAL_HEADER64* oh =
        (const NX_OPTIONAL_HEADER64*)(nt + 4 + sizeof(NX_FILE_HEADER));
    const NX_DATA_DIRECTORY* dirs =
        (const NX_DATA_DIRECTORY*)((const uint8_t*)oh +
                                   sizeof(NX_OPTIONAL_HEADER64));
    const NX_DATA_DIRECTORY* exp = &dirs[NX_DIR_EXPORT];
    if (exp->Size == 0 || exp->VirtualAddress == 0) {
        return NULL;
    }

    const NX_EXPORT_DIRECTORY* ed =
        (const NX_EXPORT_DIRECTORY*)rva_to_ptr(g_dll_image_base, g_dll_fh,
                                                g_dll_sec, exp->VirtualAddress);
    if (!ed) return NULL;

    const uint32_t* name_rvas =
        (const uint32_t*)rva_to_ptr(g_dll_image_base, g_dll_fh, g_dll_sec,
                                    ed->AddressOfNames);
    const uint16_t* ordinals =
        (const uint16_t*)rva_to_ptr(g_dll_image_base, g_dll_fh, g_dll_sec,
                                    ed->AddressOfNameOrdinals);
    const uint32_t* func_rvas =
        (const uint32_t*)rva_to_ptr(g_dll_image_base, g_dll_fh, g_dll_sec,
                                    ed->AddressOfFunctions);
    if (!name_rvas || !ordinals || !func_rvas) return NULL;

    for (uint32_t i = 0; i < ed->NumberOfNames; i++) {
        const char* export_name =
            (const char*)rva_to_ptr(g_dll_image_base, g_dll_fh, g_dll_sec,
                                    name_rvas[i]);
        if (!export_name) continue;
        // Compare up to 256 bytes, stopping at null terminator.
        bool match = true;
        for (int j = 0; j < 256; j++) {
            char c1 = export_name[j];
            char c2 = name[j];
            if (c1 != c2) { match = false; break; }
            if (c1 == '\0') break;
        }
        if (match) {
            uint16_t ordinal = ordinals[i];
            uint32_t func_rva = func_rvas[ordinal];
            uint8_t* func_addr =
                rva_to_ptr(g_dll_image_base, g_dll_fh, g_dll_sec, func_rva);
            if (!func_addr) return NULL;
            return (FARPROC)(uintptr_t)func_addr;
        }
    }
    return NULL;
}

// Get export name by index for enumeration.
static const char* dll_get_export_name(uint32_t index) {
    if (!g_dll_image_base || !g_dll_pe_buf || !g_dll_fh || !g_dll_sec) {
        return NULL;
    }

    const NX_DOS_HEADER* dos = (const NX_DOS_HEADER*)g_dll_pe_buf;
    const uint8_t* nt = g_dll_pe_buf + dos->e_lfanew;
    const NX_OPTIONAL_HEADER64* oh =
        (const NX_OPTIONAL_HEADER64*)(nt + 4 + sizeof(NX_FILE_HEADER));
    const NX_DATA_DIRECTORY* dirs =
        (const NX_DATA_DIRECTORY*)((const uint8_t*)oh +
                                   sizeof(NX_OPTIONAL_HEADER64));
    const NX_DATA_DIRECTORY* exp = &dirs[NX_DIR_EXPORT];
    if (exp->Size == 0 || exp->VirtualAddress == 0) {
        return NULL;
    }

    const NX_EXPORT_DIRECTORY* ed =
        (const NX_EXPORT_DIRECTORY*)rva_to_ptr(g_dll_image_base, g_dll_fh,
                                                g_dll_sec, exp->VirtualAddress);
    if (!ed || index >= ed->NumberOfNames) return NULL;

    const uint32_t* name_rvas =
        (const uint32_t*)rva_to_ptr(g_dll_image_base, g_dll_fh, g_dll_sec,
                                    ed->AddressOfNames);
    if (!name_rvas) return NULL;

    return (const char*)rva_to_ptr(g_dll_image_base, g_dll_fh, g_dll_sec,
                                   name_rvas[index]);
}

// Get total number of exported names.
static uint32_t dll_get_export_count(void) {
    if (!g_dll_image_base || !g_dll_pe_buf || !g_dll_fh || !g_dll_sec) {
        return 0;
    }

    const NX_DOS_HEADER* dos = (const NX_DOS_HEADER*)g_dll_pe_buf;
    const uint8_t* nt = g_dll_pe_buf + dos->e_lfanew;
    const NX_OPTIONAL_HEADER64* oh =
        (const NX_OPTIONAL_HEADER64*)(nt + 4 + sizeof(NX_FILE_HEADER));
    const NX_DATA_DIRECTORY* dirs =
        (const NX_DATA_DIRECTORY*)((const uint8_t*)oh +
                                   sizeof(NX_OPTIONAL_HEADER64));
    const NX_DATA_DIRECTORY* exp = &dirs[NX_DIR_EXPORT];
    if (exp->Size == 0 || exp->VirtualAddress == 0) {
        return 0;
    }

    const NX_EXPORT_DIRECTORY* ed =
        (const NX_EXPORT_DIRECTORY*)rva_to_ptr(g_dll_image_base, g_dll_fh,
                                                g_dll_sec, exp->VirtualAddress);
    if (!ed) return 0;
    return ed->NumberOfNames;
}

//-----------------------------------------------------------------------------
// Helpers (no CRT dependency)
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

static void* nx_memcpy(void* dst, const void* src, size_t n) {
    volatile uint8_t* d = (volatile uint8_t*)dst;
    const volatile uint8_t* s = (const volatile uint8_t*)src;
    for (size_t i = 0; i < n; i++) d[i] = s[i];
    return dst;
}

static void* nx_memset(void* dst, int c, size_t n) {
    volatile uint8_t* d = (volatile uint8_t*)dst;
    uint8_t v = (uint8_t)c;
    for (size_t i = 0; i < n; i++) d[i] = v;
    return dst;
}

static int nx_memcmp(const void* s1, const void* s2, size_t n) {
    const volatile uint8_t* a = (const volatile uint8_t*)s1;
    const volatile uint8_t* b = (const volatile uint8_t*)s2;
    for (size_t i = 0; i < n; i++) {
        if (a[i] != b[i]) return (int)(a[i] - b[i]);
    }
    return 0;
}

// Read entire own file into allocated buffer.
static uint8_t* read_own_file(HMODULE hmod, size_t* out_size) {
    wchar_t path[MAX_PATH];
    if (GetModuleFileNameW(hmod, path, MAX_PATH) == 0) return NULL;
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    LARGE_INTEGER fsize;
    if (!GetFileSizeEx(h, &fsize)) { CloseHandle(h); return NULL; }
    if (fsize.QuadPart == 0 || fsize.QuadPart > (1ull << 40)) {
        CloseHandle(h);
        return NULL;
    }
    uint8_t* buf = (uint8_t*)VirtualAlloc(NULL, (SIZE_T)fsize.QuadPart,
                                          MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf) { CloseHandle(h); return NULL; }
    DWORD read = 0;
    if (!ReadFile(h, buf, (DWORD)fsize.QuadPart, &read, NULL) || read != fsize.QuadPart) {
        VirtualFree(buf, 0, MEM_RELEASE);
        CloseHandle(h);
        return NULL;
    }
    CloseHandle(h);
    *out_size = fsize.QuadPart;
    return buf;
}

// Map RVA to in-memory pointer using section table.
static uint8_t* rva_to_ptr(uint8_t* image_base, const NX_FILE_HEADER* fh,
                           const NX_SECTION_HEADER* sec, uint32_t rva) {
    for (uint16_t i = 0; i < fh->NumberOfSections; i++) {
        if (rva >= sec[i].VirtualAddress &&
            rva < sec[i].VirtualAddress + sec[i].VirtualSize) {
            return image_base + sec[i].VirtualAddress + (rva - sec[i].VirtualAddress);
        }
    }
    return NULL;
}

// Apply base relocations.
static bool apply_relocations(uint8_t* image, uint64_t delta,
                              const uint8_t* pe_buf) {
    const NX_DOS_HEADER* dos = (const NX_DOS_HEADER*)pe_buf;
    const uint8_t* nt = pe_buf + dos->e_lfanew;
    const NX_FILE_HEADER* fh = (const NX_FILE_HEADER*)(nt + 4);
    const NX_OPTIONAL_HEADER64* oh =
        (const NX_OPTIONAL_HEADER64*)(nt + 4 + sizeof(NX_FILE_HEADER));
    const NX_DATA_DIRECTORY* dirs =
        (const NX_DATA_DIRECTORY*)((const uint8_t*)oh +
                                   sizeof(NX_OPTIONAL_HEADER64));
    const NX_DATA_DIRECTORY* reloc = &dirs[NX_DIR_BASERELOC];
    if (reloc->Size == 0 || reloc->VirtualAddress == 0) return true;

    const NX_SECTION_HEADER* sec =
        (const NX_SECTION_HEADER*)((const uint8_t*)oh +
                                   sizeof(NX_OPTIONAL_HEADER64) +
                                   oh->NumberOfRvaAndSizes * sizeof(NX_DATA_DIRECTORY));

    uint8_t* reloc_start = rva_to_ptr(image, fh, sec, reloc->VirtualAddress);
    if (!reloc_start) return false;

    uint32_t end = reloc->VirtualAddress + reloc->Size;
    uint32_t cur = reloc->VirtualAddress;
    while (cur < end) {
        const NX_BASE_RELOCATION* block =
            (const NX_BASE_RELOCATION*)(reloc_start + (cur - reloc->VirtualAddress));
        uint32_t count = (block->SizeOfBlock - sizeof(NX_BASE_RELOCATION)) / 2;
        const uint16_t* entries = (const uint16_t*)(block + 1);
        uint8_t* block_base = rva_to_ptr(image, fh, sec, block->VirtualAddress);
        if (!block_base) return false;
        for (uint32_t i = 0; i < count; i++) {
            uint16_t entry = entries[i];
            uint32_t type = entry >> 12, off = entry & 0xFFF;
            if (type == NX_REL_DIR64) {
                *(uint64_t*)(block_base + off) += delta;
            } else if (type == NX_REL_HIGHLOW) {
                *(uint32_t*)(block_base + off) += (uint32_t)delta;
            }
        }
        cur += block->SizeOfBlock;
    }
    return true;
}

// Resolve imports.
static bool resolve_imports(uint8_t* image, const uint8_t* pe_buf) {
    const NX_DOS_HEADER* dos = (const NX_DOS_HEADER*)pe_buf;
    const uint8_t* nt = pe_buf + dos->e_lfanew;
    const NX_FILE_HEADER* fh = (const NX_FILE_HEADER*)(nt + 4);
    const NX_OPTIONAL_HEADER64* oh =
        (const NX_OPTIONAL_HEADER64*)(nt + 4 + sizeof(NX_FILE_HEADER));
    const NX_DATA_DIRECTORY* dirs =
        (const NX_DATA_DIRECTORY*)((const uint8_t*)oh +
                                   sizeof(NX_OPTIONAL_HEADER64));
    const NX_DATA_DIRECTORY* imp = &dirs[NX_DIR_IMPORT];
    if (imp->Size == 0 || imp->VirtualAddress == 0) return true;

    const NX_SECTION_HEADER* sec =
        (const NX_SECTION_HEADER*)((const uint8_t*)oh +
                                   sizeof(NX_OPTIONAL_HEADER64) +
                                   oh->NumberOfRvaAndSizes * sizeof(NX_DATA_DIRECTORY));

    uint8_t* imp_start = rva_to_ptr(image, fh, sec, imp->VirtualAddress);
    if (!imp_start) return false;

    uint32_t end = imp->VirtualAddress + imp->Size;
    uint32_t cur = imp->VirtualAddress;
    while (cur < end) {
        const NX_IMPORT_DESCRIPTOR* desc =
            (const NX_IMPORT_DESCRIPTOR*)(imp_start + (cur - imp->VirtualAddress));
        if (desc->Name == 0) break;
        const char* dll_name = (const char*)rva_to_ptr(image, fh, sec, desc->Name);
        if (!dll_name) return false;
        HMODULE hmod = LoadLibraryA(dll_name);
        if (!hmod) return false;
        uint8_t* iat = rva_to_ptr(image, fh, sec, desc->FirstThunk);
        uint8_t* ilt = rva_to_ptr(image, fh, sec, desc->OriginalFirstThunk);
        if (!iat) return false;
        if (!ilt) ilt = iat;
        uint32_t idx = 0;
        while (true) {
            uint64_t thunk = rd64(ilt + idx * 8);
            if (thunk == 0) break;
            uint8_t* addr = iat + idx * 8;
            if (thunk & 0x8000000000000000ull) {
                FARPROC proc = GetProcAddress(hmod, (LPCSTR)(uintptr_t)(uint16_t)thunk);
                if (!proc) return false;
                *(uint64_t*)addr = (uint64_t)(uintptr_t)proc;
            } else {
                const char* name = (const char*)rva_to_ptr(image, fh, sec, (uint32_t)thunk);
                if (!name) return false;
                name += 2; // skip hint
                FARPROC proc = GetProcAddress(hmod, name);
                if (!proc) return false;
                *(uint64_t*)addr = (uint64_t)(uintptr_t)proc;
            }
            idx++;
        }
        cur += sizeof(NX_IMPORT_DESCRIPTOR);
    }
    return true;
}

// Decompress payload using the appropriate codec.
static bool decompress_payload(const uint8_t* payload, uint64_t payload_size,
                               uint32_t codec_id, uint64_t expected_size,
                               uint8_t** out_buf, uint64_t* out_size) {
    if (codec_id == NX_CODEC_STORE) {
        *out_buf = (uint8_t*)VirtualAlloc(NULL, (SIZE_T)expected_size,
                                          MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!*out_buf) return false;
        nx_memcpy(*out_buf, payload, (size_t)expected_size);
        *out_size = expected_size;
        return true;
    }

    if (codec_id == NX_CODEC_ZSTD) {
        long long content_size = ZSTD_getFrameContentSize(payload, payload_size);
        if (content_size < 0) return false;
        uint64_t out_sz = (expected_size != 0) ? expected_size
                                               : (uint64_t)content_size;
        uint8_t* out = (uint8_t*)VirtualAlloc(NULL, (SIZE_T)out_sz,
                                              MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!out) return false;
        size_t rc = ZSTD_decompress(out, out_sz, payload, payload_size);
        if (ZSTD_isError(rc)) {
            VirtualFree(out, 0, MEM_RELEASE);
            return false;
        }
        *out_buf = out;
        *out_size = rc;
        return true;
    }

    if (codec_id == NX_CODEC_LZ4) {
        if (expected_size == 0) return false;
        uint8_t* out = (uint8_t*)VirtualAlloc(NULL, (SIZE_T)expected_size,
                                              MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!out) return false;
        int rc = LZ4_decompress_safe((const char*)payload, (char*)out,
                                     (int)payload_size, (int)expected_size);
        if (rc < 0) {
            VirtualFree(out, 0, MEM_RELEASE);
            return false;
        }
        *out_buf = out;
        *out_size = (uint64_t)rc;
        return true;
    }

    if (codec_id == NX_CODEC_LZMA) {
        if (payload_size < LZMA_PROPS_SIZE) return false;
        CLzmaProps props;
        SRes res = LzmaProps_Decode(&props,
                                    reinterpret_cast<const Byte*>(payload),
                                    LZMA_PROPS_SIZE);
        if (res != SZ_OK) return false;

        CLzmaDec dec;
        LzmaDec_Construct(&dec);
        res = LzmaDec_Allocate(&dec,
                               reinterpret_cast<const Byte*>(payload),
                               LZMA_PROPS_SIZE, &g_Alloc);
        if (res != SZ_OK) return false;

        LzmaDec_Init(&dec);

        SizeT lzma_out_size = static_cast<SizeT>(expected_size);
        uint8_t* out = (uint8_t*)VirtualAlloc(NULL, (SIZE_T)lzma_out_size,
                                              MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!out) {
            LzmaDec_Free(&dec, &g_Alloc);
            return false;
        }

        const Byte* src = payload + LZMA_PROPS_SIZE;
        SizeT src_size = static_cast<SizeT>(payload_size) - LZMA_PROPS_SIZE;
        ELzmaStatus status;
        res = LzmaDec_DecodeToBuf(&dec, out, &lzma_out_size, src, &src_size,
                                  LZMA_FINISH_ANY, &status);

        bool ok = (res == SZ_OK);
        if (!ok) {
            VirtualFree(out, 0, MEM_RELEASE);
            LzmaDec_Free(&dec, &g_Alloc);
            return false;
        }

        LzmaDec_Free(&dec, &g_Alloc);
        *out_buf = out;
        *out_size = lzma_out_size;
        return true;
    }

    return false; // unsupported codec
}

// Set section memory protections.
static void set_protections(uint8_t* image, const NX_FILE_HEADER* fh,
                            const NX_SECTION_HEADER* sec) {
    for (uint16_t i = 0; i < fh->NumberOfSections; i++) {
        DWORD prot = PAGE_READONLY;
        uint32_t c = sec[i].Characteristics;
        bool exec = (c & 0x80000000) != 0 || (c & 0x20) != 0;
        bool write = (c & 0x20000000) != 0;
        bool read = (c & 0x40000000) != 0;
        bool is_data = (c & 0x40) != 0 || (c & 0x80) != 0;
        if (is_data) write = true;
        if (exec && write && read) prot = PAGE_EXECUTE_READWRITE;
        else if (exec && read) prot = PAGE_EXECUTE_READ;
        else if (exec) prot = PAGE_EXECUTE_READ;
        else if (write && read) prot = PAGE_READWRITE;
        else if (write) prot = PAGE_READWRITE;
        else if (read) prot = PAGE_READONLY;
        DWORD old = 0;
        VirtualProtect(image + sec[i].VirtualAddress, sec[i].VirtualSize, prot, &old);
    }
}

// XOR-decrypt a section using xorshift32 keystream (same as encryption).
static void decrypt_section(uint8_t* data, size_t size, uint64_t seed) {
    uint32_t s = static_cast<uint32_t>(seed);
    for (size_t i = 0; i < size; i++) {
        s ^= s << 13;
        s ^= s >> 17;
        s ^= s << 5;
        data[i] ^= static_cast<uint8_t>(s & 0xFF);
    }
}

//-----------------------------------------------------------------------------
// DLL Entry Point
//-----------------------------------------------------------------------------

typedef BOOL (WINAPI *DllEntryPoint)(HINSTANCE, DWORD, LPVOID);

extern "C" BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH: {
            DisableThreadLibraryCalls(hinstDLL);

            size_t file_size = 0;
            uint8_t* file = read_own_file(hinstDLL, &file_size);
            if (!file || file_size < sizeof(NX_META_HEADER) + 8) {
                VirtualFree(file, 0, MEM_RELEASE);
                return FALSE;
            }

            // Footer: last 8 bytes = metadata offset
            uint64_t meta_off = rd64(file + file_size - 8);
            if (meta_off >= file_size) {
                VirtualFree(file, 0, MEM_RELEASE);
                return FALSE;
            }

            const NX_META_HEADER* meta = (const NX_META_HEADER*)(file + meta_off);
            if (nx_memcmp(meta->magic, NX_MAGIC, 4) != 0 ||
                meta->version != NX_META_VERSION) {
                VirtualFree(file, 0, MEM_RELEASE);
                return FALSE;
            }
            if (meta->codec_id != NX_CODEC_STORE &&
                meta->codec_id != NX_CODEC_ZSTD &&
                meta->codec_id != NX_CODEC_LZ4 &&
                meta->codec_id != NX_CODEC_LZMA) {
                VirtualFree(file, 0, MEM_RELEASE);
                return FALSE;
            }
            if (meta->payload_offset >= file_size ||
                meta->payload_size > file_size - meta->payload_offset) {
                VirtualFree(file, 0, MEM_RELEASE);
                return FALSE;
            }

            const uint8_t* payload = file + meta->payload_offset;
            uint64_t pe_size = meta->payload_size;

            // Decompress payload using the appropriate codec
            uint8_t* pe_buf_alloc = NULL;
            const uint8_t* pe_buf = payload;
            if (!decompress_payload(payload, meta->payload_size, meta->codec_id,
                                    meta->original_file_size, &pe_buf_alloc, &pe_size)) {
                VirtualFree(file, 0, MEM_RELEASE);
                return FALSE;
            }
            if (pe_buf_alloc) pe_buf = pe_buf_alloc;

            if (pe_size < sizeof(NX_DOS_HEADER) || nx_memcmp(pe_buf, "MZ", 2) != 0) {
                if (pe_buf_alloc) VirtualFree(pe_buf_alloc, 0, MEM_RELEASE);
                VirtualFree(file, 0, MEM_RELEASE);
                return FALSE;
            }
            const NX_DOS_HEADER* dos = (const NX_DOS_HEADER*)pe_buf;
            if (pe_size < (size_t)dos->e_lfanew + 4 + sizeof(NX_FILE_HEADER)) {
                VirtualFree(file, 0, MEM_RELEASE);
                return FALSE;
            }
            const uint8_t* nt = pe_buf + dos->e_lfanew;
            if (nx_memcmp(nt, "PE\0\0", 4) != 0) {
                VirtualFree(file, 0, MEM_RELEASE);
                return FALSE;
            }
            const NX_FILE_HEADER* fh = (const NX_FILE_HEADER*)(nt + 4);
            const NX_OPTIONAL_HEADER64* oh =
                (const NX_OPTIONAL_HEADER64*)(nt + 4 + sizeof(NX_FILE_HEADER));
            if (oh->Magic != 0x20b) {
                VirtualFree(file, 0, MEM_RELEASE);
                return FALSE;
            }

            uint8_t* image = (uint8_t*)VirtualAlloc(NULL, (SIZE_T)oh->SizeOfImage,
                                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!image) {
                VirtualFree(file, 0, MEM_RELEASE);
                return FALSE;
            }

            nx_memcpy(image, pe_buf, oh->SizeOfHeaders);

            const NX_SECTION_HEADER* sec =
                (const NX_SECTION_HEADER*)((const uint8_t*)oh +
                                           sizeof(NX_OPTIONAL_HEADER64) +
                                           oh->NumberOfRvaAndSizes * sizeof(NX_DATA_DIRECTORY));
            for (uint16_t i = 0; i < fh->NumberOfSections; i++) {
                if (sec[i].SizeOfRawData == 0) continue;
                nx_memcpy(image + sec[i].VirtualAddress,
                          pe_buf + sec[i].PointerToRawData,
                          sec[i].SizeOfRawData);
                if (sec[i].VirtualSize > sec[i].SizeOfRawData) {
                    nx_memset(image + sec[i].VirtualAddress + sec[i].SizeOfRawData, 0,
                              sec[i].VirtualSize - sec[i].SizeOfRawData);
                }
            }

            // Decrypt any protected sections
            if (meta->num_encrypted_sections > 0) {
                const uint8_t* enc_data = file + meta_off + sizeof(NX_META_HEADER);
                for (uint32_t i = 0; i < meta->num_encrypted_sections; i++) {
                    const NX_SECTION_ENCRYPTION* enc =
                        (const NX_SECTION_ENCRYPTION*)(enc_data + i * sizeof(NX_SECTION_ENCRYPTION));
                    if (enc->section_index >= fh->NumberOfSections) continue;
                    uint8_t* sec_data = image + sec[enc->section_index].VirtualAddress;
                    uint32_t sec_size = sec[enc->section_index].SizeOfRawData;
                    decrypt_section(sec_data, sec_size, enc->xor_key);
                }
            }

            uint64_t delta = (uint64_t)(image - oh->ImageBase);
            if (!apply_relocations(image, delta, pe_buf)) {
                VirtualFree(image, 0, MEM_RELEASE);
                VirtualFree(file, 0, MEM_RELEASE);
                return FALSE;
            }
            if (!resolve_imports(image, pe_buf)) {
                VirtualFree(image, 0, MEM_RELEASE);
                VirtualFree(file, 0, MEM_RELEASE);
                return FALSE;
            }
            set_protections(image, fh, sec);

            // Store reconstructed image globally for export forwarding.
            g_dll_image_base = image;
            g_dll_pe_buf = pe_buf;
            g_dll_fh = fh;
            g_dll_sec = sec;
            g_dll_pe_buf_alloc = pe_buf_alloc; // keep alive for export lookups

            // Call the original DLL's entry point with the reconstructed
            // image base as HINSTANCE.
            DllEntryPoint orig_entry =
                (DllEntryPoint)(image + oh->AddressOfEntryPoint);
            BOOL result = orig_entry((HINSTANCE)image, DLL_PROCESS_ATTACH,
                                     lpvReserved);

            VirtualFree(file, 0, MEM_RELEASE);
            // NOTE: pe_buf_alloc is intentionally NOT freed — export lookups
            // need g_dll_pe_buf and g_dll_sec which point into it.
            return result;
        }
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            // Note: g_dll_image_base and g_dll_pe_buf_alloc are intentionally
            // not freed here — process exit will reclaim them, and freeing
            // during DLL unload can cause access violations if the C runtime
            // is already torn down.
            g_dll_pe_buf = NULL;
            g_dll_fh = NULL;
            g_dll_sec = NULL;
            break;
    }
    return TRUE;
}

//-----------------------------------------------------------------------------
// Export forwarding API — allows hosts to resolve exports from the
// reconstructed DLL image using GetProcAddress semantics.
//-----------------------------------------------------------------------------

extern "C" __declspec(dllexport) FARPROC WINAPI NexaPackDllGetProcAddress(
    HMODULE hModule, LPCSTR lpProcName) {
    (void)hModule; // The reconstructed image is tracked globally.
    return dll_get_proc_address(lpProcName);
}

extern "C" __declspec(dllexport) uint32_t WINAPI NexaPackDllGetExportCount(void) {
    return dll_get_export_count();
}

extern "C" __declspec(dllexport) const char* WINAPI NexaPackDllGetExportName(
    uint32_t index) {
    return dll_get_export_name(index);
}

