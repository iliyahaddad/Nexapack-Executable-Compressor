# NexaPack

Independent executable compression and protection product for Windows PE32+ x64 executables.

## Overview

NexaPack is a professional executable packer that compresses executable files while preserving their ability to execute directly. Packed executables contain compressed payload data, a native Runtime Stub, and decompression code — all reconstructed in memory at runtime with no temporary file extraction.

## Supported Platforms

- Windows 10 / Windows 11
- x64 architecture
- PE32+ EXE and DLL files

## Supported Compression Codecs

| Codec | Description |
|-------|-------------|
| Store | No compression (pass-through) |
| ZSTD | Zstandard v1.6.0 compression |
| LZ4 | LZ4 v1.11.0 compression |
| LZMA | LZMA SDK v16.06 compression |

## Compression Profiles

- **FAST** — Prioritize compression and decompression speed
- **BALANCED** — Balance final size and speed (default)
- **MAXIMUM** — Prioritize smallest final executable size
- **AUTO** — Automatic algorithm selection based on input analysis
- **CUSTOM** — User-specified compression level

## Protection Profiles

- **NONE** — No protection
- **BASIC** — Integrity / anti-tamper metadata
- **STANDARD** — Integrity + symbol stripping
- **ADVANCED** — Integrity + symbol stripping + section encryption
- **MAXIMUM** — Integrity + symbol stripping + section encryption

## Command Line Interface

```
nexapack pack <input> -o <output>
nexapack unpack <input> -o <output>
nexapack inspect <input>
nexapack verify <input>
nexapack benchmark <input>
nexapack compare <input>
nexapack batch <directory>
nexapack codecs
nexapack profiles
nexapack version
nexapack help
```

### Pack Options

- `--profile fast|balanced|maximum|auto|custom`
- `--codec store|zstd|lz4|lzma|auto`
- `--level <N>`
- `--best`
- `--force`
- `--verbose`
- `--json`
- `--protection none|basic|standard|advanced|maximum`
- `--threads <N>`

## GUI — NexaPack Studio

NexaPack Studio is a Qt 6 graphical interface included in the project under `apps/gui/`. It provides the same functionality as the CLI through a native desktop application with pages for packing, unpacking, inspecting, benchmarking, batch processing, settings, and about information.

## Installation

### Prerequisites

- Windows 10 or Windows 11
- CMake 3.20 or later
- Ninja build system
- Microsoft Visual Studio 2022 (MSVC 14.44 or later) with x64 toolchain
- Qt 6.12 or later (for building NexaPack Studio GUI)

### Building

1. Open the VS 2022 x64 Native Tools Command Prompt
2. Navigate to the project directory
3. Run the configure script:
   ```
   build_configure.bat
   ```
4. Build the project:
   ```
   build_build.bat
   ```

This produces `build/nexapack.exe` (CLI) and `build/nexapack_studio.exe` (GUI).

## Runtime Stubs

The packed executables include a native Runtime Stub that reconstructs the original executable image in memory and transfers execution to it. Stub binaries (`stub.exe` for EXE, `stub_dll.dll` for DLL) must be deployed alongside `nexapack.exe` for packing to work.

Build stubs using:
- `build_stub.bat` — EXE runtime stub
- `build_stub_dll.bat` — DLL runtime stub

## Testing

Run unit tests with:
```
build_tests.bat
```

Test fixtures are in the `tests/fixtures/` directory.

## Project Structure

```
src/           — Core engine source code
  core/        — Error, logging, metadata, codec interface, analyzer, planner
  codecs/      — Store, ZSTD, LZ4, LZMA compression codecs
  formats/     — PE and ELF format analyzers
  protection/  — NexaProtect symbol, section, MBA, integrity protection
  runtime/     — Windows PE runtime stubs
  cli/         — Command line interface parser
apps/gui/      — NexaPack Studio Qt 6 GUI
tests/         — Unit tests and test fixtures
docs/          — Phase completion reports and architecture docs
```

## Format

NexaPack uses its own on-disk metadata format with magic identifier `NXP\0`, little-endian fixed-width integer fields, and explicit versioning. The packed file layout is:

```
[Runtime Stub] [NXP Metadata] [Compressed Payload] [Optional Protection Data] [8-byte Footer]
```

No temporary executable files are created during execution — the original executable is reconstructed entirely in memory.