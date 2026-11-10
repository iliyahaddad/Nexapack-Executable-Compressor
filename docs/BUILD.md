# NexaPack Build Instructions

## Prerequisites (Windows)
- CMake 3.18+ (4.4.4 installed)
- Ninja (1.13.2 installed)
- Microsoft Visual C++ (cl.exe) — located at:
  `C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\cl.exe`

## Configure and build

Open a developer command prompt (x64 native tools), then:

```powershell
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

## Build configurations
- Debug: `-DCMAKE_BUILD_TYPE=Debug`
- Release (default): `-DCMAKE_BUILD_TYPE=Release`
- RelWithDebInfo: `-DCMAKE_BUILD_TYPE=RelWithDebInfo`

## Enable/disable tests
- `-DBUILD_TESTING=ON` (default)
- `-DBUILD_TESTING=OFF`

## Output
- CLI: `build/bin/nexapack.exe`
- Core library: `build/lib/nexapack_core.lib`
- Tests: `build/bin/nexapack_tests.exe`

## Notes
- The MSVC C runtime is forced to static (`/MT`) so the produced tooling has no
  Visual Studio redistributable dependency.
- zstd and lz4 sources are compiled directly into `nexapack_core` from the local
  `zstd-dev` and `lz4-dev` directories on the Desktop.
