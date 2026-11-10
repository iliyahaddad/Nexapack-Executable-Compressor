cmake_minimum_required(VERSION 3.18 FATAL_ERROR)

project(NexaPack
    VERSION 0.1.0
    LANGUAGES CXX C
    DESCRIPTION "NexaPack — Independent, advanced, cross-platform executable packer"
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "RelWithDebInfo" "MinSizeRel")
endif()

if(MSVC)
    set(CRT_MODE "MT" CACHE STRING "MSVC C runtime: MT or MD")
    if(CRT_MODE STREQUAL "MT")
        set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    endif()
    set(MSVC_INCLUDE_DIR "C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC/14.44.35207/include")
    set(MSVC_LIB_DIR "C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Tools/MSVC/14.44.35207/lib/x64")
    set(WINDOWS_SDK_INCLUDE_DIR "C:/Program Files (x86)/Windows Kits/10/Include/10.0.19041.0/ucrt")
    set(WINDOWS_SDK_UM_INCLUDE_DIR "C:/Program Files (x86)/Windows Kits/10/Include/10.0.19041.0/um")
    set(WINDOWS_SDK_SHARED_INCLUDE_DIR "C:/Program Files (x86)/Windows Kits/10/Include/10.0.19041.0/shared")
    set(WINDOWS_SDK_INCLUDE_DIR_2 "C:/Program Files (x86)/Windows Kits/10/Include/10.0.26100.0/ucrt")
    set(WINDOWS_SDK_LIB_DIR "C:/Program Files (x86)/Windows Kits/10/Lib/10.0.19041.0/ucrt/x64")
    set(WINDOWS_SDK_LIB_DIR_2 "C:/Program Files (x86)/Windows Kits/10/Lib/10.0.26100.0/um/x64")
    if(EXISTS "${MSVC_INCLUDE_DIR}")
        include_directories("${MSVC_INCLUDE_DIR}")
    endif()
    if(EXISTS "${WINDOWS_SDK_INCLUDE_DIR}")
        include_directories("${WINDOWS_SDK_INCLUDE_DIR}")
    endif()
    if(EXISTS "${WINDOWS_SDK_UM_INCLUDE_DIR}")
        include_directories("${WINDOWS_SDK_UM_INCLUDE_DIR}")
    endif()
    if(EXISTS "${WINDOWS_SDK_SHARED_INCLUDE_DIR}")
        include_directories("${WINDOWS_SDK_SHARED_INCLUDE_DIR}")
    endif()
    if(EXISTS "${WINDOWS_SDK_INCLUDE_DIR_2}")
        include_directories("${WINDOWS_SDK_INCLUDE_DIR_2}")
    endif()
endif()

set(ZSTD_SOURCE_DIR "" CACHE PATH "Zstandard library source directory")
set(LZ4_SOURCE_DIR  "" CACHE PATH "LZ4 library source directory")
set(LZMA_SOURCE_DIR "" CACHE PATH "LZMA SDK source directory")

if(ZSTD_SOURCE_DIR STREQUAL "")
    message(WARNING "ZSTD_SOURCE_DIR not set. ZSTD codec will not be available.")
endif()
if(LZ4_SOURCE_DIR STREQUAL "")
    message(WARNING "LZ4_SOURCE_DIR not set. LZ4 codec will not be available.")
endif()

file(GLOB ZSTD_SOURCES "${ZSTD_SOURCE_DIR}/common/*.c" "${ZSTD_SOURCE_DIR}/compress/*.c" "${ZSTD_SOURCE_DIR}/decompress/*.c")
list(FILTER ZSTD_SOURCES EXCLUDE REGEX "legacy")

set(LZ4_SOURCES
    ${LZ4_SOURCE_DIR}/lz4.c
    ${LZ4_SOURCE_DIR}/lz4hc.c
    ${LZ4_SOURCE_DIR}/lz4frame.c
    ${LZ4_SOURCE_DIR}/xxhash.c
)

set(LZMA_SOURCES
    ${LZMA_SOURCE_DIR}/C/LzmaDec.c
    ${LZMA_SOURCE_DIR}/C/LzmaEnc.c
    ${LZMA_SOURCE_DIR}/C/LzFind.c
    ${LZMA_SOURCE_DIR}/C/CpuArch.c
    ${LZMA_SOURCE_DIR}/C/7zBuf.c
    ${LZMA_SOURCE_DIR}/C/7zCrc.c
)

add_library(nexapack_core STATIC
    src/core/error.cpp
    src/core/logging.cpp
    src/core/metadata.cpp
    src/core/codec_interface.cpp
    src/core/analyzer/analyzer.cpp
    src/core/planner/planner.cpp
    src/formats/pe/pe_analyzer.cpp
    src/formats/elf/elf_analyzer.cpp
    src/codecs/store/store_codec.cpp
    src/codecs/zstd/zstd_codec.cpp
    src/codecs/lz4/lz4_codec.cpp
    src/codecs/lzma/lzma_codec.cpp
    src/codecs/codec_registry.cpp
    src/protection/nexaprotect/nexaprotect.cpp
    src/protection/symbols/symbols.cpp
    src/protection/mba/mba.cpp
    src/protection/section_protection/section_protection.cpp
    src/protection/integrity/integrity.cpp
    ${ZSTD_SOURCES}
    ${LZ4_SOURCES}
    ${LZMA_SOURCES}
)

target_include_directories(nexapack_core PUBLIC
    ${CMAKE_SOURCE_DIR}/src
    ${ZSTD_SOURCE_DIR}
    ${LZ4_SOURCE_DIR}
    ${LZMA_SOURCE_DIR}/C
)

target_compile_definitions(nexapack_core PUBLIC
    NEXAPACK_CORE_EXPORTS
    ZSTD_DISABLE_ASM
    ZSTD_HEAPMODE=0
    Z7_ST
    _CRT_SECURE_NO_WARNINGS
    _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING
)

if(MSVC)
    target_compile_options(nexapack_core PRIVATE /W4 /WX- /permissive-)
    target_link_libraries(nexapack_core PRIVATE kernel32.lib user32.lib advapi32.lib)
    target_link_directories(nexapack_core PRIVATE "${MSVC_LIB_DIR}" "${WINDOWS_SDK_LIB_DIR}" "${WINDOWS_SDK_LIB_DIR_2}")
else()
    target_compile_options(nexapack_core PRIVATE -Wall -Wextra -Wpedantic -std=c++20)
endif()

add_executable(nexapack src/main.cpp src/cli/cli.cpp)
target_link_libraries(nexapack PRIVATE nexapack_core kernel32.lib user32.lib advapi32.lib)
target_link_directories(nexapack PRIVATE "${MSVC_LIB_DIR}" "${WINDOWS_SDK_LIB_DIR}" "${WINDOWS_SDK_LIB_DIR_2}")
target_compile_definitions(nexapack PRIVATE NEXAPACK_CLI)

if(MSVC)
    target_compile_options(nexapack PRIVATE /W4 /WX- /permissive-)
else()
    target_compile_options(nexapack PRIVATE -Wall -Wextra -Wpedantic -std=c++20)
endif()

#-----------------------------------------------------------------------------
# Qt 6 GUI — NexaPack Studio
#-----------------------------------------------------------------------------
option(BUILD_GUI "Build NexaPack Studio GUI (requires Qt 6)" ON)

if(BUILD_GUI)
    find_package(Qt6 REQUIRED COMPONENTS Core Widgets Quick QuickControls2)
    message(STATUS "Qt 6 found: ${Qt6_VERSION} (${Qt6_QMAKE_LOCATION})")

    set(GUI_SRC_DIR "${CMAKE_SOURCE_DIR}/apps/gui")

    qt_add_executable(nexapack_studio
        ${GUI_SRC_DIR}/main.cpp
        ${GUI_SRC_DIR}/nexapack_backend.cpp
        ${GUI_SRC_DIR}/qml/qml_resources.qrc
    )

    target_link_libraries(nexapack_studio PRIVATE
        nexapack_core
        Qt6::Core
        Qt6::Widgets
        Qt6::Quick
        Qt6::QuickControls2
    )

    target_include_directories(nexapack_studio PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${GUI_SRC_DIR}
    )

    target_compile_definitions(nexapack_studio PRIVATE
        NEXAPACK_GUI
    )

    if(MSVC)
        target_compile_options(nexapack_studio PRIVATE /W4 /WX- /permissive-)
        target_link_libraries(nexapack_studio PRIVATE kernel32.lib user32.lib advapi32.lib)
        target_link_directories(nexapack_studio PRIVATE "${MSVC_LIB_DIR}" "${WINDOWS_SDK_LIB_DIR}" "${WINDOWS_SDK_LIB_DIR_2}")
    else()
        target_compile_options(nexapack_studio PRIVATE -Wall -Wextra -Wpedantic -std=c++20)
    endif()

    install(TARGETS nexapack_studio RUNTIME DESTINATION bin)
endif()

option(BUILD_TESTING "Build unit tests" OFF)

if(BUILD_TESTING)
    include(CTest)
    set(CATCH2_SHIM_DIR "C:/Users/manshadi.PDF/Desktop/catch2-shim" CACHE PATH "Catch2 shim directory")
    add_executable(nexapack_tests tests/unit/test_codec_store.cpp
        tests/unit/test_codec_zstd.cpp
        tests/unit/test_codec_lz4.cpp
        tests/unit/test_metadata.cpp
        tests/unit/test_codec_interface.cpp
        tests/unit/test_pe_analyzer.cpp
        tests/unit/test_elf_analyzer.cpp
        tests/unit/test_analyzer.cpp
        tests/unit/test_planner.cpp
        tests/unit/test_protection.cpp
        ${CATCH2_SHIM_DIR}/catch_main.cpp
    )
    target_link_libraries(nexapack_tests PRIVATE nexapack_core)
    target_include_directories(nexapack_tests PRIVATE ${CATCH2_SHIM_DIR})
    target_compile_definitions(nexapack_tests PRIVATE NEXAPACK_TESTS)
    add_test(NAME nexapack_unit_tests COMMAND nexapack_tests)
endif()

install(TARGETS nexapack RUNTIME DESTINATION bin)
install(TARGETS nexapack_core ARCHIVE DESTINATION lib)