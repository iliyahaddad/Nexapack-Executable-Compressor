# NexaPack Studio GUI CMake
# Requires Qt 6. If Qt 6 is not found, GUI is skipped with a message.

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Core Quick Controls QuickTemplates2 Layouts)
set(QT_VERSION_MAJOR ${QT_VERSION_MAJOR})

set(GUI_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)
set(GUI_QML_DIR ${CMAKE_CURRENT_SOURCE_DIR}/qml)
set(GUI_RESOURCES_DIR ${CMAKE_CURRENT_SOURCE_DIR}/resources)

add_library(nexapack_gui_backend STATIC
    ${GUI_SOURCE_DIR}/backend.cpp
)

target_include_directories(nexapack_gui_backend PUBLIC
    ${GUI_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(nexapack_gui_backend PUBLIC
    nexapack_core
    Qt${QT_VERSION_MAJOR}::Core
    Qt${QT_VERSION_MAJOR}::Quick
    Qt${QT_VERSION_MAJOR}::Controls
    Qt${QT_VERSION_MAJOR}::QuickTemplates2
    Qt${QT_VERSION_MAJOR}::Layouts
)

if(QT_VERSION_MAJOR EQUAL 6)
    target_compile_definitions(nexapack_gui_backend PUBLIC QT_VERSION_MAJOR=6)
endif()

add_executable(nexapack_studio
    ${GUI_SOURCE_DIR}/main.cpp
)

target_link_libraries(nexapack_studio PRIVATE
    nexapack_gui_backend
    Qt${QT_VERSION_MAJOR}::Core
    Qt${QT_VERSION_MAJOR}::Quick
    Qt${QT_VERSION_MAJOR}::Controls
    Qt${QT_VERSION_MAJOR}::QuickTemplates2
    Qt${QT_VERSION_MAJOR}::Layouts
)

qt_add_resources(nexapack_studio
    ${GUI_RESOURCES_DIR}/nexapack_studio.qrc
)

set_target_properties(nexapack_studio PROPERTIES
    WIN32_EXECUTABLE TRUE
    MACOSX_BUNDLE TRUE
)

install(TARGETS nexapack_studio RUNTIME DESTINATION bin)
install(TARGETS nexapack_gui_backend ARCHIVE DESTINATION lib)
