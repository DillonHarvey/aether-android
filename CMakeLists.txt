cmake_minimum_required(VERSION 3.25)
project(Aether VERSION 0.1.0 LANGUAGES C CXX)

if(NOT WIN32 OR NOT MSVC)
    message(FATAL_ERROR "Aether currently requires Windows x64 with the MSVC toolchain. See docs/BUILD_WINDOWS.md.")
endif()
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8 OR NOT CMAKE_SYSTEM_PROCESSOR MATCHES "^(AMD64|amd64|x86_64|X86_64)$")
    message(FATAL_ERROR "Aether requires an x86-64 host build, not Win32 or ARM64.")
endif()
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
    message(FATAL_ERROR "Use a preset: build outputs belong in out/build/<preset>.")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
include(CTest)
find_package(Python3 3.10 REQUIRED COMPONENTS Interpreter)
include(GenerateExportHeader)
include(cmake/Dynarmic.cmake)
include(cmake/Angle.cmake)
include(cmake/WebP.cmake)
add_library(aether_miniz STATIC third_party/miniz/miniz.c third_party/miniz/miniz_tinfl.c third_party/miniz/miniz_zip.c)
generate_export_header(aether_miniz BASE_NAME MINIZ EXPORT_FILE_NAME "${CMAKE_CURRENT_BINARY_DIR}/generated/miniz_export.h")
target_include_directories(aether_miniz SYSTEM PUBLIC third_party/miniz "${CMAKE_CURRENT_BINARY_DIR}/generated")
target_compile_definitions(aether_miniz PUBLIC MINIZ_STATIC_DEFINE MINIZ_NO_STDIO MINIZ_NO_TIME MINIZ_NO_DEFLATE_APIS MINIZ_NO_ARCHIVE_WRITING_APIS MINIZ_NO_ZLIB_COMPATIBLE_NAMES)

add_library(aether_options INTERFACE)
target_compile_definitions(aether_options INTERFACE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
target_compile_options(aether_options INTERFACE /W4 /WX /permissive- /utf-8 /EHsc /sdl)
target_link_options(aether_options INTERFACE /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA)

configure_file(include/aether/build_info.hpp.in generated/aether/build_info.hpp @ONLY)
add_library(aether_core STATIC
    src/common/text.cpp
    src/common/prefix_strings.cpp
    src/diagnostics/diagnostic.cpp
    src/host/windows/doctor.cpp
    src/host/windows/package_io.cpp
    src/host/windows/time_service.cpp
    src/host/windows/file_service.cpp
    src/apk/archive.cpp
    src/apk/manifest.cpp
    src/apk/xml.cpp
    src/apk/package_set.cpp
    src/apk/package.cpp
    src/apk/launcher.cpp
    src/apk/string_pool.cpp
    src/apk/resources.cpp
    src/apk/dex.cpp
    src/apk/elf.cpp
    src/apk/inspect.cpp
    src/apk/compatibility.cpp
    src/apk/native_inventory.cpp
    src/apk/signature_report.cpp
    src/apk/artwork.cpp
    src/apk/drawable.cpp
    src/apk/vector.cpp
    src/apk/preview.cpp
    src/apk/preview_container.cpp
    src/apk/preview_toc.cpp
)
target_include_directories(aether_core PUBLIC include "${CMAKE_CURRENT_BINARY_DIR}/generated")
target_link_libraries(aether_core PUBLIC aether_options PRIVATE advapi32 bcrypt ntdll aether_miniz aether_webp_decoder)

add_library(aether_runtime_permissions STATIC src/security/worker_image.cpp)
target_include_directories(aether_runtime_permissions PUBLIC include)
target_link_libraries(aether_runtime_permissions PUBLIC aether_options PRIVATE advapi32)
add_executable(aether_runtime_setup apps/aether-runtime-setup/main.cpp)
target_link_libraries(aether_runtime_setup PRIVATE aether_runtime_permissions)

# Certificate/key parsing is a host inspection concern; isolated workers do not
# link the Crypt32 verifier or acquire new signing-based execution authority.
add_library(aether_apk_signing STATIC src/apk/signature.cpp src/apk/package_set_signing.cpp)
target_include_directories(aether_apk_signing PUBLIC include)
target_link_libraries(aether_apk_signing PUBLIC aether_core PRIVATE bcrypt crypt32)

add_custom_command(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/generated/aether/privacy_content.hpp"
    COMMAND "${Python3_EXECUTABLE}" -B "${CMAKE_CURRENT_SOURCE_DIR}/tools/compile-privacy.py"
        --output "${CMAKE_CURRENT_BINARY_DIR}/generated/aether/privacy_content.hpp"
    DEPENDS tools/compile-privacy.py src/install/privacy_guide.txt
    VERBATIM)
add_library(aether_install STATIC src/install/store.cpp src/install/cli.cpp src/install/shell.cpp src/install/explorer.cpp src/install/runtime.cpp
    src/install/runtime_bundle.cpp src/install/runtime_registration.cpp src/install/diagnostics.cpp
    src/install/troubleshooting.cpp src/install/privacy.cpp
    "${CMAKE_CURRENT_BINARY_DIR}/generated/aether/privacy_content.hpp")
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/apps/aether-setup/uninstall-controller.ps1" AETHER_UNINSTALL_CONTROLLER)
configure_file(src/install/uninstall_controller.hpp.in generated/aether/uninstall_controller.hpp @ONLY)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS apps/aether-setup/uninstall-controller.ps1)
target_include_directories(aether_install PUBLIC include)
target_link_libraries(aether_install PUBLIC aether_core PRIVATE aether_apk_signing aether_runtime_permissions aether_window aether_icon_cache shell32 ole32 advapi32 bcrypt userenv)

add_library(aether_a64 STATIC src/a64/guest_memory.cpp src/a64/guest_cpu.cpp src/a64/selftest.cpp)
target_include_directories(aether_a64 PUBLIC include)
target_link_libraries(aether_a64 PUBLIC aether_options PRIVATE dynarmic aether_core)

add_library(aether_elf STATIC src/elf/image.cpp src/elf/guest_loader.cpp src/elf/archive_source.cpp)
target_include_directories(aether_elf PUBLIC include)
target_link_libraries(aether_elf PUBLIC aether_a64 PRIVATE aether_core)

add_library(aether_bionic STATIC src/bionic/guest_posix.cpp)
target_include_directories(aether_bionic PUBLIC include)
target_link_libraries(aether_bionic PUBLIC aether_elf PRIVATE aether_core)

add_library(aether_native STATIC src/elf/selftest.cpp)
target_link_libraries(aether_native PUBLIC aether_bionic PRIVATE aether_core)

add_library(aether_host_audio STATIC src/host/windows/audio_stream.cpp)
target_include_directories(aether_host_audio PUBLIC include)
target_link_libraries(aether_host_audio PUBLIC aether_options PRIVATE aether_core ole32 uuid)
add_library(aether_audio STATIC src/audio/guest.cpp)
target_include_directories(aether_audio PUBLIC include)
target_link_libraries(aether_audio PUBLIC aether_elf aether_host_audio)
add_library(aether_audio_selftest STATIC src/audio/selftest.cpp)
target_link_libraries(aether_audio_selftest PUBLIC aether_audio PRIVATE aether_bionic aether_core)

add_library(aether_graphics STATIC src/graphics/command.cpp src/graphics/guest.cpp src/graphics/gles.cpp src/graphics/shared_window.cpp src/host/windows/graphics_surface.cpp)
target_include_directories(aether_graphics PUBLIC include)
target_link_libraries(aether_graphics PUBLIC aether_elf PRIVATE aether_angle aether_core)
add_library(aether_graphics_selftest STATIC src/graphics/selftest.cpp src/graphics/fixture_runtime.cpp)
target_link_libraries(aether_graphics_selftest PUBLIC aether_graphics PRIVATE aether_bionic aether_core aether_window)

add_library(aether_dex STATIC src/dex/image.cpp src/dex/annotations.cpp src/dex/bytecode.cpp src/dex/runtime.cpp src/dex/linker.cpp src/dex/source.cpp src/dex/archive_source.cpp)
target_include_directories(aether_dex PUBLIC include)
target_link_libraries(aether_dex PUBLIC aether_options PRIVATE aether_core)

add_library(aether_jni STATIC src/jni/bridge.cpp)
target_include_directories(aether_jni PUBLIC include)
target_link_libraries(aether_jni PUBLIC aether_dex aether_bionic)

add_library(aether_managed STATIC src/dex/selftest.cpp)
target_link_libraries(aether_managed PUBLIC aether_jni PRIVATE aether_core)

add_library(aether_android STATIC src/android/framework.cpp src/android/registry.cpp src/android/selftest.cpp)
target_include_directories(aether_android PUBLIC include)
target_link_libraries(aether_android PUBLIC aether_jni PRIVATE aether_core)

add_library(aether_window STATIC src/host/windows/window.cpp src/host/windows/input.cpp)
target_include_directories(aether_window PUBLIC include)
target_link_libraries(aether_window PUBLIC aether_android PRIVATE aether_core user32 gdi32 ole32 windowscodecs shell32 propsys)

add_executable(aether apps/aether-cli/main.cpp)
target_link_libraries(aether PRIVATE aether_apk_signing aether_core aether_a64 aether_native aether_managed aether_android aether_window aether_graphics_selftest aether_audio_selftest aether_install)
enable_language(RC)
set(AETHER_PACKAGE_ICON "${CMAKE_CURRENT_BINARY_DIR}/generated/shell/package.ico")
set(AETHER_BUNDLE_ICON "${CMAKE_CURRENT_BINARY_DIR}/generated/shell/bundle.ico")
add_custom_command(OUTPUT "${AETHER_PACKAGE_ICON}" "${AETHER_BUNDLE_ICON}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${CMAKE_CURRENT_BINARY_DIR}/generated/shell"
    COMMAND $<TARGET_FILE:aether> shell-icons build-assets "${CMAKE_CURRENT_BINARY_DIR}/generated/shell"
    DEPENDS aether VERBATIM)
configure_file(src/shell/icons.rc.in generated/shell/icons.rc @ONLY)
set_source_files_properties("${CMAKE_CURRENT_BINARY_DIR}/generated/shell/icons.rc" PROPERTIES
    OBJECT_DEPENDS "${AETHER_PACKAGE_ICON};${AETHER_BUNDLE_ICON}")
# Keep this dependency graph independent of aether_core and every package/image parser.
add_library(aether_icon_cache STATIC src/shell/icon_cache.cpp src/shell/icon_path.cpp
    src/shell/icon_queue.cpp src/shell/icon_ipc.cpp)
target_include_directories(aether_icon_cache PUBLIC include)
target_link_libraries(aether_icon_cache PUBLIC aether_options PRIVATE aether_runtime_permissions bcrypt shell32 ole32)
target_compile_options(aether_icon_cache PRIVATE /guard:cf)
add_library(aether_shell_icons SHARED src/shell/icon_handler.cpp src/shell/icon_client.cpp src/shell/icons.def
    "${CMAKE_CURRENT_BINARY_DIR}/generated/shell/icons.rc")
set_target_properties(aether_shell_icons PROPERTIES OUTPUT_NAME AetherShellIcons)
target_include_directories(aether_shell_icons PRIVATE include)
target_link_libraries(aether_shell_icons PRIVATE aether_icon_cache ole32 uuid user32)
target_compile_options(aether_shell_icons PRIVATE /guard:cf)
target_link_options(aether_shell_icons PRIVATE /guard:cf "/MAP:${CMAKE_CURRENT_BINARY_DIR}/AetherShellIcons.map")
add_library(aether_privacy_ui STATIC apps/common/privacy_dialog.cpp)
target_include_directories(aether_privacy_ui PUBLIC apps/common)
target_link_libraries(aether_privacy_ui PUBLIC aether_install PRIVATE user32)
add_executable(aether_shell WIN32 apps/aether-shell/main.cpp apps/aether-shell/install_dialog.cpp
    apps/aether-shell/app_dialog.cpp apps/aether-shell/app_dialog.rc apps/common/privacy.rc)
set_target_properties(aether_shell PROPERTIES OUTPUT_NAME "aether-shell")
target_link_libraries(aether_shell PRIVATE aether_privacy_ui comctl32)
add_executable(aether_setup WIN32 apps/aether-setup/main.cpp apps/common/privacy.rc)
set_target_properties(aether_setup PROPERTIES OUTPUT_NAME "aether-setup")
target_link_libraries(aether_setup PRIVATE aether_privacy_ui comctl32)
get_filename_component(AETHER_PRESET_NAME "${CMAKE_CURRENT_BINARY_DIR}" NAME)
add_custom_target(aether_distribution ALL
    COMMAND "${Python3_EXECUTABLE}" -B "${CMAKE_CURRENT_SOURCE_DIR}/tools/package-runtime.py"
        --build "${CMAKE_CURRENT_BINARY_DIR}"
        --output "${CMAKE_CURRENT_SOURCE_DIR}/out/distribution/${AETHER_PRESET_NAME}/AetherSetup.exe"
    COMMAND "${Python3_EXECUTABLE}" -B "${CMAKE_CURRENT_SOURCE_DIR}/tools/verify-distribution.py"
        --build "${CMAKE_CURRENT_BINARY_DIR}"
        --bundle "${CMAKE_CURRENT_SOURCE_DIR}/out/distribution/${AETHER_PRESET_NAME}/AetherSetup.exe"
        --evidence "${CMAKE_CURRENT_BINARY_DIR}/distribution-build-evidence.json"
    DEPENDS aether_setup aether aether_shell aether_runtime_setup aether_worker aether_graphics_worker
        aether_icon_worker aether_shell_icons
    VERBATIM)

add_library(aether_security STATIC src/security/protocol.cpp src/security/broker.cpp src/security/worker.cpp
    src/security/audit.cpp src/security/audit_file.cpp
    src/security/client.cpp src/security/audio_protocol.cpp src/security/audio_broker.cpp src/security/audio_client.cpp
    src/security/storage.cpp src/security/apk_result.cpp src/security/activity_protocol.cpp)
target_include_directories(aether_security PUBLIC include)
target_link_libraries(aether_security PUBLIC aether_core PRIVATE aether_runtime_permissions userenv advapi32 OneCoreUAP)
add_library(aether_isolated_apk STATIC src/security/apk_runtime.cpp src/security/apk_selftest.cpp)
target_link_libraries(aether_isolated_apk PUBLIC aether_security PRIVATE aether_android)
target_link_libraries(aether PRIVATE aether_isolated_apk)
add_library(aether_activity_host STATIC src/security/activity_host.cpp src/security/activity_dispatcher.cpp)
target_link_libraries(aether_activity_host PUBLIC aether_security)
add_library(aether_activity_runtime STATIC src/security/activity_runtime.cpp)
target_link_libraries(aether_activity_runtime PUBLIC aether_security PRIVATE aether_android)
target_link_libraries(aether_window PRIVATE aether_activity_host)
add_library(aether_isolated_audio STATIC src/security/audio_result.cpp src/security/audio_selftest.cpp)
target_link_libraries(aether_isolated_audio PUBLIC aether_security PRIVATE aether_audio_selftest)
target_link_libraries(aether PRIVATE aether_isolated_audio)
add_library(aether_isolated_graphics STATIC src/security/graphics_protocol.cpp src/security/graphics_channel.cpp
    src/security/graphics_process.cpp src/host/windows/graphics_presenter.cpp
    src/security/graphics_result.cpp src/security/graphics_selftest.cpp src/security/graphics_window_protocol.cpp
    src/security/graphics_window_runtime.cpp)
target_link_libraries(aether_isolated_graphics PUBLIC aether_security PRIVATE aether_graphics_selftest d3d11)
target_link_libraries(aether PRIVATE aether_isolated_graphics)
add_library(aether_graphics_window STATIC src/graphics/window.cpp src/security/graphics_window_session.cpp)
target_link_libraries(aether_graphics_window PUBLIC aether_graphics_selftest PRIVATE aether_isolated_graphics aether_window)
target_link_libraries(aether PRIVATE aether_graphics_window)
add_executable(aether_worker apps/aether-worker/main.cpp apps/aether-worker/probes.cpp)
target_link_libraries(aether_worker PRIVATE aether_isolated_graphics aether_isolated_audio aether_isolated_apk aether_activity_runtime aether_a64 aether_host_audio aether_angle userenv ws2_32)
set_target_properties(aether_worker PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/runtime")
add_custom_target(aether_runtime_directory
    COMMAND $<TARGET_FILE:aether_runtime_setup> --prepare-directory "${CMAKE_CURRENT_BINARY_DIR}/runtime" VERBATIM)
add_dependencies(aether_worker aether_runtime_directory)
add_custom_command(TARGET aether_worker POST_BUILD
    COMMAND $<TARGET_FILE:aether_runtime_setup> --provision $<TARGET_FILE:aether_worker> VERBATIM)
add_executable(aether_graphics_worker apps/aether-graphics-worker/main.cpp)
target_link_libraries(aether_graphics_worker PRIVATE aether_isolated_graphics userenv)
set_target_properties(aether_graphics_worker PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/runtime")
add_dependencies(aether_graphics_worker aether_runtime_directory)
add_custom_command(TARGET aether_graphics_worker POST_BUILD
    COMMAND $<TARGET_FILE:aether_runtime_setup> --provision $<TARGET_FILE:aether_graphics_worker> VERBATIM)

add_library(aether_metadata_protocol STATIC src/security/metadata_protocol.cpp)
target_link_libraries(aether_metadata_protocol PUBLIC aether_security)
add_library(aether_metadata_process STATIC src/security/metadata_process.cpp)
target_link_libraries(aether_metadata_process PUBLIC aether_metadata_protocol aether_icon_cache PRIVATE bcrypt)
add_library(aether_icon_broker STATIC src/shell/icon_broker.cpp)
target_link_libraries(aether_icon_broker PUBLIC aether_metadata_process PRIVATE shell32)
target_link_libraries(aether PRIVATE aether_icon_broker)
add_executable(aether_icon_worker apps/aether-icon-worker/main.cpp)
target_link_libraries(aether_icon_worker PRIVATE aether_metadata_protocol userenv)
set_target_properties(aether_icon_worker PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/runtime")
add_dependencies(aether_icon_worker aether_runtime_directory)
add_custom_command(TARGET aether_icon_worker POST_BUILD
    COMMAND $<TARGET_FILE:aether_runtime_setup> --provision $<TARGET_FILE:aether_icon_worker> VERBATIM)
add_dependencies(aether aether_icon_worker)

if(BUILD_TESTING)
    add_executable(aether_artwork_fixture tests/integration/artwork_fixture_main.cpp)
    target_link_libraries(aether_artwork_fixture PRIVATE aether_core)
    add_executable(aether_runtime_icon_tests tests/integration/runtime_icon_tests.cpp src/install/runtime.cpp
        src/install/explorer.cpp)
    # Bind only this fixture's default-store lookup. The actual production
    # lifecycle source, filesystem ACLs and journal checks are otherwise shared.
    target_compile_definitions(aether_runtime_icon_tests PRIVATE default_store_root=runtime_icon_test_store
        icon_cache_root=runtime_icon_test_cache icon_endpoint=runtime_icon_test_endpoint)
    target_link_libraries(aether_runtime_icon_tests PRIVATE aether_install)
    add_test(NAME aether.integration.runtime_icons COMMAND aether_runtime_icon_tests
        "${CMAKE_CURRENT_SOURCE_DIR}/out/distribution/${AETHER_PRESET_NAME}/AetherSetup.exe"
        "${CMAKE_CURRENT_BINARY_DIR}")
    set_tests_properties(aether.integration.runtime_icons PROPERTIES TIMEOUT 90 RUN_SERIAL TRUE)
    add_executable(aether_icon_broker_tests tests/integration/icon_broker_tests.cpp)
    target_link_libraries(aether_icon_broker_tests PRIVATE aether_icon_broker shell32 ole32 user32)
    add_dependencies(aether_icon_broker_tests aether_icon_worker)
    add_test(NAME aether.integration.icon_broker COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/icon_broker_tests.py" $<TARGET_FILE:aether>
        $<TARGET_FILE:aether_icon_broker_tests> $<TARGET_FILE:aether_icon_worker>)
    set_tests_properties(aether.integration.icon_broker PROPERTIES TIMEOUT 90 RUN_SERIAL TRUE)
    add_executable(aether_icon_worker_probe tests/security/icon_worker_probe.cpp)
    target_link_libraries(aether_icon_worker_probe PRIVATE aether_metadata_protocol ws2_32)
    set_target_properties(aether_icon_worker_probe PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/runtime")
    add_dependencies(aether_icon_worker_probe aether_runtime_directory)
    add_custom_command(TARGET aether_icon_worker_probe POST_BUILD
        COMMAND $<TARGET_FILE:aether_runtime_setup> --provision $<TARGET_FILE:aether_icon_worker_probe> VERBATIM)
    add_executable(aether_icon_worker_tests tests/security/icon_worker_tests.cpp)
    target_link_libraries(aether_icon_worker_tests PRIVATE aether_metadata_process ws2_32 ole32)
    add_dependencies(aether_icon_worker_tests aether_icon_worker_probe)
    add_test(NAME aether.security.icon_worker COMMAND aether_icon_worker_tests
        $<TARGET_FILE:aether_icon_worker_probe> "${CMAKE_CURRENT_BINARY_DIR}")
    set_tests_properties(aether.security.icon_worker PROPERTIES TIMEOUT 45 RUN_SERIAL TRUE)
    add_test(NAME aether.integration.metadata_preview COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/metadata_preview_tests.py" $<TARGET_FILE:aether>)
    set_tests_properties(aether.integration.metadata_preview PROPERTIES TIMEOUT 180)
    add_executable(aether_icon_queue_tests tests/integration/icon_queue_tests.cpp)
    target_link_libraries(aether_icon_queue_tests PRIVATE aether_icon_cache)
    add_test(NAME aether.integration.icon_queue COMMAND aether_icon_queue_tests)
    set_tests_properties(aether.integration.icon_queue PROPERTIES TIMEOUT 60)
    add_executable(aether_icon_cache_tests tests/integration/icon_cache_tests.cpp)
    target_link_libraries(aether_icon_cache_tests PRIVATE aether_core aether_icon_cache ole32)
    add_test(NAME aether.integration.icon_cache COMMAND aether_icon_cache_tests "${CMAKE_CURRENT_BINARY_DIR}")
    set_tests_properties(aether.integration.icon_cache PROPERTIES TIMEOUT 60)
    add_executable(aether_shell_icons_tests tests/integration/shell_icons_tests.cpp)
    target_include_directories(aether_shell_icons_tests PRIVATE include)
    target_link_libraries(aether_shell_icons_tests PRIVATE aether_options ole32 uuid user32 gdi32)
    add_dependencies(aether_shell_icons_tests aether_shell_icons)
    add_test(NAME aether.integration.shell_icons COMMAND aether_shell_icons_tests $<TARGET_FILE:aether_shell_icons>)
    set_tests_properties(aether.integration.shell_icons PROPERTIES TIMEOUT 30)
    add_test(NAME aether.integration.troubleshooting COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/troubleshooting_tests.py" "$<TARGET_FILE:aether>")
    set_tests_properties(aether.integration.troubleshooting PROPERTIES TIMEOUT 240 RUN_SERIAL TRUE
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_test(NAME aether.integration.app_controls COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/app_controls_tests.py" "$<TARGET_FILE:aether>")
    set_tests_properties(aether.integration.app_controls PROPERTIES TIMEOUT 240 RUN_SERIAL TRUE
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_test(NAME aether.integration.diagnostics COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/diagnostics_tests.py" "$<TARGET_FILE:aether>")
    set_tests_properties(aether.integration.diagnostics PROPERTIES TIMEOUT 120 RUN_SERIAL TRUE
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_test(NAME aether.integration.signing_store COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/signing_store_tests.py" "$<TARGET_FILE:aether>")
    set_tests_properties(aether.integration.signing_store PROPERTIES TIMEOUT 120 RUN_SERIAL TRUE
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_test(NAME aether.integration.update COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/update_tests.py" "$<TARGET_FILE:aether>")
    set_tests_properties(aether.integration.update PROPERTIES TIMEOUT 180 RUN_SERIAL TRUE
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_test(NAME aether.integration.update_failures COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/update_failure_tests.py" "$<TARGET_FILE:aether>")
    set_tests_properties(aether.integration.update_failures PROPERTIES TIMEOUT 240 RUN_SERIAL TRUE
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_test(NAME aether.integration.signing COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/signing_tests.py" "$<TARGET_FILE:aether>")
    add_test(NAME aether.integration.signing_v31 COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/signing_v31_tests.py" "$<TARGET_FILE:aether>")
    set_tests_properties(aether.integration.signing_v31 PROPERTIES TIMEOUT 120
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_test(NAME aether.integration.package_set COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/package_set_tests.py" "$<TARGET_FILE:aether>")
    set_tests_properties(aether.integration.package_set PROPERTIES TIMEOUT 120
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_test(NAME aether.integration.split_install COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/split_install_tests.py" "$<TARGET_FILE:aether>")
    set_tests_properties(aether.integration.split_install PROPERTIES TIMEOUT 180 RUN_SERIAL TRUE
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    set_tests_properties(aether.integration.signing PROPERTIES TIMEOUT 180
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_test(NAME aether.integration.native_runtime COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/native_runtime_tests.py" "$<TARGET_FILE:aether>")
    set_tests_properties(aether.integration.native_runtime PROPERTIES TIMEOUT 180 RUN_SERIAL TRUE
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_test(NAME aether.integration.runtime_upgrade COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/runtime_upgrade_tests.py" "$<TARGET_FILE:aether>")
    set_tests_properties(aether.integration.runtime_upgrade PROPERTIES TIMEOUT 240 RUN_SERIAL TRUE
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_test(NAME aether.integration.runtime_install COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/runtime_install_tests.py" "$<TARGET_FILE:aether>")
    set_tests_properties(aether.integration.runtime_install PROPERTIES TIMEOUT 240 RUN_SERIAL TRUE
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_test(NAME aether.integration.explorer COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/explorer_tests.py" "$<TARGET_FILE:aether>")
    set_tests_properties(aether.integration.explorer PROPERTIES TIMEOUT 150 RUN_SERIAL TRUE
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_test(NAME aether.integration.native_install COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/native_install_tests.py" "$<TARGET_FILE:aether>")
    set_tests_properties(aether.integration.native_install PROPERTIES TIMEOUT 150 RUN_SERIAL TRUE
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_test(NAME aether.integration.artwork COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/artwork_tests.py" "$<TARGET_FILE:aether>")
    set_tests_properties(aether.integration.artwork PROPERTIES TIMEOUT 90
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_test(NAME aether.integration.installed_artwork COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/installed_artwork_tests.py" "$<TARGET_FILE:aether>")
    set_tests_properties(aether.integration.installed_artwork PROPERTIES TIMEOUT 90 RUN_SERIAL TRUE
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_test(NAME aether.integration.package_preview COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/package_preview_tests.py" "$<TARGET_FILE:aether>")
    set_tests_properties(aether.integration.package_preview PROPERTIES TIMEOUT 90
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_test(NAME aether.integration.drawable COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/drawable_tests.py" "$<TARGET_FILE:aether>")
    set_tests_properties(aether.integration.drawable PROPERTIES TIMEOUT 120
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_test(NAME aether.integration.preview_container COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/preview_container_tests.py" "$<TARGET_FILE:aether>")
    set_tests_properties(aether.integration.preview_container PROPERTIES TIMEOUT 120
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_test(NAME aether.integration.preview_sparse COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/preview_sparse_tests.py" "$<TARGET_FILE:aether>")
    set_tests_properties(aether.integration.preview_sparse PROPERTIES TIMEOUT 30
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1;PYTHONPATH=${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures")
    add_test(NAME aether.integration.shell_registration COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/shell_registration_tests.py" "$<TARGET_FILE:aether>")
    set_tests_properties(aether.integration.shell_registration PROPERTIES TIMEOUT 150 RUN_SERIAL TRUE
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_test(NAME aether.integration.installed_launch COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/installed_launch_tests.py" "$<TARGET_FILE:aether>")
    set_tests_properties(aether.integration.installed_launch PROPERTIES TIMEOUT 180 RUN_SERIAL TRUE
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_test(NAME aether.integration.install COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/install_tests.py" "$<TARGET_FILE:aether>")
    set_tests_properties(aether.integration.install PROPERTIES TIMEOUT 90 RUN_SERIAL TRUE
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_executable(aether_activity_tests tests/security/activity_tests.cpp)
    target_link_libraries(aether_activity_tests PRIVATE aether_activity_host)
    add_test(NAME aether.security.activity COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/security/activity_tests.py" "$<TARGET_FILE:aether_activity_tests>"
        "$<TARGET_FILE:aether_worker>" "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/hello-aether.apk")
    set_tests_properties(aether.security.activity PROPERTIES TIMEOUT 60 RUN_SERIAL TRUE
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_test(NAME aether.security.isolated_apk COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/security/isolated_apk_tests.py" "$<TARGET_FILE:aether>")
    set_tests_properties(aether.security.isolated_apk PROPERTIES TIMEOUT 90 RUN_SERIAL TRUE
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_executable(aether_worker_tests tests/security/worker_tests.cpp tests/security/worker_resource_tests.cpp)
    target_link_libraries(aether_worker_tests PRIVATE aether_security bcrypt ws2_32)
    add_test(NAME aether.security.worker COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/security/worker_tests.py" "$<TARGET_FILE:aether_worker_tests>"
        "$<TARGET_FILE:aether_worker>" "${CMAKE_CURRENT_SOURCE_DIR}/tests/security/denied-probe.txt")
    set_tests_properties(aether.security.worker PROPERTIES TIMEOUT 90 RUN_SERIAL TRUE ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_test(NAME aether.security.runtime_permissions COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/security/runtime_permissions_tests.py" "$<TARGET_FILE:aether_runtime_setup>")
    set_tests_properties(aether.security.runtime_permissions PROPERTIES TIMEOUT 40 RUN_SERIAL TRUE
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_executable(aether_graphics_process_probe tests/security/graphics_process_probe.cpp)
    target_link_libraries(aether_graphics_process_probe PRIVATE aether_security aether_angle userenv user32 d3d11 OneCoreUAP ole32 uuid)
    set_target_properties(aether_graphics_process_probe PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/runtime")
    add_dependencies(aether_graphics_process_probe aether_runtime_directory)
    add_custom_command(TARGET aether_graphics_process_probe POST_BUILD
        COMMAND $<TARGET_FILE:aether_runtime_setup> --provision $<TARGET_FILE:aether_graphics_process_probe> VERBATIM)
    add_executable(aether_graphics_process_tests tests/security/graphics_process_tests.cpp
        tests/security/graphics_surface_tests.cpp)
    target_link_libraries(aether_graphics_process_tests PRIVATE aether_isolated_graphics)
    add_test(NAME aether.security.graphics_process COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/security/graphics_process_tests.py" "$<TARGET_FILE:aether_graphics_process_probe>"
        "$<TARGET_FILE:aether_graphics_process_tests>" "$<TARGET_FILE:aether_graphics_worker>"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/security/denied-probe.txt")
    set_tests_properties(aether.security.graphics_process PROPERTIES TIMEOUT 100 RUN_SERIAL TRUE
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_test(NAME aether.security.lpac_policy COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/security/lpac_policy_tests.py" "$<TARGET_FILE:aether_graphics_process_probe>"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/security/denied-probe.txt")
    set_tests_properties(aether.security.lpac_policy PROPERTIES TIMEOUT 40 RUN_SERIAL TRUE
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_executable(aether_shader_corpus_tests tests/security/shader_corpus_tests.cpp)
    target_link_libraries(aether_shader_corpus_tests PRIVATE aether_isolated_graphics)
    target_include_directories(aether_shader_corpus_tests SYSTEM PRIVATE third_party/angle/include)
    add_test(NAME aether.security.shader_corpus COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/security/shader_corpus_tests.py"
        "$<TARGET_FILE:aether_shader_corpus_tests>" "$<TARGET_FILE:aether_graphics_worker>")
    set_tests_properties(aether.security.shader_corpus PROPERTIES TIMEOUT 180 RUN_SERIAL TRUE
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_executable(aether_renderer_access_tests tests/security/renderer_access_tests.cpp)
    target_link_libraries(aether_renderer_access_tests PRIVATE aether_isolated_graphics ws2_32 ole32 uuid)
    target_include_directories(aether_renderer_access_tests SYSTEM PRIVATE third_party/angle/include)
    set_target_properties(aether_renderer_access_tests PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/runtime")
    add_dependencies(aether_renderer_access_tests aether_runtime_directory)
    add_custom_command(TARGET aether_renderer_access_tests POST_BUILD
        COMMAND $<TARGET_FILE:aether_runtime_setup> --provision $<TARGET_FILE:aether_renderer_access_tests> VERBATIM)
    add_test(NAME aether.security.renderer_access COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/security/renderer_access_tests.py"
        "$<TARGET_FILE:aether_renderer_access_tests>" "$<TARGET_FILE:aether_graphics_worker>")
    set_tests_properties(aether.security.renderer_access PROPERTIES TIMEOUT 30 RUN_SERIAL TRUE
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_executable(aether_host_resource_tests tests/security/host_resource_tests.cpp)
    target_link_libraries(aether_host_resource_tests PRIVATE aether_security ws2_32 ole32 uuid user32 bcrypt)
    set_target_properties(aether_host_resource_tests PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/runtime")
    add_dependencies(aether_host_resource_tests aether_runtime_directory)
    add_custom_command(TARGET aether_host_resource_tests POST_BUILD
        COMMAND $<TARGET_FILE:aether_runtime_setup> --provision $<TARGET_FILE:aether_host_resource_tests> VERBATIM)
    add_test(NAME aether.security.host_resources COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/security/host_resource_tests.py" "$<TARGET_FILE:aether_host_resource_tests>")
    set_tests_properties(aether.security.host_resources PROPERTIES TIMEOUT 35 RUN_SERIAL TRUE
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_executable(aether_angle_probe tests/graphics/angle_probe.cpp)
    target_link_libraries(aether_angle_probe PRIVATE aether_angle aether_core)
    add_test(NAME aether.integration.angle_host COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/angle_tests.py" "$<TARGET_FILE:aether_angle_probe>")
    set_tests_properties(aether.integration.angle_host PROPERTIES TIMEOUT 60 RUN_SERIAL TRUE)
    add_library(aether_doctest INTERFACE)
    target_include_directories(aether_doctest SYSTEM INTERFACE third_party/doctest)
    add_executable(aether_security_tests tests/unit/security_tests.cpp tests/unit/security_storage_tests.cpp
        tests/unit/activity_protocol_tests.cpp tests/unit/security_audio_tests.cpp tests/unit/security_audit_tests.cpp)
    target_link_libraries(aether_security_tests PRIVATE aether_security aether_doctest)
    target_compile_definitions(aether_security_tests PRIVATE
        AETHER_SECURITY_TEST_DATA_DIR="${CMAKE_CURRENT_BINARY_DIR}/security-unit-data")
    add_test(NAME aether.unit.security COMMAND aether_security_tests)
    set_tests_properties(aether.unit.security PROPERTIES TIMEOUT 30)
    add_executable(aether_audio_tests tests/unit/audio_tests.cpp)
    target_link_libraries(aether_audio_tests PRIVATE aether_audio aether_doctest)
    add_test(NAME aether.unit.audio COMMAND aether_audio_tests)
    set_tests_properties(aether.unit.audio PROPERTIES TIMEOUT 30 RUN_SERIAL TRUE)
    add_test(NAME aether.integration.audio COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/audio_tests.py" "$<TARGET_FILE:aether>")
    set_tests_properties(aether.integration.audio PROPERTIES TIMEOUT 45 RUN_SERIAL TRUE
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_executable(aether_graphics_tests tests/unit/graphics_tests.cpp tests/unit/graphics_protocol_tests.cpp
        tests/unit/graphics_window_session_tests.cpp)
    target_link_libraries(aether_graphics_tests PRIVATE aether_graphics aether_isolated_graphics aether_graphics_window aether_angle aether_doctest)
    target_compile_definitions(aether_graphics_tests PRIVATE
        AETHER_GRAPHICS_FIXTURE="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/graphics/libaether_gles.so")
    add_test(NAME aether.unit.graphics COMMAND aether_graphics_tests)
    set_tests_properties(aether.unit.graphics PROPERTIES TIMEOUT 60 RUN_SERIAL TRUE)
    add_test(NAME aether.integration.graphics COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/graphics_tests.py" "$<TARGET_FILE:aether>")
    set_tests_properties(aether.integration.graphics PROPERTIES TIMEOUT 60 RUN_SERIAL TRUE)
    add_test(NAME aether.integration.graphics_window COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/graphics_window_tests.py" "$<TARGET_FILE:aether>")
    set_tests_properties(aether.integration.graphics_window PROPERTIES TIMEOUT 60 RUN_SERIAL TRUE)
    set_tests_properties(aether.integration.angle_host aether.integration.graphics aether.integration.graphics_window PROPERTIES
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_executable(aether_tests tests/unit/foundation_tests.cpp tests/unit/prefix_strings_tests.cpp tests/unit/native_inventory_tests.cpp)
    target_link_libraries(aether_tests PRIVATE aether_core aether_doctest)
    add_test(NAME aether.unit.foundation COMMAND aether_tests)
    add_executable(aether_a64_tests tests/unit/a64_tests.cpp)
    target_link_libraries(aether_a64_tests PRIVATE aether_a64 aether_doctest)
    add_test(NAME aether.unit.a64 COMMAND aether_a64_tests)
    add_executable(aether_elf_tests tests/unit/elf_tests.cpp tests/unit/elf_stream_tests.cpp)
    target_link_libraries(aether_elf_tests PRIVATE aether_bionic aether_core aether_doctest)
    target_compile_definitions(aether_elf_tests PRIVATE
        AETHER_NATIVE_FIXTURE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/native"
        AETHER_NATIVE_TEST_DATA_DIR="${CMAKE_CURRENT_BINARY_DIR}/native-unit-data")
    add_test(NAME aether.unit.elf_bionic COMMAND aether_elf_tests)
    set_tests_properties(aether.unit.elf_bionic PROPERTIES TIMEOUT 60)
    add_executable(aether_dex_tests tests/unit/dex_tests.cpp tests/unit/dex_linker_tests.cpp tests/unit/dex_source_tests.cpp tests/unit/dex_array_clone_tests.cpp tests/unit/dex038_tests.cpp)
    target_link_libraries(aether_dex_tests PRIVATE aether_jni aether_core aether_doctest)
    target_compile_definitions(aether_dex_tests PRIVATE AETHER_DEX_FIXTURE_APK="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/hello-aether.apk")
    target_compile_definitions(aether_dex_tests PRIVATE AETHER_MULTIDEX_FIXTURE_APK="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/multidex-aether.apk")
    target_compile_definitions(aether_dex_tests PRIVATE AETHER_DEX038_FIXTURE_APK="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/dex038-aether.apk")
    target_compile_definitions(aether_dex_tests PRIVATE AETHER_ARRAY_CLONE_FIXTURE_APK="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/array-clone-aether.apk")
    add_test(NAME aether.unit.dex COMMAND aether_dex_tests)
    set_tests_properties(aether.unit.dex PROPERTIES TIMEOUT 45)
    add_executable(aether_framework_tests tests/unit/framework_tests.cpp)
    target_link_libraries(aether_framework_tests PRIVATE aether_android aether_jni aether_core aether_doctest)
    target_compile_definitions(aether_framework_tests PRIVATE AETHER_FRAMEWORK_FIXTURE_APK="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/hello-aether.apk")
    add_test(NAME aether.unit.framework COMMAND aether_framework_tests)
    set_tests_properties(aether.unit.framework PROPERTIES TIMEOUT 45)
    add_executable(aether_window_input_tests tests/unit/window_input_tests.cpp)
    target_link_libraries(aether_window_input_tests PRIVATE aether_window aether_doctest)
    add_test(NAME aether.unit.window_input COMMAND aether_window_input_tests)
    set_tests_properties(aether.unit.window_input PROPERTIES TIMEOUT 30)
    add_executable(aether_sandbox_probe tests/security/sandbox_probe.cpp)
    target_link_libraries(aether_sandbox_probe PRIVATE aether_a64 aether_runtime_permissions userenv advapi32)
    set_target_properties(aether_sandbox_probe PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/runtime")
    add_dependencies(aether_sandbox_probe aether_runtime_directory)
    add_custom_command(TARGET aether_sandbox_probe POST_BUILD
        COMMAND $<TARGET_FILE:aether_runtime_setup> --provision $<TARGET_FILE:aether_sandbox_probe> VERBATIM)
    find_package(Python3 3.10 REQUIRED COMPONENTS Interpreter)
    add_test(NAME aether.security.appcontainer_jit COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/security/sandbox_tests.py" "$<TARGET_FILE:aether_sandbox_probe>"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/security/denied-probe.txt")
    set_tests_properties(aether.security.appcontainer_jit PROPERTIES TIMEOUT 50 RUN_SERIAL TRUE)
    add_test(NAME aether.dependencies.integrity COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tools/verify-dependencies.py"
        --evidence "${CMAKE_CURRENT_BINARY_DIR}/dependency-integrity-evidence.json")
    set_tests_properties(aether.dependencies.integrity PROPERTIES TIMEOUT 90)
    add_test(NAME aether.distribution.integrity COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tools/verify-distribution.py"
        --build "${CMAKE_CURRENT_BINARY_DIR}"
        --bundle "${CMAKE_CURRENT_SOURCE_DIR}/out/distribution/${AETHER_PRESET_NAME}/AetherSetup.exe"
        --evidence "${CMAKE_CURRENT_BINARY_DIR}/distribution-integrity-evidence.json")
    set_tests_properties(aether.distribution.integrity PROPERTIES TIMEOUT 60
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_test(NAME aether.integration.translation COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/translation_tests.py" "$<TARGET_FILE:aether>")
    set_tests_properties(aether.unit.a64 aether.integration.translation PROPERTIES TIMEOUT 45)
    add_test(NAME aether.integration.native COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/native_tests.py" "$<TARGET_FILE:aether>")
    set_tests_properties(aether.integration.native PROPERTIES TIMEOUT 60)
    add_test(NAME aether.integration.managed COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/managed_tests.py" "$<TARGET_FILE:aether>")
    set_tests_properties(aether.integration.managed PROPERTIES TIMEOUT 60)
    add_test(NAME aether.integration.framework COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/framework_tests.py" "$<TARGET_FILE:aether>")
    set_tests_properties(aether.integration.framework PROPERTIES TIMEOUT 60)
    add_test(NAME aether.integration.window COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/window_tests.py" "$<TARGET_FILE:aether>")
    set_tests_properties(aether.integration.window PROPERTIES TIMEOUT 60 RUN_SERIAL TRUE
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_test(NAME aether.integration.cli COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/cli_tests.py" "$<TARGET_FILE:aether>")
    add_test(NAME aether.integration.manifest_namespaces COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/manifest_namespace_tests.py" "$<TARGET_FILE:aether>")
    set_tests_properties(aether.integration.manifest_namespaces PROPERTIES TIMEOUT 45)
    add_test(NAME aether.integration.manifest_inventory COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/manifest_inventory_tests.py" "$<TARGET_FILE:aether>")
    set_tests_properties(aether.integration.manifest_inventory PROPERTIES TIMEOUT 60)
    add_test(NAME aether.integration.launcher COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/launcher_tests.py" "$<TARGET_FILE:aether>")
    set_tests_properties(aether.integration.launcher PROPERTIES TIMEOUT 60)
    add_test(NAME aether.integration.native_payloads COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/native_payload_tests.py" "$<TARGET_FILE:aether>")
    set_tests_properties(aether.integration.native_payloads PROPERTIES TIMEOUT 45)
    add_test(NAME aether.integration.archive_stream COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/archive_stream_tests.py" "$<TARGET_FILE:aether>")
    set_tests_properties(aether.integration.archive_stream PROPERTIES TIMEOUT 120)
    add_test(NAME aether.unit.privacy_text COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/unit/privacy_text_tests.py")
    add_test(NAME aether.integration.privacy COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/privacy_tests.py" "$<TARGET_FILE:aether>")
    set_tests_properties(aether.unit.privacy_text PROPERTIES TIMEOUT 15)
    set_tests_properties(aether.integration.privacy PROPERTIES TIMEOUT 90 RUN_SERIAL TRUE)
    add_test(NAME aether.security.packages COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/security/package_tests.py" "$<TARGET_FILE:aether>")
    set_tests_properties(aether.security.packages PROPERTIES TIMEOUT 90 ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    # Parser-only entry point: actual ELF loading; never construct a CPU or run lifecycle calls.
    add_executable(aether_parser_probe tests/security/parser_probe.cpp src/dex/image.cpp src/dex/annotations.cpp
        src/dex/bytecode.cpp tests/security/parser_elf.cpp tests/security/parser_package.cpp)
    target_link_libraries(aether_parser_probe PRIVATE aether_security aether_bionic userenv)
    set_target_properties(aether_parser_probe PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/runtime")
    add_dependencies(aether_parser_probe aether_runtime_directory)
    add_custom_command(TARGET aether_parser_probe POST_BUILD
        COMMAND $<TARGET_FILE:aether_runtime_setup> --provision $<TARGET_FILE:aether_parser_probe> VERBATIM)
    add_test(NAME aether.security.parser_apk COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/security/parser_fuzz_tests.py" "$<TARGET_FILE:aether_parser_probe>" --slice apk)
    set_tests_properties(aether.security.parser_apk PROPERTIES TIMEOUT 180 RUN_SERIAL TRUE
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_test(NAME aether.security.parser_supervision COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/security/parser_supervision_tests.py" "$<TARGET_FILE:aether_parser_probe>")
    set_tests_properties(aether.security.parser_supervision PROPERTIES TIMEOUT 45 RUN_SERIAL TRUE
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_test(NAME aether.security.parser_dex COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/security/parser_fuzz_tests.py" "$<TARGET_FILE:aether_parser_probe>" --slice dex)
    set_tests_properties(aether.security.parser_dex PROPERTIES TIMEOUT 180 RUN_SERIAL TRUE
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_test(NAME aether.security.parser_elf COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/security/parser_fuzz_tests.py" "$<TARGET_FILE:aether_parser_probe>" --slice elf)
    set_tests_properties(aether.security.parser_elf PROPERTIES TIMEOUT 180 RUN_SERIAL TRUE
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_executable(aether_package_admission tests/security/package_admission.cpp)
    target_link_libraries(aether_package_admission PRIVATE aether_security)
    add_dependencies(aether_package_admission aether_worker)
    add_test(NAME aether.security.package_admission COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/security/package_admission_tests.py"
        "$<TARGET_FILE:aether_parser_probe>" "$<TARGET_FILE:aether_package_admission>" "$<TARGET_FILE:aether>")
    set_tests_properties(aether.security.package_admission PROPERTIES TIMEOUT 180 RUN_SERIAL TRUE
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_executable(aether_jit_boundary_tests tests/security/jit_boundary_tests.cpp tests/security/jit_boundary_cases.cpp)
    target_link_libraries(aether_jit_boundary_tests PRIVATE aether_security aether_bionic userenv)
    set_target_properties(aether_jit_boundary_tests PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/runtime")
    add_dependencies(aether_jit_boundary_tests aether_runtime_directory)
    add_custom_command(TARGET aether_jit_boundary_tests POST_BUILD
        COMMAND $<TARGET_FILE:aether_runtime_setup> --provision $<TARGET_FILE:aether_jit_boundary_tests> VERBATIM)
    add_test(NAME aether.security.jit_boundaries COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/security/jit_boundary_tests.py" "$<TARGET_FILE:aether_jit_boundary_tests>")
    set_tests_properties(aether.security.jit_boundaries PROPERTIES TIMEOUT 45 RUN_SERIAL TRUE
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_executable(aether_winhttp_tests tests/security/winhttp_tests.cpp)
    target_link_libraries(aether_winhttp_tests PRIVATE aether_security userenv winhttp ws2_32)
    set_target_properties(aether_winhttp_tests PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/runtime")
    add_dependencies(aether_winhttp_tests aether_runtime_directory)
    add_custom_command(TARGET aether_winhttp_tests POST_BUILD
        COMMAND $<TARGET_FILE:aether_runtime_setup> --provision $<TARGET_FILE:aether_winhttp_tests> VERBATIM)
    add_test(NAME aether.security.winhttp COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/security/winhttp_tests.py" "$<TARGET_FILE:aether_winhttp_tests>")
    add_test(NAME aether.security.network_startup COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/security/network_startup_tests.py" "$<TARGET_FILE:aether_winhttp_tests>")
    set_tests_properties(aether.security.network_startup PROPERTIES TIMEOUT 60 RUN_SERIAL TRUE
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    set_tests_properties(aether.security.winhttp PROPERTIES TIMEOUT 60 RUN_SERIAL TRUE
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_executable(aether_capture_tests tests/security/capture_tests.cpp)
    target_link_libraries(aether_capture_tests PRIVATE aether_security userenv setupapi winmm mf mfplat mfuuid ole32)
    set_target_properties(aether_capture_tests PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/runtime")
    add_dependencies(aether_capture_tests aether_runtime_directory)
    add_custom_command(TARGET aether_capture_tests POST_BUILD
        COMMAND $<TARGET_FILE:aether_runtime_setup> --provision $<TARGET_FILE:aether_capture_tests> VERBATIM)
    add_test(NAME aether.security.capture_interfaces COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/security/capture_tests.py" "$<TARGET_FILE:aether_capture_tests>")
    set_tests_properties(aether.security.capture_interfaces PROPERTIES TIMEOUT 60 RUN_SERIAL TRUE
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_test(NAME aether.security.capture_open COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/security/capture_tests.py" "$<TARGET_FILE:aether_capture_tests>"
        --device-access)
    set_tests_properties(aether.security.capture_open PROPERTIES TIMEOUT 60 RUN_SERIAL TRUE
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_test(NAME aether.integration.hello_apk COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration/fixture_tests.py" "$<TARGET_FILE:aether>"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/hello-aether.apk")
    set_tests_properties(aether.integration.hello_apk PROPERTIES TIMEOUT 30)
    set_tests_properties(aether.unit.foundation aether.integration.cli PROPERTIES TIMEOUT 30)
    # Replace only the presenter's object in this non-installed executable. Production libraries,
    # guest/renderer images and their policy contain no fault selector or test hook.
    add_executable(aether_graphics_device_tests tests/security/graphics_device_tests.cpp
        src/host/windows/graphics_presenter.cpp)
    target_link_libraries(aether_graphics_device_tests PRIVATE aether_graphics_window aether_isolated_graphics d3d11)
    target_include_directories(aether_graphics_device_tests PRIVATE tests/security)
    target_compile_definitions(aether_graphics_device_tests PRIVATE AETHER_GRAPHICS_FAULT_TESTING
        AETHER_GRAPHICS_FIXTURE="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/graphics/libaether_gles.so")
    add_dependencies(aether_graphics_device_tests aether_worker aether_graphics_worker)
    add_test(NAME aether.security.graphics_device COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/security/graphics_device_tests.py" "$<TARGET_FILE:aether_graphics_device_tests>")
    set_tests_properties(aether.security.graphics_device PROPERTIES TIMEOUT 120 RUN_SERIAL TRUE
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    # Compile the real main/graphics sources with owned-state callbacks only in this test worker.
    # Policy checks and all other objects remain the production implementation.
    add_executable(aether_graphics_context_worker apps/aether-graphics-worker/main.cpp
        tests/security/graphics_context_faults.cpp src/graphics/guest.cpp)
    target_link_libraries(aether_graphics_context_worker PRIVATE aether_isolated_graphics aether_angle userenv)
    target_compile_definitions(aether_graphics_context_worker PRIVATE AETHER_GRAPHICS_CONTEXT_TESTING
        ANGLE_ENABLE_SHARE_CONTEXT_LOCK=1 ANGLE_ENABLE_CONTEXT_MUTEX=1 ANGLE_CAPTURE_ENABLED=0)
    target_include_directories(aether_graphics_context_worker SYSTEM PRIVATE third_party/angle/src
        third_party/angle/src/common/base third_party/angle/src/common/third_party/xxhash "${aether_angle_generated}")
    set_target_properties(aether_graphics_context_worker PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/runtime")
    add_dependencies(aether_graphics_context_worker aether_runtime_directory)
    add_custom_command(TARGET aether_graphics_context_worker POST_BUILD
        COMMAND $<TARGET_FILE:aether_runtime_setup> --provision $<TARGET_FILE:aether_graphics_context_worker> VERBATIM)
    add_executable(aether_graphics_context_tests tests/security/graphics_context_tests.cpp
        src/security/graphics_window_session.cpp)
    target_link_libraries(aether_graphics_context_tests PRIVATE aether_graphics_window aether_isolated_graphics)
    target_compile_definitions(aether_graphics_context_tests PRIVATE AETHER_GRAPHICS_REBIND_TESTING
        AETHER_GRAPHICS_FIXTURE="${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/graphics/libaether_gles.so")
    target_include_directories(aether_graphics_context_tests SYSTEM PRIVATE third_party/angle/include)
    add_dependencies(aether_graphics_context_tests aether_graphics_context_worker aether_graphics_worker aether_worker)
    add_test(NAME aether.security.graphics_context COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/security/graphics_context_tests.py" "$<TARGET_FILE:aether_graphics_context_tests>"
        "$<TARGET_FILE:aether_graphics_context_worker>" "$<TARGET_FILE:aether_graphics_worker>")
    set_tests_properties(aether.security.graphics_context PROPERTIES TIMEOUT 120 RUN_SERIAL TRUE
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_test(NAME aether.unit.dependency_verifier COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/unit/dependency_verifier_tests.py")
    set_tests_properties(aether.unit.dependency_verifier PROPERTIES TIMEOUT 15
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_test(NAME aether.unit.distribution_verifier COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/unit/distribution_verifier_tests.py" "${CMAKE_CURRENT_BINARY_DIR}")
    set_tests_properties(aether.unit.distribution_verifier PROPERTIES TIMEOUT 30
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    add_test(NAME aether.unit.inventory_report COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/unit/inventory_report_tests.py")
    add_test(NAME aether.compatibility.catalogue COMMAND "${Python3_EXECUTABLE}" -B
        "${CMAKE_CURRENT_SOURCE_DIR}/tools/aether_inventory_report.py" --check --check-xlsx)
    set_tests_properties(aether.unit.inventory_report aether.compatibility.catalogue PROPERTIES TIMEOUT 30
        ENVIRONMENT "PYTHONDONTWRITEBYTECODE=1")
    # Test helpers are source, not a cache location. Preserve other per-test
    # environment settings while preventing bytecode litter for every selection.
    get_property(aether_registered_tests DIRECTORY PROPERTY TESTS)
    set_property(TEST ${aether_registered_tests} APPEND PROPERTY ENVIRONMENT_MODIFICATION
        "PYTHONDONTWRITEBYTECODE=set:1")
endif()

install(TARGETS aether aether_shell aether_runtime_setup RUNTIME DESTINATION .)
install(CODE [[
    execute_process(COMMAND "${CMAKE_INSTALL_PREFIX}/aether_runtime_setup.exe" --prepare-directory
        "${CMAKE_INSTALL_PREFIX}/runtime" RESULT_VARIABLE aether_permissions_result)
    if(NOT aether_permissions_result EQUAL 0)
        message(FATAL_ERROR "Cannot prepare the protected Aether runtime directory.")
    endif()
]])
install(TARGETS aether_worker aether_graphics_worker aether_icon_worker RUNTIME DESTINATION runtime)
install(CODE "
    file(SHA256 \"$<TARGET_FILE:aether_shell_icons>\" aether_icon_hash)
    foreach(aether_icon_directory \"shell-icons\" \"shell-icons/\${aether_icon_hash}\")
        execute_process(COMMAND \"\${CMAKE_INSTALL_PREFIX}/aether_runtime_setup.exe\" --prepare-directory
            \"\${CMAKE_INSTALL_PREFIX}/\${aether_icon_directory}\" RESULT_VARIABLE aether_permissions_result)
        if(NOT aether_permissions_result EQUAL 0)
            message(FATAL_ERROR \"Cannot prepare the protected shell icon directory.\")
        endif()
    endforeach()
    file(INSTALL DESTINATION \"\${CMAKE_INSTALL_PREFIX}/shell-icons/\${aether_icon_hash}\"
        TYPE FILE FILES \"$<TARGET_FILE:aether_shell_icons>\")
")
install(DIRECTORY third_party/licenses/ DESTINATION licenses FILES_MATCHING PATTERN "*.txt")
install(CODE [[
    foreach(aether_worker_name aether_worker aether_graphics_worker aether_icon_worker)
    execute_process(COMMAND "${CMAKE_INSTALL_PREFIX}/aether_runtime_setup.exe" --provision
        "${CMAKE_INSTALL_PREFIX}/runtime/${aether_worker_name}.exe" RESULT_VARIABLE aether_permissions_result)
    if(NOT aether_permissions_result EQUAL 0)
        message(FATAL_ERROR "Aether runtime permissions could not be provisioned; worker launch will refuse this installation.")
    endif()
    endforeach()
]])
