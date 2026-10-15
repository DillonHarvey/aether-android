# Original offline adapter for the reviewed, pinned Windows/D3D11 ANGLE subset.
# The GN inventories remain authoritative; no upstream generator is executed.
find_package(Python3 3.10 REQUIRED COMPONENTS Interpreter)
set(aether_angle_root "${CMAKE_CURRENT_SOURCE_DIR}/third_party/angle")
set(aether_angle_generated "${CMAKE_CURRENT_BINARY_DIR}/generated/angle")
# Track byte-level version inputs as well as source inventories when using cmake --build directly.
file(GLOB_RECURSE aether_angle_version_inputs CONFIGURE_DEPENDS LIST_DIRECTORIES FALSE
    "${aether_angle_root}/*")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    ${aether_angle_version_inputs}
    "${CMAKE_CURRENT_SOURCE_DIR}/tools/angle_sources.py"
    "${aether_angle_root}/src/libGLESv2.gni"
    "${aether_angle_root}/src/compiler.gni"
    "${aether_angle_root}/src/libANGLE/renderer/d3d/d3d_backend.gni")
execute_process(COMMAND "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/tools/angle_sources.py"
    "${aether_angle_root}" "${aether_angle_generated}"
    --build-identity "${CMAKE_CXX_COMPILER_ID}|${CMAKE_CXX_COMPILER_VERSION}|x64|${CMAKE_BUILD_TYPE}|static-CRT"
    COMMAND_ERROR_IS_FATAL ANY)
include("${aether_angle_generated}/sources.cmake")

set(aether_zlib_root "${CMAKE_CURRENT_SOURCE_DIR}/third_party/angle-zlib")
add_library(aether_angle_zlib STATIC
    "${aether_zlib_root}/adler32.c" "${aether_zlib_root}/compress.c"
    "${aether_zlib_root}/crc32.c" "${aether_zlib_root}/deflate.c"
    "${aether_zlib_root}/infback.c" "${aether_zlib_root}/inffast.c"
    "${aether_zlib_root}/inflate.c" "${aether_zlib_root}/inftrees.c"
    "${aether_zlib_root}/trees.c" "${aether_zlib_root}/uncompr.c"
    "${aether_zlib_root}/zutil.c"
    "${aether_zlib_root}/google/compression_utils_portable.cc")
target_include_directories(aether_angle_zlib SYSTEM PUBLIC
    "${aether_zlib_root}" "${aether_zlib_root}/google")
target_compile_definitions(aether_angle_zlib PRIVATE _CRT_SECURE_NO_WARNINGS)
target_compile_options(aether_angle_zlib PRIVATE /W3 /utf-8 /EHsc)

add_library(aether_angle STATIC ${AETHER_ANGLE_SOURCES})
target_include_directories(aether_angle SYSTEM PUBLIC "${aether_angle_root}/include")
target_include_directories(aether_angle PRIVATE "${aether_angle_root}/src"
    "${aether_angle_root}/src/common/base"
    "${aether_angle_root}/src/common/third_party/xxhash" "${aether_angle_generated}")
target_compile_definitions(aether_angle PUBLIC
    ANGLE_STATIC=1 ANGLE_EXPORT= ANGLE_UTIL_EXPORT= EGLAPI= GL_APICALL= GL_API=)
target_compile_definitions(aether_angle PRIVATE
    ANGLE_IS_WIN ANGLE_ENABLE_D3D11 ANGLE_ENABLE_HLSL
    LIBANGLE_IMPLEMENTATION ANGLE_PLATFORM_EXPORT= ANGLE_CAPTURE_ENABLED=0
    ANGLE_ENABLE_SHARE_CONTEXT_LOCK=1 ANGLE_ENABLE_CONTEXT_MUTEX=1
    GL_GLES_PROTOTYPES=0 EGL_EGL_PROTOTYPES=0
    WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
target_compile_definitions(aether_angle INTERFACE
    GL_GLES_PROTOTYPES=1 EGL_EGL_PROTOTYPES=1 GL_GLEXT_PROTOTYPES EGL_EGLEXT_PROTOTYPES)
# Keep vendor warnings separate from the original Aether /W4 /WX targets.
target_compile_options(aether_angle PRIVATE /W3 /utf-8 /EHsc /bigobj /Zc:__cplusplus)
target_link_libraries(aether_angle PRIVATE aether_angle_zlib
    d3d11 dxgi dxguid user32 gdi32 synchronization)
# Large generated shader/compiler units must not exhaust the build host's memory.
set_property(GLOBAL APPEND PROPERTY JOB_POOLS aether_angle_compile=3)
set_property(TARGET aether_angle PROPERTY JOB_POOL_COMPILE aether_angle_compile)
