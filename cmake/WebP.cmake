# Pinned BSD-3-Clause decoder closure, reviewed in third_party/README.md.
# The imported tree contains only the decoder/common .c sources. No build-time
# downloads, encoder, external codec discovery, or worker-created threads.
file(GLOB aether_webp_decoder_sources CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libwebp/src/dec/*.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libwebp/src/dsp/*.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/third_party/libwebp/src/utils/*.c")
add_library(aether_webp_decoder STATIC ${aether_webp_decoder_sources})
file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/generated/webp/src/webp")
file(GENERATE OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/generated/webp/src/webp/config.h" CONTENT
    "/* Aether scalar decoder configuration; no SIMD or worker threads. */\n#define PACKAGE_VERSION \"1.6.0\"\n")
target_include_directories(aether_webp_decoder PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated/webp")
target_include_directories(aether_webp_decoder SYSTEM PUBLIC third_party/libwebp)
target_compile_definitions(aether_webp_decoder PRIVATE HAVE_CONFIG_H WEBP_STATIC WEBP_DSP_OMIT_C_CODE=0)
target_compile_options(aether_webp_decoder PRIVATE /W3 /sdl)
target_link_options(aether_webp_decoder PRIVATE /NXCOMPAT /DYNAMICBASE)
