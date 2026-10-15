# Reviewed, fully vendored dependencies; configuration never downloads code.
set(CMAKE_POLICY_DEFAULT_CMP0167 OLD)
set(CMAKE_POLICY_DEFAULT_CMP0144 NEW)
set(BOOST_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/third_party/boost")
set(Boost_NO_SYSTEM_PATHS ON)
set(Boost_NO_BOOST_CMAKE ON)
set(DYNARMIC_FRONTENDS A64 CACHE STRING "Aether guest frontend" FORCE)
set(DYNARMIC_ENABLE_NO_EXECUTE_SUPPORT ON CACHE BOOL "Require W^X JIT memory" FORCE)
set(DYNARMIC_USE_BUNDLED_EXTERNALS ON CACHE BOOL "Pinned dependencies only" FORCE)
set(DYNARMIC_TESTS OFF CACHE BOOL "Aether owns its integration tests" FORCE)
set(DYNARMIC_TESTS_USE_UNICORN OFF CACHE BOOL "No secondary guest engine" FORCE)
set(DYNARMIC_USE_LLVM OFF CACHE BOOL "Use pinned Zydis for disassembly" FORCE)
set(DYNARMIC_WARNINGS_AS_ERRORS OFF CACHE BOOL "Aether warnings remain errors" FORCE)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Static runtime dependencies" FORCE)
add_subdirectory(third_party/dynarmic EXCLUDE_FROM_ALL)
# fmt lists its README/changelog as IDE sources. Neither is a compilation input;
# the public source repository intentionally carries only Aether's root README.
# Adjust the target here so the reviewed vendored source stays byte-for-byte intact.
get_target_property(aether_fmt_sources fmt SOURCES)
list(FILTER aether_fmt_sources EXCLUDE REGEX "[.][mM][dD]$")
set_property(TARGET fmt PROPERTY SOURCES "${aether_fmt_sources}")
# mcl's old MSVC workaround appends /std:c++latest despite requesting C++20.
# The pinned code builds as C++20 with this compiler; retain one explicit standard.
get_target_property(aether_mcl_options mcl COMPILE_OPTIONS)
list(REMOVE_ITEM aether_mcl_options /std:c++latest)
set_property(TARGET mcl PROPERTY COMPILE_OPTIONS "${aether_mcl_options}")
# Treat vendor headers as external in Aether's /WX translation units.
set_property(TARGET dynarmic PROPERTY INTERFACE_SYSTEM_INCLUDE_DIRECTORIES
    "${CMAKE_CURRENT_SOURCE_DIR}/third_party/dynarmic/src")
