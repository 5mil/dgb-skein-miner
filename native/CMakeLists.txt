# Rake :: native/CMakeLists.txt
# Builds libskein_bridge.a — statically linked into the Unison runtime.
#
# Static only. No shared library target. No dlopen path.
# The Unison binary links this archive at compile time.

cmake_minimum_required(VERSION 3.16)
project(rake_skein_bridge C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Build flags: optimize for the host CPU in release, debug-friendly in debug.
# -march=native is intentional: we want the best scalar codegen on the build
# machine. SIMD paths will be added explicitly in Phase 5 — not via
# auto-vectorization flags that could silently diverge across machines.
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_compile_options(-O3 -march=native -funroll-loops -fomit-frame-pointer)
elseif(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(-O0 -g3 -fsanitize=address,undefined)
    add_link_options(-fsanitize=address,undefined)
else()
    add_compile_options(-O2)
endif()

# Strict warnings — the reference C must compile cleanly
add_compile_options(
    -Wall -Wextra -Wpedantic
    -Wno-unused-parameter
)

# Static archive target
add_library(skein_bridge STATIC
    skein.c
    skein_bridge.c
)

target_include_directories(skein_bridge PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Standalone self-test binary (run `make selftest` to validate vectors)
add_executable(selftest selftest_main.c)
target_link_libraries(selftest PRIVATE skein_bridge)

# Install the static lib and headers for the Unison build system
install(TARGETS skein_bridge ARCHIVE DESTINATION lib)
install(FILES skein_bridge.h skein.h DESTINATION include)
