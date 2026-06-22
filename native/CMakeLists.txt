cmake_minimum_required(VERSION 3.16)
project(rake_native C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(MSVC)
  add_compile_options(/W4 /WX)
else()
  add_compile_options(-Wall -Wextra -Werror -Wno-unused-parameter)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  if(NOT MSVC)
    add_compile_options(-O0 -g3 -fsanitize=address,undefined)
    add_link_options(-fsanitize=address,undefined)
  endif()
elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
  if(NOT MSVC)
    add_compile_options(-O3 -march=native)
  else()
    add_compile_options(/O2 /arch:AVX2)
  endif()
endif()

if(WIN32)
  add_compile_definitions(RAKE_WINDOWS)
  set(PLATFORM_LIBS ws2_32)
else()
  set(PLATFORM_LIBS "")
endif()

# -------------------------------------------------------------------------
# skein_avx2.c compiled with -mavx2; everything else is plain scalar
# -------------------------------------------------------------------------
set(SCALAR_SOURCES
  skein.c
  skein_bridge.c
  skein_dispatch.c
  sha256d.c
  tcp_bridge.c
  yescrypt.c
  yescryptr16_bridge.c
)

set(AVX2_SOURCES
  skein_avx2.c
)

# -------------------------------------------------------------------------
# Scalar static library
# -------------------------------------------------------------------------
add_library(rake_scalar STATIC ${SCALAR_SOURCES})
target_include_directories(rake_scalar PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(rake_scalar ${PLATFORM_LIBS})

# -------------------------------------------------------------------------
# AVX2 object (compiled separately with -mavx2 / /arch:AVX2)
# -------------------------------------------------------------------------
add_library(rake_avx2_obj OBJECT ${AVX2_SOURCES})
target_include_directories(rake_avx2_obj PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
if(MSVC)
  target_compile_options(rake_avx2_obj PRIVATE /arch:AVX2)
else()
  target_compile_options(rake_avx2_obj PRIVATE -mavx2)
endif()

# -------------------------------------------------------------------------
# Combined archive: librake_native
# -------------------------------------------------------------------------
add_library(rake_native STATIC
  ${SCALAR_SOURCES}
  $<TARGET_OBJECTS:rake_avx2_obj>
)
target_include_directories(rake_native PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(rake_native ${PLATFORM_LIBS})

# -------------------------------------------------------------------------
# Standalone selftest binary
# -------------------------------------------------------------------------
add_executable(selftest
  skein.c
  skein_bridge.c
  sha256d.c
  skein_dispatch.c
  yescrypt.c
  yescryptr16_bridge.c
  $<TARGET_OBJECTS:rake_avx2_obj>
  selftest_main.c
)
target_include_directories(selftest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(selftest ${PLATFORM_LIBS})
