cmake_minimum_required(VERSION 3.16)
project(rake_native C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# -------------------------------------------------------------------------
# Compiler flags
# -------------------------------------------------------------------------
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
    add_compile_options(/O2)
  endif()
endif()

# Windows: link Winsock
if(WIN32)
  add_compile_definitions(RAKE_WINDOWS)
  set(PLATFORM_LIBS ws2_32)
else()
  set(PLATFORM_LIBS "")
endif()

# -------------------------------------------------------------------------
# Sources
# -------------------------------------------------------------------------
set(SKEIN_SOURCES
  skein.c
  skein_bridge.c
)

set(SHA256D_SOURCES
  sha256d.c
)

set(TCP_SOURCES
  tcp_bridge.c
)

# -------------------------------------------------------------------------
# Static archive: libskein_bridge.a / .lib
# -------------------------------------------------------------------------
add_library(skein_bridge STATIC ${SKEIN_SOURCES})
target_include_directories(skein_bridge PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# -------------------------------------------------------------------------
# Static archive: libsha256d.a / .lib
# -------------------------------------------------------------------------
add_library(sha256d STATIC ${SHA256D_SOURCES})
target_include_directories(sha256d PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# -------------------------------------------------------------------------
# Static archive: libtcp_bridge.a / .lib
# -------------------------------------------------------------------------
add_library(tcp_bridge STATIC ${TCP_SOURCES})
target_include_directories(tcp_bridge PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(tcp_bridge ${PLATFORM_LIBS})

# -------------------------------------------------------------------------
# Combined archive: librake_native.a (all three)
# -------------------------------------------------------------------------
add_library(rake_native STATIC
  ${SKEIN_SOURCES}
  ${SHA256D_SOURCES}
  ${TCP_SOURCES}
)
target_include_directories(rake_native PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(rake_native ${PLATFORM_LIBS})

# -------------------------------------------------------------------------
# Standalone selftest binary
# -------------------------------------------------------------------------
add_executable(selftest
  skein_bridge.c
  skein.c
  sha256d.c
  selftest_main.c
)
target_include_directories(selftest PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(selftest ${PLATFORM_LIBS})
