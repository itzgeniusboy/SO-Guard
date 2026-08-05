cmake_minimum_required(VERSION 3.10.2)
project(so_protector_stub C)

set(CMAKE_C_STANDARD 11)

add_definitions(-DPROTECTION_LEVEL=3)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_library(protected_stub SHARED
    loader.c
    anti_debug.c
    anti_hook.c
    anti_env.c
)

target_link_libraries(protected_stub
    log
    android
)
