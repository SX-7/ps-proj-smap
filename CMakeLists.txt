cmake_minimum_required(VERSION 3.7.0)
project(smap VERSION 0.1.0 LANGUAGES C)

add_library(scan scan.c smap.h)
add_library(utils utils.c smap.h)
add_library(discovery discovery.c smap.h)
add_executable(smap main.c smap.h)
target_link_libraries(smap PRIVATE discovery)
target_link_libraries(discovery PRIVATE utils)
target_link_libraries(smap PRIVATE scan)
target_link_libraries(scan PRIVATE utils)
target_include_directories(smap PRIVATE "${PROJECT_BINARY_DIR}" "${PROJECT_SOURCE_DIR}")

