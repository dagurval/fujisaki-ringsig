cmake_minimum_required (VERSION 2.8.11)
project (singsig_examples)

link_directories("${CMAKE_CURRENT_SOURCE_DIR}/../target/debug")

add_executable(c_example c_example.c)
target_include_directories(c_example
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/..")
target_link_libraries(c_example fujisaki_ringsig)
