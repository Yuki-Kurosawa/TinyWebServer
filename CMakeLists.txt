cmake_minimum_required(VERSION 3.10)

project(www_project VERSION 1.0)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_compile_definitions(
    GLOBAL_CONFIG_PATH="./www.conf"
    SITES_DIR_PATH="./sites"
)

include_directories(include)

file(GLOB_RECURSE SOURCES
    "src/*.c"
    "src/handlers/*.c"
)

add_executable(www ${SOURCES})

target_link_libraries(www
    pthread
    ssl
    crypto
    pcre2-8
    magic
)

