# CMake minimum version
cmake_minimum_required(VERSION 3.8)

# Project Infomation
project(engine C)

# Debug
set(CMAKE_BUILD_TYPE "Debug")

# CFLAGS
set(CMAKE_C_FLAGS_DEBUG "$ENV{CFLAGS} -O0 -w -g -ggdb -std=gnu99")

# Reset output path
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/library)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/library)

# install gmssl
set(scripts_dir ${PROJECT_SOURCE_DIR}/scripts)
execute_process(COMMAND sh ${scripts_dir}/install_gmssl.sh)

# engine library
set(engine_dir ${PROJECT_SOURCE_DIR})
include_directories(${engine_dir})
aux_source_directory(${engine_dir} engine_source)

# gmssl
set(gmssl_dir ${PROJECT_SOURCE_DIR}/ext/gmssl)
include_directories(${gmssl_dir}/include)
link_directories(${gmssl_dir}/lib)

add_library(gmssl_engine SHARED ${engine_source})
add_library(gmssl_engine_static STATIC ${engine_source})
set_target_properties(gmssl_engine_static PROPERTIES OUTPUT_NAME "gmssl_engine")
target_link_libraries(gmssl_engine ssl crypto dl pthread)

set(engine_dir ${PROJECT_SOURCE_DIR}/ext/gmssl/lib/engines-1.1)
install(TARGETS gmssl_engine DESTINATION ${engine_dir})

set(scripts_dir ${PROJECT_SOURCE_DIR}/scripts)
add_custom_target(
    tls_server
    ALL
    COMMAND cp ${scripts_dir}/tls_* ${CMAKE_BINARY_DIR}
    COMMENT "copying scripts to ${CMAKE_BINARY_DIR}"
)

add_custom_target(
    export_engine
    ALL
    COMMAND export OPENSSL_ENGINES=${engine_dir}
    COMMENT "set OPENSSL_ENGINES Environmental variable"
)
