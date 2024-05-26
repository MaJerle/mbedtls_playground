cmake_minimum_required(VERSION 3.22)

# Setup project
project(mbedtls_playground)

# Set as executable
add_executable(${PROJECT_NAME})

file(GLOB MBEDTLS_FILES ${CMAKE_CURRENT_LIST_DIR}/mbedtls/library/*.c)

# Add key executable block
target_sources(${PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/main.c
    ${CMAKE_CURRENT_LIST_DIR}/cert_playground.c
    ${CMAKE_CURRENT_LIST_DIR}/ecdh_playground.c
    ${CMAKE_CURRENT_LIST_DIR}/ecdsa_playground.c
    ${MBEDTLS_FILES}
)

# Add key include paths
target_include_directories(${PROJECT_NAME} PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}/dev
    ${CMAKE_CURRENT_LIST_DIR}
    ${CMAKE_CURRENT_LIST_DIR}/mbedtls/include
)

# Compilation definition information
target_compile_definitions(${PROJECT_NAME} PUBLIC
    WIN32
    _DEBUG
    CONSOLE
)

# Compiler options
target_compile_options(${PROJECT_NAME} PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)