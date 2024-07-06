cmake_minimum_required(VERSION 3.28)

# Project name
project(chrome_project)

# Set the C standard
set(CMAKE_C_STANDARD 99)

# Add the source file
add_executable(chrome chrome.c)

# Find the required packages
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
find_library(CJSON_LIB cjson REQUIRED)
find_path(CJSON_INCLUDE_DIR cjson/cJSON.h REQUIRED)

# Link cJSON, sqlite3, OpenSSL, and Crypt32 libraries
pkg_check_modules(SQLITE3 REQUIRED sqlite3)

target_link_libraries(chrome PRIVATE ${CJSON_LIB} ${SQLITE3_LIBRARIES} OpenSSL::SSL OpenSSL::Crypto crypt32)

# Include directories for cJSON and sqlite3
target_include_directories(chrome PRIVATE ${CJSON_INCLUDE_DIR} ${SQLITE3_INCLUDE_DIRS})
