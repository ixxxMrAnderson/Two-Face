cmake_minimum_required(VERSION 3.10)
project(twoface CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Define source files
set(SOURCES main.cpp)

# Include directories
include_directories(/opt/homebrew/Cellar/openssl@3/3.4.1/include)
include_directories(/usr/local/include)

# Link directories
link_directories(/opt/homebrew/Cellar/openssl@3/3.4.1/lib)

# Create executable
add_executable(twoface ${SOURCES})

# Link OpenSSL libraries
target_link_libraries(twoface ssl crypto)