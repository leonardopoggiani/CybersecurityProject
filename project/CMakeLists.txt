cmake_minimum_required(VERSION 3.19)
project(project)

set(CMAKE_CXX_STANDARD 20)
include_directories(/usr/include/openssl/)
link_libraries(openssl)

add_executable(project main.cpp)