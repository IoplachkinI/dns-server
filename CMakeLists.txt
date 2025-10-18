cmake_minimum_required(VERSION 3.16)
project(dns_server)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(yaml-cpp REQUIRED)

add_executable(dns_server main.cpp)
target_link_libraries(dns_server yaml-cpp)
