
cmake_minimum_required(VERSION 3.31)
project(vuln_scan)

set(CMAKE_CXX_STANDARD 17)



add_executable(vuln_scan src/main.cpp
        src/include/xss.h
        src/include/csrf.h
        src/include/fupload.h
        src/include/sqlinj.h
        src/xss.cpp
        src/csrf.cpp
        src/fupload.cpp
        src/sqlinj.cpp
        src/menu.cpp
        src/include/menu.h
)
target_precompile_headers(vuln_scan PRIVATE src/include/pch.h)
include_directories(${CMAKE_SOURCE_DIR}/src/include)