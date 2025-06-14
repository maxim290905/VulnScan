cmake_minimum_required(VERSION 3.31)
project(vuln_scan)

set(CMAKE_CXX_STANDARD 17)

find_package(Boost 1.83 REQUIRED COMPONENTS system regex url)
find_package(OpenSSL REQUIRED)

 # -----------------------------------------------------------


# Make Boost.URL stay header-only – avoid missing symbols
add_compile_definitions(BOOST_URL_HEADER_ONLY)

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

target_include_directories(vuln_scan
        PRIVATE
        ${Boost_INCLUDE_DIRS}
        ${CMAKE_SOURCE_DIR}/src/include
)

target_link_libraries(vuln_scan
        PRIVATE
        Boost::url          # already present
        Boost::system
        Boost::regex
        OpenSSL::SSL
        OpenSSL::Crypto
)