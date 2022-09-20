cmake_minimum_required(VERSION 3.23)
project(jpki_rs)

set(CMAKE_CXX_STANDARD 14)

add_executable(jpki_rs
        main.cpp
        jpki.h)

if (CMAKE_BUILD_TYPE MATCHES Debug)
    target_link_libraries(jpki_rs ${CMAKE_SOURCE_DIR}/../../target/debug/libjpki.dylib)
elseif(CMAKE_BUILD_TYPE MATCHES Release)
    target_link_libraries(jpki_rs ${CMAKE_SOURCE_DIR}/../../target/release/libjpki.dylib)
endif()
