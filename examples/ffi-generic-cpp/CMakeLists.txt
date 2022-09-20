cmake_minimum_required(VERSION 3.23)
project(jpki_rs)

set(CMAKE_CXX_STANDARD 14)

add_executable(jpki_rs
        main.cpp
        jpki.h)

target_link_libraries(jpki_rs ${CMAKE_SOURCE_DIR}/../../target/debug/libjpki.dylib)
