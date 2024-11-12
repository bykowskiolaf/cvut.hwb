cmake_minimum_required(VERSION 3.29)
project(HWB_4)

set(CMAKE_CXX_STANDARD 26)

add_executable(HWB_4 src/main.cpp
        src/helper/helper.cpp
        src/helper/helper.h
        src/aes/aes.cpp
        src/aes/aes.h
        src/aes/aes_consts.h
        src/main_helpers/main_helpers.cpp
        src/main_helpers/main_helpers.h)
