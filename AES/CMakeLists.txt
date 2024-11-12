cmake_minimum_required(VERSION 3.29)
project(HWB_AES)

set(CMAKE_CXX_STANDARD 26)

add_subdirectory("${PROJECT_SOURCE_DIR}/HWB-4" "${PROJECT_SOURCE_DIR}/HWB-4/cmake-build-debug")
add_subdirectory("${PROJECT_SOURCE_DIR}/HWB-5" "${PROJECT_SOURCE_DIR}/HWB-5/cmake-build-debug")
add_subdirectory("${PROJECT_SOURCE_DIR}/HWB-5-2" "${PROJECT_SOURCE_DIR}/HWB-5-2/cmake-build-debug")
