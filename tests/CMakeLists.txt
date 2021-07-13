cmake_minimum_required(VERSION 3.13.0)
project(keymanager)
 
# Locate GTest
find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})
 
add_executable(runTest test.cpp)
target_link_libraries(runTest ${GTEST_LIBRARIES} pthread)
