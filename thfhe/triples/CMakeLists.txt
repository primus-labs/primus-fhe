cmake_minimum_required(VERSION 3.5)
project(otls)
set(NAME "otls")

find_path(CMAKE_FOLDER NAMES cmake/emp-tool-config.cmake)
include(${CMAKE_FOLDER}/cmake/emp-base.cmake)

find_package(emp-ot REQUIRED)
include_directories(${EMP-OT_INCLUDE_DIRS})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

install(FILES cmake/otls-config.cmake DESTINATION cmake/)
install(DIRECTORY ole DESTINATION include)

ENABLE_TESTING()
ADD_SUBDIRECTORY(test)
