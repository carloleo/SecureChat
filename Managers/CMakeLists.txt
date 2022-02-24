add_library(Managers STATIC managers.cpp)
# allow compiler to find the library when other files link to it
target_include_directories(Managers PUBLIC  ${CMAKE_CURRENT_SOURCE_DIR})