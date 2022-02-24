cmake_minimum_required(VERSION 3.21)
project(SecureChat)

set(CMAKE_CXX_STANDARD 14)
# library directory
add_subdirectory(Managers)
# server executable
add_executable(server Server/server.cpp Common/utility.h)
# client executable
add_executable(client Client/client.cpp Common/utility.h)
# linking Managers library
target_link_libraries(server LINK_PUBLIC Managers)
target_link_libraries(client LINK_PUBLIC Managers)
