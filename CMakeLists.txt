cmake_minimum_required(VERSION 3.18)
project(SecureChat)

set(CMAKE_CXX_STANDARD 14)
# Search OpenSSL because it is required
find_package(PkgConfig REQUIRED)
pkg_search_module(OPENSSL REQUIRED openssl)

if( OPENSSL_FOUND )
    include_directories(${OPENSSL_INCLUDE_DIRS})
    message(STATUS "Using OpenSSL ${OPENSSL_VERSION}")
else()
    exit(1)
endif()

include_directories(${OPENSSL_INCLUDE_DIRS})

# library directory
add_subdirectory(Managers)
# server executable
add_executable(server Server/server.cpp Common/utility.h Common/Message.cpp Server/Classes/Session.cpp Server/Classes/Session.h Server/Classes/User.cpp Server/Classes/User.h)
# client executable
add_executable(client Client/client.cpp Common/utility.h Common/Message.cpp)
# linking Managers and OpenSSL library
target_link_libraries(server LINK_PUBLIC Managers crypto)
target_link_libraries(client LINK_PUBLIC Managers crypto)


