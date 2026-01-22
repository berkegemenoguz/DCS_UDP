cmake_minimum_required(VERSION 3.10)
project(DCS_UDP)

set(CMAKE_CXX_STANDARD 17)

# Windows Socket library
if(WIN32)
    set(EXTRA_LIBS ws2_32)
endif()

# Server executable
add_executable(server server.cpp)
target_link_libraries(server ${EXTRA_LIBS})

# Client executable
add_executable(client client.cpp)
target_link_libraries(client ${EXTRA_LIBS})
