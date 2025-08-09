cmake_minimum_required(VERSION 3.28)
project(pppoe-atm-relay C)

set(CMAKE_C_STANDARD 11)

add_executable(pppoe-atm-relay pppoe-atm-relay.c)

install(TARGETS pppoe-atm-relay
        RUNTIME DESTINATION bin)

set(AC_NAME "pppoe-atm-relay" CACHE STRING "Custom AC Name")
target_compile_definitions(pppoe-atm-relay PRIVATE AC_NAME="${AC_NAME}")
MESSAGE(STATUS "AC Name used in building: ${AC_NAME}")