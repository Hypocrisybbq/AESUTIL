cmake_minimum_required(VERSION 3.4.1)

add_library( # Specifies the name of the library.
        util

        # Sets the library as a shared library.
        SHARED

        # Provides a relative path to your source file(s).
        src/main/cpp/util.cpp
        src/main/cpp/aes.h
        src/main/cpp/aes.cpp
        )
include_directories(src/main/cpp/include/)

find_library( # Defines the name of the path variable that stores the
        # location of the NDK library.
        log-lib

        # Specifies the name of the NDK library that
        # CMake needs to locate.
        log)

target_link_libraries( # Specifies the target library.
        util

        # Links the log library to the target library.
        ${log-lib})