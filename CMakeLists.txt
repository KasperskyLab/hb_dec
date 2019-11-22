cmake_minimum_required(VERSION 3.12)

include_directories(
                        /usr/local/include
                        include/wine/
                        include/harbour/
                        include/git/
                        )

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 ")

if ( WIN32 )
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static-libgcc -static-libstdc++ ")
endif ( WIN32 )

add_library(hb_dec_compat ${CMAKE_CURRENT_SOURCE_DIR}/include/git/compat/memmem_awked.c )

add_executable(hb_dec hb_dec.cpp pe_helper.cpp harbour_helper.cpp harbour_decompiler.cpp writer.cpp)
target_link_libraries(hb_dec hb_dec_compat)
