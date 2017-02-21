cmake_minimum_required(VERSION 3.5)

project(pe-parser)

add_library(pe-parser
	pe.cpp
	pe-res.cpp
)

target_include_directories(pe-parser PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(pe-parser mstd)
