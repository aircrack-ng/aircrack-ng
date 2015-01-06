cmake_minimum_required(VERSION 2.6)
project(radiotap)

add_definitions("-D_BSD_SOURCE -DRADIOTAP_SUPPORT_OVERRIDES")

add_library(radiotap SHARED radiotap.c)
set_target_properties(radiotap PROPERTIES
		      COMPILE_FLAGS "-Wall -Wextra")

install(TARGETS radiotap DESTINATION lib)
install(FILES radiotap.h radiotap_iter.h DESTINATION include)

add_executable(parse parse.c)
set_target_properties(parse PROPERTIES
		      COMPILE_FLAGS "-Wall -Wextra")
target_link_libraries(parse radiotap)


add_custom_target(radiotap_check ALL
		  COMMAND ${CMAKE_SOURCE_DIR}/check/check.sh ${CMAKE_BINARY_DIR}
		  DEPENDS ${CMAKE_SOURCE_DIR}/check/*
		  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/check/
		  COMMENT "Check examples")
add_dependencies(radiotap_check parse)
