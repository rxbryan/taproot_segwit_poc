# Define the subdirectory containing the shared library
set(SHARED_LIB_DIR ../crypto)

file(GLOB SOURCES ./*.c)

add_library(release STATIC ${SOURCES})
target_include_directories(release PUBLIC ${CMAKE_CURRENT_LIST_DIR})

target_link_libraries(release crypto)