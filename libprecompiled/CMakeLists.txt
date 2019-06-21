
file(GLOB_RECURSE SRC_LIST "*.cpp")
file(GLOB_RECURSE HEADERS "*.h")

add_library(precompiled ${SRC_LIST} ${HEADERS})
target_link_libraries(precompiled PRIVATE blockverifier ethcore)
target_link_libraries(precompiled PUBLIC storage devcore JsonCpp "/mnt/e/test_home/demo/lprecompile/target/debug/librustprecompile.so")

add_subdirectory(extension)
