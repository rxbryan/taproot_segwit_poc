add_executable(e2etest e2e_test.c)

target_link_libraries(e2etest release crypto unity)
add_test(e2etest e2etest)

