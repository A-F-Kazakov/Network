message(STATUS "Build ${PROJECT_NAME} tests enabled")

set(TEST_HEAD ${PROJECT_NAME}_test)

enable_testing()

set(TEST_NAME ${TEST_HEAD}_first)
add_executable(${TEST_NAME} first.cpp)
target_link_libraries(${TEST_NAME} PUBLIC ${PROJECT_NAME})

add_test(${TEST_NAME} ${TEST_NAME})

add_custom_command(TARGET ${TEST_NAME} POST_BUILD
	WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
	COMMAND ctest -C $<CONFIGURATION>
)
