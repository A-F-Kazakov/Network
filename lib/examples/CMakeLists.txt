message(STATUS "Build ${PROJECT_NAME} examples enabled")

set(EXAMPLE_HEAD ${PROJECT_NAME}_example)

set(EXAMPLE_NAME ${EXAMPLE_HEAD}_first)
add_executable(${EXAMPLE_NAME} first.cpp)
target_link_libraries(${EXAMPLE_NAME} PUBLIC ${PROJECT_NAME})
