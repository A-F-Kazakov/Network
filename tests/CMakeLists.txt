message(STATUS "Build ${PROJECT_NAME} tests enabled")

set(TARGET_NAME_HEAD ${PROJECT_NAME}_test)

find_package(Catch2 REQUIRED)

add_library(Catch main.cpp)
target_compile_options(Catch INTERFACE -O0 -g --coverage)
target_link_libraries(Catch PUBLIC Catch2::Catch2 INTERFACE --coverage)

enable_testing()

link_libraries(${PROJECT_NAME} Catch)

set(TARGET_NAME ${TARGET_NAME_HEAD}_address_v4)

add_executable(${TARGET_NAME} address_v4.cpp)

add_test(NAME ${TARGET_NAME} COMMAND ${TARGET_NAME} -o address_v4.xml -r junit)

#
set(TARGET_NAME ${TARGET_NAME_HEAD}_address_v6)

add_executable(${TARGET_NAME} address_v6.cpp)

add_test(NAME ${TARGET_NAME} COMMAND ${TARGET_NAME} -o address_v6.xml -r junit)

#
set(TARGET_NAME ${TARGET_NAME_HEAD}_address)

add_executable(${TARGET_NAME} address.cpp)

add_test(NAME ${TARGET_NAME} COMMAND ${TARGET_NAME} -o address.xml -r junit)

