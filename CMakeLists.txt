cmake_minimum_required(VERSION 3.26)
project(ssl_survey_v2 C)

set(CMAKE_C_STANDARD 17)
find_package(OpenSSL REQUIRED)

link_directories(${OpenSSL_LIBRARIES_DIR})

add_executable(ssl_survey ssl_survey.c)
target_link_libraries(ssl_survey ssl crypto)

