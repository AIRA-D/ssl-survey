cmake_minimum_required(VERSION 3.26)
project(ssl_survey_v2 C)

set(CMAKE_C_STANDARD 17)

add_executable(ssl_survey_v2 ssl_survey.c)
target_link_libraries(ssl_survey_v2 ssl crypto)
