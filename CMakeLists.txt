cmake_minimum_required(VERSION 3.22.1)
project(BPFEXEC
        VERSION 1.0
        DESCRIPTION "Remote BPF Execution Tool"
        LANGUAGES C)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/c2/deploy)

add_subdirectory(agent/)