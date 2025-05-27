set(AGENT "agent_x86_64")

set (RELEASE_FLAGS -Wall -Werror -Wextra -Wpedantic -Wconversion -Wunreachable-code -Werror -Os)

add_executable(${AGENT})
target_include_directories(${AGENT} PUBLIC ${CMAKE_SOURCE_DIR}/agent/include)

add_subdirectory(src/)
add_subdirectory(core/)

