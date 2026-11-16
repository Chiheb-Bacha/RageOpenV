cmake_minimum_required(VERSION 3.15)

project(RageOpenV)
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "RageOpenV supports x64 GTA V only")
endif()
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

file(GLOB_RECURSE PROJECT_SOURCE_FILES "src/*.h" "src/*.cpp")
option(RAGEOPENV_NEWMODS "Enable experimental loose-file virtual devices (newmods folder)" ON)
if(NOT RAGEOPENV_NEWMODS)
    list(FILTER PROJECT_SOURCE_FILES EXCLUDE REGEX "/hooks/CustomDevice\\.cpp$")
    list(FILTER PROJECT_SOURCE_FILES EXCLUDE REGEX "/gtav/rage/fiDevice\\.cpp$")
endif()
add_compile_definitions(NOMINMAX WIN32_LEAN_AND_MEAN)

macro(GroupSources curdir groupindex)
    file(GLOB children RELATIVE ${curdir} ${curdir}/*)

    foreach(child ${children})
        if(IS_DIRECTORY ${curdir}/${child})
            GroupSources(${curdir}/${child} ${groupindex}/${child})
        else()
            string(REPLACE "/" "\\" groupname ${groupindex})
            source_group(${groupname} FILES ${curdir}/${child})
        endif()
    endforeach()
endmacro()

GroupSources(${CMAKE_SOURCE_DIR}/src "Source Files")

add_subdirectory("src/vendor/minhook")

add_library(RageOpenV SHARED ${PROJECT_SOURCE_FILES})
add_dependencies(RageOpenV minhook)

include_directories(
    ./src
)

set_target_properties(RageOpenV PROPERTIES
    OUTPUT_NAME "RageOpenV"
    SUFFIX ".asi"
    CXX_STANDARD 20
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/BIN/"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/BIN/Debug/"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/BIN/Release/"
)

set_target_properties( minhook
    PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/LIB"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/LIB"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/LIB"
    LIBRARY_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/LIB"
    LIBRARY_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/LIB"
)

set(CMAKE_CONFIGURATION_TYPES Debug Release RelWithDebInfo)
if(ENABLE_LOGS)
    target_compile_definitions(RageOpenV PRIVATE _LOG)
endif()

target_link_libraries(RageOpenV PRIVATE version minhook)

include(CTest)
if(BUILD_TESTING)
    add_library(minhook_test STATIC src/vendor/minhook/src/buffer.c src/vendor/minhook/src/hook.c
        src/vendor/minhook/src/trampoline.c src/vendor/minhook/src/hde/hde64.c)
    target_include_directories(minhook_test PRIVATE src/vendor/minhook/include src/vendor/minhook/src)
    target_compile_definitions(minhook_test PRIVATE MH_TX_TESTING)
    add_executable(memory_tests tests/memory_tests.cpp)
    target_include_directories(memory_tests PRIVATE src)
    target_compile_features(memory_tests PRIVATE cxx_std_20)
    target_compile_definitions(memory_tests PRIVATE MH_TX_TESTING)
    target_link_libraries(memory_tests PRIVATE minhook_test)
    foreach(test unique duplicate missing data_only malformed final_offset staged discard commit conflict null_address bad_call unwind chained_unwind hook_commit hook_discard rollback partial_activation concurrent raw_interior thread_exit_churn)
        add_test(NAME ${test} COMMAND memory_tests ${test})
    endforeach()
    add_executable(signature_probe tests/signature_probe.cpp)
    target_include_directories(signature_probe PRIVATE src)
    target_compile_features(signature_probe PRIVATE cxx_std_20)
    target_link_libraries(signature_probe PRIVATE minhook)
endif()

