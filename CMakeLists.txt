cmake_minimum_required(VERSION 3.22)
set(SC_MODULE sftp)
project(simply-cpp-${SC_MODULE} HOMEPAGE_URL "https://github.com/roelofrossouw/simply-cpp-sftp" LANGUAGES CXX)
include(cmake/sc_bootstrap.cmake)

option(SC_SFTP_BUILD_TESTS "Build simply-cpp-sftp tests" ${PROJECT_IS_TOP_LEVEL})

get_sc_version()
message(STATUS "SimplyCPP ${SC_MODULE} Version: ${SC_VERSION}")

# sc::params for sftp-tool; libssh2 (BSD-3-Clause) for SSH and SFTP, from the system.
find_or_install_package(sc-core simply-cpp-dev simply-cpp 1.24.0)
config_or_install_package(Libssh2 libssh2-1-dev libssh2)

set(SOURCE_OBJECTS)
set(SOURCE_LIBRARIES)
set(SOURCE_LINK_LIBRARIES)

add_sc_object(sc_sftp
        LINK_LIBRARIES sc::sc-core PkgConfig::Libssh2
        PUBLIC_LINK_LIBRARIES sc::sc-core PkgConfig::Libssh2)

add_sc_libraries(DESCRIPTION "simply-cpp SFTP client on libssh2: list, read, write, rename, with known_hosts checking")
target_compile_features(sc-sftp PUBLIC cxx_std_20)
target_compile_features(sc-sftp-shared PUBLIC cxx_std_20)

install_sc_module(PATH_VARS CMAKE_INSTALL_INCLUDEDIR)
install(FILES cmake/SimplyCppFunctions.cmake cmake/sc_bootstrap.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/sc-sftp
        COMPONENT development)

if (SC_SFTP_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests sc-sftp-test)
endif ()

add_sc_example(sc-sftp-demo)

# sftp-tool, the program: lists, copies, renames and removes files on an SFTP server, for trying one by hand.
add_executable(sftp-tool apps/sftp-tool.cpp)
target_link_libraries(sftp-tool PRIVATE sc::sc-sftp-shared sc::sc-core)
target_compile_definitions(sftp-tool PRIVATE SC_SFTP_VERSION="${SC_VERSION}")
sc_program_info(sftp-tool)
install(TARGETS sftp-tool RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT runtime)
sc_man_page(sftp-tool EXTRA ${CMAKE_CURRENT_SOURCE_DIR}/man/sftp-tool.md COMPONENT runtime)

package_sc_module(DEV_DEPENDS "simply-cpp-dev (>= 1.24.0~)" libssh2-1-dev)
