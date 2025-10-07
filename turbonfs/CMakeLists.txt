cmake_minimum_required(VERSION 3.7)

# Assert package version cannot be empty.
if(NOT DEFINED PACKAGE_VERSION OR PACKAGE_VERSION STREQUAL "")
    message(FATAL_ERROR "PACKAGE_VERSION not defined or not valid. Please provide a valid version, e.g., 0.0.1")
endif()

project(aznfsclient
        DESCRIPTION "FUSE driver for mounting Blob NFS shares"
        LANGUAGES CXX
        VERSION ${PACKAGE_VERSION})

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

#
# Add options here.
#
option(ENABLE_TESTS "Build and run test programs" OFF)
option(ENABLE_NO_FUSE "Build nofuse shared library" OFF)
option(ENABLE_DOCUMENTATION "Build Documentation" OFF)
option(ENABLE_PARANOID "Enable paranoid checking in the code" ON)
option(ENABLE_NON_AZURE_NFS "Enable support for general NFS servers" OFF)
option(ENABLE_CHATTY "Enable super verbose logs" OFF)
option(ENABLE_TCMALLOC "Use tcmalloc for malloc/free/new/delete" OFF)
option(ENABLE_JEMALLOC "Use jemalloc for malloc/free/new/delete" ON)
option(ENABLE_INSECURE_AUTH_FOR_DEVTEST "Enable AZAUTH for non-TLS connections" OFF)
option(ENABLE_DYNAMIC_LINKS "Use dynamic linking instead of bundling libs" OFF)

#
# Builds that make it to customers need to be extra careful about any unnecessary
# logging. Some warning logs we have in our code are to attract developer
# attention, those are not useful for customers and unnecessarily flood their
# logs.
# Note: Don't use it for anything other than logging control!
#
option(ENABLE_RELEASE_BUILD "Turn it on when making release builds used by customers" ON)

#
# Enable paranoid checks only in debug builds.
# Disable asan for nofuse as it doesn't work well with that.
#
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  add_definitions(-DENABLE_DEBUG)
  set(MESON_BUILD_TYPE debug)
  if(ENABLE_PARANOID)
    add_definitions(-DENABLE_PARANOID)
  endif()
  if(NOT ENABLE_NO_FUSE)
    add_compile_options(-fsanitize=address)
    add_link_options(-fsanitize=address)
  endif()
else()
  if(ENABLE_RELEASE_BUILD)
    add_definitions(-DENABLE_RELEASE_BUILD)
  endif()
  set(MESON_BUILD_TYPE release)
endif()

#
# Enable shard library for all components when building nofuse shared lib.
#
if(ENABLE_NO_FUSE)
  set(BUILD_SHARED_LIBS ON CACHE INTERNAL "Build shared libs" FORCE)
  set(YAML_BUILD_SHARED_LIBS ON CACHE INTERNAL "Build yaml-cpp shared library" FORCE)
  set(SPDLOG_BUILD_SHARED ON CACHE INTERNAL "Build spdlog shared library" FORCE)
  add_definitions(-DENABLE_NO_FUSE)
else()
  set(BUILD_SHARED_LIBS OFF CACHE INTERNAL "Build shared libs" FORCE)
  set(YAML_BUILD_SHARED_LIBS OFF CACHE INTERNAL "Build yaml-cpp shared library" FORCE)
  set(SPDLOG_BUILD_SHARED OFF CACHE INTERNAL "Build spdlog shared library" FORCE)
endif()

if(ENABLE_NON_AZURE_NFS)
  add_definitions(-DENABLE_NON_AZURE_NFS)
endif()

#if(ENABLE_RELEASE_BUILD)
#  add_definitions(-DENABLE_RELEASE_BUILD)
#endif()

if(ENABLE_CHATTY)
  add_definitions(-DENABLE_CHATTY)
endif()

set(INSTALL_BIN_DIR "${CMAKE_INSTALL_PREFIX}/bin" CACHE PATH "Installation directory for binaries")
set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/CMake" ${CMAKE_MODULE_PATH})

# Only set libfuse paths for static builds
if(NOT ENABLE_DYNAMIC_LINKS)
    set(LIBFUSE_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/extern/libfuse")
    set(LIBFUSE_BUILD_DIR "${CMAKE_BINARY_DIR}/extern/libfuse")
endif()

#
# We add the following submodule(s), update them as needed, before starting.
# git submodule add https://github.com/linuxsmiths/libnfs extern/libnfs
# git submodule add https://github.com/jbeder/yaml-cpp.git extern/yaml-cpp
# git submodule add https://github.com/gabime/spdlog.git extern/spdlog
# git submodule add https://github.com/libfuse/libfuse.git extern/libfuse
# git submodule add https://github.com/microsoft/vcpkg.git extern/vcpkg
# git submodule add https://github.com/nlohmann/json.git extern/json
#
find_package(Git QUIET)
if(GIT_FOUND AND EXISTS "${PROJECT_SOURCE_DIR}/../.git")
    option(GIT_SUBMODULE "Check submodules during build" ON)
    if(GIT_SUBMODULE)
        message(STATUS "Submodule update")
        execute_process(COMMAND ${GIT_EXECUTABLE} submodule update --init --recursive
                        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                        RESULT_VARIABLE GIT_SUBMOD_RESULT)
        if(NOT GIT_SUBMOD_RESULT EQUAL "0")
            message(FATAL_ERROR "git submodule update --init --recursive failed with ${GIT_SUBMOD_RESULT}, please checkout submodules")
        endif()
    endif()
endif()

if(NOT EXISTS "${PROJECT_SOURCE_DIR}/extern/libnfs/CMakeLists.txt")
    message(FATAL_ERROR "The libnfs submodule was not downloaded! GIT_SUBMODULE was turned off or failed. Please update submodules and try again.")
endif()

if(NOT EXISTS "${PROJECT_SOURCE_DIR}/extern/yaml-cpp/CMakeLists.txt")
    message(FATAL_ERROR "The yaml-cpp submodule was not downloaded! GIT_SUBMODULE was turned off or failed. Please update submodules and try again.")
endif()

if(NOT EXISTS "${PROJECT_SOURCE_DIR}/extern/spdlog/CMakeLists.txt")
    message(FATAL_ERROR "The spdlog submodule was not downloaded! GIT_SUBMODULE was turned off or failed. Please update submodules and try again.")
endif()

# Only check libfuse submodule for static builds
if(NOT ENABLE_DYNAMIC_LINKS)
    if(NOT EXISTS "${PROJECT_SOURCE_DIR}/extern/libfuse/meson.build")
        message(FATAL_ERROR "The libfuse submodule was not downloaded! GIT_SUBMODULE was turned off or failed. Please update submodules and try again.")
    endif()
endif()

if(NOT EXISTS "${PROJECT_SOURCE_DIR}/extern/vcpkg/bootstrap-vcpkg.sh")
    message(FATAL_ERROR "The vcpkg submodule was not downloaded! GIT_SUBMODULE was turned off or failed. Please update submodules and try again.")
endif()

if(NOT EXISTS "${PROJECT_SOURCE_DIR}/extern/json/CMakeLists.txt")
    message(FATAL_ERROR "The json submodule was not downloaded! GIT_SUBMODULE was turned off or failed. Please update submodules and try again.")
endif()

find_package(azure-identity-cpp CONFIG QUIET)
if(NOT azure-identity-cpp_FOUND)
    message(FATAL_ERROR "azure-identity-cpp not found! Did you run cmake with -DCMAKE_TOOLCHAIN_FILE?")
endif()

find_package(azure-storage-blobs-cpp CONFIG QUIET)
if(NOT azure-storage-blobs-cpp_FOUND)
    message(FATAL_ERROR "azure-storage-blobs-cpp not found! Did you run cmake with -DCMAKE_TOOLCHAIN_FILE?")
endif()

# Choose package manager based on ENABLE_DYNAMIC_LINKS
if(ENABLE_DYNAMIC_LINKS)
    set(PKG_MGR tdnf)
else()
    set(PKG_MGR apt)
endif()

#
# Ensure pkg_search_module(), needed for configuring some packages.
#
find_package(PkgConfig QUIET)
if(NOT PKG_CONFIG_FOUND)
    message(STATUS "pkg-config not found, trying to install pkg-config!")
    execute_process(COMMAND sudo ${PKG_MGR} install -y pkg-config
            RESULT_VARIABLE PKGCONFIG_INSTALL_RESULT)
    if(NOT PKGCONFIG_INSTALL_RESULT EQUAL "0")
        message(FATAL_ERROR "${PKG_MGR} install pkg-config failed with ${PKGCONFIG_INSTALL_RESULT}, try installing pkg-config manually and then run cmake again")
    else()
        # Call once more to ensure above install completed fine and also
        # add the pkg_search_module() command.
        find_package(PkgConfig REQUIRED)
    endif()
endif()

#
# Handle FUSE3 based on build type
#
if(ENABLE_DYNAMIC_LINKS)
    #
    # For dynamic builds, use system-installed fuse3 shared library
    #
    message(STATUS "Using system-installed fuse3 (dynamic linking)")

    # First try to find fuse3 via pkg-config
    find_package(PkgConfig REQUIRED)
    pkg_search_module(FUSE3 QUIET fuse3)

    if(NOT FUSE3_FOUND)
        message(STATUS "fuse3 not found via pkg-config, trying to install the devel package")

        if(PKG_MGR STREQUAL "apt")
            set(FUSE3_PKG "libfuse3-dev")
        else()
            set(FUSE3_PKG "fuse3-devel")
        endif()

        execute_process(COMMAND sudo ${PKG_MGR} install -y ${FUSE3_PKG}
                        RESULT_VARIABLE FUSE3_INSTALL_RESULT)

        if(NOT FUSE3_INSTALL_RESULT EQUAL "0")
            message(FATAL_ERROR "Failed to install ${FUSE3_PKG}, please install manually")
        endif()

        # Retry finding fuse3 after installation
        pkg_search_module(FUSE3 REQUIRED fuse3)
    endif()

    message(STATUS "Found fuse3 libraries: ${FUSE3_LIBRARIES}")
    message(STATUS "Found fuse3 include dirs: ${FUSE3_INCLUDE_DIRS}")
    message(STATUS "Found fuse3 library dirs: ${FUSE3_LIBRARY_DIRS}")
else()
    #
    # For static builds, build libfuse from source
    #
    message(STATUS "Building libfuse from source (static linking)")
    
    #
    # We need meson to compile libfuse.
    #
    find_program(MESON_EXECUTABLE meson QUIET)
    if(NOT MESON_FOUND)
        message(STATUS "meson not found, trying to install meson!")
        execute_process(COMMAND sudo ${PKG_MGR} install -y meson
                        RESULT_VARIABLE MESON_INSTALL_RESULT)
        if(NOT MESON_INSTALL_RESULT EQUAL "0")
            message(FATAL_ERROR "${PKG_MGR} install meson failed with ${MESON_INSTALL_RESULT}, try installing meson manually and then run cmake again")
        else()
            find_program(MESON_EXECUTABLE meson REQUIRED)
        endif()
    endif()

    #
    # We need ninja to install libfuse in build dir.
    #
    find_program(NINJA_EXECUTABLE ninja QUIET)
    if(NOT NINJA_FOUND)
        message(STATUS "ninja not found, trying to install ninja-build!")
        execute_process(COMMAND sudo ${PKG_MGR} install -y ninja-build
                        RESULT_VARIABLE NINJA_INSTALL_RESULT)
        if(NOT NINJA_INSTALL_RESULT EQUAL "0")
            message(FATAL_ERROR "${PKG_MGR} install ninja-build failed with ${NINJA_INSTALL_RESULT}, try installing ninja-build manually and then run cmake again")
        else()
            find_program(NINJA_EXECUTABLE ninja REQUIRED)
        endif()
    endif()

    # Use multiarch layout for static builds
    set(fuse3_LIBRARY "/usr/local/lib/${CMAKE_SYSTEM_PROCESSOR}-linux-gnu/libfuse3.a")
    set(fuse3_INCLUDE_DIR "/usr/local/include")

    add_custom_command(
        OUTPUT ${fuse3_LIBRARY}
        COMMAND ${MESON_EXECUTABLE} setup ${LIBFUSE_BUILD_DIR} ${LIBFUSE_SOURCE_DIR} --default-library=static --buildtype=${MESON_BUILD_TYPE}
        COMMAND ${MESON_EXECUTABLE} compile -C ${LIBFUSE_BUILD_DIR}
        COMMAND sudo ${MESON_EXECUTABLE} install -C ${LIBFUSE_BUILD_DIR}
    )

    add_custom_target(libfuse ALL DEPENDS ${fuse3_LIBRARY})
endif()

#
# We need GnuTLS for secure libnfs transport.
#
find_package(GnuTLS "3.4.6" QUIET)
if(NOT GNUTLS_FOUND)
    message(STATUS "GnuTLS not found, trying to install gnutls-dev!")
    if(PKG_MGR STREQUAL "apt")
        set(GNUTLS_PKG "gnutls-dev")
    else()
        set(GNUTLS_PKG "gnutls-devel")
    endif()
    execute_process(COMMAND sudo ${PKG_MGR} install -y ${GNUTLS_PKG}
                    RESULT_VARIABLE GNUTLS_INSTALL_RESULT)
    if(NOT GNUTLS_INSTALL_RESULT EQUAL "0")
        message(FATAL_ERROR "${PKG_MGR} install ${GNUTLS_PKG} failed with ${GNUTLS_INSTALL_RESULT}, try installing ${GNUTLS_PKG} manually and then run cmake again")
    else()
        find_package(GnuTLS "3.4.6" REQUIRED)
    endif()
endif()

#
# Find tcmalloc and if not found try to install.
#
if(ENABLE_TCMALLOC)
if(ENABLE_JEMALLOC)
    message(FATAL_ERROR "Only one of ENABLE_TCMALLOC and ENABLE_JEMALLOC can be set")
endif()

find_package(tcmalloc QUIET)
if(NOT tcmalloc_FOUND)
    if(PKG_MGR STREQUAL "apt")
        set(TCMALLOC_PKG "libgoogle-perftools-dev")
    else()
        set(TCMALLOC_PKG "gperftools-devel")
    endif()
    message(STATUS "tcmalloc not found, trying to install ${TCMALLOC_PKG}!")
    execute_process(COMMAND sudo ${PKG_MGR} install -y ${TCMALLOC_PKG}
            RESULT_VARIABLE tcmalloc_INSTALL_RESULT)
    if(NOT tcmalloc_INSTALL_RESULT EQUAL "0")
        message(FATAL_ERROR "${PKG_MGR} install ${TCMALLOC_PKG} failed with ${tcmalloc_INSTALL_RESULT}, try installing ${TCMALLOC_PKG} manually and then run cmake again")
    else()
        # Call once more to ensure above install completed fine and also
        # will set tcmalloc_INCLUDE_DIR and tcmalloc_LIBRARY variables.
        find_package(tcmalloc REQUIRED)
    endif()
else()
    message(STATUS "Using tcmalloc lib ${tcmalloc_LIBRARY}")
    message(STATUS "Using tcmalloc include dir ${tcmalloc_INCLUDE_DIR}")
endif()
endif()

#
# Find jemalloc and if not found try to install.
#
if(ENABLE_JEMALLOC)
if(ENABLE_TCMALLOC)
    message(FATAL_ERROR "Only one of ENABLE_TCMALLOC and ENABLE_JEMALLOC can be set")
endif()

pkg_search_module(JEMALLOC QUIET jemalloc)

if(NOT JEMALLOC_FOUND)
    if(${PKG_MGR} STREQUAL "tdnf")
        set(JEMALLOC_PKG jemalloc-devel)
    else()
        set(JEMALLOC_PKG libjemalloc-dev)
    endif()
    message(STATUS "jemalloc not found, trying to install ${JEMALLOC_PKG}!")
    execute_process(COMMAND sudo ${PKG_MGR} install -y ${JEMALLOC_PKG}
            RESULT_VARIABLE JEMALLOC_INSTALL_RESULT)
    if(NOT JEMALLOC_INSTALL_RESULT EQUAL "0")
        message(FATAL_ERROR "${PKG_MGR} install ${JEMALLOC_PKG} failed with ${JEMALLOC_INSTALL_RESULT}, try installing ${JEMALLOC_PKG} manually and then run cmake again")
    else()
        # Call once more to ensure above install completed fine and also
        # will set JEMALLOC_LIBRARIES variable.
        pkg_search_module(JEMALLOC REQUIRED jemalloc)
    endif()
endif()

if(ENABLE_DYNAMIC_LINKS)
    message(STATUS "Using jemalloc lib ${JEMALLOC_LIBRARIES}")
else()
    # We want to link against the static jemalloc lib.
    message(STATUS "Using jemalloc static lib ${JEMALLOC_LIBRARY_DIRS}")
endif()
endif()

#
# Find uuid library if not, try to install.
#
pkg_search_module(UUID QUIET uuid)
if(NOT UUID_FOUND)
    if(PKG_MGR STREQUAL "apt")
        set(UUID_PKG "uuid-dev")
    else()
        set(UUID_PKG "uuid-devel")
    endif()
    message(STATUS "uuid not found, trying to install ${UUID_PKG}!")
    execute_process(COMMAND sudo ${PKG_MGR} install -y ${UUID_PKG}
            RESULT_VARIABLE UUID_INSTALL_RESULT)
    if(NOT UUID_INSTALL_RESULT EQUAL "0")
        message(FATAL_ERROR "${PKG_MGR} install ${UUID_PKG} failed with ${UUID_INSTALL_RESULT}, try installing ${UUID_PKG} manually and then run cmake again")
    else()
        pkg_search_module(UUID REQUIRED uuid)
    endif()
endif()

message(STATUS "Using uuid lib ${UUID_LIBRARIES}")
message(STATUS "Using uuid include dir ${UUID_INCLUDE_DIRS}")

#
# Install zlib for crc32.
#
find_package(ZLIB QUIET)
if(NOT ZLIB_FOUND)
    if(PKG_MGR STREQUAL "apt")
        set(ZLIB_PKG "zlib1g-dev")
    else()
        set(ZLIB_PKG "zlib-devel")
    endif()
    message(STATUS "zlib not found, trying to install ${ZLIB_PKG}!")
    execute_process(COMMAND sudo ${PKG_MGR} install -y ${ZLIB_PKG}
		    RESULT_VARIABLE ZLIB_INSTALL_RESULT)
    if(NOT ZLIB_INSTALL_RESULT EQUAL "0")
        message(FATAL_ERROR "${PKG_MGR} install ${ZLIB_PKG} failed with ${ZLIB_INSTALL_RESULT}, try installing ${ZLIB_PKG} manually and then run cmake again")
    else()
        # Call once more to ensure above install completed fine and also
        # will set ZLIB_INCLUDE_DIR and ZLIB_LIBRARY variables.
        find_package(ZLIB REQUIRED)
    endif()
else()
    message(STATUS "Using zlib lib ${ZLIB_LIBRARIES}")
    message(STATUS "Using zlib include dir ${ZLIB_INCLUDE_DIRS}")
endif()

# Build libnfs (with multithreading enabled).
set(ENABLE_MULTITHREADING ON)
set(ENABLE_EXAMPLES ON)
add_subdirectory(extern/libnfs)

add_subdirectory(extern/yaml-cpp)

# Build static library for spdlog.
add_subdirectory(extern/spdlog)

# Need to add this run nlohmann_json cmake which will correctly add the include directory.
add_subdirectory(extern/json)

configure_file(inc/aznfsc_config.h.in inc/aznfsc_config.h)

set(sources
    src/config.cpp
    src/util.cpp
    src/log.cpp
    src/fcsm.cpp
    src/nfs_client.cpp
    src/rpc_transport.cpp
    src/rpc_task.cpp
    src/rpc_readdir.cpp
    src/connection.cpp
    src/nfs_inode.cpp
    src/file_cache.cpp
    src/readahead.cpp
    src/rpc_stats.cpp)

if(ENABLE_NO_FUSE)
# libaznfsclient.so.
set(sources ${sources} src/nofuse.cpp)
add_library(${CMAKE_PROJECT_NAME} SHARED
            ${sources})
else()
# aznfsclient executable.
set(sources ${sources} src/main.cpp)
add_executable(${CMAKE_PROJECT_NAME}
               ${sources})
    # Only add libfuse dependency for static builds
    if(NOT ENABLE_DYNAMIC_LINKS)
        add_dependencies(${CMAKE_PROJECT_NAME} libfuse)
    endif()
endif()

# All include directories.
target_include_directories(${CMAKE_PROJECT_NAME}
                           PRIVATE "${PROJECT_SOURCE_DIR}/inc"
                           PRIVATE "${PROJECT_BINARY_DIR}/inc"
                           PRIVATE "${ZLIB_INCLUDE_DIRS}"
                           PRIVATE "${PROJECT_SOURCE_DIR}/extern/libnfs/nfs"
                           PRIVATE "${PROJECT_SOURCE_DIR}/extern/libnfs/include"
                           PRIVATE "${PROJECT_SOURCE_DIR}/extern/libnfs/include/nfsc"
                           PRIVATE "${PROJECT_SOURCE_DIR}/extern/libnfs/mount"
                           PRIVATE "${PROJECT_SOURCE_DIR}/extern/spdlog/include")

if(NOT ENABLE_NO_FUSE)
    if(ENABLE_DYNAMIC_LINKS)
        # Use system fuse3 include directories
        target_include_directories(${CMAKE_PROJECT_NAME}
                                   PRIVATE ${FUSE3_INCLUDE_DIRS})
    else()
        # Use built-from-source fuse3 include directory
        target_include_directories(${CMAKE_PROJECT_NAME}
                                   PRIVATE "${fuse3_INCLUDE_DIR}")
    endif()
endif()

target_compile_options(${CMAKE_PROJECT_NAME}
                       PRIVATE -Wall
                       PRIVATE -Wextra -Wno-unused-parameter
                       PRIVATE -Werror
                       )

# Only use static gnutls linking when ENABLE_DYNAMIC_LINKS is NOT set.
if(NOT ENABLE_DYNAMIC_LINKS)
    #
    # Libraries for statically linking gnutls.
    # libp11-kit and libunistring do not have a static version available, so we are
    # forced to use the shared version and bundle it.
    #
    set(CMAKE_FIND_LIBRARY_SUFFIXES .a)

    find_library(GNUTLS_STATIC_LIB libgnutls.a REQUIRED)
    #
    # arm64 libgnutls.a has multiple definitions for some symbols exported by
    # libcrypto.a. The libcrypto.a object has some more symbols which are needed,
    # so we delete the offending object from libgnutls.a before linking.
    #
    if(CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64" OR CMAKE_SYSTEM_PROCESSOR STREQUAL "arm64")
    execute_process(
        COMMAND bash -c "cp -vf ${GNUTLS_STATIC_LIB} /tmp/gnutls.a; ar dv /tmp/gnutls.a aes-aarch64.o"
        COMMAND_ERROR_IS_FATAL ANY)
    set(GNUTLS_STATIC_LIB /tmp/gnutls.a)
    endif()

    find_library(HOGWEED_STATIC_LIB libhogweed.a REQUIRED)
    find_library(NETTLE_STATIC_LIB libnettle.a REQUIRED)
    find_library(TASN1_STATIC_LIB libtasn1.a REQUIRED)
    find_library(IDN2_STATIC_LIB libidn2.a REQUIRED)
    find_library(GMP_STATIC_LIB libgmp.a REQUIRED)
    set(CMAKE_FIND_LIBRARY_SUFFIXES .so)
    find_library(P11_KIT_SHARED_LIB libp11-kit.so REQUIRED)
    find_library(UNISTRING_SHARED_LIB NAMES
                libunistring.so
                libunistring.so.5
                libunistring.so.2
                REQUIRED)

    set(GNUTLS_ALL_LIBRARIES
        ${GNUTLS_STATIC_LIB}
        ${HOGWEED_STATIC_LIB}
        ${NETTLE_STATIC_LIB}
        ${TASN1_STATIC_LIB}
        ${IDN2_STATIC_LIB}
        ${GMP_STATIC_LIB}
        ${P11_KIT_SHARED_LIB}
        ${UNISTRING_SHARED_LIB})
    message(STATUS "Using gnutls libraries: ${GNUTLS_ALL_LIBRARIES}")
endif()

# All libraries.
if(ENABLE_DYNAMIC_LINKS)
  # Dynamic linking: No static flags, use GnuTLS::GnuTLS target
  target_link_libraries(${CMAKE_PROJECT_NAME}
                        ${ZLIB_LIBRARIES}
                        dl
                        pthread
                        nfs
                        yaml-cpp
                        spdlog
                        Azure::azure-identity
                        Azure::azure-storage-blobs
                        nlohmann_json::nlohmann_json
                        uuid
                        GnuTLS::GnuTLS)
  
  # Link against system fuse3 (only if not building nofuse)
  if(NOT ENABLE_NO_FUSE)
    target_link_libraries(${CMAKE_PROJECT_NAME} ${FUSE3_LIBRARIES})
  endif()
else()
  # Static linking: Use static-libgcc/libstdc++ and explicit gnutls libraries
  target_link_libraries(${CMAKE_PROJECT_NAME}
                        -static-libgcc -static-libstdc++
                        -Wl,-rpath,/opt/microsoft/aznfs/libs
                        ${ZLIB_LIBRARIES}
                        dl
                        pthread
                        nfs
                        ${GNUTLS_ALL_LIBRARIES}
                        yaml-cpp
                        spdlog
                        Azure::azure-identity
                        Azure::azure-storage-blobs
                        nlohmann_json::nlohmann_json
                        uuid)
  
  # Link against static fuse3 (only if not building nofuse)
  if(NOT ENABLE_NO_FUSE)
    target_link_libraries(${CMAKE_PROJECT_NAME} ${fuse3_LIBRARY})
  endif()
endif()

if(ENABLE_TCMALLOC)
target_link_libraries(${CMAKE_PROJECT_NAME}
                      ${tcmalloc_LIBRARY})
endif()

if(ENABLE_JEMALLOC)
  if(ENABLE_DYNAMIC_LINKS)
    target_link_libraries(${CMAKE_PROJECT_NAME}
                          ${JEMALLOC_LIBRARIES})
  else()
    target_link_libraries(${CMAKE_PROJECT_NAME}
                          ${JEMALLOC_LIBRARY_DIRS}/libjemalloc.a)
  endif()
endif()

install(TARGETS ${CMAKE_PROJECT_NAME})
