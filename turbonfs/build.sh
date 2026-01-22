#!/bin/bash

if [ $# -ne 1 ] || [ "$1" != "Release" -a "$1" != "Debug" ]; then
    echo "Usage: ./build.sh <Release|Debug>"
    exit 1
fi

BUILD_TYPE=$1

export VCPKG_ROOT=extern/vcpkg

# Update (vcpkg) submodules before calling cmake as toolchain build expects it.
git submodule update --recursive --init

# Cleanup old build directory (before vcpkg changes) if present.
if [ ! -d build/vcpkg_installed ]; then
    rm -fr build
fi

mkdir -p build && cd build

# vcpkg required env variable VCPKG_FORCE_SYSTEM_BINARIES to be set for arm64.
if [ "$(uname -m)" == "aarch64" ]; then
    export VCPKG_FORCE_SYSTEM_BINARIES=1
fi

if [ "$BUILD_TYPE" == "Debug" ]; then
    # tcmalloc doesn't play well with ASAN.
    JEMALLOC=ON
    PARANOID=ON
    INSECURE_AUTH_FOR_DEVTEST=ON
else
    JEMALLOC=ON
    PARANOID=OFF
    INSECURE_AUTH_FOR_DEVTEST=ON
fi

cmake -DCMAKE_BUILD_TYPE=$BUILD_TYPE \
      -DENABLE_JEMALLOC=$JEMALLOC \
      -DENABLE_PARANOID=$PARANOID \
      -DENABLE_INSECURE_AUTH_FOR_DEVTEST=$INSECURE_AUTH_FOR_DEVTEST \
      -DCMAKE_TOOLCHAIN_FILE=${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake ..

#cmake -DCMAKE_BUILD_TYPE=Debug -DENABLE_NO_FUSE=ON ..

make
