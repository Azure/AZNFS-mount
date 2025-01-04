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

if [ "$BUILD_TYPE" == "Debug" ]; then
    # tcmalloc doesn't play well with ASAN.
    TCMALLOC=OFF
else
    TCMALLOC=ON
fi

cmake -DCMAKE_BUILD_TYPE=$BUILD_TYPE \
      -DENABLE_TCMALLOC=$TCMALLOC \
      -DCMAKE_TOOLCHAIN_FILE=${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake ..

#cmake -DCMAKE_BUILD_TYPE=Debug -DENABLE_NO_FUSE=ON ..

make
