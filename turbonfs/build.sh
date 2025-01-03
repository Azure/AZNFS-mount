#!/bin/bash
export VCPKG_ROOT=extern/vcpkg
# We need to update the submodules before calling cmake as toolchain build expects it.
git submodule update --recursive --init
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Debug -DENABLE_TCMALLOC=OFF -DCMAKE_TOOLCHAIN_FILE=${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake ..
#cmake -DCMAKE_BUILD_TYPE=Release ..
#cmake -DCMAKE_BUILD_TYPE=Debug -DENABLE_NO_FUSE=ON ..
make
