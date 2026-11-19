#!/bin/bash

if [ $# -ne 1 ] || [ "$1" != "Release" -a "$1" != "Debug" ]; then
    echo "Usage: ./build.sh <Release|Debug>"
    exit 1
fi

BUILD_TYPE=$1
RELEASE_NUMBER="0.0.1"

export VCPKG_ROOT=extern/vcpkg

is_azurelinux()
{
    if [ ! -r /etc/os-release ]; then
        return 1
    fi

    . /etc/os-release
    [ "${ID:-}" == "azurelinux" ] || [ "${ID:-}" == "mariner" ] || \
        [[ " ${ID_LIKE:-} " == *" azurelinux "* ]] || [[ " ${ID_LIKE:-} " == *" mariner "* ]]
}

normalize_cmake_bool()
{
    case "$1" in
        1|ON|On|on|TRUE|True|true|YES|Yes|yes)
            echo "ON"
            ;;
        *)
            echo "OFF"
            ;;
    esac
}

if [ -n "${ENABLE_DYNAMIC_LINKS+x}" ]; then
    DYNAMIC_LINKS=$(normalize_cmake_bool "${ENABLE_DYNAMIC_LINKS}")
elif is_azurelinux; then
    DYNAMIC_LINKS=ON
else
    DYNAMIC_LINKS=OFF
fi

echo "ENABLE_DYNAMIC_LINKS=${DYNAMIC_LINKS}"

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
    # TLS support has been removed from libnfs, so AZAUTH is always sent over
    # the non-TLS connection, which requires this to be ON.
    INSECURE_AUTH_FOR_DEVTEST=ON
fi

cmake -DCMAKE_BUILD_TYPE=$BUILD_TYPE \
      -DENABLE_JEMALLOC=$JEMALLOC \
      -DENABLE_PARANOID=$PARANOID \
      -DENABLE_INSECURE_AUTH_FOR_DEVTEST=$INSECURE_AUTH_FOR_DEVTEST \
      -DENABLE_DYNAMIC_LINKS=$DYNAMIC_LINKS \
      -DPACKAGE_VERSION=$RELEASE_NUMBER \
      -DCMAKE_TOOLCHAIN_FILE=${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake ..

#cmake -DCMAKE_BUILD_TYPE=Debug -DENABLE_NO_FUSE=ON ..

make
