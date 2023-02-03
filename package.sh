#!/bin/bash

# Exit on error.
set -e

echo "===== package.sh called. ====="

#STG_DIR, BUILD_NUMBER and SOURCE_DIR will be taken as env var.

pkg_name="aznfs"
pkg_dir=${pkg_name}_${BUILD_NUMBER}_arm64
opt_dir="/opt/microsoft/${pkg_name}"

# Create the directory to hold the package control and data files.
mkdir -p ${STG_DIR}/${pkg_dir}

# Copy the debian control file(s) and maintainer scripts.
cp -avf ${SOURCE_DIR}/packaging/${pkg_name}/* ${STG_DIR}/${pkg_dir}/

# Insert current build number.
sed -i -e "s/Version: x.y.z/Version: ${BUILD_NUMBER}/g" ${STG_DIR}/${pkg_dir}/DEBIAN/control

# Copy other static package file(s).
mkdir -p ${STG_DIR}/${pkg_dir}/sbin
cp -avf ${SOURCE_DIR}/src/mount.aznfs ${STG_DIR}/${pkg_dir}/sbin/
cp -avf ${SOURCE_DIR}/src/aznfswatchdog ${STG_DIR}/${pkg_dir}/sbin/

mkdir -p ${STG_DIR}/${pkg_dir}/${opt_dir}
cp -avf ${SOURCE_DIR}/lib/common.sh ${STG_DIR}/${pkg_dir}/${opt_dir}/

cd $STG_DIR

# Create the package.
dpkg-deb --build $pkg_dir