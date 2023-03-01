#!/bin/bash

# Exit on error.
set -e

#STG_DIR, RELEASE_NUMBER and SOURCE_DIR will be taken as env var.
pkg_name="aznfs"
pkg_dir="${pkg_name}_${RELEASE_NUMBER}_amd64"
opt_dir="/opt/microsoft/${pkg_name}"
system_dir="/lib/systemd/system"

# Create the directory to hold the package control and data files.
mkdir -p ${STG_DIR}/${pkg_dir}

# Copy the debian control file(s) and maintainer scripts.
cp -avf ${SOURCE_DIR}/packaging/${pkg_name}/* ${STG_DIR}/${pkg_dir}/
chmod +x ${STG_DIR}/${pkg_dir}/DEBIAN/*

# Insert current build number.
sed -i -e "s/Version: x.y.z/Version: ${RELEASE_NUMBER}/g" ${STG_DIR}/${pkg_dir}/DEBIAN/control

# Copy other static package file(s).
mkdir -p ${STG_DIR}/${pkg_dir}/sbin
cp -avf ${SOURCE_DIR}/src/aznfswatchdog ${STG_DIR}/${pkg_dir}/sbin/

# Compile mount.aznfs.c and put the executable into ${STG_DIR}/${pkg_dir}/sbin.
gcc -static ${SOURCE_DIR}/src/mount.aznfs.c -o ${STG_DIR}/${pkg_dir}/sbin/mount.aznfs

mkdir -p ${STG_DIR}/${pkg_dir}${opt_dir}
cp -avf ${SOURCE_DIR}/lib/common.sh ${STG_DIR}/${pkg_dir}${opt_dir}/
cp -avf ${SOURCE_DIR}/src/mountscript.sh ${STG_DIR}/${pkg_dir}${opt_dir}/

mkdir -p ${STG_DIR}/${pkg_dir}${system_dir}
cp -avf ${SOURCE_DIR}/src/aznfswatchdog.service ${STG_DIR}/${pkg_dir}${system_dir}

cd $STG_DIR

# Create the package.
dpkg-deb --root-owner-group --build $pkg_dir