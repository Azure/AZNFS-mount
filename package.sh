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
cp -avf ${SOURCE_DIR}/src/mount.aznfs ${STG_DIR}/${pkg_dir}/sbin/

mkdir -p ${STG_DIR}/${pkg_dir}${opt_dir}
cp -avf ${SOURCE_DIR}/lib/common.sh ${STG_DIR}/${pkg_dir}${opt_dir}/

mkdir -p ${STG_DIR}/${pkg_dir}${system_dir}
cp -avf ${SOURCE_DIR}/src/aznfswatchdog.service ${STG_DIR}/${pkg_dir}${system_dir}

#
# Change path to ${STG_DIR}/${pkg_dir} so that aznfswatchdog and mount.aznfs
# can correctly source common.sh while generating binaries.
#
cd ${STG_DIR}/${pkg_dir}

# Create the binaries of aznfswatchdog and mount.aznfs to distribute.
shc -f ${STG_DIR}/${pkg_dir}/sbin/aznfswatchdog
shc -S -f ${STG_DIR}/${pkg_dir}/sbin/mount.aznfs

# Remove the bash scripts since those will not be distributed to client.
rm -r ${STG_DIR}/${pkg_dir}/sbin/aznfswatchdog
rm -r ${STG_DIR}/${pkg_dir}/sbin/mount.aznfs
rm -r ${STG_DIR}/${pkg_dir}${opt_dir}/common.sh

# Rename the binary files to original file name.
mv -vf ${STG_DIR}/${pkg_dir}/sbin/aznfswatchdog.x ${STG_DIR}/${pkg_dir}/sbin/aznfswatchdog
mv -vf ${STG_DIR}/${pkg_dir}/sbin/mount.aznfs.x ${STG_DIR}/${pkg_dir}/sbin/mount.aznfs

# Remove .x.c file.
rm -r ${STG_DIR}/${pkg_dir}/sbin/aznfswatchdog.x.c
rm -r ${STG_DIR}/${pkg_dir}/sbin/mount.aznfs.x.c

cd $STG_DIR

# Create the package.
dpkg-deb --root-owner-group --build $pkg_dir