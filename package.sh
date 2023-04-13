#!/bin/bash

# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

# Exit on error.
set -e

#STG_DIR, RELEASE_NUMBER and SOURCE_DIR will be taken as env var.
pkg_name="aznfs"
pkg_dir="${pkg_name}_${RELEASE_NUMBER}_amd64"
opt_dir="/opt/microsoft/${pkg_name}"
system_dir="/lib/systemd/system"
rpmbuild_dir="/root/rpmbuild"
rpm_buildroot_dir="${rpmbuild_dir}/BUILDROOT"
rpm_source_dir="${rpmbuild_dir}/SOURCE"

# Insert releaes number to aznfs_install.sh
sed -i -e "s/RELEASE_NUMBER=x.y.z/RELEASE_NUMBER=${RELEASE_NUMBER}/g" ${SOURCE_DIR}/scripts/aznfs_install.sh

#Genrate .deb package.

# Create the directory to hold the package control and data files for deb package.
mkdir -p ${STG_DIR}/deb/${pkg_dir}/DEBIAN

# Copy the debian control file(s) and maintainer scripts.
cp -avf ${SOURCE_DIR}/packaging/${pkg_name}/DEBIAN/* ${STG_DIR}/deb/${pkg_dir}/DEBIAN/
chmod +x ${STG_DIR}/deb/${pkg_dir}/DEBIAN/*

# Insert current release number.
sed -i -e "s/Version: x.y.z/Version: ${RELEASE_NUMBER}/g" ${STG_DIR}/deb/${pkg_dir}/DEBIAN/control

# Copy other static package file(s).
mkdir -p ${STG_DIR}/deb/${pkg_dir}/usr/sbin
cp -avf ${SOURCE_DIR}/src/aznfswatchdog ${STG_DIR}/deb/${pkg_dir}/usr/sbin/

# Compile mount.aznfs.c and put the executable into ${STG_DIR}/deb/${pkg_dir}/sbin.
mkdir -p ${STG_DIR}/deb/${pkg_dir}/sbin
gcc -static ${SOURCE_DIR}/src/mount.aznfs.c -o ${STG_DIR}/deb/${pkg_dir}/sbin/mount.aznfs

mkdir -p ${STG_DIR}/deb/${pkg_dir}${opt_dir}
cp -avf ${SOURCE_DIR}/lib/common.sh ${STG_DIR}/deb/${pkg_dir}${opt_dir}/
cp -avf ${SOURCE_DIR}/src/mountscript.sh ${STG_DIR}/deb/${pkg_dir}${opt_dir}/

mkdir -p ${STG_DIR}/deb/${pkg_dir}${system_dir}
cp -avf ${SOURCE_DIR}/src/aznfswatchdog.service ${STG_DIR}/deb/${pkg_dir}${system_dir}

# Create the deb package.
dpkg-deb --root-owner-group --build $STG_DIR/deb/$pkg_dir

#Generate .rpm package.

# Create the directory to hold the package control and data files for RPM package.
mkdir -p ${STG_DIR}/rpm/tmp${rpm_buildroot_dir}/${pkg_dir}

# Copy other static package file(s).
mkdir -p ${STG_DIR}/rpm/tmp${rpm_buildroot_dir}/${pkg_dir}/usr/sbin
cp -avf ${SOURCE_DIR}/src/aznfswatchdog ${STG_DIR}/rpm/tmp${rpm_buildroot_dir}/${pkg_dir}/usr/sbin/

# Compile mount.aznfs.c and put the executable into ${STG_DIR}/rpm/${pkg_dir}/tmp/sbin.
mkdir -p ${STG_DIR}/rpm/tmp${rpm_buildroot_dir}/${pkg_dir}/sbin
gcc -static ${SOURCE_DIR}/src/mount.aznfs.c -o ${STG_DIR}/rpm/tmp${rpm_buildroot_dir}/${pkg_dir}/sbin/mount.aznfs

mkdir -p ${STG_DIR}/rpm/tmp${rpm_buildroot_dir}/${pkg_dir}${opt_dir}
cp -avf ${SOURCE_DIR}/lib/common.sh ${STG_DIR}/rpm/tmp${rpm_buildroot_dir}/${pkg_dir}${opt_dir}/
cp -avf ${SOURCE_DIR}/src/mountscript.sh ${STG_DIR}/rpm/tmp${rpm_buildroot_dir}/${pkg_dir}${opt_dir}/

mkdir -p ${STG_DIR}/rpm/tmp${rpm_buildroot_dir}/${pkg_dir}${system_dir}
cp -avf ${SOURCE_DIR}/src/aznfswatchdog.service ${STG_DIR}/rpm/tmp${rpm_buildroot_dir}/${pkg_dir}${system_dir}

# Create the archive for the package.
tar -cvzf ${pkg_dir}.tar.gz -C ${STG_DIR}/rpm/tmp root

# Insert current release number.
sed -i -e "s/Version: x.y.z/Version: ${RELEASE_NUMBER}/g" ${STG_DIR}/rpm/${pkg_dir}/SPECS/aznfs.spec

# Create the rpm package.
rpmbuild --define "_topdir ${STG_DIR}/rpm${rpmbuild_dir}" -v -bb ${SOURCE_DIR}/RPM/aznfs.spec