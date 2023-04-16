#!/bin/bash

# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

# Exit on error.
set -e

#STG_DIR, RELEASE_NUMBER and SOURCE_DIR will be taken as env var.
pkg_name="aznfs"
pkg_dir="${pkg_name}-${RELEASE_NUMBER}-1_amd64"
rpm_pkg_dir="${pkg_name}-${RELEASE_NUMBER}-1.x86_64"
rpm_suse_pkg_dir="${pkg_name}_sles-${RELEASE_NUMBER}-1.x86_64"
opt_dir="/opt/microsoft/${pkg_name}"
system_dir="/lib/systemd/system"
rpmbuild_dir="/root/rpmbuild"
rpm_buildroot_dir="${rpmbuild_dir}/BUILDROOT"

# Insert release number to aznfs_install.sh
sed -i -e "s/RELEASE_NUMBER=x.y.z/RELEASE_NUMBER=${RELEASE_NUMBER}/g" ${SOURCE_DIR}/scripts/aznfs_install.sh

#########################
# Generate .deb package #
#########################

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

#########################
# Generate .rpm package #
#########################

# Create the directory to hold the package spec and data files for RPM package.
mkdir -p ${STG_DIR}/rpm/tmp${rpm_buildroot_dir}/${rpm_pkg_dir}

# Copy static package file(s).
mkdir -p ${STG_DIR}/rpm/tmp${rpm_buildroot_dir}/${rpm_pkg_dir}/usr/sbin
cp -avf ${SOURCE_DIR}/src/aznfswatchdog ${STG_DIR}/rpm/tmp${rpm_buildroot_dir}/${rpm_pkg_dir}/usr/sbin/

# Compile mount.aznfs.c and put the executable into ${STG_DIR}/rpm/tmp${rpm_buildroot_dir}/${rpm_pkg_dir}/sbin.
mkdir -p ${STG_DIR}/rpm/tmp${rpm_buildroot_dir}/${rpm_pkg_dir}/sbin
gcc -static ${SOURCE_DIR}/src/mount.aznfs.c -o ${STG_DIR}/rpm/tmp${rpm_buildroot_dir}/${rpm_pkg_dir}/sbin/mount.aznfs

mkdir -p ${STG_DIR}/rpm/tmp${rpm_buildroot_dir}/${rpm_pkg_dir}${opt_dir}
cp -avf ${SOURCE_DIR}/lib/common.sh ${STG_DIR}/rpm/tmp${rpm_buildroot_dir}/${rpm_pkg_dir}${opt_dir}/
cp -avf ${SOURCE_DIR}/src/mountscript.sh ${STG_DIR}/rpm/tmp${rpm_buildroot_dir}/${rpm_pkg_dir}${opt_dir}/

mkdir -p ${STG_DIR}/rpm/tmp${rpm_buildroot_dir}/${rpm_pkg_dir}${system_dir}
cp -avf ${SOURCE_DIR}/src/aznfswatchdog.service ${STG_DIR}/rpm/tmp${rpm_buildroot_dir}/${rpm_pkg_dir}${system_dir}

# Create the archive for the package.
tar -cvzf ${rpm_pkg_dir}.tar.gz -C ${STG_DIR}/rpm/tmp root

# Insert current release number.
sed -i -e "s/Version: x.y.z/Version: ${RELEASE_NUMBER}/g" ${SOURCE_DIR}/packaging/${pkg_name}/RPM/aznfs.spec

# Create the rpm package.
rpmbuild --define "_topdir ${STG_DIR}/rpm${rpmbuild_dir}" -v -bb ${SOURCE_DIR}/packaging/${pkg_name}/RPM/aznfs.spec

##################################
# Generate .rpm package for SUSE #
##################################

# Create the directory to hold the package spec and data files for RPM package.
mkdir -p ${STG_DIR}/rpmSUSE/tmp${rpm_buildroot_dir}/${rpm_suse_pkg_dir}

# Copy static package file(s).
mkdir -p ${STG_DIR}/rpmSUSE/tmp${rpm_buildroot_dir}/${rpm_suse_pkg_dir}/usr/sbin
cp -avf ${SOURCE_DIR}/src/aznfswatchdog ${STG_DIR}/rpmSUSE/tmp${rpm_buildroot_dir}/${rpm_suse_pkg_dir}/usr/sbin/

# Compile mount.aznfs.c and put the executable into ${STG_DIR}/rpmSUSE/tmp${rpm_buildroot_dir}/${rpm_suse_pkg_dir}/sbin.
mkdir -p ${STG_DIR}/rpmSUSE/tmp${rpm_buildroot_dir}/${rpm_suse_pkg_dir}/sbin
gcc -static ${SOURCE_DIR}/src/mount.aznfs.c -o ${STG_DIR}/rpmSUSE/tmp${rpm_buildroot_dir}/${rpm_suse_pkg_dir}/sbin/mount.aznfs

mkdir -p ${STG_DIR}/rpmSUSE/tmp${rpm_buildroot_dir}/${rpm_suse_pkg_dir}${opt_dir}
cp -avf ${SOURCE_DIR}/lib/common.sh ${STG_DIR}/rpmSUSE/tmp${rpm_buildroot_dir}/${rpm_suse_pkg_dir}${opt_dir}/
cp -avf ${SOURCE_DIR}/src/mountscript.sh ${STG_DIR}/rpmSUSE/tmp${rpm_buildroot_dir}/${rpm_suse_pkg_dir}${opt_dir}/

mkdir -p ${STG_DIR}/rpmSUSE/tmp${rpm_buildroot_dir}/${rpm_suse_pkg_dir}${system_dir}
cp -avf ${SOURCE_DIR}/src/aznfswatchdog.service ${STG_DIR}/rpmSUSE/tmp${rpm_buildroot_dir}/${rpm_suse_pkg_dir}${system_dir}

# Create the archive for the package.
tar -cvzf ${rpm_suse_pkg_dir}.tar.gz -C ${STG_DIR}/rpmSUSE/tmp root

# Insert current release number.
sed -i -e "s/Version: x.y.z/Version: ${RELEASE_NUMBER}/g" ${SOURCE_DIR}/packaging/${pkg_name}/RPM/SUSE/aznfs.spec

# Create the rpm package.
rpmbuild --define "_topdir ${STG_DIR}/rpmSUSE${rpmbuild_dir}" -v -bb ${SOURCE_DIR}/packaging/${pkg_name}/RPM/SUSE/aznfs.spec