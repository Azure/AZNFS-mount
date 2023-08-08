#!/bin/bash

# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

# Exit on error.
set -e

generate_rpm_package()
{
	rpm_dir=$1

	# Overwrite rpm_pkg_dir in case of SUSE.
	if [ "$rpm_dir" == "suse" ]; then
		rpm_pkg_dir="${pkg_name}_sles-${RELEASE_NUMBER}-1.x86_64"
	fi

	# Create the directory to hold the package spec and data files for RPM package.
	mkdir -p ${STG_DIR}/${rpm_dir}/tmp${rpm_buildroot_dir}/${rpm_pkg_dir}

	# Copy static package file(s).
	mkdir -p ${STG_DIR}/${rpm_dir}/tmp${rpm_buildroot_dir}/${rpm_pkg_dir}/usr/sbin
	cp -avf ${SOURCE_DIR}/src/aznfswatchdog ${STG_DIR}/${rpm_dir}/tmp${rpm_buildroot_dir}/${rpm_pkg_dir}/usr/sbin/

	# Compile mount.aznfs.c and put the executable into ${STG_DIR}/${rpm_dir}/tmp${rpm_buildroot_dir}/${rpm_pkg_dir}/sbin.
	mkdir -p ${STG_DIR}/${rpm_dir}/tmp${rpm_buildroot_dir}/${rpm_pkg_dir}/sbin
	gcc -static ${SOURCE_DIR}/src/mount.aznfs.c -o ${STG_DIR}/${rpm_dir}/tmp${rpm_buildroot_dir}/${rpm_pkg_dir}/sbin/mount.aznfs

	mkdir -p ${STG_DIR}/${rpm_dir}/tmp${rpm_buildroot_dir}/${rpm_pkg_dir}${opt_dir}
	cp -avf ${SOURCE_DIR}/lib/common.sh ${STG_DIR}/${rpm_dir}/tmp${rpm_buildroot_dir}/${rpm_pkg_dir}${opt_dir}/
	cp -avf ${SOURCE_DIR}/src/mountscript.sh ${STG_DIR}/${rpm_dir}/tmp${rpm_buildroot_dir}/${rpm_pkg_dir}${opt_dir}/

	mkdir -p ${STG_DIR}/${rpm_dir}/tmp${rpm_buildroot_dir}/${rpm_pkg_dir}${system_dir}
	cp -avf ${SOURCE_DIR}/src/aznfswatchdog.service ${STG_DIR}/${rpm_dir}/tmp${rpm_buildroot_dir}/${rpm_pkg_dir}${system_dir}

	# Create the archive for the package.
	tar -cvzf ${rpm_pkg_dir}.tar.gz -C ${STG_DIR}/${rpm_dir}/tmp root

	# Copy the SPEC file to change the placeholders depending upon the RPM distro.
	cp -avf ${SOURCE_DIR}/packaging/${pkg_name}/RPM/aznfs.spec ${STG_DIR}/${rpm_dir}/tmp/

	# Insert current release number and RPM_DIR value.
	sed -i -e "s/Version: x.y.z/Version: ${RELEASE_NUMBER}/g" ${STG_DIR}/${rpm_dir}/tmp/aznfs.spec
	sed -i -e "s/RPM_DIR/${rpm_dir}/g" ${STG_DIR}/${rpm_dir}/tmp/aznfs.spec
	
	# Replace the placeholders for various package names in aznfs.spec file. 
	if [ "$rpm_dir" == "suse" ]; then
		sed -i -e "s/AZNFS_PACKAGE_NAME/${pkg_name}_sles/g" ${STG_DIR}/${rpm_dir}/tmp/aznfs.spec
		sed -i -e "s/NETCAT_PACKAGE_NAME/netcat-openbsd/g" ${STG_DIR}/${rpm_dir}/tmp/aznfs.spec
		sed -i -e "s/DISTRO/suse/g" ${STG_DIR}/${rpm_dir}/tmp/aznfs.spec
	else
		sed -i -e "s/AZNFS_PACKAGE_NAME/${pkg_name}/g" ${STG_DIR}/${rpm_dir}/tmp/aznfs.spec
		sed -i -e "s/NETCAT_PACKAGE_NAME/nmap-ncat/g" ${STG_DIR}/${rpm_dir}/tmp/aznfs.spec
		sed -i -e "s/DISTRO/rpm/g" ${STG_DIR}/${rpm_dir}/tmp/aznfs.spec
		sed -i -e "s/INSTALL_CMD/yum/g" ${STG_DIR}/${rpm_dir}/tmp/aznfs.spec
	fi

	# Create the rpm package.
	rpmbuild --define "_topdir ${STG_DIR}/${rpm_dir}${rpmbuild_dir}" -v -bb ${STG_DIR}/${rpm_dir}/tmp/aznfs.spec
}

#STG_DIR, RELEASE_NUMBER and SOURCE_DIR will be taken as env var.
pkg_name="aznfs"
pkg_dir="${pkg_name}-${RELEASE_NUMBER}-1_amd64"
rpm_pkg_dir="${pkg_name}-${RELEASE_NUMBER}-1.x86_64"
tar_pkg_dir="${pkg_name}-${RELEASE_NUMBER}-1_amd64"
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
dpkg-deb -Zgzip --root-owner-group --build $STG_DIR/deb/$pkg_dir

#########################
# Generate .rpm package #
#########################

generate_rpm_package rpm
generate_rpm_package suse

######################
# Generating Tarball #
######################

# Create the directory to hold the package contents.
mkdir -p ${STG_DIR}/tarball/${tar_pkg_dir}

# Copy other static package file(s).
mkdir -p ${STG_DIR}/tarball/${tar_pkg_dir}/usr/sbin
cp -avf ${SOURCE_DIR}/src/aznfswatchdog ${STG_DIR}/tarball/${tar_pkg_dir}/usr/sbin

# Compile mount.aznfs.c and put the executable into ${STG_DIR}/tarball/${tar_pkg_dir}/
mkdir -p ${STG_DIR}/tarball/${tar_pkg_dir}/sbin
gcc -static ${SOURCE_DIR}/src/mount.aznfs.c -o ${STG_DIR}/tarball/${tar_pkg_dir}/sbin/mount.aznfs

# Copy the required files to the package directory.
mkdir -p ${STG_DIR}/tarball/${tar_pkg_dir}${opt_dir}
cp -avf ${SOURCE_DIR}/lib/common.sh ${STG_DIR}/tarball/${tar_pkg_dir}${opt_dir}/
cp -avf ${SOURCE_DIR}/src/mountscript.sh ${STG_DIR}/tarball/${tar_pkg_dir}${opt_dir}/

# Set appropriate permissions.
chmod 0755 ${STG_DIR}/tarball/${tar_pkg_dir}${opt_dir}/
chmod 0755 ${STG_DIR}/tarball/${tar_pkg_dir}/usr/sbin/aznfswatchdog
chmod 0755 ${STG_DIR}/tarball/${tar_pkg_dir}${opt_dir}/mountscript.sh
chmod 0644 ${STG_DIR}/tarball/${tar_pkg_dir}${opt_dir}/common.sh
chmod 4755 ${STG_DIR}/tarball/${tar_pkg_dir}/sbin/mount.aznfs

# Create the tar.gz package.
cd ${STG_DIR}/tarball/${tar_pkg_dir}
tar -czvf ${STG_DIR}/tarball/${tar_pkg_dir}.tar.gz *