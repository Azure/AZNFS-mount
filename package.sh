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
	is_mariner=0

	# Overwrite rpm_pkg_dir in case of SUSE.
	if [ "$rpm_dir" == "suse" ]; then
		rpm_pkg_dir="${pkg_name}_sles-${RELEASE_NUMBER}-1.x86_64"
	fi

	# Overwrite rpm_pkg_dir in case of Mariner.
	if [ "$rpm_dir" == "mariner" ]; then
		rpm_pkg_dir="${pkg_name}_mariner-${RELEASE_NUMBER}-1.x86_64"
		is_mariner=1
	fi

	# Create the directory to hold the package spec and data files for RPM package.
	mkdir -p ${STG_DIR}/${rpm_dir}/tmp${rpm_buildroot_dir}/${rpm_pkg_dir}

	# Copy static package file(s).
	mkdir -p ${STG_DIR}/${rpm_dir}/tmp${rpm_buildroot_dir}/${rpm_pkg_dir}/usr/sbin
	cp -avf ${SOURCE_DIR}/src/aznfswatchdog ${STG_DIR}/${rpm_dir}/tmp${rpm_buildroot_dir}/${rpm_pkg_dir}/usr/sbin/
	cp -avf ${SOURCE_DIR}/src/aznfswatchdogv4 ${STG_DIR}/${rpm_dir}/tmp${rpm_buildroot_dir}/${rpm_pkg_dir}/usr/sbin/

	# Compile mount.aznfs.c and put the executable into ${STG_DIR}/${rpm_dir}/tmp${rpm_buildroot_dir}/${rpm_pkg_dir}/sbin.
	mkdir -p ${STG_DIR}/${rpm_dir}/tmp${rpm_buildroot_dir}/${rpm_pkg_dir}/sbin
	gcc -static ${SOURCE_DIR}/src/mount.aznfs.c -o ${STG_DIR}/${rpm_dir}/tmp${rpm_buildroot_dir}/${rpm_pkg_dir}/sbin/mount.aznfs

	mkdir -p ${STG_DIR}/${rpm_dir}/tmp${rpm_buildroot_dir}/${rpm_pkg_dir}${opt_dir}
	cp -avf ${SOURCE_DIR}/lib/common.sh ${STG_DIR}/${rpm_dir}/tmp${rpm_buildroot_dir}/${rpm_pkg_dir}${opt_dir}/
	cp -avf ${SOURCE_DIR}/src/mountscript.sh ${STG_DIR}/${rpm_dir}/tmp${rpm_buildroot_dir}/${rpm_pkg_dir}${opt_dir}/
	cp -avf ${SOURCE_DIR}/src/nfsv3mountscript.sh ${STG_DIR}/${rpm_dir}/tmp${rpm_buildroot_dir}/${rpm_pkg_dir}${opt_dir}/
	cp -avf ${SOURCE_DIR}/src/nfsv4mountscript.sh ${STG_DIR}/${rpm_dir}/tmp${rpm_buildroot_dir}/${rpm_pkg_dir}${opt_dir}/
	cp -avf ${SOURCE_DIR}/scripts/aznfs_install.sh ${STG_DIR}/${rpm_dir}/tmp${rpm_buildroot_dir}/${rpm_pkg_dir}${opt_dir}/

	mkdir -p ${STG_DIR}/${rpm_dir}/tmp${rpm_buildroot_dir}/${rpm_pkg_dir}${system_dir}
	cp -avf ${SOURCE_DIR}/src/aznfswatchdog.service ${STG_DIR}/${rpm_dir}/tmp${rpm_buildroot_dir}/${rpm_pkg_dir}${system_dir}
	cp -avf ${SOURCE_DIR}/src/aznfswatchdogv4.service ${STG_DIR}/${rpm_dir}/tmp${rpm_buildroot_dir}/${rpm_pkg_dir}${system_dir}

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
		# For SLES, sysvinit-tools provides pidof.
		sed -i -e "s/PROCPS_PACKAGE_NAME/sysvinit-tools/g" ${STG_DIR}/${rpm_dir}/tmp/aznfs.spec
		sed -i -e "s/DISTRO/suse/g" ${STG_DIR}/${rpm_dir}/tmp/aznfs.spec
	elif [ "$rpm_dir" == "mariner" ]; then
		sed -i -e "s/AZNFS_PACKAGE_NAME/${pkg_name}_mariner/g" ${STG_DIR}/${rpm_dir}/tmp/aznfs.spec
		sed -i -e "s/NETCAT_PACKAGE_NAME/nmap-ncat/g" ${STG_DIR}/${rpm_dir}/tmp/aznfs.spec
		# In new versions of Centos/RedHat/Rocky, procps-ng provides pidof. For older versions, it is provided by sysvinit-tools but since it is not
		# present in new versions, only install procps-ng which exists in all versions.
		sed -i -e "s/PROCPS_PACKAGE_NAME/procps-ng/g" ${STG_DIR}/${rpm_dir}/tmp/aznfs.spec
		sed -i -e "s/DISTRO/mariner/g" ${STG_DIR}/${rpm_dir}/tmp/aznfs.spec
		sed -i -e "s/INSTALL_CMD/yum/g" ${STG_DIR}/${rpm_dir}/tmp/aznfs.spec
	else
		sed -i -e "s/AZNFS_PACKAGE_NAME/${pkg_name}/g" ${STG_DIR}/${rpm_dir}/tmp/aznfs.spec
		sed -i -e "s/NETCAT_PACKAGE_NAME/nmap-ncat/g" ${STG_DIR}/${rpm_dir}/tmp/aznfs.spec
		# In new versions of Centos/RedHat/Rocky, procps-ng provides pidof. For older versions, it is provided by sysvinit-tools but since it is not
		# present in new versions, only install procps-ng which exists in all versions.
		sed -i -e "s/PROCPS_PACKAGE_NAME/procps-ng/g" ${STG_DIR}/${rpm_dir}/tmp/aznfs.spec
		sed -i -e "s/DISTRO/rpm/g" ${STG_DIR}/${rpm_dir}/tmp/aznfs.spec
		sed -i -e "s/INSTALL_CMD/yum/g" ${STG_DIR}/${rpm_dir}/tmp/aznfs.spec
	fi

	# Create the rpm package.
	rpmbuild --define "mariner $is_mariner" --define "_topdir ${STG_DIR}/${rpm_dir}${rpmbuild_dir}" -v -bb ${STG_DIR}/${rpm_dir}/tmp/aznfs.spec
}

generate_tarball_package() {
    local arch=$1
    local tar_pkg_dir
    local compiler

    if [ "$arch" == "amd64" ]; then
        tar_pkg_dir="${pkg_name}-${RELEASE_NUMBER}-1.x86_64"
        compiler="gcc"
    elif [ "$arch" == "arm64" ]; then
        tar_pkg_dir="${pkg_name}-${RELEASE_NUMBER}-1.arm64"
        compiler="aarch64-linux-gnu-gcc"
    else
        echo "Unsupported architecture: $arch"
        return 1
    fi

    # Create the directory to hold the package contents.
    mkdir -p ${STG_DIR}/tarball/${tar_pkg_dir}

    # Copy other static package file(s).
    mkdir -p ${STG_DIR}/tarball/${tar_pkg_dir}/usr/sbin
    cp -avf ${SOURCE_DIR}/src/aznfswatchdog ${STG_DIR}/tarball/${tar_pkg_dir}/usr/sbin
    cp -avf ${SOURCE_DIR}/src/aznfswatchdogv4 ${STG_DIR}/tarball/${tar_pkg_dir}/usr/sbin

    # Compile mount.aznfs.c and put the executable into ${STG_DIR}/tarball/${tar_pkg_dir}/
    mkdir -p ${STG_DIR}/tarball/${tar_pkg_dir}/sbin
    $compiler -static ${SOURCE_DIR}/src/mount.aznfs.c -o ${STG_DIR}/tarball/${tar_pkg_dir}/sbin/mount.aznfs

    # Copy the required files to the package directory.
    mkdir -p ${STG_DIR}/tarball/${tar_pkg_dir}${opt_dir}
    cp -avf ${SOURCE_DIR}/lib/common.sh ${STG_DIR}/tarball/${tar_pkg_dir}${opt_dir}/
    cp -avf ${SOURCE_DIR}/src/mountscript.sh ${STG_DIR}/tarball/${tar_pkg_dir}${opt_dir}/
    cp -avf ${SOURCE_DIR}/src/nfsv3mountscript.sh ${STG_DIR}/tarball/${tar_pkg_dir}${opt_dir}/
    cp -avf ${SOURCE_DIR}/src/nfsv4mountscript.sh ${STG_DIR}/tarball/${tar_pkg_dir}${opt_dir}/
    cp -avf ${SOURCE_DIR}/scripts/aznfs_install.sh ${STG_DIR}/tarball/${tar_pkg_dir}${opt_dir}/

    # Set AKS_USER variable to true inside aznfswatchdog to indicate use by Azure Kubernetes Service (AKS).
    sed -i -e 's/AKS_USER="false"/AKS_USER="true"/' -e "s/RELEASE_NUMBER_FOR_AKS=x.y.z/RELEASE_NUMBER_FOR_AKS=${RELEASE_NUMBER}/" ${STG_DIR}/tarball/${tar_pkg_dir}${opt_dir}/common.sh

    # Set appropriate permissions.
    chmod 0755 ${STG_DIR}/tarball/${tar_pkg_dir}${opt_dir}/
    chmod 0755 ${STG_DIR}/tarball/${tar_pkg_dir}/usr/sbin/aznfswatchdog
    chmod 0755 ${STG_DIR}/tarball/${tar_pkg_dir}/usr/sbin/aznfswatchdogv4
    chmod 0755 ${STG_DIR}/tarball/${tar_pkg_dir}${opt_dir}/mountscript.sh
    chmod 0755 ${STG_DIR}/tarball/${tar_pkg_dir}${opt_dir}/nfsv3mountscript.sh
    chmod 0755 ${STG_DIR}/tarball/${tar_pkg_dir}${opt_dir}/nfsv4mountscript.sh
    chmod 0755 ${STG_DIR}/tarball/${tar_pkg_dir}${opt_dir}/aznfs_install.sh
    chmod 0644 ${STG_DIR}/tarball/${tar_pkg_dir}${opt_dir}/common.sh
    chmod 4755 ${STG_DIR}/tarball/${tar_pkg_dir}/sbin/mount.aznfs

    # Create the tar.gz package.
    cd ${STG_DIR}/tarball/${tar_pkg_dir}
    tar -czvf ${STG_DIR}/tarball/${tar_pkg_dir}.tar.gz *
}

#STG_DIR, RELEASE_NUMBER and SOURCE_DIR will be taken as env var.
pkg_name="aznfs"
pkg_dir="${pkg_name}-${RELEASE_NUMBER}-1_amd64"
rpm_pkg_dir="${pkg_name}-${RELEASE_NUMBER}-1.x86_64"
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
cp -avf ${SOURCE_DIR}/src/aznfswatchdogv4 ${STG_DIR}/deb/${pkg_dir}/usr/sbin/

# Compile mount.aznfs.c and put the executable into ${STG_DIR}/deb/${pkg_dir}/sbin.
mkdir -p ${STG_DIR}/deb/${pkg_dir}/sbin
gcc -static ${SOURCE_DIR}/src/mount.aznfs.c -o ${STG_DIR}/deb/${pkg_dir}/sbin/mount.aznfs

#
# We build the turbonfs project here, note that we can set all cmake options in the 
# future using env variables.
#

pushd ${SOURCE_DIR}/turbonfs
export VCPKG_ROOT=${SOURCE_DIR}/turbonfs/extern/vcpkg
# We need to update the submodules before calling cmake as toolchain build expects it.
git submodule update --recursive --init
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=${BUILD_TYPE} -DCMAKE_TOOLCHAIN_FILE=${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake ..
make
popd

cp -avf ${SOURCE_DIR}/turbonfs/build/aznfsclient ${STG_DIR}/deb/${pkg_dir}/sbin/aznfsclient

mkdir -p ${STG_DIR}/deb/${pkg_dir}${opt_dir}
cp -avf ${SOURCE_DIR}/lib/common.sh ${STG_DIR}/deb/${pkg_dir}${opt_dir}/
cp -avf ${SOURCE_DIR}/src/mountscript.sh ${STG_DIR}/deb/${pkg_dir}${opt_dir}/
cp -avf ${SOURCE_DIR}/src/nfsv3mountscript.sh ${STG_DIR}/deb/${pkg_dir}${opt_dir}/
cp -avf ${SOURCE_DIR}/src/nfsv4mountscript.sh ${STG_DIR}/deb/${pkg_dir}${opt_dir}/
cp -avf ${SOURCE_DIR}/scripts/aznfs_install.sh ${STG_DIR}/deb/${pkg_dir}${opt_dir}/
cp -avf ${SOURCE_DIR}/turbonfs/sample-turbo-config.yaml ${STG_DIR}/deb/${pkg_dir}/${opt_dir}/

mkdir -p ${STG_DIR}/deb/${pkg_dir}${system_dir}
cp -avf ${SOURCE_DIR}/src/aznfswatchdog.service ${STG_DIR}/deb/${pkg_dir}${system_dir}
cp -avf ${SOURCE_DIR}/src/aznfswatchdogv4.service ${STG_DIR}/deb/${pkg_dir}${system_dir}

# Create the deb package.
dpkg-deb -Zgzip --root-owner-group --build $STG_DIR/deb/$pkg_dir

#########################
# Generate .rpm package #
#########################

generate_rpm_package rpm
generate_rpm_package suse
generate_rpm_package mariner

##########################################
# Generating Tarball for amd64 and arm64 #
##########################################

generate_tarball_package amd64
generate_tarball_package arm64
