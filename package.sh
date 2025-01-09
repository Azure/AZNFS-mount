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
	rpmbuild --define "_topdir ${STG_DIR}/${rpm_dir}${rpmbuild_dir}" -v -bb ${STG_DIR}/${rpm_dir}/tmp/aznfs.spec
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
pkg_dir="${pkg_name}-${RELEASE_NUMBER}-1"
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

# Define target architectures using Debian's naming conventions
architectures=("amd64" "arm64")  # Add other architectures as needed

# Determine host architecture and map it to Debian-Package naming
host_arch_raw=$(uname -m)
declare -A arch_map=( ["x86_64"]="amd64" ["aarch64"]="aarch64" )

# Map the host architecture to Debian's naming
host_arch="${arch_map[$host_arch_raw]}"
if [ -z "$host_arch" ]; then
    echo "Unsupported host architecture: $host_arch_raw"
    exit 1
fi

# Iterate over each architecture
for ARCH in "${architectures[@]}"; do
    echo "Building package for architecture: $ARCH"
    
    # Determine the appropriate compiler
    if [ "$ARCH" == "$host_arch" ]; then
        compiler="gcc"
    else
        compiler="${host_arch_raw}-linux-gnu-gcc"
    fi

    # Check if the compiler exists
    if ! command -v "$compiler" &> /dev/null; then
        echo "Compiler $compiler not found. Please install it before proceeding."
        exit 1
    fi

    # Set up architecture-specific staging directory
    ARCH_STG_DIR="${STG_DIR}/deb/${pkg_dir}_${ARCH}"
    mkdir -p "${ARCH_STG_DIR}/DEBIAN"

    # Copy the Debian control file(s) and maintainer scripts
    cp -avf "${SOURCE_DIR}/packaging/${pkg_name}/DEBIAN/"* "${ARCH_STG_DIR}/DEBIAN/"
    chmod +x "${ARCH_STG_DIR}/DEBIAN/"*

    # Insert current release number and architecture into the control file
    sed -i -e "s/Version: x.y.z/Version: ${RELEASE_NUMBER}-${ARCH}/g" "${ARCH_STG_DIR}/DEBIAN/control"
    sed -i -e "s/Architecture: any/Architecture: ${ARCH}/g" "${ARCH_STG_DIR}/DEBIAN/control"

    # Copy other static package files
    mkdir -p "${ARCH_STG_DIR}/usr/sbin"
    cp -avf "${SOURCE_DIR}/src/aznfswatchdog" "${ARCH_STG_DIR}/usr/sbin/"
    cp -avf "${SOURCE_DIR}/src/aznfswatchdogv4" "${ARCH_STG_DIR}/usr/sbin/"

    # Compile mount.aznfs.c for the target architecture and place the executable into sbin
    mkdir -p "${ARCH_STG_DIR}/sbin"
    echo "Compiling mount.aznfs.c using $compiler"
    $compiler -static "${SOURCE_DIR}/src/mount.aznfs.c" -o "${ARCH_STG_DIR}/sbin/mount.aznfs"
    
    # Verify if compilation was successful
    if [ $? -ne 0 ]; then
        echo "Compilation failed for architecture: $ARCH"
        exit 1
    fi

    # Copy optional scripts and libraries
    mkdir -p "${ARCH_STG_DIR}${opt_dir}"
    cp -avf "${SOURCE_DIR}/lib/common.sh" "${ARCH_STG_DIR}${opt_dir}/"
    cp -avf "${SOURCE_DIR}/src/mountscript.sh" "${ARCH_STG_DIR}${opt_dir}/"
    cp -avf "${SOURCE_DIR}/src/nfsv3mountscript.sh" "${ARCH_STG_DIR}${opt_dir}/"
    cp -avf "${SOURCE_DIR}/src/nfsv4mountscript.sh" "${ARCH_STG_DIR}${opt_dir}/"
    cp -avf "${SOURCE_DIR}/scripts/aznfs_install.sh" "${ARCH_STG_DIR}${opt_dir}/"

    # Copy systemd service files
    mkdir -p "${ARCH_STG_DIR}${system_dir}"
    cp -avf "${SOURCE_DIR}/src/aznfswatchdog.service" "${ARCH_STG_DIR}${system_dir}/"
    cp -avf "${SOURCE_DIR}/src/aznfswatchdogv4.service" "${ARCH_STG_DIR}${system_dir}/"

    # Build the Debian package
    dpkg-deb -Zgzip --root-owner-group --build "${ARCH_STG_DIR}" "${ARCH_STG_DIR}.deb"
    
    # Check if dpkg-deb succeeded
    if [ $? -ne 0 ]; then
        echo "dpkg-deb failed for architecture: $ARCH"
        exit 1
    fi

    # Move the package to a designated output directory
    OUTPUT_DIR="${STG_DIR}/packages"
    mkdir -p "${OUTPUT_DIR}"
    mv "${ARCH_STG_DIR}.deb" "${OUTPUT_DIR}/${pkg_dir}_${ARCH}.deb"

    echo "Package for $ARCH built successfully: ${OUTPUT_DIR}/${pkg_dir}_${ARCH}.deb"
done

#########################
# Generate .rpm package #
#########################

generate_rpm_package rpm
generate_rpm_package suse

##########################################
# Generating Tarball for amd64 and arm64 #
##########################################

generate_tarball_package amd64
generate_tarball_package arm64
