#!/bin/bash

# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

# Exit on error.
set -e

# Debian uses amd64/arm64 in place of x86_64/aarch64.
if [ "$(uname -m)" == "x86_64" ]; then
	arch="x86_64"
	debarch="amd64"
elif [ "$(uname -m)" == "aarch64" ]; then
	arch="aarch64"
	debarch="arm64"
else
	echo "Unsupported architecture: $(uname -m)"
	exit 1
fi

generate_rpm_package()
{
	rpm_dir=$1
	custom_stunnel_required=0

	# Overwrite rpm_pkg_dir in case of SUSE.
	if [ "$rpm_dir" == "suse" ]; then
		rpm_pkg_dir="${pkg_name}_sles-${RELEASE_NUMBER}-1.$arch"
	fi

	# Overwrite rpm_pkg_dir in case of Mariner, RedHat7, and Centos7.
	if [ "$rpm_dir" == "stunnel" ]; then
		rpm_pkg_dir="${pkg_name}_stunnel_custom-${RELEASE_NUMBER}-1.$arch"
		custom_stunnel_required=1
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

	###########################################
	# Bundle aznfsclient and its dependencies #
	###########################################

	# copy the aznfsclient config file.
	cp -avf ${SOURCE_DIR}/turbonfs/sample-turbo-config.yaml ${STG_DIR}/${rpm_dir}/tmp${rpm_buildroot_dir}/${rpm_pkg_dir}${opt_dir}/

	# copy the aznfsclient binary.
	cp -avf ${aznfsclient} ${STG_DIR}/${rpm_dir}/tmp${rpm_buildroot_dir}/${rpm_pkg_dir}/sbin/aznfsclient

	#
	# Package aznfsclient dependencies in opt_dir/libs.
	# libs_dir must already be populated with the required dependencies from
	# the debian packaging step. Simply copy all those to rpm_libs_dir.
	#
	rpm_libs_dir=${STG_DIR}/${rpm_dir}/tmp${rpm_buildroot_dir}/${rpm_pkg_dir}${opt_dir}/libs
	mkdir -p ${rpm_libs_dir}
	cp -avfH ${libs_dir}/* ${rpm_libs_dir}

	# Create the archive for the package.
	tar -cvzf ${STG_DIR}/${rpm_pkg_dir}.tar.gz -C ${STG_DIR}/${rpm_dir}/tmp root

	# Copy the SPEC file to change the placeholders depending upon the RPM distro.
	cp -avf ${SOURCE_DIR}/packaging/${pkg_name}/RPM/aznfs.spec ${STG_DIR}/${rpm_dir}/tmp/

	#
	# Insert the contents of ${rpm_libs_dir}.
	# This is variable due to the shared library versions.
	# sed doesn't (easily) support replace target to be multi-line, so we use
	# awk for this one.
	#
	opt_libs=$(for lib in ${rpm_libs_dir}/*; do echo ${opt_dir}/libs/$(basename $lib); done)
	awk -i inplace -v r="$opt_libs" '{gsub(/OPT_LIBS/,r)}1' ${STG_DIR}/${rpm_dir}/tmp/aznfs.spec

	# Insert current release number and RPM_DIR value.
	sed -i -e "s/Version: x.y.z/Version: ${RELEASE_NUMBER}/g" ${STG_DIR}/${rpm_dir}/tmp/aznfs.spec
	sed -i -e "s/RPM_DIR/${rpm_dir}/g" ${STG_DIR}/${rpm_dir}/tmp/aznfs.spec
	sed -i -e "s/BUILD_ARCH/${arch}/g" ${STG_DIR}/${rpm_dir}/tmp/aznfs.spec
	
	# Replace the placeholders for various package names in aznfs.spec file. 
	if [ "$rpm_dir" == "suse" ]; then
		sed -i -e "s/AZNFS_PACKAGE_NAME/${pkg_name}_sles/g" ${STG_DIR}/${rpm_dir}/tmp/aznfs.spec
		sed -i -e "s/NETCAT_PACKAGE_NAME/netcat-openbsd/g" ${STG_DIR}/${rpm_dir}/tmp/aznfs.spec
		# For SLES, sysvinit-tools provides pidof.
		sed -i -e "s/PROCPS_PACKAGE_NAME/sysvinit-tools/g" ${STG_DIR}/${rpm_dir}/tmp/aznfs.spec
		sed -i -e "s/DISTRO/suse/g" ${STG_DIR}/${rpm_dir}/tmp/aznfs.spec
	else
		if [ "$rpm_dir" == "stunnel" ]; then
			sed -i -e "s/AZNFS_PACKAGE_NAME/${pkg_name}_stunnel_custom/g" ${STG_DIR}/${rpm_dir}/tmp/aznfs.spec
		else
			sed -i -e "s/AZNFS_PACKAGE_NAME/${pkg_name}/g" ${STG_DIR}/${rpm_dir}/tmp/aznfs.spec
		fi

		sed -i -e "s/NETCAT_PACKAGE_NAME/nmap-ncat/g" ${STG_DIR}/${rpm_dir}/tmp/aznfs.spec
		# In new versions of Centos/RedHat/Rocky, procps-ng provides pidof. For older versions, it is provided by sysvinit-tools but since it is not
		# present in new versions, only install procps-ng which exists in all versions.
		sed -i -e "s/PROCPS_PACKAGE_NAME/procps-ng/g" ${STG_DIR}/${rpm_dir}/tmp/aznfs.spec
		sed -i -e "s/DISTRO/rpm/g" ${STG_DIR}/${rpm_dir}/tmp/aznfs.spec
		sed -i -e "s/INSTALL_CMD/yum/g" ${STG_DIR}/${rpm_dir}/tmp/aznfs.spec
	fi

	# Create the rpm package.
	rpmbuild --define "custom_stunnel $custom_stunnel_required" --define "_topdir ${STG_DIR}/${rpm_dir}${rpmbuild_dir}" -v -bb ${STG_DIR}/${rpm_dir}/tmp/aznfs.spec
}

generate_tarball_package()
{
    local arch=$1
    local tar_pkg_dir
    local compiler

    tar_pkg_dir="${pkg_name}-${RELEASE_NUMBER}-1.$arch"
    compiler="gcc"

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

    ###########################################
    # Bundle aznfsclient and its dependencies #
    ###########################################

    # copy the aznfsclient config file.
    cp -avf ${SOURCE_DIR}/turbonfs/sample-turbo-config.yaml ${STG_DIR}/tarball/${tar_pkg_dir}${opt_dir}/

    # copy the aznfsclient binary.
    cp -avf ${aznfsclient} ${STG_DIR}/tarball/${tar_pkg_dir}/sbin/aznfsclient

    #
    # Package aznfsclient dependencies in opt_dir/libs.
    # libs_dir must already be populated with the required dependencies from
    # the debian packaging step. Simply copy all those to rpm_libs_dir.
    #
    tarball_libs_dir=${STG_DIR}/tarball/${tar_pkg_dir}${opt_dir}/libs
    mkdir -p ${tarball_libs_dir}
    cp -avfH ${libs_dir}/* ${tarball_libs_dir}

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
pkg_dir="${pkg_name}-${RELEASE_NUMBER}-1_$debarch"
rpm_pkg_dir="${pkg_name}-${RELEASE_NUMBER}-1.$arch"
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
sed -i -e "s/BUILD_ARCH/${debarch}/g" ${STG_DIR}/deb/${pkg_dir}/DEBIAN/control

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

if [ "${BUILD_TYPE}" == "Debug" ]; then
    PARANOID=ON
    INSECURE_AUTH_FOR_DEVTEST=ON
else
    PARANOID=OFF
    INSECURE_AUTH_FOR_DEVTEST=ON
fi
echo "ENABLE_INSECURE_AUTH_FOR_DEVTEST is set to: ${INSECURE_AUTH_FOR_DEVTEST}"

# vcpkg required env variable VCPKG_FORCE_SYSTEM_BINARIES to be set for arm64.
if [ "$(uname -m)" == "aarch64" ]; then
    export VCPKG_FORCE_SYSTEM_BINARIES=1
fi

cmake -DCMAKE_BUILD_TYPE=${BUILD_TYPE} \
      -DENABLE_PARANOID=${PARANOID} \
      -DENABLE_INSECURE_AUTH_FOR_DEVTEST=${INSECURE_AUTH_FOR_DEVTEST} \
      -DPACKAGE_VERSION="${RELEASE_NUMBER}" \
      -DCMAKE_TOOLCHAIN_FILE=${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake ..
make
popd

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

###########################################
# Bundle aznfsclient and its dependencies #
###########################################

# aznfsclient in the final target dir.
aznfsclient=${STG_DIR}/deb/${pkg_dir}/sbin/aznfsclient
cp -avf ${SOURCE_DIR}/turbonfs/build/aznfsclient ${aznfsclient}

# Package aznfsclient dependencies in opt_dir.
libs_dir=${STG_DIR}/deb/${pkg_dir}${opt_dir}/libs
mkdir -p ${libs_dir}

# Copy the dependencies.
cp -avfH $(ldd ${aznfsclient} | grep "=>" | awk '{print $3}') ${libs_dir}

#
# Patch all the libs to reference shared libs from ${libs_dir}.
# This is our very simple containerization.
#
for lib in ${libs_dir}/*.so*; do
	echo "Setting rpath to ${opt_dir}/libs for $lib"
	patchelf --set-rpath ${opt_dir}/libs "$lib"
done

#
# Final containerization effort - bundle and use the same interpreter as the
# build machine.
#
ld_linux_path=$(ldd ${aznfsclient} | grep "ld-linux" | awk '{print $1}')
ld_linux_name=$(basename "$ld_linux_path")
ld_linux="${libs_dir}/${ld_linux_name}"
cp -avfH  "${ld_linux_path}" "${ld_linux}"

patchelf --set-interpreter ${opt_dir}/libs/${ld_linux_name} ${aznfsclient}

# Create the deb package.
dpkg-deb -Zgzip --root-owner-group --build $STG_DIR/deb/$pkg_dir

#########################
# Generate .rpm package #
#########################

generate_rpm_package rpm
generate_rpm_package suse
# Generate rpm package with custom stunnel installation for Mariner, RedHat7, and Centos7.
generate_rpm_package stunnel

#############################
# Generating Tarball for AKS#
#############################

generate_tarball_package $arch
