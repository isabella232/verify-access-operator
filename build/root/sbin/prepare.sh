#!/bin/sh

##############################################################################
# Copyright contributors to the IBM Security Verify Access Operator project
##############################################################################

set -e

#
# Install the pre-requisite RedHat RPMs
#

yum -y install make git 

yum module -y install go-toolset

#
# Install kubectl.
#

cat <<EOF > /etc/yum.repos.d/kubernetes.repo
[kubernetes]
name=Kubernetes
baseurl=https://packages.cloud.google.com/yum/repos/kubernetes-el7-x86_64
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://packages.cloud.google.com/yum/doc/yum-key.gpg https://packages.cloud.google.com/yum/doc/rpm-package-key.gpg
EOF

yum install -y kubectl

#
# Install docker.
#

dnf config-manager --add-repo=https://download.docker.com/linux/centos/docker-ce.repo

dnf -y install docker-ce 

#
# Install the operator SDK.  This code comes directly from the Operator SDK
# Web site: 
#   https://sdk.operatorframework.io/docs/installation/#install-from-github-release
#

export ARCH=amd64
export OS=$(uname | awk '{print tolower($0)}')
export OPERATOR_SDK_DL_URL=https://github.com/operator-framework/operator-sdk/releases/download/v1.7.2

curl -LO ${OPERATOR_SDK_DL_URL}/operator-sdk_${OS}_${ARCH}

#
# Verify that the operator has been downloaded OK.
#

gpg --keyserver keyserver.ubuntu.com --recv-keys 052996E2A20B5C7E

curl -LO ${OPERATOR_SDK_DL_URL}/checksums.txt
curl -LO ${OPERATOR_SDK_DL_URL}/checksums.txt.asc
gpg -u "Operator SDK (release) <cncf-operator-sdk@cncf.io>" \
    --verify checksums.txt.asc

grep operator-sdk_${OS}_${ARCH} checksums.txt | sha256sum -c -

#
# Install the operator.
#

chmod +x operator-sdk_${OS}_${ARCH} 

mv operator-sdk_${OS}_${ARCH} /usr/local/bin/operator-sdk

#
# Set up the motd file, and ensure that we show this file whenever we
# start a shell.
#

cat > /etc/motd << EOF
This shell can be used to build the Verify Access Operator docker images.

The following make targets can be used:

    help:
        This target will display general help information on all targets
        contained within the Makefile.

    build:
        This target should be executed to generate a new build.

    docker-build:
        This target will build the main controller image.

    bundle:
        This target is used to generate the OLM bundle.

    bundle-build:
        This target will build the OLM bundle image.

In order to deploy the image, using OLM, to a Kubernetes environment:
    1. operator-sdk olm install
    2. operator-sdk run bundle ibmcom/verify-access-operator-bundle:v0.0.1

EOF

cat >> /etc/bashrc << EOF
help() {
    cat /etc/motd
}

help

EOF

#
# Clean-up the temporary files.
#

rm -f checksums.txt checksums.txt.asc

yum clean all

