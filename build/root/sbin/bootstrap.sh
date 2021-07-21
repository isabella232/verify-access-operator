#!/bin/sh

##############################################################################
# Copyright contributors to the IBM Security Verify Access Operator project
##############################################################################

# Set up the build area, symbolically linking files from our workspace.
mkdir -p /build

rsync -az /workspace/src /build

# Set the current working directory to the build area and then start a bash
# shell.
cd /build/src

/usr/bin/bash

