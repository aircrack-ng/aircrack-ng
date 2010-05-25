#!/usr/bin/make
# Configure prefix here:
prefix="/usr/local"
aircrack_prefix="/usr/local" # for packaged aircrack-ng change me to /usr
OSTYPE:=$(shell uname -s|cut -d_ -f1)
include Makefile-$(OSTYPE)
