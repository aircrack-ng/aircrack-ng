#!/usr/bin/make
# Configure prefix here:
prefix="/usr/local"

OSTYPE:=$(shell uname -s|cut -d_ -f1)
include Makefile-$(OSTYPE)
