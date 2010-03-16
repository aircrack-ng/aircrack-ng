#!/usr/bin/env python
__author__  = "Marfi"
__version__ = "?"

from os import system, geteuid
from sys import exit
if geteuid() != 0:
	print "airdrop-ng must be root. Please \n'su' or 'sudo -i' and run again. \nExiting..."
	exit(1)

yno = raw_input ("You shouldn't need this. Remove? (y/n): ")
if yno == "y":
	print "Removing man entry and airdrop-ng..."
	system ("sudo rm /usr/share/man/man1/airdrop-ng.1")
	system ("sudo rm /usr/bin/airdrop-ng")
	system ("sudo rm -r /usr/lib/airdrop-ng")
else:
	print "Exiting..."
	exit()
