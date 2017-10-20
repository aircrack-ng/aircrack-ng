#!/usr/bin/env python
__version__ = "1.13.2010.21:00"
__author__  = "Marfi"

'''
This is the installer file for airdrop-ng. It first checks for 
different dependencies, such as make, svn, etc. 
'''
import os
import sys
from shutil import rmtree

if os.geteuid() != 0:
	print "Installer must be root to run. \nPlease 'su' or 'sudo -i' and try again. \nExiting..."
	sys.exit(1)

class checkDepend:
	def __init__ (self):
		clear = "\n" *100
		print clear
		print "Checking for dependencies used by the installer..."
		self.a = 0
		self.deps = ["make", "svn", "tar", "gcc"]

		for depends in self.deps:
			if (os.path.isfile("/usr/bin/" + depends) or os.path.isfile("/usr/sbin/" + depends) or os.path.isfile("/usr/local/bin/" + depends) or os.path.isfile("/usr/local/sbin/" + depends) or os.path.isfile ("/bin/" + depends) ) == True:
				pass
			else:
				self.a = 1
				print depends + " not installed."

		if self.a == 0:
			print "All dependencies installed! Continuing...\n"
			print "#### NOTE: For Ubuntu based distro's, \npython2.6-dev must be installed. Please \nmake sure it is installed before continuing!\n"
		else:
			print "Please install dependencies. Exiting...\n\n"
			exit()

class installAirdrop:
	def __init__(self):


		print "Welcome to the airdrop-ng installer!\nYou will be prompted for installing\nAirdrop-ng, lorcon, and pylorcon.\n"
		yno = raw_input ("Continue with installer? (y/n): ")
		if yno == "y":

			pass
		else:
			print "Fine, be that way. Exiting..."
			exit()

		yno = raw_input ("Install airdrop-ng? (y/n): ")
		if yno == "y":
			self.install()
		else:
			print "airdrop-ng not installed. Continuing..."
			pass


	def install(self):
		print "Build exist? "
		if os.path.isdir("build"):
			rmtree("build")  # imported from shutil, or shutil.rmtree()
			print "File exists. Cleaning it..."
			os.mkdir ("build")
		else:
			os.mkdir ("build")
			print "Didn't exist. Creating..."

		# moves everything to build/. This is to keep everything clean,
		# and not clutter up the directory. 
 
		os.system ("cp airdrop-ng build/ && cp -r lib build/ && cp docs/airdrop-ng.1 build/")
		print "Files copied. Now, moving to directory..."
		os.chdir ("build")
		if os.path.isdir("/usr/lib/airdrop-ng") == True:
			rmtree ("/usr/lib/airdrop-ng")
		print "Moving airdrop-ng to /usr/bin, lib to \n/usr/lib/airdrop-ng, and installing man pages..."
		os.system ("cp airdrop-ng /usr/bin/airdrop-ng && cp -r lib /usr/lib/airdrop-ng && cp airdrop-ng.1 /usr/share/man/man1/")
		#os.chdir ("..")
		print "airdrop-ng installed!  =)"

class installLorcon:
	def __init__(self):
		yno = raw_input ("Would you like to install lorcon? (y/n): ")
		if yno == "y":
			print "Running svn co http://802.11ninja.net/svn/lorcon/branch/lorcon-old. This may take a while..."
			os.system ("svn co http://802.11ninja.net/svn/lorcon/branch/lorcon-old")
			os.chdir("lorcon-old")
			os.system ("./configure && make && make install")
			print "Creating symlinks..."
			os.system ("ln -s /usr/local/lib/liborcon-1.0.0.so /usr/lib")
			os.chdir("..")
		else:
			print "Lorcon wasn't installed. "

class installPylorcon:
	def __init__(self):
		yno = raw_input ("Would you like to install pylorcon? (y/n): ")
		if yno == "y":

			import urllib
			urllib.urlretrieve("http://pylorcon.googlecode.com/files/pylorcon-3.tar.bz2", "pylorcon-3.tar.bz2")
			os.system ("tar -xvf pylorcon-3.tar.bz2")
			os.chdir ("pylorcon")
			os.system ("python setup.py install")
			os.chdir("..")


# What actually runs the classes	
checkDepend()
installAirdrop()
installLorcon()
installPylorcon()

yno = raw_input ("Clean up? (y/n): ")
if yno == "y":
	os.chdir("..")
	if os.path.isdir("build") == True:
		rmtree("build")

print "Operation(s) complete! May the source be with you. =) "
sys.exit()
