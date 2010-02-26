#!/usr/bin/env python
__author__ = 'Ben "TheX1le" Smith, Marfi'
__email__ = 'thex1le@gmail.com'
__website__= ''
__date__ = '09/19/09'
__version__ = '2009.11.23'
__file__ = 'ouiParse.py'
__data__ = 'a class for dealing with the oui txt file'

"""
########################################
#
# This program and its support programs are free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation; version 2.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
#########################################
"""

import re, urllib2, sys, os
class macOUI_lookup:
	"""
	A class for deaing with OUIs and deterimining device type
	"""
	def __init__(self,oui=None):
		"""
		generate the two dictionaries and return them
		"""
		#a poor fix where if we have no file it trys to download it
		self.ouiTxtUrl   = "http://standards.ieee.org/regauth/oui/oui.txt"
		self.ouiUnPath   = '/usr/lib/airdrop-ng/'#path to oui.txt if module is installed
		self.ouiInPath   = './support/'         #path to oui.txt if module is not installed
		if oui == None:
			"if the file name is not provided attempt to get it"
			self.ouiTxt  = None
			self.ouiUpdate()
		else:
			self.ouiTxt	 = oui 			#location of the oui txtfile on the hard drive
	
		self.ouiRaw      = self.ouiOpen()
		self.oui_company = self.ouiParse() 	#dict where oui's are the keys to company names
		self.company_oui = self.companyParse()	#dict where company name is the key to oui's
	
	def compKeyChk(self,name):
		"""
		check for valid company name key
		"""
		compMatch = re.compile(name,re.I)
		if self.company_oui.has_key(name):
			return True
		for key in self.company_oui.keys():
				if compMatch.search(key) is not None:	
					return True
		return False

	def ouiKeyChk(self,name):
		"""
		check for a valid oui prefix
		"""

		if self.oui_company.has_key(name): 
			return True
		else: 
			return False

	def lookup_OUI(self,mac):
		"""
		Lookup a oui and return the company name
		"""
		if self.ouiKeyChk(mac) is not False:
			return self.oui_company[mac][0]
		else: 
			return False
	
	def lookup_company(self,companyLst):
		"""
		look up a company name and return their OUI's
		"""
		oui = []
		if type(companyLst).__name__ == "list":
			for name in companyLst:
				compMatch = re.compile(name,re.I)
				if self.company_oui.has_key(name):
					oui.extend(self.company_oui[name])
				else:
					for key in self.company_oui:
						if compMatch.search(key) is not None:
							oui.extend(self.company_oui[key])

		elif type(companyLst).__name__ == "str":
			if self.company_oui.has_key(companyLst):
				oui = self.company_oui[companyLst]
			else:
				
				compMatch = re.compile(companyLst,re.I)
				for key in self.company_oui:
					if compMatch.search(key) is not None:
						oui.extend(self.company_oui[key]) #return the oui for that key
		return oui
				
	def ouiOpen(self):
		"""
		open the file and read it in
		"""
		ouiFile = open(self.ouiTxt, "r")
		text = ouiFile.read()
		return text
	
	def ouiParse(self): 
		"""
		generate a oui to company lookup dict
		"""
		HexOui= {}
		Hex = re.compile('.*(hex).*')
		#matches the following example "00-00-00   (hex)\t\tXEROX CORPORATION" 
		ouiLines = self.ouiRaw.split("\n\n") 
		#split each company into a list one company per position
		for line in ouiLines:
			if Hex.search(line) != None: 
				lineList = Hex.search(line).group().replace("\t"," ").split("  ") 
				#return the matched text and build a list out of it
				HexOui[lineList[0].replace("-",":")] = [lineList[2]] 
				#build a dict in the format of mac:company name	
		return HexOui
	
	def companyParse(self):
		"""
		generate a company to oui lookup dict
		"""
		company_oui = {}
		for oui in self.oui_company:
			if company_oui.has_key(self.oui_company[oui][0]):
				company_oui[self.oui_company[oui][0]].append(oui)
			else:
				company_oui[self.oui_company[oui][0]] = [oui]
		return company_oui
		

	def ouiUpdate(self):
		"""
		Grab the oui txt file off the ieee.org website
		"""
		if os.path.isdir (self.ouiInPath) == True:
			print "Going to support/ to install new oui.txt..."
			ouiDIR = self.ouiInPath
		else:
			print "Going to /usr/lib/airdrop-ng to install new oui.txt..."
			ouiDIR = self.ouiUnPath
			try:
				os.remove(ouiDIR+"oui.txt")
			except OSError:
				print "Unable to delete oui.txt"
		try:
			# Checks to see if it's running from a directory when not installed.
			# If not, then goes to /usr/lib/airdrop-ng , where the main file is. 
			ouiOnline = urllib2.urlopen(self.ouiTxtUrl)
			print "Writing OUI file"
			#lFile = open (ouiDIR+"oui.txt", "w")
			#lFile.writelines(ouiOnline)
			#lFile.close()	
			#ouiOnline.close()
			#self.ouiTxt = ouiDIR+"oui.txt"
			dire = ouiDIR + "oui.txt"
			import urllib
			urllib.urlretrieve(self.ouiTxtUrl, dire)
			print "Completed Successfully"
			sys.exit(0)
		except Exception,e:
			print e
			print "Could not download file."
			print "Exiting airdrop-ng. Card in monitor mode or not root?"
			sys.exit(0)

#used for testing
if __name__ == "__main__": 
	lookup = macOUI_lookup("../support/oui.txt")
	print lookup.lookup_OUI('00:20:DB')
	value = lookup.lookup_company("apple")
	print value
	print len(value)


