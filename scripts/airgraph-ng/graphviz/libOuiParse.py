#!/usr/bin/env python
__author__ = 'Ben "TheX1le" Smith, Marfi'
__email__ = 'thex1le@gmail.com'
__website__= ''
__date__ = '04/26/2011'
__version__ = '2011.4.26'
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

import re
import urllib
import sys
import os
import pdb
#this lib is crap and needs to be rewritten -Textile 

if os.path.isdir('./support/'):
    path='./support/'
elif os.path.isdir('/usr/local/share/airgraph-ng/'):
    path='/usr/local/share/airgraph-ng/'
elif os.path.isdir('/usr/share/airgraph-ng/'):
    path='/usr/share/airgraph-ng/'
else:
    raise Exception("Could not determine path, please, check your installation")

class macOUI_lookup:
    """
    A class for deaing with OUIs and deterimining device type
    """
    def __init__(self, oui=False):
        """
        generate the two dictionaries and return them
        """
        #a poor fix where if we have no file it trys to download it
        self.ouiTxtUrl   = "http://standards.ieee.org/regauth/oui/oui.txt"

        self.ouiTxt = oui
        if not oui or not os.path.isfile(self.ouiTxt):
            self.ouiUpdate()
            self.ouiTxt = path + "oui.txt"
        self.last_error = None
        self.identDeviceDict(path + 'ouiDevice.txt')
        self.identDeviceDictWhacMac(path + 'whatcDB.csv')
        self.ouiRaw      = self.ouiOpen(self.ouiTxt)
        self.oui_company = self.ouiParse()  #dict where oui's are the keys to company names
        self.company_oui = self.companyParse()  #dict where company name is the key to oui's

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
            return self.oui_company[mac]
        else: 
            return False
    
    def lookup_company(self,companyLst):
        """
        look up a company name and return their OUI's
        """
        oui = []
        if type(companyLst) is list:
            for name in companyLst:
                compMatch = re.compile(name,re.I)
                if self.company_oui.has_key(name):
                    oui.extend(self.company_oui[name])
                else:
                    for key in self.company_oui:
                        if compMatch.search(key) is not None:
                            oui.extend(self.company_oui[key])

        elif type(companyLst) is str:
            if self.company_oui.has_key(companyLst):
                oui = self.company_oui[companyLst]
            else:
                
                compMatch = re.compile(companyLst,re.I)
                for key in self.company_oui:
                    if compMatch.search(key) is not None:
                        oui.extend(self.company_oui[key]) #return the oui for that key
        return oui
                
    def ouiOpen(self,fname,flag='R'):
        """
        open the file and read it in
        flag denotes use of read or readlines
        """
        try:
            with open(fname, "r") as fid:
                if flag == 'RL':
                    text = fid.readlines()
                elif flag == 'R':
                    text = fid.read()
            return text
        except IOError:
            return False

    
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
            if Hex.search(line) is not None: 
                lineList = Hex.search(line).group().replace("\t"," ").split("  ") 
                #return the matched text and build a list out of it
                HexOui[lineList[0].replace("-",":")] = lineList[2] 
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
        try:
            print("Getting OUI file from %s to %s" %(self.ouiTxtUrl, path))
            urllib.urlretrieve(self.ouiTxtUrl, path + "oui.txt")
            print "Completed Successfully"
        except Exception, error:
            print("Could not download file:\n %s\n Exiting airgraph-ng" %(error))
            sys.exit(0)
   
    def identDeviceDict(self,fname):
        """
        Create two dicts allowing device type lookup
        one for oui to device and one from device to OUI group
        """
        self.ouitodevice = {}
        self.devicetooui = {}
        data = self.ouiOpen(fname,'RL')
        if data == False:
            self.last_error = "Unable to open lookup file for parsing"
            return False
        for line in data:
            dat = line.strip().split(',')
            self.ouitodevice[dat[1]] = dat[0]
            if dat[0] in self.devicetooui.keys():
                self.devicetooui[dat[0]].append(dat[1])
            else:
                self.devicetooui[dat[0]] = [dat[1]]

    def identDeviceDictWhacMac(self,fname):
        """
        Create two dicts allowing device type lookup from whatmac DB
        one for oui to device and one from the device to OUI group
        """
        self.ouitodeviceWhatmac3 = {}
        self.ouitodeviceWhatmac = {}
        self.devicetoouiWhacmac = {}
        data = self.ouiOpen(fname,'RL')
        if data == False:
            self.last_error = "Unble to open lookup file for parsing"
            return False
        for line in data:
            dat = line.strip().split(',')
            dat[0] = dat[0].upper()
            self.ouitodeviceWhatmac[dat[0]] = dat[1]
            self.ouitodeviceWhatmac3[dat[0][0:8]] = dat[1] # a db to support the 3byte lookup from whatmac
            if dat[1] in self.devicetoouiWhacmac.keys():
                self.devicetoouiWhacmac[dat[1]].append(dat[0])
            else:
                self.devicetoouiWhacmac[dat[1]] = [dat[0]]

