#~ /usr/bin/env python
#this is a support lib for airgraph-ng
#file name [lib_Airgraphviz.py] 
########################################
#
# Airgraph-ng.py --- Generate Graphs from airodump CSV Files
#
# Copyright (C) 2008 Ben Smith <thex1le@gmail.com>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation; version 2.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
#########################################

import pdb

def AP_Label_Color(Label,color):
	# returns the Colors for the AP, enc = Label[3], essid = Label[1], bssid = Label[0], channel = Label[2]  //position that each bit of inforamtion comes in from the caller
	graph = ['\t','"',Label[0],'"','[label="',Label[0],'\\nEssid:',Label[1],'\\nChannel:',Label[2],'\\nEncryption:',Label[3],'"','color="',color,'"',' fontcolor="',color,'"','];\n']
	return graph

def Client_Label_Color(mac,color):
	#creates a label for the client information passed in is our label info and the mac address of the client
	label = mac #in the future i assuem ill be brining some info in that we will want to write on our client
	graph = ['\t','"',mac,'"','[label="',label,'"','color="',color,'"','];\n']
	return graph
	
def Return_Enc_type(enc):
	#check the type of encryption in use and returns the correct color to use based on it
	if enc == "OPN":
		color = "crimson"
	elif enc == "WEP":
		color = "darkgoldenrod2"
	elif enc in ["WPA","WPA2WPA","WPA2","WPAOPN"]:
		color = "darkgreen"
	else:
		color = "black"  #idealy no AP should ever get to this point as they will either be encrypted or open
	return color


def graphviz_link(objA,sep,objB):
	#this is the basic dot format with object one linked to object two linked by a sperator we define
	graph =['\t','"',objA,'"',sep,'"',objB,'"',';\n']
	return graph

def dot_close(input,footer):
	#closes our graphviz config file and returns the final output to be written
	#pdb.set_trace()   #debugging break point
	input.extend(footer)
	input.append("}")
	output = ''.join(input)
	return output

def dot_write(data): #write out our config file
        file = open('airGconfig.dot','a')
	file.writelines(data)
	file.close()


