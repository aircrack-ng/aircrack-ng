__author__ = 'Ben "TheX1le" Smith'
__email__ = 'thex1le@gmail.com'
__website__= 'http://trac.aircrack-ng.org/browser/trunk/scripts/airgraph-ng/'
__date__ = '03/02/09'
__version__ = ''
__file__ = 'lib_Airgraphviz.py'
__data__ = 'This library supports airgraph-ng'

"""
########################################
#
# Airgraph-ng.py --- Generate Graphs from airodump CSV Files
#
# Copyright (C) 2009 Ben Smith <thex1le[a.t]gmail.com>
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
"""

""" Airgraph-ng Support Library """

def apColor(Label,APcolorList): #OLDNAME AP_Label_Color
	"""
        Inputs a list containing AP information and the AP color information
        Returns a graph object that holds AP information (colors and details)
        TODO: Get sample data for each line?
	"""
	APcolor = APcolorList[0]
	fontColor = APcolorList[1]

	graph = ['\t','"',Label[0],'"',
		 '[label="',Label[0],
		 '\\nEssid: ',Label[1].rstrip('\x00'), #NULL ESSID is equal to binary space, must remove
		 '\\nChannel: ',Label[2],
		 '\\nEncryption: ',Label[3],
		 '\\nNumber of Clients: ','%s' %(Label[4]), #Check to see if this method is actually needed
		 '"',' style=filled',
		 ' fillcolor="',APcolor,
		 '"',' fontcolor="',fontColor,
		 '"',' fontsize=7','];\n']
	return graph

def clientColor(mac,color,label=""): #OLDNAME Client_Label_Color
	"""
	Creates a label for the client information passed in (mac, color)
	Returns a graph object
        TODO: Pass a label in that may hold additional client data that could in turn be written on the client.
	"""
	if label == "":
		label = mac
	graph = ['\t','"',mac,'"',' [label="',label,'"',' color="',color,'"',' fontsize=7','];\n']
	return graph

def encryptionColor(enc): #OLDNAME Return_Enc_type
	"""
        Take in the encryption used by the AP and return the proper color scheme based on that value.
        Returns a list containing the AP fill color and AP font color
        """
	fontColor = "black" #Default Font Color to be used

	if enc == "OPN":
		color = "firebrick2"
	elif enc == "WEP":
		color = "gold2"
	elif enc in ["WPA","WPA2WPA","WPA2","WPAOPN"]:
		color = "green3"
	else: #No AP should ever get to this point as they will either be encrypted or open
		color = "black"
		fontColor = "white"

	APcolorList = (color,fontColor) #OLDNAME colorLS
	return APcolorList


def graphvizLinker(objA,sep,objB): #OLDNAME graphviz_link
	"""
        Return a graph object that links 2 objects together. Both objects are passed in with a separator
        """
	graph =['\t','"',objA,'"',sep,'"',objB,'"',';\n']
	return graph

def dotClose(input,footer): #OLDNAME dot_close
	"""
        Close the graphiz config file
        Return final output to be written
        """
	input.extend(footer)
	input.append("}")
	output = ''.join(input)
	return output

def dotWrite(data): #OLDNAME dot_write
	"""
        Write all the information obtained to a configuration file
        """
	try:
		subprocess.Popen(["rm","-rf","airGconfig.dot"]) #Delete the file if it already exists
	except Exception:
		pass
	with open('airGconfig.dot','a') as fid:
		fid.writelines(data)

def subGraph(items,graphName,graphType,tracked,parse): #OLDNAME subgraph
	"""
        Create a subgraph based on the incoming values
        TODO: Figure out what this does and clean it up
        """
	subgraph = ['\tsubgraph cluster_',graphType,'{\n\tlabel="',graphName,'" ;\n']

	if parse == "y":
		for line in items:
			clientMAC = line[0]
			probe_req = ', '.join(line[6:])
			for bssid in tracked:
				if clientMAC not in tracked[bssid]:#check to make sure were not creating a node for a client that has an association already
					subgraph.extend(['\tnode [label="',clientMAC,' \\nProbe Requests: ',probe_req,'" ] "',clientMAC,'";\n'])
		subgraph.extend(['\t}\n'])
	elif parse == "n":
		subgraph.extend(items)
	subgraph.extend(['\t}\n'])
	return subgraph


###############################################
#                Filter Class                 #
###############################################
#def filter_enc(input,enc):
#	AP = info[1]
#	for key in AP:
#		bssid = AP[key]
#		if bssid[5] != enc:
#			del AP[bssid]
#	return_list = [info[0],AP]
#	return return_list




#encryption type
#number of clients
#OUI
#channel
#beacon rate?
#essid
#speed
#time
#probe requests
#whore mode... search for ANY one wanting to connect
