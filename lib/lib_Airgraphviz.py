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
try:
	import psyco
	psyco.full()
#	pass
except ImportError:
	pass

def AP_Label_Color(Label,colorLS):
	# returns the Colors for the AP, enc = Label[3], essid = Label[1], bssid = Label[0], channel = Label[2]  //position that each bit of inforamtion comes in from the caller
	color = colorLS[0]
	fontC = colorLS[1]
	essid = Label[1].rstrip('\x00') #when readidng a null essid it has binary space? so rstrip removes this
	graph = ['\t','"',Label[0],'"','[label="',Label[0],'\\nEssid: ',essid,'\\nChannel: ',Label[2],'\\nEncryption: ',Label[3],'\\nNumber of Clients: ','%s' %(Label[4]),'"',' style=filled',' fillcolor="',color,'"',' fontcolor="',fontC,'"',' fontsize=7','];\n']
	return graph

def Client_Label_Color(mac,color,label = ''):
	#creates a label for the client information passed in is our label info and the mac address of the client
	if label == '':	
		label = mac #in the future i assume ill be brining some info in that we will want to write on our client
	graph = ['\t','"',mac,'"',' [label="',label,'"',' color="',color,'"',' fontsize=7','];\n']
	return graph
	
def Return_Enc_type(enc):
	#check the type of encryption in use and returns the correct color to use based on it
	fontC = "black"
	if enc == "OPN":
		color = "firebrick2"
	elif enc == "WEP":
		color = "gold2"
	elif enc in ["WPA","WPA2WPA","WPA2","WPAOPN"]:
		color = "green3"
	else:
		color = "black"  #idealy no AP should ever get to this point as they will either be encrypted or open
		fontC = "white"
	colorLS = (color,fontC)
	return colorLS


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
        #pdb.set_trace() #debug break point 
	try:
		subprocess.Popen(["rm","-rf","airGconfig.dot"]) # insures that if the file exists that were not apending to it
	except Exception:
		pass
	file = open('airGconfig.dot','a')
	file.writelines(data)
	file.close()

def subgraph(items,name,graph_name,tracked,parse='y'):
	#pdb.set_trace()
	#items is an incomeing dictonary 
	subgraph = ['\tsubgraph cluster_',graph_name,'{\n\tlabel="',name,'" ;\n']
	if parse == "y":
		for line in items:
			#print line[0]
			clientMAC = line[0]
			probe_req = ', '.join(line[6:])
			for bssid in tracked:
				if clientMAC not in tracked[bssid]:#check to make sure were not creating a node for a client that has an association allready
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
