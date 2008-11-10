#!/usr/bin/env python
#Welcome to airgraph written by TheX1le
#Special Thanks to Rel1k and Zero_Chaos two people whom with out i would not be who I am!
#I would also like to thank muts and Remote Exploit Community for all their help and support!

########################################
#
# Airgraph-ng.py --- Generate Graphs from airodump CSV Files
#
# Copyright (C) 2005 Ben Smith <thex1le@gmail.com>
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
# Import Psyco if available to speed up execution
try:
	import psyco
	psyco.full()
except ImportError:
	print "Psyco optimizer not installed, You may want to download and install it!"


import getopt, subprocess, sys, pdb

####################################
#      Global Vars                 # 
####################################
PROG = "airgraph-ng"
block = '\n####################################\n'

####################################
# Module to open aircrack dump     #
####################################

def airDumpOpen(file):
       	raw_macs = open(file, "r")
	Rmacs = raw_macs.readlines() #reads each line one at a time and store them a list
	cleanup = []
	for line in Rmacs: #iterates through the lines and strips of the new line and line returns ie \r\n
		cleanup.append(line.rstrip())
	raw_macs.close()
	return cleanup
####################################
# Modules to Parse targets into a  #
# Logical format for keeping track #
# of targets "bssid:info"          #
####################################
def airDumpParse(ardump):
	del ardump[0] #remove the first line of text with the headings
	stationStart = ardump.index('Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs') 
	del ardump[stationStart] #this removes the client Station Mac, ect heading.....
	Clients = ardump[stationStart:] #splits off the clients into their own list
	del ardump[stationStart:]#removed all of the client info leaving only the info on available target AP's in ardump maby i should create a new list for APs?
	def dictCreate(device):
		dict = {}
		for entry in device: #the following loop through the Clients List creates a nexsted list of each client in its own list grouped by a parent list of client info
			entry = entry.replace(' ','') #remove spaces
			string_list = entry.split(',') #splits the string line and turns it into a list object
			if string_list[0] != '':
				dict[string_list[0]] = string_list[:] #if the line isnt a blank line then it is stored in dictionlary with the MAC/BSSID as the key
		return dict			
	ApDict = dictCreate(ardump)
	ClientsDict = dictCreate(Clients)
	retVar = [ClientsDict,ApDict]
	return retVar

##################################
# User land information          #
##################################

def about():
	print block , "#     Welcome to",PROG,"      #" , block
def showBanner():
	print "Usage",PROG,"-i[airodumpfile.txt] -o[outputfile.png] -t[CAPR OR CPG]\n\t-i\tInput File\n\t-o\tOutput File\n\t-t\tChoose the Graph Type Current types are [CAPR (Client to AP Relationship) & CPG (Common probe graph)]\n\t-a\tPrint the about\n\t-h\tPrint this help"

###################################
#          Graphviz work          #
###################################
def dot_write(data):
 	file = open('airGconfig.dot','a')
	file.writelines(data)
	file.close()

def dot_create(info,graph_type):
	graph = ['digraph G {\n\tsize ="96,96";\n\toverlap=scale;\n'] #start the graphviz config file
	NA = [] #create a var to keep the not associdated clients
	NAP = [] #create a var to keep track of associated clients to AP's we cant see
	AP_Count = {} # track the number of access points with clients connected and keep track of dumplicate lables
	Client_count = {} # count the number of clients dict is faster the list
		
	def ZKS_main(info): # Zero Chaos Kitchen Sink Mode..... Every Thing but the Kitchen Sink!
		return_var = CARP_main(info)
		APNC = return_var[0]
		CNAP = return_var[1]
			
		def subgraph(items,name,graph_name):
			subgraph = ['\tsubgraph cluster_',graph_name,'{\n\tlabel="',name,'" ;\n']
			for line in items:
				clientMAC = line[0]
				probe_req = ', '.join(line[6:])
				subgraph.extend(['\tnode [label="',clientMAC,' \\nProbe Requests: ',probe_req,'" ] "',clientMAC,'";\n'])
			subgraph.extend(['\t}\n'])
			return subgraph
				
		if len(APNC) != 0: # there should be a better way to check for null lists
			subAP = subgraph(APNC,'Acess Points with no Clients','AP')
			graph.extend(subAP)
		if len(CNAP) != 0:
			subClient = subgraph(CNAP,'Clients that are Not Assoicated','Clients')
			graph.extend(subClient)
		return graph


	def CPG_main(info): #CPG stands for Common Probe Graph
		Clients = info[0]
		AP = info[1]
		Clients_list = []
		Probe_list = []
		
		for mac in (Clients):
			key = Clients[mac]
			for probe in key[6:]:
				if probe == '':
					pass
				else:
					Clients_list.append(key[0])
					if probe not in Probe_list:
						Probe_list.append(probe)
					graphviz_format(key[0],'->',probe)
		
		graph.extend(['label="Generated by Airgraph-ng','\\n%s'%(len(Clients_list)),' Clients and','\\n%s'%(len(Probe_list)),' Probes are shown";\n'])
		graph.append("}")
		return graph		

	def CARP_main(info): #The Main Module for Client AP Relationship Grpah
		Clients = info[0]
		AP = info[1]

        	def CAPR_Colorize_AP(Label,color): # returns the Colors for the APs
                	enc = Label[3]
                	essid = Label[1] # these var renaming lines could be called directly in the line to cut code but it much easier to see it layed out this way
                	bssid = Label[0]
                	channel = Label[2]
                	graph.extend(['\t','"',bssid,'"','[label="',bssid,'\\nEssid:',essid,'\\nChannel:',channel,'\\nEncryption:',enc,'"','color="',color,'"',' fontcolor="',color,'"','];\n'])

		
		def CAPR_graphviz_label_client(client,label):# does the labe names for the client
                	if Client_count.has_key(client):
                        	pass

                	else:
                        	graph.extend(['\t','"',client,'"','[label="',label,'"];\n'])
                        	Client_count[client] = client

		def CAPR_graphviz_label_AP(Label): # Generates lable names and chooses the color for the AP
                	enc = Label[3]
                	essid = Label[1]
                	bssid = Label[0]
                	if AP_Count.has_key(bssid):
                        	pass
                	else:
                        	if enc == "OPN":
                                	CAPR_Colorize_AP(Label,"crimson")

                        	elif enc == "WEP":
                                	CAPR_Colorize_AP(Label,"darkgoldenrod2")

                        	elif enc in ["WPA","WPA2WPA","WPA2","WPAOPN"]:
                                	CAPR_Colorize_AP(Label,"darkgreen")
                        	else:
                                	CAPR_Colorize_AP(Label,"black")
                        	AP_Count[bssid] = essid


		for mac in (Clients):
			key = Clients[mac]
			if key[5] != "(notassociated)":
				if AP.has_key(key[5]): # does key look up in the Access point dictionary
					bssidI = AP[key[5]] # stores teh correct acess point in the var
					essid = bssidI[13].rstrip('\x00') #when readidng a null essid it has binary space? so rstrip removes this 
					graphviz_format(key[5],'->',mac)
					CAPR_graphviz_label_client(mac,mac)
					AP_label = [key[5],essid,bssidI[3],bssidI[5]]
					CAPR_graphviz_label_AP(AP_label)
				
				else:
					NAP.append(key)
			else: 
				NA.append(key) #stores the lines of the none assocated AP's in a list
		
		chaftLST = [NAP,NA] # the chaft list is where we store all the lines that eneded up on the cutting room floor
		return chaftLST 
	def graphviz_close(input):
		input.extend(['label="Generated by Airgraph-ng','\\n%s'%(len(AP_Count)),' Access Points and','\\n%s'%(len(Client_count)),' Clients are shown";\n']) #adding 1 to each as it counts from 0
		input.append("}")
		output = ''.join(graph)
		return output
                
	def graphviz_format(objA,sep,objB):
		graph.extend(['\t','"',objA,'"',sep,'"',objB,'"',';\n'])

	if graph_type == "CAPR":
		CARP_main(info)
		return_var = graphviz_close(graph)
	elif graph_type == "CPG":
		return_var = CPG_main(info)
	elif graph_type == "ZKS":
		return_var = ZKS_main(info)
		return_var = graphviz_close(return_var)		
	
	return return_var	


def grpahviz_Call(output):
	print "Creating your Graph, Depending on your system this can take a bit. Please standby.............."
	subprocess.Popen(["fdp","-Tpng","airGconfig.dot","-o",output]).wait()
	subprocess.Popen(["rm","-rf","airGconfig.dot"])  # commenting out this line will leave the dot config file for debuging
	print "Graph Creation Complete!"
###################################
#               MAIN              #
###################################

if __name__ == "__main__":
	graph_type = ''
	if len(sys.argv) <= 1:
        	about()
        	showBanner()
        	sys.exit(1)


        try:
                opts, args = getopt.getopt(sys.argv[1:],'t:i:o:,a,h')

        except getopt.GetoptError, e:
                print e

        for o, a in opts:
                if o == '-i':
             		in_file = a
	
                elif o == '-o':
                        filename = a
                        
                elif o == '-t':
			graph_type = a
			
		elif o == '-a':
                        about()
                        sys.exit(0)
                if o == '-h':
                        about()
                        showBanner()
                        sys.exit(0)
	
	#pdb.set_trace()
	if graph_type not in ['CAPR','CPG','ZKS']:
		print "Error Invalid Graph Type\nVaild types are CAPR or CPG"
		sys.exit(1)
	if graph_type == '':
		print "Error No Graph Type Defined"
		sys.exit(1)
	returned_var = airDumpOpen(in_file)
	returned_var = airDumpParse(returned_var)
	returned_var = dot_create(returned_var,graph_type)
	dot_write(returned_var)
	grpahviz_Call(filename)
	
		

################################################################################
#                                     EOF                                      #
################################################################################

