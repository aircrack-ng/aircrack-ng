#!/usr/bin/python
#Welcome to airgraph written by TheX1le
#Special Thanks to Rel1k and Zero_Chaos two people whom with out i would not be who I am!
#I would also like to thank muts and Remote Exploit Community for all their help and support!

########################################
#
# Airgraph-ng.py --- Generate Graphs from airodump CSV Files
#
# Copyright (C) 2008 Ben Smith <thex1le@gmail.com>
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
# Import Psyco if available to speed up execution
# When debugging airgraph-ng comment out the two lines after try and uncomment pass or pdb will not function
try:
	import psyco
	psyco.full()
#	pass
except ImportError:
	print "Psyco optimizer not installed, You may want to download and install it!"


import getopt, subprocess, sys, pdb, optparse
try:
	sys.path.append("./lib/")
	import lib_Airgraphviz   #note this should be further down
	dot_libs = lib_Airgraphviz #i dont think i need this but ill look at it later
except ImportError:
	print "Support libary import error does lib_Airgraphviz exist?"
	sys.exit(1)

#pdb.set_trace() #debug point
####################################
#      Global Vars                 # 
####################################
PROG = "airgraph-ng"
block = '\n####################################\n'

####################################
#          Maltego Support         #
####################################
def airgraph_maltegoRTN(in_file,graph_type="CAPR"):
	        returned_var = airDumpOpen(in_file)
		#pdb.set_trace() #debug point
		returned_var = airDumpParse(returned_var) #returns the info dictionary list with the client and ap dictionarys
		info_lst = returned_var
		returned_var = dot_create(returned_var,graph_type,"true")

		maltegoRTN = [info_lst,returned_var[2],returned_var[3],returned_var[4]]
		return maltegoRTN
		#info_list comes in a list Clients Dictionary at postion 0 and AP Dictionary at postion 1 the key for the Clients dict is the mac addy of the client. this will return all the info about the client. the Key for AP dict is the bssid of the Ap returning all the info about the AP.
		#return_var[3]  create a var to keep the not associdated clients
		#return_var[2] create a var to keep track of associated clients to AP's we cant see
		#return_var[4] a dictionary file in the format of BSSID:[Clients] where clients is a nested list of all attachd clients.

####################################
# Module to open aircrack dump     #
####################################

def airDumpOpen(file):
	try:
		raw_macs = open(file, "r")
	except Exception:
		print "Error Opening file ",file,". Please check and try again"
		sys.exit(1)
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
	try: #some very basic error handeling to make sure they are loading up the correct file
		del ardump[0] #remove the first line of text with the headings
		stationStart = ardump.index('Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs') 
	except Exception:
		print "You Seem to have provided an improper input file please make sure you are loading an airodump csv file and not a pcap"
		sys.exit(1)
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
	print "Usage",PROG,"-i [airodumpfile.csv] -o [outputfile.png] -g [CAPR OR CPG]\n\t-i\tInput File\n\t-o\tOutput File\n\t-g\tChoose the Graph Type Current types are [CAPR (Client to AP Relationship) & CPG (Common probe graph)]\n\t-a\tPrint the about\n\t-h\tPrint this help"

###################################
#          Graphviz work          #
###################################

def dot_create(info,graph_type,maltego="false"):
	#please dont try to use this feature yet its not finish and will error	
	def ZKS_main(info): # Zero_Chaos Kitchen Sink Mode..... Every Thing but the Kitchen Sink!
		#info comes in as list Clients Dictionary at postion 0 and AP Dictionary at postion1
		print "Feature is not ready yet"
		sys.exit(1)
		#pdb.set_trace() #debug point
		return_var = CAPR_main(info)
		#dot_file = return_var[0]
		APNC = return_var[2]
		CNAP = return_var[3]
		CAPR = return_var[0]
		del CAPR[:1] #remove the graphviz heading...
		dot_file = ['digraph G {\n\tsize ="96,96";\n\toverlap=scale;\n'] #start the graphviz config file
		dot_file.extend(dot_libs.subgraph(CAPR,'Clients to AP Relationships','CAPR',return_var[4],'n'))

		if len(APNC) != 0: # there should be a better way to check for null lists
			dot_file.extend(dot_libs.subgraph(APNC,'Acess Points with no Clients','AP',return_var[4]))
		if len(CNAP) != 0:
			dot_file.extend(dot_libs.subgraph(CNAP,'Clients that are Not Assoicated','Clients',return_var[4]))
		footer = ['test','test']
		return_lst = [dot_file,footer]
		return return_lst


	def CPG_main(info): #CPG stands for Common Probe Graph
		#info comes in a list Clients Dictionary at postion 0 and AP Dictionary at postion 1
		Clients = info[0]
		AP = info[1]
		probe_count = 0 #keep track of our probes
		Probe_list = [] #keep track of requested probes
		dot_file = ['digraph G {\n\tsize ="144,144";\n\toverlap=false;\n'] #start the graphviz config file
		client_probe = {}

		for key in (Clients):
			mac = Clients[key]
			for probe in mac[6:]:
				if probe != '':
					if client_probe.has_key(mac[0]):
						client_probe[mac[0]].extend([probe])
					else:
						client_probe[mac[0]] = [probe]

		for Client in (client_probe):
			#pdb.set_trace()
			for probe in client_probe[Client]:				
				Lprobe_count = len(client_probe[Client]) #local probe count
				probe_count += Lprobe_count
				client_label = [Client,"\\nRequesting ","%s" %(Lprobe_count)," Probes"]
				dot_file.extend(dot_libs.Client_Label_Color(probe,"blue"))
				dot_file.extend(dot_libs.Client_Label_Color(Client,"black",''.join(client_label)))
				dot_file.extend(dot_libs.graphviz_link(Client,'->',probe))

		
		
		footer = ['label="Generated by Airgraph-ng','\\n%s'%(len(client_probe)),' Probes and','\\n%s'%(probe_count),' Clients are shown";\n']
		return_list = [dot_file,footer]
		return return_list 

	def CAPR_main(info): #The Main Module for Client AP Relationship Grpah
		#info comes in a list Clients Dictionary at postion 0 and AP Dictionary at postion 1
		Clients = info[0]
		AP = info[1]
		dot_file = ['digraph G {\n\tsize ="144,144";\n\toverlap=false;\n'] #start the graphviz config file
		NA = [] #create a var to keep the not associdated clients
		NAP = [] #create a var to keep track of associated clients to AP's we cant see
		AP_count = {} # count number of Aps dict is faster the list stored as BSSID:number of essids
		Client_count = 0
		AP_client = {} #dict that stores bssid and clients as a nested list 
		#more parsing 
		for key in (Clients):
			mac = Clients[key] #mac denotes the mac addy of the client
			if mac[5] != '(notassociated)': #one line of of our dictionary of clients
				if AP.has_key(mac[5]): # if it is check to see its an AP we can see and have info on
					if AP_client.has_key(mac[5]): #if key exists append new client
						AP_client[mac[5]].extend([key])
					else: #create new key and append the client
						AP_client[mac[5]] = [key]
				else:	
					NAP.append(key) # stores the clients that are talking to an access point we cant see

			else:
				NA.append(key) #stores the lines of the not assocated AP's in a list
		#labeling starts
		#pdb.set_trace()
		for bssid in (AP_client):
			client_list = AP_client[bssid]
			for client in (client_list):
				dot_file.extend(dot_libs.graphviz_link(bssid,'->',client)) #create a basic link between the two devices
				dot_file.extend(dot_libs.Client_Label_Color(client,"black")) #label the client with a name and a color
			AP_count[bssid] = len(client_list) #count the number of APs
			Client_count += len(client_list) #count the number of Clients

			bssidI = AP[bssid] #get the BSSID info from the AP dict
			color = dot_libs.Return_Enc_type(bssidI[5]) # Deterimine what color the graph should be
			if bssidI[5] == '': #if there is no encryption detected we set it to unknown
				bssidI[5] = "Unknown"
			AP_label = [bssid,bssidI[13],bssidI[3],bssidI[5],len(client_list)]# Create a list with all our info to label the clients with
			dot_file.extend(dot_libs.AP_Label_Color(AP_label,color)) #label the access point and add it to the dotfile

			
		
		#pdb.set_trace()
		footer = ['label="Generated by Airgraph-ng','\\n%s'%(len(AP_count)),' Access Points and','\\n%s'%(Client_count),' Clients are shown";\n']
		return_list = [dot_file,footer,NAP,NA,AP_client] 
		return return_list
                
	if maltego == "true":
		return_var = CAPR_main(info)
		return return_var
	if graph_type == "CAPR":
		return_var = CAPR_main(info) #return_var is a list, dotfile postion 0, Not asscioated clients in  3 and Clients talking to access points we cant see 2, the footer in 1
		return_var = dot_libs.dot_close(return_var[0],return_var[1])
	elif graph_type == "CPG":
		return_var = CPG_main(info) #return_var is a list, dotfile postion 0, the footer in 1
		return_var = dot_libs.dot_close(return_var[0],return_var[1])
	elif graph_type == "ZKS":
		return_var = ZKS_main(info)
		return_var = dot_libs.dot_close(return_var[0],return_var[1])		
	
	return return_var	


def grpahviz_Call(output):
	print "Warning Images can be large!"
	print "Creating your Graph, Depending on your system this can take a bit. Please standby.............."
	try:
		subprocess.Popen(["fdp","-Tpng","airGconfig.dot","-o",output,"-Gcharset=latin1"]).wait()
	except Exception:
		subprocess.Popen(["rm","-rf","airGconfig.dot"])
		print "You seem to be missing the Graphviz tool set did you check out the deps in the README?"
		sys.exit(1)
	subprocess.Popen(["rm","-rf","airGconfig.dot"])  # commenting out this line will leave the dot config file for debuging
	print "Graph Creation Complete!"
###################################
#              MAIN               #
###################################

if __name__ == "__main__":
	#graph_type = ''  #creats the graph type var so its declared
	if len(sys.argv) <= 1:
        	about()  #may not be needed
        	showBanner()
        	sys.exit(0)

        parser = optparse.OptionParser("usage: %prog [options] -i input -o output -g graph type .....")  #read up more on this
	parser.add_option("-o", "--output",  dest="output",nargs=1, help="Our Output Image ie... Image.png")
	parser.add_option("-i", "--dump", dest="input", nargs=1 ,help="Airodump csv file in CSV format NOT the pcap")
	parser.add_option("-g", "--graph", dest="graph_type", nargs=1 ,help="Choose the Graph Type Current types are [CAPR (Client to AP Relationship) & CPG (Common probe graph)]")
	(options, args) = parser.parse_args()
	filename = options.output
	graph_type = options.graph_type
	in_file = options.input
	if filename == None:	
		print "You must choose an output file name"
		sys.exit(1)
	if graph_type not in ['CAPR','CPG','ZKS']:
		print "Error Invalid Graph Type\nVaild types are CAPR or CPG"
		sys.exit(1)
	if graph_type == '':
		print "Error No Graph Type Defined"
		sys.exit(1)
	#pdb.set_trace() #debug point
	returned_var = airDumpOpen(in_file)
	#pdb.set_trace() #debug point
	returned_var = airDumpParse(returned_var)
	#pdb.set_trace() #debut point	
	returned_var = dot_create(returned_var,graph_type)
	#pdb.set_trace() #debug point 
	dot_libs.dot_write(returned_var)
	grpahviz_Call(filename)
	
		

################################################################################
#                                     EOF                                      #
################################################################################
#notes windows port
#subprocess.Popen(["del","airGconfig.dot"])  # commenting out this line will leave the dot config file for debuging
#subprocess.Popen(["c:\\Program Files\\Graphviz2.21\\bin\\fdp.exe","-Tpng","airGconfig.dot","-o",output,"-Kfdp"]).wait()
