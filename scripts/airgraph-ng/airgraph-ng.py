#!/usr/bin/python
__author__ = 'Ben "TheX1le" Smith'
__email__ = 'thex1le@gmail.com'
__website__= 'http://trac.aircrack-ng.org/browser/trunk/scripts/airgraph-ng/'
__date__ = '03/02/09'
__version__ = ''
__file__ = 'airgraph-ng'
__data__ = 'This is the main airgraph-ng file'

"""
Welcome to airgraph written by TheX1le
Special Thanks to Rel1k and Zero_Chaos two people whom with out i would not be who I am!
More Thanks to Brandon x0ne Dixon who really cleaned up the code forced it into pydoc format and cleaned up the logic a bit Thanks Man!
I would also like to thank muts and Remote Exploit Community for all their help and support!

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
"""

""" Airgraph-ng """

import getopt, subprocess, sys, pdb, optparse
def importPsyco():
	try: # Import Psyco if available to speed up execution
		import psyco 
		psyco.full()
	except ImportError:
		print "Psyco optimizer not installed, You may want to download and install it!"

try:
	sys.path.append("./lib/")
	# The previous line works fine and find the lib if psyco isn't installed
	# When psyco is installed, it does not work anymore and a full path has to be used
	sys.path.append("/usr/local/bin/lib/")
	import lib_Airgraphviz
	dot_libs = lib_Airgraphviz #i dont think i need this but ill look at it later
except ImportError:
	print "Support libary import error. Does lib_Airgraphviz exist?"
	sys.exit(1)

def airgraphMaltego(inFile,graphType="CAPR"):
	"""
        Enables airgraph-ng to have support with Maltego
        TODO: Comment out code and show what is going on
        """
	returned_var = airDumpOpen(inFile)
	returned_var = airDumpParse(returned_var) #returns the info dictionary list with the client and ap dictionarys
	info_lst = returned_var
	returned_var = dotCreate(returned_var,graphType,"true")

	maltegoRTN = [info_lst,returned_var[2],returned_var[3],returned_var[4]]
	return maltegoRTN

def airDumpOpen(file):
	"""
        Takes one argument (the input file) and opens it for reading
        Returns a list full of data
        """
	openedFile = open(file, "r")
	data = openedFile.readlines()
	cleanedData = []
	for line in data:
		cleanedData.append(line.rstrip())
	openedFile.close()
	return cleanedData

def airDumpParse(cleanedDump):
	"""
        Function takes parsed dump file list and does some more cleaning.
        Returns a list of 2 dictionaries (Clients and APs)
        """
	try: #some very basic error handeling to make sure they are loading up the correct file
		try:
			apStart = cleanedDump.index('BSSID, First time seen, Last time seen, Channel, Speed, Privacy, Power, # beacons, # data, LAN IP, ESSID')
		except Exception:
			apStart = cleanedDump.index('BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key')
		del cleanedDump[apStart] #remove the first line of text with the headings
		try:
			stationStart = cleanedDump.index('Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs')
		except Exception:
			stationStart = cleanedDump.index('Station MAC, First time seen, Last time seen, Power, # packets, BSSID, ESSID')
	except Exception:
		print "You Seem to have provided an improper input file please make sure you are loading an airodump txt file and not a pcap"
		sys.exit(1)

	#pdb.set_trace()
	del cleanedDump[stationStart] #Remove the heading line
	clientList = cleanedDump[stationStart:] #Splits all client data into its own list
	del cleanedDump[stationStart:] #The remaining list is all of the AP information
	#apDict = dictCreate(cleanedDump) #Create a dictionary from the list
	#clientDict = dictCreate(clientList) #Create a dictionary from the list
	apDict = apTag(cleanedDump)
	clientDict = clientTag(clientList)
	resultDicts = [clientDict,apDict] #Put both dictionaries into a list
	return resultDicts

def apTag(devices):
	"""
	Create a ap dictionary with tags of the data type on an incoming list
	"""
	dict = {}
	for entry in devices:
		ap = {}
		string_list = entry.split(',')
		#entry = entry.replace(' ','')
		#sorry for the clusterfuck but i swear it all makse sense
		len(string_list)
		if len(string_list) == 15:
			ap = {"bssid":string_list[0].replace(' ',''),"fts":string_list[1],"lts":string_list[2],"channel":string_list[3].replace(' ',''),"speed":string_list[4],"privacy":string_list[5].replace(' ',''),"cipher":string_list[6],"auth":string_list[7],"power":string_list[8],"beacons":string_list[9],"iv":string_list[10],"ip":string_list[11],"id":string_list[12],"essid":string_list[13][1:],"key":string_list[14]}
		elif len(string_list) == 11:
			ap = {"bssid":string_list[0].replace(' ',''),"fts":string_list[1],"lts":string_list[2],"channel":string_list[3].replace(' ',''),"speed":string_list[4],"privacy":string_list[5].replace(' ',''),"power":string_list[6],"beacons":string_list[7],"data":string_list[8],"ip":string_list[9],"essid":string_list[10][1:]}
		if len(ap) != 0:
			dict[string_list[0]] = ap
	return dict

def clientTag(devices):
	"""
	Create a client dictionary with tags of the data type on an incoming list
	"""
	dict = {}
	for entry in devices:
		client = {}
		string_list = entry.split(',')
		if len(string_list) >= 7:
			client = {"station":string_list[0].replace(' ',''),"fts":string_list[1],"lts":string_list[2],"power":string_list[3],"packets":string_list[4],"bssid":string_list[5].replace(' ',''),"probe":string_list[6:][1:]}
		if len(client) != 0:
			dict[string_list[0]] = client
	return dict

def dictCreate(device):
	#deprecated
	"""
        Create a dictionary using an incoming list
        """
	dict = {}
	for entry in device: #the following loop through the Clients List creates a nested list of each client in its own list grouped by a parent list of client info
		entry = entry.replace(' ','')
		string_list = entry.split(',')
		if string_list[0] != '':
			dict[string_list[0]] = string_list[:] #if the line isnt a blank line then it is stored in dictionlary with the MAC/BSSID as the key
	return dict

def usage():
	"""
        Prints the usage to use airgraph-ng
        """
	print "############################################","\n#         Welcome to Airgraph-ng           #","\n############################################\n"
	print "Usage: python airgraph-ng -i [airodumpfile.txt] -o [outputfile.png] -g [CAPR OR CPG]"
	print "\n-i\tInput File\n-o\tOutput File\n-g\tGraph Type [CAPR (Client to AP Relationship) OR CPG (Common probe graph)]\n-p\tDisable Psyco JIT compiler\n-h\tPrint this help"

def dotCreate(info,graphType,maltego="false"):
	"""
        Graphviz function to support the graph types
        TODO: Possibly move this to the library?
        """


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
		dot_file.extend(dot_libs.subGraph(CAPR,'Clients to AP Relationships','CAPR',return_var[4],'n'))

		if len(APNC) != 0: # there should be a better way to check for null lists
			dot_file.extend(dot_libs.subGraph(APNC,'Acess Points with no Clients','AP',return_var[4]))
		if len(CNAP) != 0:
			dot_file.extend(dot_libs.subGraph(CNAP,'Clients that are Not Assoicated','Clients',return_var[4]))
		footer = ['test','test']
		return_lst = [dot_file,footer]
		return return_lst


	def CPG_main(info):
		"""
                CPG stands for Common Probe Graph
		Information comes in a list - Clients Dictionary at postion 0 and AP Dictionary at postion 1
		Returns a single list containing a list for the dotFile and the footer
		"""
		clients = info[0]
		AP = info[1]
		probeCount = 0 #keep track of our probes
		probeList = [] #keep track of requested probes
		dotFile = ['digraph G {\n\tsize ="144,144";\n\toverlap=false;\n'] #start the graphviz config file
		clientProbe = {}

		#pdb.set_trace()
		for key in (clients):
			mac = clients[key]
			if len(mac["probe"]) > 1 or mac["probe"] != ['']:
				for probe in mac["probe"]:
					if probe != '':
						if clientProbe.has_key(mac["station"]):
							clientProbe[mac["station"]].extend([probe])
						else:
							clientProbe[mac["station"]] = [probe]

		for Client in (clientProbe):
			for probe in clientProbe[Client]:				
				localProbeCount = len(clientProbe[Client])
				probeCount += localProbeCount
				client_label = [Client,"\\nRequesting ","%s" %(localProbeCount)," Probes"]
				dotFile.extend(dot_libs.clientColor(probe,"blue"))
				dotFile.extend(dot_libs.clientColor(Client,"black",''.join(client_label)))
				dotFile.extend(dot_libs.graphvizLinker(Client,'->',probe))

		footer = ['label="Generated by Airgraph-ng','\\n%s'%(len(clientProbe)),' Probes and','\\n%s'%(probeCount),' Clients are shown";\n']
		CPGresults = [dotFile,footer]
		return CPGresults 

	def CAPR_main(info):
		"""
                The Main Module for Client AP Relationship Grpah
		Information comes in a list - Clients Dictionary at postion 0 and AP Dictionary at postion 1
		"""
		clients = info[0]
		AP = info[1]
		dotFile = ['digraph G {\n\tsize ="144,144";\n\toverlap=false;\n'] #start the graphviz config file
		NA = [] #create a var to keep the not associdated clients
		NAP = [] #create a var to keep track of associated clients to AP's we cant see
		apCount = {} #count number of Aps dict is faster the list stored as BSSID:number of essids
		clientCount = 0
		apClient = {} #dict that stores bssid and clients as a nested list 

		for key in (clients):
			mac = clients[key] #mac is the MAC address of the client
			if mac["bssid"] != ' (notassociated) ': #one line of of our dictionary of clients
				if AP.has_key(mac["bssid"]): # if it is check to see its an AP we can see and have info on
					if apClient.has_key(mac["bssid"]): #if key exists append new client
						apClient[mac["bssid"]].extend([key])
					else: #create new key and append the client
						apClient[mac["bssid"]] = [key]
				else:	
					NAP.append(key) # stores the clients that are talking to an access point we cant see

			else:
				NA.append(key) #stores the lines of the not assocated AP's in a list

		for bssid in (apClient):
			clientList = apClient[bssid]
			for client in (clientList):
				dotFile.extend(dot_libs.graphvizLinker(bssid,'->',client)) #create a basic link between the two devices
				dotFile.extend(dot_libs.clientColor(client,"black")) #label the client with a name and a color
			apCount[bssid] = len(clientList) #count the number of APs
			clientCount += len(clientList) #count the number of clients

			#pdb.set_trace()
			#note the following code is an ulgy hack and will need to be cleaned up for direct tag calling
			bssidI = AP[bssid]["bssid"] #get the BSSID info from the AP dict
			color = dot_libs.encryptionColor(AP[bssid]["privacy"]) # Deterimine what color the graph should be
			if AP[bssid]["privacy"] == '': #if there is no encryption detected we set it to unknown
				AP[bssid]["privacy"] = "Unknown"
			AP_label = [bssid,AP[bssid]["essid"],AP[bssid]["channel"],AP[bssid]["privacy"],len(clientList)]# Create a list with all our info to label the clients with
			dotFile.extend(dot_libs.apColor(AP_label,color)) #label the access point and add it to the dotfile

		footer = ['label="Generated by Airgraph-ng','\\n%s'%(len(apCount)),' Access Points and','\\n%s'%(clientCount),' Clients are shown";\n']
		CAPRresults = [dotFile,footer,NAP,NA,apClient] 
		return CAPRresults
		
	if maltego == "true":
		return_var = CAPR_main(info)
		return return_var
	if graphType == "CAPR":
		return_var = CAPR_main(info) #return_var is a list, dotfile postion 0, Not asscioated clients in  3 and clients talking to access points we cant see 2, the footer in 1
		return_var = dot_libs.dotClose(return_var[0],return_var[1])
	elif graphType == "CPG":
		return_var = CPG_main(info) #return_var is a list, dotfile postion 0, the footer in 1
		return_var = dot_libs.dotClose(return_var[0],return_var[1])
	elif graphType == "ZKS":
		return_var = ZKS_main(info)
		return_var = dot_libs.dotClose(return_var[0],return_var[1])		

	return return_var	


def graphvizCreation(output):
	"""
        Create the graph image using our data
        """
	try:
		subprocess.Popen(["fdp","-Tpng","airGconfig.dot","-o",output,"-Gcharset=latin1"]).wait()
	except Exception:
		subprocess.Popen(["rm","-rf","airGconfig.dot"])
		print "You seem to be missing the Graphviz tool set did you check out the deps in the README?"
		sys.exit(1)
	subprocess.Popen(["rm","-rf","airGconfig.dot"])  #Commenting out this line will leave the dot config file for debuging

def graphvizProgress():
	print "\n**** WARNING Images can be large! ****\n"
	print "Creating your Graph using", inFile, "and outputting to", outFile
	print "Depending on your system this can take a bit. Please standby......."

def graphvizComplete():
	print "Graph Creation Complete!"

if __name__ == "__main__":
	"""
        Main function.
        Parses command line input for proper switches and arguments. Error checking is done in here.
        Variables are defined and all calls are made from MAIN.
        """
	if len(sys.argv) <= 1:
		usage()
		sys.exit(0)

	parser = optparse.OptionParser("usage: %prog [options] -i input -o output -g graph type .....")  #read up more on this
	parser.add_option("-o", "--output",  dest="output",nargs=1, help="Our Output Image ie... Image.png")
	parser.add_option("-i", "--dump", dest="input", nargs=1 ,help="Airodump txt file in CSV format NOT the pcap")
	parser.add_option("-g", "--graph", dest="graph_type", nargs=1 ,help="Graph Type Current [CAPR (Client to AP Relationship) OR CPG (Common probe graph)]")
	parser.add_option("-p", "--nopsyco",dest="pysco",action="store_false",default=True,help="Disable the use of Psyco JIT")
	(options, args) = parser.parse_args()

	outFile = options.output
	graphType = options.graph_type
	inFile = options.input
	if options.pysco == True:
		importPsyco()

	if inFile == None:
		print "Error No Input File Specified"
		sys.exit(1)
	if outFile == None:	
		outFile = options.input.replace('.txt', '.png')
	if graphType not in ['CAPR','CPG','ZKS']:
		print "Error Invalid Graph Type\nVaild types are CAPR or CPG"
		sys.exit(1)
	if graphType == None:
		print "Error No Graph Type Defined"
		sys.exit(1)

	fileOpenResults = airDumpOpen(inFile)
	parsedResults = airDumpParse(fileOpenResults)	
	returned_var = dotCreate(parsedResults,graphType)
	dot_libs.dotWrite(returned_var)
	graphvizProgress()
	graphvizCreation(outFile)
	graphvizComplete()

################################################################################
#                                     EOF                                      #
################################################################################
#notes windows port
#subprocess.Popen(["del","airGconfig.dot"])  # commenting out this line will leave the dot config file for debuging
#subprocess.Popen(["c:\\Program Files\\Graphviz2.21\\bin\\fdp.exe","-Tpng","airGconfig.dot","-o",output,"-Kfdp"]).wait()
