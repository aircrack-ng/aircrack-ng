#!/usr/bin/env python
#Welcome to airgraph written by TheX1le
#Speical Thanks to Rel1k and Zero_Chaos two people whom with out i would not be who I am!
#I would also like to thank muts and Remote Exploit Community for all their help and support!
import getopt, subprocess, sys
####################################
#      Global Vars                 # 
####################################
PROG = "airgraph-ng"
block = '\n#################################\n'
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
	print "Usage",PROG,"-i[file]-o[file]\n\t-i\tInput File\n\t-o\tOutput File\n\t-a\tPrint the about\n\t-h\tPrint this help"

###################################
#          Graphviz work          #
###################################
def dot_write(data):
 	file = open('airGconfig.dot','a')
	file.writelines(data)
	file.close()

def dot_create(info):
	graph = ["digraph G {\n"] #start the graphviz config file
	Clients = info[0]
	AP = info[1]	
	NA = [] #create a var to keep the not associdated clients
	NAP = [] #create a var to keep track of associated clients to AP's we cant see
	def graphviz_link(objA,sep,objB):
		graph.extend(['\t','"',objA,'"',sep,'"',objB,'"',';\n'])

	def graphviz_label_client(client,label):
		graph.extend(['\t','"',client,'"','[label="',label,'"];\n',])

	def graphviz_label_AP(bssid,essidi,channel):
		graph.extend(['\t','"',bssid,'"','[label="',bssid,'\\nEssid:',essid,'\\nChannel:',channel,'"];\n'])

	for mac in (Clients):
		key = Clients[mac]
		if key[5] != "(notassociated)":
			if AP.has_key(key[5]): # does key look up in the Access point dictionary
				bssidI = AP[key[5]] # stores teh correct acess point in the var
				essid = bssidI[13].rstrip('\x00') #when readidng a null essid it has binary space? so rstrip removes this 
				graphviz_link(key[5],'->',mac)
				graphviz_label_client(mac,mac)
				graphviz_label_AP(key[5],essid,bssidI[3]) 
			else:
				NAP.append(key)
		else: 
			NA.append(key) #stores the lines of the none assocated AP's in a list
	graph.append("}")
	output = ''.join(graph)
	return output	
def grpahviz_Call(output):
	subprocess.Popen(["dot","-Tpng","airGconfig.dot","-o",output])
	##subprocess.Popen(["rm","-rf","airGconfig.dot"])
###################################
#               MAIN              #
###################################

if __name__ == "__main__":
	if len(sys.argv) <= 1:
        	about()
        	showBanner()
        	sys.exit(1)


        try:
                opts, args = getopt.getopt(sys.argv[1:],'i:o:,a,h')

        except getopt.GetoptError, e:
                print e

        for o, a in opts:
                if o == '-i':
             		in_file = a
	
                elif o == '-o':
                        filename = a
                        
                elif o == '-a':
                        about()
                        sys.exit(0)
                if o == '-h':
                        about()
                        showBanner()
                        sys.exit(0)
	
	returned_var = airDumpOpen(in_file)
	returned_var = airDumpParse(returned_var)
	returned_var = dot_create(returned_var)
	dot_write(returned_var)
	grpahviz_Call(filename)

################################################################################
#                                     EOF                                      #
################################################################################

