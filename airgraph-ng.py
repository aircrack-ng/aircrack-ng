#!/usr/bin/env python
#Welcome to airgraph written by TheX1le
#Special Thanks to Rel1k and Zero_Chaos two people whom with out i would not be who I am!
#I would also like to thank muts and Remote Exploit Community for all their help and support!
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
	graph = ['digraph G {\n\tsize ="48,48";\n\toverlap=scale;\n'] #start the graphviz config file
	NA = [] #create a var to keep the not associdated clients
	NAP = [] #create a var to keep track of associated clients to AP's we cant see
	AP_Count = {} # track the number of access points with clients connected and keep track of dumplicate lables
	Client_count = {} # count the number of clients dict is faster the list
	#CAPR stands for Client AP Relationship
	
	def CAPR_Colorize_AP(Label,color):
		enc = Label[3]
		essid = Label[1] # these var renaming lines could be called directly in the line to cut code but it much easier to see it layed out this way
		bssid = Label[0]
		channel = Label[2]
		graph.extend(['\t','"',bssid,'"','[label="',bssid,'\\nEssid:',essid,'\\nChannel:',channel,'\\nEncryption:',enc,'"','color="',color,'"',' fontcolor="',color,'"','];\n'])

	def CPG_main(info): #CPG stands for Common Probe Graph
		Clients = info[0]
		AP = info[1]
		def CPG_graphviz_format(objA,sep,objB):
			graph.extend(['\t','"',objA,'"',sep,'"',objB,'"',';\n'])
		
		for mac in (Clients):
			key = Clients[mac]
			for probe in key[6:]:
				if probe == '':
					pass
				else:
					CPG_graphviz_format(key[0],'->',probe)
		graph.append("}")
		return graph		

	
	def CAPR_graphviz_link(objA,sep,objB):
		graph.extend(['\t','"',objA,'"',sep,'"',objB,'"',';\n'])

	def CAPR_graphviz_label_client(client,label):
		if Client_count.has_key(client):
			pass

		else:
			graph.extend(['\t','"',client,'"','[label="',label,'"];\n'])
			Client_count[client] = client

	def CAPR_graphviz_label_AP(Label):
		enc = Label[3]
		essid = Label[1]
		bssid = Label[0]
		if AP_Count.has_key(bssid):
			pass
		else:
			if enc == "OPN":
				CAPR_Colorize_AP(Label,"crimson")
			
			elif enc == "WEP" or enc == "WEP40WEP":
				CAPR_Colorize_AP(Label,"darkgoldenrod2")

			elif enc == "WPA" or enc == "TKIP" or enc == "CCMP" or enc == "CCMPTKIP":
				CAPR_Colorize_AP(Label,"darkgreen")
			else:
				CAPR_Colorize_AP(Label,"black")
			AP_Count[bssid] = essid

	def CARP_main(info):
		Clients = info[0]
		AP = info[1]
		for mac in (Clients):
			key = Clients[mac]
			if key[5] != "(notassociated)":
				if AP.has_key(key[5]): # does key look up in the Access point dictionary
					bssidI = AP[key[5]] # stores teh correct acess point in the var
					essid = bssidI[13].rstrip('\x00') #when readidng a null essid it has binary space? so rstrip removes this 
					CAPR_graphviz_link(key[5],'->',mac)
					CAPR_graphviz_label_client(mac,mac)
					AP_label = [key[5],essid,bssidI[3],bssidI[5]]
					CAPR_graphviz_label_AP(AP_label)
				
				else:
					NAP.append(key)
			else: 
				NA.append(key) #stores the lines of the none assocated AP's in a list
	
		graph.extend(['label="Generated by Airgraph-ng','\\n%s'%(len(AP_Count)),' Access Points and','\\n%s'%(len(Client_count)),' Clients are shown";\n']) #adding 1 to each as it counts from 0
		graph.append("}")
		output = ''.join(graph)
		return output
	

	if graph_type == "CAPR":
		return_var = CARP_main(info)
	elif graph_type == "CPG":
		return_var = CPG_main(info)
	
	return return_var	

def grpahviz_Call(output):
	subprocess.Popen(["neato","-Tpng","airGconfig.dot","-o",output])
	subprocess.Popen(["rm","-rf","airGconfig.dot"])  # commenting out this line will leave the dot config file for debuging
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
	if graph_type not in ['CAPR','CPG']:
		print "Error Invalid Graph Type\nVaild types are CAPR or CPG"
		sys.exit(1)
	if graph_type == '':
		print "Error No Graph Type Defined"
		sys.exit(1)
	returned_var = airDumpOpen(in_file)
	returned_var = airDumpParse(returned_var)
	#print returned_var   # debug point
	returned_var = dot_create(returned_var,graph_type)
	#print returned_var   # debug point
	dot_write(returned_var)
	grpahviz_Call(filename)
	
		

################################################################################
#                                     EOF                                      #
################################################################################

