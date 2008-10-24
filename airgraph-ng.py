#!/usr/bin/env python
import getopt, subprocess, sys
####################################
#      Global Vars                 # 
####################################
PROG = "AirGraph"
block = '\n#################################\n'
####################################
# Module to open aircrack dump     #
####################################

def airDumpOpen(file):
       	#note this is all fucked up and so im coding around an issue its reading each line into a long ass string instead of a list ask rel1k
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
		for entry in device[:]: #the following loop through the Clients List creates a nexsted list of each client in its own list grouped by a parent list of client info
			string_list = entry[1:-1].split(',') #splits the string line and turns it into a list object
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
	sep = '->'
	graph = ["digraph G {\n"]
	Clients = info[0]
	AP = info[1]	
	for mac in (Clients):
		key = Clients[mac]
		graph.extend(['\t','"',key[5],'"',sep,'"',mac,'"',';\n','\t','"',mac,'"','[label="',mac,'"];\n','\t','"',key[5],'"','[label="',key[5],'"];\n']) 
		
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
	
	#if in_file != None and filename != None:
	returned_var = airDumpOpen(in_file)
	returned_var = airDumpParse(returned_var)
	returned_var = dot_create(returned_var)
	dot_write(returned_var)
	grpahviz_Call(filename)
	#else:
	#	print "You must provide an input and output file!"
	#	about()
	#	showBanner()
	#	sys.exit(1)
################################################################################
#                                     EOF                                      #
################################################################################

