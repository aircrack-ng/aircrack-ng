
#!/usr/bin/python
# this script is a total hack it works and ill clean it up later
import sys,getopt, optparse, pdb, re
def raw_lines(file):
        try:
		raw_lines = open(file, "r")
	except Exception:
		print "Failed to open ",file,". Do you have the file name correct?"
		sys.exit(1)
        Rlines = raw_lines.readlines() 
       	return Rlines

def parse_file(file,file_name):
	cleanup = []
	for line in file:
               # match=re.search("\n", line) # the next few lines are notes and can be ignored
               # if match:
               #   line=line.replace("\n","")
		#for x in line:
		#	clean = filter(lambda y: y != '\n', x)
		clean = line.rstrip()
		cleanup.append(clean)
	try:
		header = cleanup.index('BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key')
		stationStart = cleanup.index('Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs')
        	del cleanup[header]
	except Exception:
		print "You seem to have provided an improper input file"" '",file_name,"' ""Please make sure you are loading an airodump csv file and not a Pcap"
        	sys.exit(1)
	Clients = cleanup[stationStart:] #splits off the clients into their own list
	stationStart = stationStart - 1 #ulgy hack to make sure the heading gets deleted from end of the APs List
	del cleanup[stationStart:]#removed all of the client info leaving only the info on available target AP's in ardump maby i should create a new list for APs?
	lines = [cleanup,Clients]
	return lines
def join_write(data,name):
 	file = open(name,'a')
	for line in data[0]:
                line=line.rstrip()
                if len(line)>1:
           		file.write(line+'\n')
	for line in data [1]:
                if len(line)>1:
         		file.write(line+'\n')
	file.close()
def showBanner():
	print "Airodump Joiner\nJoin Two Airodump CSV Files\n\n\t-i\tInput Files [ foo_name_1 foo_name_2 foo_name_3 .....] \n\t-o\tOutput File\n"

def file_pool(files):
	AP = []
	Clients = []
	for file in files:
		ret = raw_lines(file)
		ret = parse_file(ret,file)
		AP.extend(ret[1])
		Clients.extend(ret[0])
	lines = [AP,Clients]
	output = sort_file(lines)
	return output

def sort_file(input):
	AP = ['BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key']
	Clients = ['\nStation MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs']
	Clients.extend(input[0])
	AP.extend(input[1])
	output = [AP,Clients]
	return output

	

if  __name__ == "__main__":
        if len(sys.argv) <= 1:
                showBanner()
                sys.exit(1)

	parser = optparse.OptionParser("usage: %prog [options] arg1 arg2 arg3 .....")
	parser.add_option("-o", "--output",  dest="output",nargs=1, help="output file to write to")
	parser.add_option("-i", "--file", dest="filename", nargs=2 ,help="Input files to read data from requires at least two arguments")
	
	(options, args) = parser.parse_args()
	filenames = options.filename
	outfile = options.output
	if outfile == None:
		print "You must provide a file name to write out to. IE... -o foo.csv\n"
		showBanner()
		sys.exit(1)
	elif filenames == None:
		print "You must provide at least two file names to join. IE... -i foo1.csv foo2.csv\n"
		showBanner()
		sys.exit(1)
	for file_name in args:
		filenames += (file_name,)	
	return_var = file_pool(filenames)
	return_var = join_write(return_var,outfile)

	
