#!/usr/bin/python
#airodump parsing lib
#returns in an array of client and Ap information
#part of the airdrop-ng project
from sys import exit as Exit

class airDumpParse:
    def parser(self,file):
        """
        One Function to call to parse a file and return the information
        """
        self.capr       = None
        self.NAP        = None
        self.NA         = None
        self.apDict     = None
        self.clientDict = None
        fileOpenResults = self.airDumpOpen(file)
        self.airDumpParse(fileOpenResults)
        self.clientApChannelRelationship()
        return {'NA':self.NA,'capr':self.capr,'apDict':self.apDict,
            'clientDict':self.clientDict,'NAP':self.NAP}
        
    def airDumpOpen(self,file):
        """
        Takes one argument (the input file) and opens it for reading
        Returns a list full of data
        """
        try:
            openedFile = open(file, "r")
        except IOError:
            print "Error Airodump File",file,"does not exist"
            Exit(1)
        data = openedFile.xreadlines()
        cleanedData = [line.rstrip() for line in data]
        openedFile.close()
        return cleanedData
    
    def airDumpParse(self,cleanedDump):
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
            print "Invalid input file. Please make sure you are loading an airodump txt file and not a pcap"
            Exit(1)
    
        del cleanedDump[stationStart] #Remove the heading line
        clientList = cleanedDump[stationStart:] #Splits all client data into its own list
        del cleanedDump[stationStart:] #The remaining list is all of the AP information
        self.apDict = self.apTag(cleanedDump)
        self.clientDict = self.clientTag(clientList)
        return
    
    def apTag(self,devices):
        """
        Create a ap dictionary with tags of the data type on an incoming list
        """
        dict = {}
        for entry in devices:
            ap = {}
            string_list = entry.split(',')
            #sorry for the clusterfuck but I swear it all makes sense, this is building a dic from our list so we don't have to do position calls later
            len(string_list)
            if len(string_list) == 15:
                ap = {"bssid":string_list[0].replace(' ',''),
                    "fts":string_list[1],
                    "lts":string_list[2],
                    "channel":string_list[3].replace(' ',''),
                    "speed":string_list[4],
                    "privacy":string_list[5].replace(' ',''),
                    "cipher":string_list[6],
                    "auth":string_list[7],
                    "power":string_list[8],
                    "beacons":string_list[9],
                    "iv":string_list[10],
                    "ip":string_list[11],
                    "id":string_list[12],
                    "essid":string_list[13][1:],
                    "key":string_list[14]}
            elif len(string_list) == 11:
                ap = {"bssid":string_list[0].replace(' ',''),
                    "fts":string_list[1],
                    "lts":string_list[2],
                    "channel":string_list[3].replace(' ',''),
                    "speed":string_list[4],
                    "privacy":string_list[5].replace(' ',''),
                    "power":string_list[6],
                    "beacons":string_list[7],
                    "data":string_list[8],
                    "ip":string_list[9],
                    "essid":string_list[10][1:]}
            if len(ap) != 0:
                dict[string_list[0]] = ap
        return dict
    
    def clientTag(self,devices):
        """
        Create a client dictionary with tags of the data type on an incoming list
        """
        dict = {}
        for entry in devices:
            client = {}
            string_list = entry.split(',')
            if len(string_list) >= 7:
                client = {"station":string_list[0].replace(' ',''),
                    "fts":string_list[1],
                    "lts":string_list[2],
                    "power":string_list[3],
                    "packets":string_list[4],
                    "bssid":string_list[5].replace(' ',''),
                    "probe":string_list[6:][0:]}
            if len(client) != 0:
                dict[string_list[0]] = client
        return dict
    
    def clientApChannelRelationship(self):
        """
        parse the dic for the relationships of client to ap
        in the process also populate list of     
        """
        clients = self.clientDict
        AP = self.apDict
        NA = [] #create a var to keep the not associated clients mac's
        NAP = [] #create a var to keep track of associated clients mac's to AP's we can't see
        apCount = {} #count number of Aps dict is faster the list stored as BSSID:number of essids
        apClient = {} #dict that stores bssid and clients as a nested list
        for key in (clients):
            mac = clients[key] #mac is the MAC address of the client
            if mac["bssid"] != ' (notassociated) ': #one line of our dictionary of clients
                if AP.has_key(mac["bssid"]): # if it is check to see it's an AP we can see and have info on
                    if apClient.has_key(mac["bssid"]): 
                        apClient[mac["bssid"]].extend([key]) #if key exists append new client
                    else: 
                        apClient[mac["bssid"]] = [key] #create new key and append the client
                else: NAP.append(key) # stores the clients that are talking to an access point we can't see
            else: NA.append(key) #stores the lines of the not associated AP's in a list
        self.NAP = NAP
        self.NA  = NA
        self.capr = apClient
        return 
