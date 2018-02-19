#!/usr/bin/python

import sys
import os
import subprocess
import random
import time
import sqlite3
import threading
import hashlib
import gzip
import json
import datetime
import re

if sys.version_info[0] >= 3:
	from socketserver import ThreadingTCPServer
	from urllib.request import urlopen, URLError
	from urllib.parse import urlparse, parse_qs
	from http.client import HTTPConnection
	from http.server import SimpleHTTPRequestHandler
else:
	from SocketServer import ThreadingTCPServer
	from urllib2 import urlopen, URLError
	from urlparse import urlparse, parse_qs
	from httplib import HTTPConnection
	from SimpleHTTPServer import SimpleHTTPRequestHandler

	bytes = lambda a, b : a

port = 1337
url = None
cid = None
tls = threading.local()
nets = {}
cracker = None

class ServerHandler(SimpleHTTPRequestHandler):
	def do_GET(s):
		result = s.do_req(s.path)

		if not result:
			return

		s.send_response(200)
		s.send_header("Content-type", "text/plain")
		s.end_headers()
		s.wfile.write(bytes(result, "UTF-8"))

	def do_POST(s):
		if ("dict" in s.path):
			s.do_upload_dict()

		if ("cap" in s.path):
			s.do_upload_cap()

		s.send_response(200)
		s.send_header("Content-type", "text/plain")
		s.end_headers()
		s.wfile.write(bytes("OK", "UTF-8"))

	def do_upload_dict(s):
		con = get_con()

		f = "dcrack-dict"
		c = f + ".gz"
		with open(c, "wb") as fid:
			cl = int(s.headers['Content-Length'])
			fid.write(s.rfile.read(cl))

		decompress(f)
	
		sha1 = hashlib.sha1()
		with open(f, "rb") as fid:
			sha1.update(fid.read())
		h = sha1.hexdigest()

		with open(f, "rb") as fid:
			for i, l in enumerate(fid):	pass
			i += 1

		n = "%s-%s.txt" % (f, h)
		os.rename(f, n)
		os.rename(c, "%s.gz" % n)

		c = con.cursor()
		c.execute("INSERT into dict values (?, ?, 0)", (h, i))
		con.commit()

	def do_upload_cap(s):
		cl = int(s.headers['Content-Length'])
		with open("dcrack.cap.tmp.gz", "wb") as fid:
			fid.write(s.rfile.read(cl))

		decompress("dcrack.cap.tmp")
		os.rename("dcrack.cap.tmp.gz", "dcrack.cap.gz")
		os.rename("dcrack.cap.tmp", "dcrack.cap")

	def do_req(s, path):
		con = get_con()

		c = con.cursor()

		c.execute("""DELETE from clients where 
			    (strftime('%s', datetime()) - strftime('%s', last))
			    > 300""")

		con.commit()

		if ("ping" in path):
			return s.do_ping(path)

		if ("getwork" in path):
			return s.do_getwork(path)

		if ("dict" in path and "status" in path):
			return s.do_dict_status(path)

		if ("dict" in path and "set" in path):
			return s.do_dict_set(path)

		if ("dict" in path):
			return s.get_dict(path)

		if ("net" in path and "/crack" in path):
			return s.do_crack(path)

		if ("net" in path and "result" in path):
			return s.do_result(path)

		if ("cap" in path):
			return s.get_cap(path)

		if ("status" in path):
			return s.get_status()

		if ("remove" in path):
			return s.remove(path)

		return "error"

	def remove(s, path):
		con = get_con()

		p = path.split("/")
		n = p[4].upper()

		c = con.cursor()
		c.execute("DELETE from nets where bssid = ?", (n,))
		con.commit()

		c.execute("DELETE from work where net = ?", (n,))
		con.commit()
		
		return "OK"

	def get_status(s):
		con = get_con()

		c = con.cursor()
		c.execute("SELECT * from clients")
	
		clients = [r['speed'] for r in c.fetchall()]

		nets = []

		c.execute("SELECT * from dict where current = 1")
		dic = c.fetchone()

		c.execute("SELECT * from nets")

		for r in c.fetchall():
			n = { "bssid" : r['bssid'] }
			if r['pass']:
				n["pass"] = r['pass']

			if r['state'] != 2:
				n["tot"] = dic["lines"]

				did = 0
				cur = con.cursor()
				cur.execute("""SELECT * from work where net = ?
						and dict = ? and state = 2""",
						(n['bssid'], dic['id']))
				for row in cur.fetchall():
					did += row['end'] - row['start']

				n["did"] = did

			nets.append(n)

		d = { "clients" : clients, "nets" : nets }

		return json.dumps(d)

	def do_result_pass(s, net, pw):
		con = get_con()

		pf = "dcrack-pass.txt"

		with open(pf, "w") as fid:
			fid.write(pw)
			fid.write("\n")

		cmd = ["aircrack-ng", "-w", pf, "-b", net, "-q", "dcrack.cap"]
		p = subprocess.Popen(cmd, stdout=subprocess.PIPE, \
			stdin=subprocess.PIPE)

		res = p.communicate()[0]
		res = str(res)

		os.remove(pf)

		if not "KEY FOUND" in res:
			return "error"

		s.net_done(net)

		c = con.cursor()
		c.execute("UPDATE nets set pass = ? where bssid = ?", \
			(pw, net))

		con.commit()

		return "OK"

	def net_done(s, net):
		con = get_con()

		c = con.cursor()
		c.execute("UPDATE nets set state = 2 where bssid = ?",
			(net,))

		c.execute("DELETE from work where net = ?", (net,))
		con.commit()

	def do_result(s, path):
		con = get_con()

		p = path.split("/")
		n = p[4].upper()

		x  = urlparse(path)
		qs = parse_qs(x.query)

		if "pass" in qs:
			return s.do_result_pass(n, qs['pass'][0])

		wl = qs['wl'][0]

		c = con.cursor()
		c.execute("SELECT * from nets where bssid = ?", (n,))
		r = c.fetchone()
		if r and r['state'] == 2:
			return "Already done"

		c.execute("""UPDATE work set state = 2 where 
			net = ? and dict = ? and start = ? and end = ?""",
			(n, wl, qs['start'][0], qs['end'][0]))

		con.commit()

		if c.rowcount == 0:
			c.execute("""INSERT into work values
				(NULL, ?, ?, ?, ?, datetime(), 2)""",
					(n, wl, qs['start'][0], qs['end'][0]))
			con.commit()

		# check status
		c.execute("""SELECT * from work where net = ? and dict = ?
			and state = 2 order by start""", (n, wl))

		i = 0
		r = c.fetchall()
		for row in r:
			if i == row['start']:
				i = row['end']
			else:
				break

		c.execute("SELECT * from dict where id = ? and lines = ?",
			(wl, i))

		r = c.fetchone()

		if r:
			s.net_done(n)

		return "OK"

	def get_cap(s, path):
		return s.serve_file("dcrack.cap.gz")

	def get_dict(s, path):
		p = path.split("/")
		n = p[4]

		fn = "dcrack-dict-%s.txt.gz" % n

		return s.serve_file(fn)

	def serve_file(s, fn):
		s.send_response(200)
		s.send_header("Content-type", "application/x-gzip")
		s.end_headers()

		# XXX openat
		with open(fn, "rb") as fid:
			s.wfile.write(fid.read())

		return None

	def do_crack(s, path):
		con = get_con()

		p = path.split("/")

		n = p[4].upper()

		c = con.cursor()
		c.execute("INSERT into nets values (?, NULL, 1)", (n,))
		con.commit()

		return "OK"

	def do_dict_set(s, path):
		con = get_con()

		p = path.split("/")

		h = p[4]

		c = con.cursor()
		c.execute("UPDATE dict set current = 0")
		c.execute("UPDATE dict set current = 1 where id = ?", (h,))
		con.commit()

		return "OK"

	def do_ping(s, path):
		con = get_con()

		p = path.split("/")

		cid = p[4]

		x  = urlparse(path)
		qs = parse_qs(x.query)

		speed = qs['speed'][0]

		c = con.cursor()
		c.execute("SELECT * from clients where id = ?", (cid,))
		r = c.fetchall()
		if (not r):
			c.execute("INSERT into clients values (?, ?, datetime())",
				  (cid, int(speed)))
		else:
			c.execute("""UPDATE clients set speed = ?, 
					last = datetime() where id = ?""",
					(int(speed), cid))

		con.commit()

		return "60"

	def try_network(s, net, d):
		con = get_con()

		c = con.cursor()
		c.execute("""SELECT * from work where net = ? and dict = ?
				order by start""", (net['bssid'], d['id']))

		r = c.fetchall()

		s     = 5000000
		i     = 0
		found = False

		for row in r:
			if found:
				if i + s > row['start']:
					s = row['start'] - i
				break

			if (row['start'] <= i <= row['end']):
				i = row['end']
			else:
				found = True

		if i + s > d['lines']:
			s = d['lines'] - i

		if s == 0:
			return None

		c.execute("INSERT into work values (NULL, ?, ?, ?, ?, datetime(), 1)",
			(net['bssid'], d['id'], i, i + s))

		con.commit()

		crack = { "net"   : net['bssid'], \
			  "dict"  : d['id'], \
			  "start" : i, \
			  "end"   : i + s }

		j = json.dumps(crack)

		return j

	def do_getwork(s, path):
		con = get_con()

		c = con.cursor()

		c.execute("""DELETE from work where 
			    ((strftime('%s', datetime()) - strftime('%s', last))
			    > 3600) and state = 1""")

		con.commit()

		c.execute("SELECT * from dict where current = 1")
		d = c.fetchone()

		c.execute("SELECT * from nets where state = 1")
		r = c.fetchall()

		for row in r:
			res = s.try_network(row, d)
			if res:
				return res

		# try some old stuff
		c.execute("""select * from work where state = 1 
			order by last limit 1""")

		res = c.fetchone()

		if res:
			c.execute("DELETE from work where id = ?", (res['id'],))
			for row in r:
				res = s.try_network(row, d)
				if res:
					return res

		res = { "interval" : "60" }

		return json.dumps(res)

	def do_dict_status(s, path):
		p = path.split("/")

		d = p[4]

		try:
			with open("dcrack-dict-%s.txt" % d): pass
			return "OK"
		except:
			return "NO"

def create_db():
	con = get_con()

	c = con.cursor()
	c.execute("""create table clients (id varchar(255),
			speed integer, last datetime)""")

	c.execute("""create table dict (id varchar(255), lines integer,
			current boolean)""")
	c.execute("""create table nets (bssid varchar(255), pass varchar(255),
			state integer)""")

	c.execute("""create table work (id integer primary key,
		net varchar(255), dict varchar(255),
		start integer, end integer, last datetime, state integer)""")

def connect_db():
	con = sqlite3.connect('dcrack.db')
	con.row_factory = sqlite3.Row

	return con

def get_con():
	global tls

	try:
		return tls.con
	except:
		tls.con = connect_db()
		return tls.con

def init_db():
	con = get_con()
	c = con.cursor()

	try:
		c.execute("SELECT * from clients")
	except:
		create_db()

def server():
	init_db()

	server_class = ThreadingTCPServer 
	httpd = server_class(('', port), ServerHandler)

	print("Starting server")
	httpd.serve_forever()

def usage():
	print("""dcrack v0.3

	Usage: dcrack.py [MODE]
	server                        Runs coordinator
	client <server addr>          Runs cracker
	cmd    <server addr> [CMD]    Sends a command to server

		[CMD] can be:
			dict   <file>
			cap    <file>
			crack  <bssid>
			remove <bssid>
			status""")
	exit(1)

def get_speed():
	print("Getting speed")
	p = subprocess.Popen(["aircrack-ng", "-S"], stdout=subprocess.PIPE)
	speed = p.stdout.readline()
	speed = speed.split()
	speed = speed[len(speed) - 2]
	return int(speed)

def get_cid():
	return random.getrandbits(64)

def do_ping(speed):
	global url, cid

	u = url + "client/" + str(cid) + "/ping?speed=" + str(speed)
	stuff = urlopen(u).read()
	interval = int(stuff)

	return interval

def pinger(speed):
	while True:
		interval = try_ping(speed)
		time.sleep(interval)

def try_ping(speed):
	while True:
		try:
			return do_ping(speed)
		except URLError:
			print("Conn refused (pinger)")
			time.sleep(60)

def get_work():
	global url, cid, cracker

	u = url + "client/" + str(cid) + "/getwork"
	stuff = urlopen(u).read()
	stuff = stuff.decode("utf-8")

	crack = json.loads(stuff)

	if "interval" in crack:
		print("Waiting")
		return int(crack['interval'])

	wl  = setup_dict(crack)
	cap = get_cap(crack)

	print("Cracking")

	cmd = ["aircrack-ng", "-w", wl, "-b", crack['net'], "-q", cap]

	p = subprocess.Popen(cmd, stdout=subprocess.PIPE, \
		stdin=subprocess.PIPE)

	cracker = p

	res = p.communicate()[0]
	res = str(res)

	cracker = None

	if ("not in dictionary" in res):
		print("No luck")
		u = "%snet/%s/result?wl=%s&start=%d&end=%d&found=0" % \
		    	(url, crack['net'], crack['dict'], \
			crack['start'], crack['end'])

		stuff = urlopen(u).read()
	elif "KEY FOUND" in res:
		pw = re.sub("^.*\[ ", "", res)

		i = pw.rfind(" ]")
		if i == -1:
			raise BaseException("Can't parse output")

		pw = pw[:i]

		print("Key for %s is %s" % (crack['net'], pw))

		u = "%snet/%s/result?pass=%s" % (url, crack['net'], pw)
		stuff = urlopen(u).read()

	return 0

def decompress(fn):
	with gzip.open(fn + ".gz") as fid1:
		with open(fn, "wb") as fid2:
			fid2.writelines(fid1)

def setup_dict(crack):
	global url

	d = crack['dict']

	fn = "dcrack-client-dict-%s.txt" % d

	try:
		with open(fn): pass
	except:
		print("Downloading dictionary %s" % d)

		u = "%sdict/%s" % (url, d)
		stuff = urlopen(u)

		with open(fn + ".gz", "wb") as fid:
			fid.write(stuff.read())

		print("Uncompressing dictionary")
		decompress(fn)
	
		sha1 = hashlib.sha1()
		with open(fn, "rb") as fid:
			sha1.update(fid.read())

		h = sha1.hexdigest()

		if h != d:
			print("bad dictionary")
			exit(1)

	s = "dcrack-client-dict-%s-%d:%d.txt" \
		% (d, crack['start'], crack['end']) 

	try:
		with open(s): pass
	except:
		print("Splitting dict %s" % s)
		with open(fn, "rb") as fid1:
			with open(s, "wb") as fid2:
				for i, l in enumerate(fid1):
					if i >= crack['end']:
						break
					if i >= crack['start']:
						fid2.write(l)
	return s

def get_cap(crack):
	global url, nets

	fn = "dcrack-client.cap"

	bssid = crack['net'].upper()

	if bssid in nets:
		return fn

	try:
		with open(fn, "rb"): pass
		check_cap(fn, bssid)
	except:
		pass

	if bssid in nets:
		return fn

	print("Downloading cap")
	u = "%scap/%s" % (url, bssid)

	stuff = urlopen(u)

	with open(fn + ".gz", "wb") as fid:
		fid.write(stuff.read())

	print("Uncompressing cap")
	decompress(fn)

	nets = {}
	check_cap(fn, bssid)

	if bssid not in nets:
		raise BaseException("Can't find net %s" % bssid)

	return fn

def process_cap(fn):
	global nets

	nets = {}

	print("Processing cap")
	p = subprocess.Popen(["aircrack-ng", fn], stdout=subprocess.PIPE, \
		stdin=subprocess.PIPE)
	found = False
	while True:
		line = p.stdout.readline()

		try:
			line = line.decode("utf-8")
		except:
			line = str(line)

		if "1 handshake" in line:
			found = True
			parts = line.split()
			b = parts[1].upper()
#			print("BSSID [%s]" % b)
			nets[b] = True

		if (found and line == "\n"):
			break

	p.stdin.write(bytes("1\n", "utf-8"))
	p.communicate()

def check_cap(fn, bssid):
	global nets

	cmd = ["aircrack-ng", "-b", bssid, fn]
	p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE)

	res = p.communicate()[0]
	res = str(res)

	if "No matching network found" not in res:
		nets[bssid] = True

def worker():
	while True:
		interval = get_work()
		time.sleep(interval)

def set_url():
	global url, port

	if len(sys.argv) < 3:
		print("Provide server addr")
		usage()

	host = sys.argv[2]

	if not ":" in host:
		host = "%s:%d" % (host, port)

	url = "http://" + host + "/" + "dcrack/"

def client():
	global cid, cracker, url

	set_url()
	url += "worker/"

	speed = get_speed()
	print("Speed", speed)

	cid = get_cid()

	print("CID", cid)

	try_ping(speed)
	t = threading.Thread(target=pinger, args=(speed,))
	t.start()

	while True:
		try:
			do_client()
			break
		except URLError:
			print("Conn refused")
			time.sleep(60)

def do_client():
	try:
		worker()
	except KeyboardInterrupt:
		if cracker:
			cracker.kill()
		print("one more time...")

def upload_file(url, f):
	x  = urlparse(url)
	c = HTTPConnection(x.netloc)

	# XXX not quite HTTP form

	with open(f, "rb") as fid:
		c.request("POST", x.path, fid)
		res = c.getresponse()
		stuff = res.read()
		c.close()

	return stuff

def compress_file(f):
	with open(f, "rb") as fid1:
		with gzip.open(f + ".gz", "wb") as fid2:
			fid2.writelines(fid1)

def send_dict():
	global url

	if len(sys.argv) < 5:
		print("Need dict")
		usage()

	d = sys.argv[4]

	print("Calculating dictionary hash for %s" % d)

	sha1 = hashlib.sha1()
	with open(d, "rb") as fid:
		sha1.update(fid.read())

	h = sha1.hexdigest()

	print("Hash is %s" % h)

	u = url + "dict/" + h + "/status"
	stuff = urlopen(u).read()

	if "NO" in str(stuff):
		u = url + "dict/create"
		print("Compressing dictionary")
		compress_file(d)
		print("Uploading dictionary")
		upload_file(u, d + ".gz")

	print("Setting dictionary to %s" % d)
	u = url + "dict/" + h + "/set"
	stuff = urlopen(u).read()

def send_cap():
	global url

	if len(sys.argv) < 5:
		print("Need cap")
		usage()

	cap = sys.argv[4]

	print("Cleaning cap %s" % cap)
	subprocess.Popen(["wpaclean", cap + ".clean", cap], \
	   stderr=subprocess.STDOUT, stdout=subprocess.PIPE).communicate()[0]

	print("Compressing cap")
	compress_file(cap + ".clean")

	u = url + "cap/create"
	upload_file(u, cap + ".clean.gz")

def cmd_crack():
	net_cmd("crack")

def net_cmd(op):
	global url

	if len(sys.argv) < 5:
		print("Need BSSID")
		usage()

	bssid = sys.argv[4]

	print("%s %s" % (op, bssid))
	u = "%snet/%s/%s" % (url, bssid, op)
	stuff = urlopen(u).read()

def cmd_remove():
	net_cmd("remove")

def cmd_status():
	u = "%sstatus" % url
	stuff = urlopen(u).read()

	stuff = json.loads(stuff.decode("utf-8"))

#	print(stuff)
#	print("=============")

	speed = 0
	for idx, c in enumerate(stuff['clients'], start=1):
		speed += c

	print("Clients\t%d\nSpeed\t%d\n" % (idx, speed))

	need = 0

	for n in stuff['nets']:
		out = n['bssid'] + " "

		if "pass" in n:
			out += n['pass']
		elif "did" in n:
			did = int(float(n['did']) / float(n['tot']) * 100.0)
			out += str(did) + "%"
			need += n['tot'] - n['did']
		else:
			out += "-"

		print(out)

	if need != 0:
		print("\nKeys left %d" % need)
		if speed != 0:
			s = int(float(need) / float(speed))
			sec = datetime.timedelta(seconds=s)
			d = datetime.datetime(1,1,1) + sec
			print("ETA %dh %dm" % (d.hour, d.minute))

def do_cmd():
	global url

	set_url()
	url += "cmd/"

	if len(sys.argv) < 4:
		print("Need CMD")
		usage()

	cmd = sys.argv[3]

	if "dict" in cmd:
		send_dict()
	elif "cap" in cmd:
		send_cap()
	elif "crack" in cmd:
		cmd_crack()
	elif "status" in cmd:
		cmd_status()
	elif "remove" in cmd:
		cmd_remove()
	else:
		print("Unknown cmd %s" % cmd)
		usage()

def main():
	if len(sys.argv) < 2:
		usage()

	cmd = sys.argv[1]

	if cmd == "server":
		server()
	elif cmd == "client":
		client()
	elif cmd == "cmd":
		do_cmd()
	else:
		print("Unknown cmd", cmd)
		usage()

	exit(0)

if __name__ == "__main__":
	main()
