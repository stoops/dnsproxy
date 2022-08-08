#!/usr/bin/env python3
# https://pypi.org/project/dnslib/#files
# brew install python3 socat
# ip route add 133.7.0.0/16 via 192.168.16.61

import os, sys, time, glob

filepath = os.path.abspath(os.path.dirname(__file__))
sys.path.append(filepath)

from dnslib import *

import ipaddress, signal, subprocess, socketserver

TIMEOUT = (6 * 60 * 60)
LISTEN = "en0"
FORWARD = "8.8.8.8"
DOMAINS = {"facebook.com":["lo0", ""], "bell.ca":["en0", ""], "youtubez.com":["en0", ""]}
PROXIES = {}
IPS = {}

def init():
	for ip in ipaddress.IPv4Network("133.7.0.0/16"):
		key = str(ip)
		IPS[key] = []

def find():
	for ip in IPS.keys():
		if (len(IPS[ip]) < 1):
			return ip
	return ""

def stop(pidn):
	try:
		os.kill(pidn, signal.SIGTERM)
	except Exception as e:
		print("error:", e)

def geta(intf):
	try:
		o = subprocess.check_output(["ifconfig '%s' | grep -i 'inet ' | grep -iv '133.7.' | awk '{ print $2 }'" % (intf)], shell=True)
		o = o.decode()
	except:
		o = ""
	return o.strip()

def fork(comd):
	print("forward: {%s}" % (comd))
	if ((len(sys.argv) > 1) and (sys.argv[1] != "")):
		return -2
	try:
		p = subprocess.Popen("%s >/dev/null 2>&1 & echo $!" % (comd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
		o = int(p.stdout.read().decode().strip())
	except:
		o = -1
	return o

def prox(address, redirect, interface):
	z = 0
	if (redirect):
		try:
			subprocess.check_call(["ifconfig", LISTEN, "alias", "%s/32" % (redirect), "up"], shell=False)
		except Exception as e:
			print("error:", e)
	if ((redirect in IPS.keys()) and (len(IPS[redirect]) < 1)):
		for port in [80, 443]:
			pidn = fork("socat TCP-LISTEN:%s,fork,reuseaddr,bind=%s TCP:%s:%s,bind=%s" % (port, redirect, address, port, interface))
			if (pidn > 0):
				IPS[redirect].append(pidn)
				z += 1
	return z

def dnsp(data):
	answers = DNSRecord()
	qname = "local."

	try:
		query = DNSRecord.parse(data)

		qname = str(query.q.qname)
		qtype = QTYPE[query.q.qtype]

		print("request: %s (%s)" % (qname, qtype))
		response = query.send(FORWARD, 53, timeout=15)

		answers = DNSRecord.parse(response)
	except Exception as e:
		print("error:",data[0:64],e)

	dname = qname.strip(".")
	seconds = int(time.time())
	records = [rr.rdata.toZone() for rr in answers.rr if rr.rtype == QTYPE.A]
	records.sort()
	tmp = records if records else answers.rr
	print("answers: %s A=%s LEN=%s (%s)" % (dname, tmp, len(answers.rr), seconds))

	interface = ""
	for domain in DOMAINS.keys():
		if ((domain == dname) or dname.endswith("."+domain)):
			interface = DOMAINS[domain][1]
			break

	redirects = []
	for address in records:
		if (address and interface):
			if (interface.startswith("127.")):
				redirects.append("127.0.0.1")
				break

			if (not address in PROXIES.keys()):
				PROXIES[address] = [0, interface, ""]

			PROXIES[address][0] = seconds
			redirect = PROXIES[address][2]

			if (not redirect):
				redirect = find()
				prox(address, redirect, interface)
				PROXIES[address][2] = redirect

			pids = IPS.get(redirect, [])
			print("proxies: %s A=%s PROXY=%s PID=%s" % (dname, address, PROXIES[address], pids))

			if (redirect):
				redirects.append(redirect)
				break

	for proxy in PROXIES.keys():
		ptime = PROXIES[proxy][0]
		redirect = PROXIES[proxy][2]
		pids = IPS.get(redirect, [])
		if ((ptime > 0) and ((seconds - ptime) >= TIMEOUT)):
			print("deletes:", proxy, PROXIES[proxy], pids)
			if (len(pids) > 0):
				for pidn in pids:
					stop(pidn)
				IPS[redirect] = []
			PROXIES[proxy][2] = ""
			PROXIES[proxy][0] = 0

	if (redirects):
		answers.rr = []
		for address in redirects:
			answers.add_answer(RR(qname, ttl=60, rdata=A(address)))

	return answers.pack()

class BaseRequestHandler(socketserver.BaseRequestHandler):
	def get_data(self):
		raise NotImplementedError

	def send_data(self, data):
		raise NotImplementedError

	def handle(self):
		data = self.get_data()
		resp = dnsp(data)
		self.send_data(resp)

class UDPRequestHandler(BaseRequestHandler):
	def get_data(self):
		return self.request[0]

	def send_data(self, data):
		return self.request[1].sendto(data, self.client_address)

def main():
	init()
	for k in DOMAINS.keys():
		DOMAINS[k][1] = geta(DOMAINS[k][0])
	server = socketserver.UDPServer(("", 53), UDPRequestHandler)
	server.serve_forever()

if (__name__ == "__main__"):
	main()
