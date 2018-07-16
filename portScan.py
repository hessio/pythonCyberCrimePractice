#! /usr/bin/env python

import optparse
from socket import *
import sys
import re
from socket import *
from threading import *

screenLock = Semaphore(value=1)
def connScan(tgtHost, tgtPort):
	try:
		connSocket = socket(AF_INET, SOCK_STREAM)
		connSocket.connect((tgtHost, tgtPort))
		connSocket.send('ViolentPython\r\n')
		results = connSocket.recv(100)
		screenLock.acquire()
		print ('[+]', tgtPort,'/tcp open')
		print ('[+] ' + str(results)) 
	except:
		screenLock.acquire()
		print ('[-]',tgtPort ,' tcp closed')
	finally:
		screenLock.release()
		connSocket.close()


def portScan(tgtHost, tgtPorts): 
	try:
		tgtIP = gethostbyname(tgtHost) 
	except:
		print ("[-] Cannot resolve ", tgtHost, ": Unknown host")
		return 
	try:
		tgtName = gethostbyaddr(tgtIP)
		print ('\n[+] Scan Results for: ', tgtName[0]) 
	except:
		print ('\n[+] Scan Results for: ', tgtIP) 
	setdefaulttimeout(1)
	for tgtPort in tgtPorts:
 		t = Thread(target=connScan, args=(tgtHost, int(tgtPort)))
 		u = Thread(target=udpScan, args=(tgtHost, int(tgtPort)))
 		u.start()
 		t.start()

def udpScan(tgtHost, tgtPort):
	try:
		connSocket = socket(AF_INET, SOCK_DGRAM)
		connSocket.connect((tgtHost, tgtPort))
		connSocket.send('ViolentPython\r\n')
		results = connSocket.recv(100)
		screenLock.acquire()
		print ('[+]', tgtPort,'/udp open')
		print ('[+] ' + str(results)) 
	except:
		screenLock.acquire()
		print ('[-]',tgtPort ,' udp closed')
	finally:
		screenLock.release()
		connSocket.close()

def main():
	length = len(sys.argv) - 4
	parser = optparse.OptionParser('usage: -H <target host>')
	parser.add_option("-H", dest="tgtHost", type="string", help="specify target host")
	tgtPorts = list()
	(options, args) = parser.parse_args()
	tgtHost = options.tgtHost
	for i in range(1, 65536):
		tgtPorts.append(i)
	if tgtHost == None:
		print ('[-] You must specify a target host.')
		exit(0) 
	portScan(tgtHost, tgtPorts)
if __name__ == '__main__': 
	main()