#! /usr/bin/env python3
# Description: 'Walk' through a directory and replace specified strings/IP addresses (FMG/FAZ backups are full directories containing DB backups)
# Author: Andrew McConnell
# Date:   5/4/2023

# FMG BACKUPS (7.2.2!!!!):
# /var/dvm/task/task.db is a DB (binary) file that will contain device data replacement should be possible
# /var/fwclienttemp/system.conf is a conf file of the FMG, data replacement is possible
# /var/pm2/ might contain some sensitive info

# FAZ 7.2.2 backups look to be the same

import sys
import re
import random
import os
from binascii import hexlify, unhexlify

# GLOBAL VARS

opflags = []
depth = 0

str_repl = dict()
ip_repl = dict()
mac_repl = dict()

ip4 = re.compile(r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.](25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.](25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.](25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')
ip6 = re.compile(r"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))")
mac = re.compile(r'([0-9a-fA-F][0-9a-fA-F]:){5}([0-9a-fA-F][0-9a-fA-F]){1}')

# Helper Functions

# RFC1918 Detector
def isRFC1918(ip):
	a,b,c,d = ip.split('.')

	# Very explicitly checks if the addresses are RFC 1918 Class A/B/C addresses
	if (int(a) == 10):
		return(True)
	elif(int(a) == 172 and int(b) in range(16,32)):
		return(True)
	elif(int(a) == 192 and int(b) == 168):
		return(True)
	else:
		return(False)

# Subnet mask detector (Insert if needed)
'''
How it works:
1) Split the IP into a list of 4 numbers (we assume IPv4)
  a) expect_0 is set to True when we view a shift in 1's to 0's								V We set it to True so if there's a '1' after a '0', it's not a net_mask
													===> 255.255.240.0 = 11111111.11111111.11110000.00000000
  b) constant is a catch-all for when we detect it isn't (or is!!!) a net_mask, and we return it accordingly

2) We take each value in the ip_list and check if it's non zero
  a) If it's non zero, we subtract 2^i from that value where i is a list from 7 to 0 (decremented).
	i) If the value hits zero during this process and i is not zero, set expect_0 to True and break out of the process [val is zero so we don't need to subtract any more]
	ii) If the value hits zero during the process and i IS zero (255 case), we continue to the next value
	###### IF AT ALL DURING THIS PROCESS THE VALUE GOES BELOW ZERO, WE SET constant = False AND BREAK AND 'return constant' ######
  b) If the value starts out as zero, we don't bother with the process and just set expect_0 to True (catches 255.0.255.0 and similar cases)
'''
def isNetMask(ip):
	_ = ip.split('.')
	ip_list = list()
	for item in _:
		ip_list.append(int(item))

	# Return false for quad 0 case (default routes)
	if (ip_list == [0,0,0,0]):
		return False

	# Netmasks ALWAYS start with 1's
	expect_0 = False
	# We start out assuming constancy
	constant = True

	for val in ip_list:
		if (val != 0):
			for i in range(7, -1, -1):
				val = val - pow(2, i)
				if (val > 0 and not expect_0):
					continue
				elif (val == 0  and i != 0):
					expect_0 = True
					break
				elif (val == 0 and not expect_0 and i == 0):
					break
				else:
					constant = False
					break
			if (not constant):
				break
		else:
			expect_0 = True
	return constant

# Mask IPs
def replace_ip4(ip):
	if (isNetMask(ip)):
		return ip
	if (ip not in ip_repl.keys()):
		repl = ""
		if (isRFC1918(ip) and "-sPIP" in opflags and "-pi" not in opflags):
			octets = ip.split('.')
			repl = f"{octets[0]}.{octets[1]}.{random.randrange(0, 256)}.{random.randrange(1, 256)}"
		elif (not isRFC1918(ip) and "-pi" not in opflags):
			repl = f"{random.randrange(1, 255)}.{random.randrange(0, 255)}.{random.randrange(0, 255)}.{random.randrange(1, 255)}"
		else:
			repl = ip
		ip_repl[ip] = repl
		return repl
	
	# If we've replaced it before, pick out that replacement and return it
	else:
		return ip_repl[ip]

def replace_ip6(ip):
	if (ip not in ip_repl.keys() and "-pi" not in opflags):
		repl = f'{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}:{hex(random.randrange(1, 65535))[2:]}'
		ip_repl[ip] = repl
		return repl
	elif ("-pi" not in opflags):
		return ip_repl[ip]
	else:
		return ip

def replace_str(s):
	if s in str_repl.keys():
		return str_repl[s]

	repl = ""
	for ch in s:
		c = 0
		if (random.random() > .5):
			c = chr(random.randint(65,90))
		else:
			c = chr(random.randint(97, 122))

		repl += c

	str_repl[s] = repl

	return repl

def repl_dicts_to_logfile(filename):
	with open(filename, 'w') as outfile:
		outfile.write("+---------- MAPPED IP ADDRESSES ----------+\n")
		for og, rep in ip_repl.items():
			outfile.write(f"Original IP: {og}\nMapped IP: {rep}\n\n")
		outfile.write("+---------- MAPPED MAC ADDRESSES ---------+\n\n")

		outfile.write("+---------- MAPPED STRING VALUES ---------+\n")
		for og, rep in str_repl.items():
			outfile.write(f"Original String: {og}\nMapped String: {rep}\n\n")
		
	print(f"Mapped address outfile written to: {filename}")

mtd = ""

# Grab all directories going 'depth' number of steps deep
# Opens a new directory to write modified files to
def buildDirTree(dir):
	mod_dir = f"{dir}_obfuscated"

	mtd = mod_dir

	dirTree = next(os.walk(dir))[0]
	slashes = dirTree.count('/') + dirTree.count('\\')

	dirTree = []

	for dirpath, dirnames, fnames in os.walk(dir):
		check = f"{dirpath}"

		if ((check.count('/') + check.count('\\')) - slashes) > depth:
			continue
		
		dirTree.append(check)

	# Create new directory to house the modified files
	os.makedirs(mod_dir, exist_ok=True)

	moddirTree = dirTree.copy()
	for i, path in enumerate(moddirTree):
		a = re.search(dir, path)
		moddirTree[i] = path[:a.span()[0]] + mod_dir + path[a.span()[1]:]

		os.makedirs(moddirTree[i], exist_ok=True)
	
	return (mtd, dirTree)

def getFiles(dirTree):
	slash = '/'

	files = []
	# Gotta love Windows
	if sys.platform == 'win32':
		slash = '\\'
	
	# list comprehension ftw! dir + slash (/ or \) + filename
	for dir in dirTree:
		files.extend([f'{dir}{slash}{i}' for i in next(os.walk(dir))[2]])
		if f'{dir}{slash}{args[0]}' in files:
			print(f"\nERROR: You cannot perform a fedwalk on a directory containing {args[0]} (itself)\n\nexiting...\n")
			sys.exit()
	
	return files

def obfTxtFile(txtfile):
	pass

def obfBinFile(binfile):
	pass

def importMap(filename):
	lines = []
	with open(filename, 'r') as o:
		lines = o.readlines()
	
	print(lines)

	imp_ip = False
	imp_mac = False
	imp_str = False

	OG = ""
	for l in lines:
		if '+---' in l:
			if 'IP' in l:
				imp_ip = True
				imp_mac = False
				imp_str = False
			elif 'MAC' in l:
				imp_ip = False
				imp_mac = True
				imp_str = False
			elif 'STRING' in l:
				imp_ip = False
				imp_mac = False
				imp_str = True
			else:
				print("Map file is improperly formatted, do not make changes to the map file unless you know what you are doing")
				sys.exit(1)
			continue

		if not len(l):
			continue

		if imp_ip:
			components = l.split(':')
			if ('Original' in components[0]):
				OG = components[1]
			else:
				ip_repl[OG] = components[1]
				OG = ""
		elif imp_mac:
			components = l.split(':')
			if ('Original' in components[0]):
				OG = components[1]
			else:
				#mac_repl[OG] = components[1]
				OG = ""
		elif imp_str:
			components = l.split(':')
			if ('Original' in components[0]):
				OG = components[1]
			else:
				str_repl[OG] = components[1]
				OG = ""
		
		else:
			print("Something went wrong, mappings might not be fully imported\n")
			print(f"Interpreted mappings based on import\nIP Mapping: {ip_repl}\nMAC Mapping:\nString Mapping: {str_repl}\n")

options = {"-h": "Display this output",\
		   "-sPIP": "Scrub private IPs. Assumes /16 subnet",\
		   "-pi":"preserve all ip addresses",\
		   "-pm":"preserve MAC addresses",\
		   "-ps":"preserve strings (not recommended, usually enabled for debugging purposes)"}

args = sys.argv

if ((len(args) < 3) or '-' in args[2]):
	print("Usage: \n\tpy fedwalk.py <directory> <depth> [options]")
	print("\t\tDirectory needs to be specified. Additionally, it needs to be a directory that fedwalk is NOT in\n\t\t\
BE CAREFUL when using this tool, specifying the wrong directory can have drastic consequences\n\t\t\
<depth> needs to be an integer, a warning will be thrown if it's greater than 5\n")
	print("Options:")
	for k, v in options.items():
		print(f'\t{k}: {v}')
	sys.exit()

try:
	depth = int(args[2])
	if depth < 0:
		raise ValueError
except ValueError:
	print("Usage: \n\tpy fedwalk.py <directory> <depth> [options]")
	print("\t\tDirectory needs to be specified. Additionally, it needs to be a directory that fedwalk is NOT in\n\t\t\
BE CAREFUL when using this tool, specifying the wrong directory can have drastic consequences\n\t\t\
<depth> needs to be greater than or equal to zero, a warning will be thrown if it's greater than 7\n")

dirTree = []
try:
	dt = buildDirTree(args[1])
	dirTree = dt[1]
	mtd = dt[0]

except Exception as t:
	print(f"Something went wrong when loading the directory: {args[1]}\nPlease double check that it is correct\n")
	print(f"\nError: {t}")
	sys.exit()

ALLFILES = getFiles(dirTree)
ALLMODFILES = []
for f in ALLFILES:
	a = re.search(args[1], f)
	ALLMODFILES.append(f[:a.span()[0]] + mtd + f[a.span()[1]:])
print(ALLFILES)
print()
print(ALLMODFILES)