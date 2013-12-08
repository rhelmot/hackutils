#!/usr/bin/python

import datetime, sys, string, re

class Packet:
	def __init__(self, config, fmtdat, debug):
		self.clear()
		self.config = config
		self.fmtdat = fmtdat
		self.debug = debug
	
	def add_line(self, line):
		self.raw_lines.append(line)
		if self.debug:
			print line
		if self.state == 0:
			if '0x00' in line:
				#quick hack for weird IGMP lengths causing errors
				return
			self.state = 1
			linecomp = line.split(' ')
			self.time = linecomp[0]
			self.datalength = getlen(line)
			baseproto = linecomp[1] if not ':' in linecomp[1] else linecomp[2]
			if baseproto == 'IP':
				protostart = line.index('proto ') + 6
				self.proto = line[protostart:line.index(' ', protostart)] + '/IP'
			else:
				self.proto = baseproto
			if baseproto in ('STP', 'ARP', 'ARP,'):
				self.state = 2
		elif self.state == 1:
			self.state = 2
			linecomp = line.split()
			sourceid = linecomp[0].split('.')
			destid = linecomp[2][:-1].split('.')
			noport = len(destid) < 5
			if not noport:
				#MEET THE FILTER FROM HELL
				tflist = map(lambda x: x == '*' or x == sourceid[4] or x == destid[4], self.config[0])
				self.matches = filter(lambda x: tflist[x[0]], enumerate(self.config[1]))
			self.ident = ('.'.join(sourceid[:4]), 0 if noport else int(sourceid[4]), '.'.join(destid[:4]), 0 if noport else int(destid[4]))
			if 'length' in line:
				self.streamlength = getlen(line)
		elif self.state == 2:
			if self.recvdlength == 0 and not '0x0000' in line:
				return
			self.data_lines.append(line)
			if len(self.matches) == 0:
				self.recvdlength += 0x10
			else:
				words = line.split()
				for word in words[1:-1]:
					self.streamdata += chr(int(word[:2], 16))
					self.recvdlength += 1
					if len(word) == 4:
						self.streamdata += chr(int(word[-2:], 16))
						self.recvdlength += 1
				if self.debug:
					print 'now at',self.recvdlength,'bytes'
			if self.recvdlength >= self.datalength:
				self.state = 3
				if self.streamlength is not None:
					self.appdata = self.streamdata[-self.streamlength:]
				else:
					self.appdata = self.streamdata
					if self.debug:
						print 'Could not determine application-layer data'
				return True


	def parse(self):
		if self.debug:
			print 'finished packet:'
			print self.streamdata
			print 'Appdata:'
			print self.appdata
			print 'Checking against',map(lambda x: x[1].pattern, self.matches)
		for fil in self.matches:
			if fil[1].search(self.streamdata):
				if self.fmtdat['header']:
					print '---------------------- Match Found ----------------------'
				for c in self.fmtdat['format']:
					if c == 'r':
						print 'Rule ' + str(fil[0]) + ', port ' + self.config[0][fil[0]] + ', ' + fil[1].pattern
					if c == 'i':
						print 'From ' +self.ident[0]+':'+str(self.ident[1])+' to '+self.ident[2]+':'+str(self.ident[3])
					if c == 't':
						print 'At ' + self.time
					if c == 'w':
						print 'Raw tcpdump data:'
						print '\n'.join(self.raw_lines)
					if c == 'a':
						print '\nApplication-layer data:'
						print self.appdata
				if self.fmtdat['module']:
					print self.fmtdat['module'].format(self)
				if self.fmtdat['footer']:
					print '----------------------- Match End -----------------------'
	
	def clear(self):
		self.state = 0
		self.datalength = 0
		self.recvdlength = 0
		self.streamlength = None
		self.time = None
		self.ident = None
		self.protocol = None
		self.raw_lines = []
		self.data_lines = []
		self.streamdata = ""
		self.appdata = ""
		self.matches = []

def minset(*args):
	try:
		return min(filter(lambda x: x != -1, *args))
	except:
		return None

def getlen(line):
	lenstart = line.index('length ') + 7
	lenend = []
	lenend.append(line.find(')', lenstart))
	lenend.append(line.find(',', lenstart))
	lenend.append(line.find(' ', lenstart))
	lenend = minset(lenend)
	return int(line[lenstart:lenend])


def usage():
	print '''tcpbread version 0.2.0
Usage: tcpdump -i <interface> -nSv -X | python tcpbread.py [<options>] <config file> [<config file> ...]
Tested with tcpdump versions 4.2.1 and 4.4.0.

Options:
	-d		Enable debugging (super verbose) output
	-H		Print matches with high-visibility header
	-F		Print matches with high-visibility footer
	-r		Print matches with the rule they matched against
	-w		Print matches with raw tcpdump data
	-a		Print matches with parsed application-layer data
	-i		Print matches with source and destination IPs and ports
	-t		Print matches with timestamp
	-x <pythonfile>	in addition to any of the above printing options,
			use a script to do some formatting

For the formatting options r, w, a, i, and t, if none are provided, the default is
equivilant to "-ati". If some are provided, only those are used, and the printing
will be done in the order they are provided.

For the formatting python scripts, they will be imported as modules, and their
format() function will be called with a Packet class as the only argument.
Read through tcpbread.py for a description of said class. They should return a 
string that can be printed to the screen, but they really have free reign in 
terms of what they can do with control flow-- i.e. they could prompt the user
for confirmation that the match is valid before submitting the metadata to 
a malicious-connection reporting service.

Config format: port:(<regex> | <pythonfile>)
See included sample configuration file for details'''

def parseconfigs(*files):
	config = []
	for cfile in files:
		config += parseconfig(cfile)
	config = [map(lambda x: x[0], config), map(lambda x: x[1], config)]
	config[1] = map(inputswitch, config[1])
	return config

def parseconfig(cfile):
	try:
		config = open(cfile).read().split('\n')
		config = map(lambda x: x[:x.index('#')] if '#' in x else x, config)
		config = map(string.strip, config)
		config = filter(lambda x: x != '', config)
		config = map(lambda x: (x.split(':')[0], x.split(':')[1]), config)
	except:
		print 'Configuration format error in ' + cfile
		usage()
		sys.exit(1)
	return config

def inputswitch(line):
	try:
		out = __import__(line[:-3])
		if 'description' not in dir(out):
			out.pattern = line
		else:
			out.pattern = out.description
		out.search = out.main
		return out
	except:
		return re.compile(line)

def main(config, fmtdat, debug):
	running = Packet(config, fmtdat, debug)
	if debug:
		print config
	
	while True:
		try:
			line = raw_input()
		except (Exception, KeyboardInterrupt) as e:
			if debug:
				print e
			print 'Exiting.'
			sys.exit(0)
		if running.add_line(line):
			running.parse()
			running.clear()

if __name__ == '__main__':
	import getopt
	try:
		opts, args = getopt.getopt(sys.argv[1:], 'dHFraitx:', ['--help'])
	except:
		usage()
		sys.exit(0)
	fstr = ''
	fmod = None
	header = False
	footer = False
	debug = False

	for opt, arg in opts:
		if opt == '-H':
			header = True
		if opt == '-F':
			footer = True
		if opt == '-d':
			debug = True
		if opt == '-x':
			fmod = __import__(arg[:-3])
			tmp = fmod.format
		if opt in ('-h', '--help'):
			usage()
			sys.exit(0)
		if opt in ('-r', '-w', '-a', '-i', '-t'):
			fstr += opt[1]
	if fstr == '':
		fstr = 'ati'
	if len(args) == 0:
		usage()
		sys.exit(1)
	config = parseconfigs(*args)
	fmtdat = {
		'format': fstr,
		'header': header,
		'footer': footer,
		'module': fmod }
	main(config, fmtdat, debug)
