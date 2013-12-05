#!/usr/bin/python

import datetime, sys, string, re

class Packet:
	def __init__(self, debug):
		self.clear()
		self.debug = debug
	
	def add_line(self, line):
		global config
		self.raw_lines.append(line)
		if self.debug:
			print line
		if self.state == 0:
			if '0x00' in line:
				#quick hack for weird IGMP lengths causing errors
				return
			self.state = 1
			linecomp = line.split(' ')
			times = map(int, linecomp[0].split('.')[0].split(':'))
			self.time = datetime.time(hour=times[0], minute=times[1], second=times[2])
			lenstart = line.index('length ') + 7
			lenend = []
			lenend.append(line.find(')', lenstart))
			lenend.append(line.find(',', lenstart))
			lenend.append(line.find(' ', lenstart))
			lenend = minset(lenend)
			self.datalength = int(line[lenstart:lenend])
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
				tflist = map(lambda x: x == '*' or x == sourceid[4] or x == destid[4], config[0])
				self.matches = filter(lambda x: tflist[x[0]], enumerate(config[1]))
			self.ident = ('.'.join(sourceid[:4]), 0 if noport else int(sourceid[4]), '.'.join(destid[:4]), 0 if noport else int(destid[4]), self.time)
			if 'length' in line:
				self.streamlength = int(line[line.rfind(' ')+1:])
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
				self.appdata = self.streamdata[-self.streamlength:] if self.streamlength else self.streamdata
				return True


	def parse(self):
		global config
		if self.debug:
			print 'finished packet:'
			print self.streamdata
		for fil in self.matches:
			if fil[1].search(self.streamdata):
				print '--------------------- Match Found ----------------------'
				print 'Rule ' + str(fil[0]) + ', port ' + config[0][fil[0]] + ', ' + fil[1].pattern
				print self.ident
				print '\n'.join(self.raw_lines)
	
	def clear(self):
		self.state = 0
		self.datalength = 0
		self.recvdlength = 0
		self.streamlength = 0
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

try:
	config = open(sys.argv[1]).read().split('\n')
except:
	print 'Usage: python tcpfind.py <config file> [<options>]\n\nConfig format:\nport:(regex|pythonfile)\n\nex:\n\t1337:(key\\{|flag\\{)\n\t5678:\\xFF\\xE4\n# asterisk (*) can be used for all ports\n\t*:globalcheck.py\n# python files will be imported as modules \n# and their "main()" function will be called with the \n# application-layer data as an argument, return \n# True or False depending on match.\n# Set the module variable "description" to give a \n# description to the check being performed.\n\nOptions:\n-d\t\tEnable debugging (super verbose) output'
	sys.exit(0)

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

config = map(string.strip, config)
config = filter(lambda x: x != '' and x[0] != '#', config)
config = map(lambda x: (x.split(':')[0], x.split(':')[1]), config)
config = [map(lambda x: x[0], config), map(lambda x: x[1], config)]
config[1] = map(inputswitch, config[1])

debug = '-d' in sys.argv
running = Packet(debug)
if debug:
	print config

while True:
	if running.add_line(raw_input()):
		running.parse()
		running.clear()
