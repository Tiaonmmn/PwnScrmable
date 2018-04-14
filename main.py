from pwn import *
from time import sleep
from method1 import method1
from method2 import method2
from method3 import method3
from method4 import method4
from method5 import method5
from method6 import method6
from method7 import method7
from method8 import method8
from method9 import method9
from method10 import method10
from method11 import method11
from method12 import method12
from method13 import method13
from method14 import method14
from method15 import method15
from random import *

logo = r'''

      ___           ___           ___                    ___           ___           ___           ___           ___           ___       ___           ___     
     /\  \         /\__\         /\__\                  /\  \         /\  \         /\  \         /\__\         /\  \         /\__\     /\  \         /\  \    
    /::\  \       /:/ _/_       /::|  |                /::\  \       /::\  \       /::\  \       /::|  |       /::\  \       /:/  /    /::\  \       /::\  \   
   /:/\:\  \     /:/ /\__\     /:|:|  |               /:/\ \  \     /:/\:\  \     /:/\:\  \     /:|:|  |      /:/\:\  \     /:/  /    /:/\:\  \     /:/\:\  \  
  /::\~\:\  \   /:/ /:/ _/_   /:/|:|  |__            _\:\~\ \  \   /:/  \:\  \   /::\~\:\  \   /:/|:|__|__   /::\~\:\__\   /:/  /    /::\~\:\  \   /::\~\:\  \ 
 /:/\:\ \:\__\ /:/_/:/ /\__\ /:/ |:| /\__\          /\ \:\ \ \__\ /:/__/ \:\__\ /:/\:\ \:\__\ /:/ |::::\__\ /:/\:\ \:|__| /:/__/    /:/\:\ \:\__\ /:/\:\ \:\__\
 \/__\:\/:/  / \:\/:/ /:/  / \/__|:|/:/  /          \:\ \:\ \/__/ \:\  \  \/__/ \/_|::\/:/  / \/__/~~/:/  / \:\~\:\/:/  / \:\  \    \:\~\:\ \/__/ \/_|::\/:/  /
      \::/  /   \::/_/:/  /      |:/:/  /            \:\ \:\__\    \:\  \          |:|::/  /        /:/  /   \:\ \::/  /   \:\  \    \:\ \:\__\      |:|::/  / 
       \/__/     \:\/:/  /       |::/  /              \:\/:/  /     \:\  \         |:|\/__/        /:/  /     \:\/:/  /     \:\  \    \:\ \/__/      |:|\/__/  
                  \::/  /        /:/  /                \::/  /       \:\__\        |:|  |         /:/  /       \::/__/       \:\__\    \:\__\        |:|  |    
                   \/__/         \/__/                  \/__/         \/__/         \|__|         \/__/         ~~            \/__/     \/__/         \|__|    
'''
print(logo)
print("Welcome to the PwnScramble.\nFirst let's input the first ip address.")
one_first_number = input("What's the first number?")
one_second_number = input("What's the second number?")
one_third_number = input("What's the third number?")
one_forth_number = input("What's the forth number?")
print("Second,input the second ip address.")
two_first_number = input("What's the first number?")
two_second_number = input("What's the second number?")
two_third_number = input("What's the third number?")
two_forth_number = input("What's the forth number?")
print("Third,input the port range")
port1 = input("What's the first port?")
port2 = input("What's the second port?")
print("Now,let's go scrambling!")
while True:
    for e in range(port1, port2 + 1):
        for a in range(one_first_number, two_first_number + 1):
            for b in range(one_second_number, two_second_number + 1):
                for c in range(one_third_number, two_third_number + 1):
                    for d in range(one_forth_number, two_forth_number + 1):
                        ip_address = "%d.%d.%d.%d" % (a, b, c, d)
                        strings = "method%s" % (randint(1, 12))  # TODO: Add this
                        # strings = "method6"  # TODO: Add this
                        try:
                            globals()[strings](ip_address, e)
                            # globals()[strings]()
                            sleep(uniform(0.1, 1.0))
                            log.success("Rubbish has been sent on Service Port %s on Host %s!" % (e, ip_address))
                        except pwnlib.exception.PwnlibException:
                            log.failure("The Service Port %s on Host %s may be down!Be careful!" % (e, ip_address))
