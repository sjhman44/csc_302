#!/usr/bin/python
from scapy.all import *

def print_pkt(pkt):
        pkt.show()

def main():
        rec_pkt = sniff(filter='icmp',prn=print_pkt)
        a = IP()
        a.dst =  rec_pkt.src
        a.src =  rec_pkt.dst
        b = ICMP()
        send(a/b)
   
           
if __name__ == "__main__":
    main()

