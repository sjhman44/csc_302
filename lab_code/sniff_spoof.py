#!/usr/bin/python
from scapy.all import *

def print_pkt(pkt):
        pkt.show()

def main():
        rec_pkt = sniff(iface="ether1",filter='icmp',prn=print_pkt)
        a = IP()
        a[IP].dst =  rec_pkt.getlayer(IP).src
        a[IP].src =  rec_pkt.getlayer(IP).dst
        b = ICMP()
        send(a/b)
   
           
if __name__ == "__main__":
    main()

