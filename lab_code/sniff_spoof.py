#!/usr/bin/python
from scapy.all import *

sniff_promisc = 1

def print_pkt(pkt):
        source_IP = pkt[IP].src
        destination_IP = pkt[IP].dst
        print("Source: " + source_IP + "\n")
        print("Destination: " + destination_IP +"\n")

        a = IP()
        a.src = destination_IP
        a.dst = source_IP
        b = ICMP()
        p = a/b
        #send(p)
def main():
        rec_pkt = sniff(monitor=True,filter='icmp',prn=print_pkt)

if __name__ == "__main__":
    main()

