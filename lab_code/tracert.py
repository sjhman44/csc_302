#1/usr/bin/python
from scapy.all import *

def print_pkt(pkt):
        pkt.show()

def main():
        a = IP()
        a.dst =  '8.8.8.8'
#       a.src = '128.105.146.158'
        b = ICMP()

        for i in range(5):
                a.ttl = i
                resc = sr(a/b)
                #pkt = sniff(filter='icmp',prn=print_pkt)
                resc[0].summary()
if __name__ == "__main__":
    main()
