#!/usr/bin/python
from scapy.all import *

def print_pkt(pkt):
        pkt.show()

def main():
        rec_pkt = sniff(iface="eth1",filter='icmp',prn=print_pkt)
        a = IP()
        a[IP].dst =  rec_pkt.getlayer(IP).src
        a[IP].src =  rec_pkt.getlayer(IP).dst
        b = ICMP()
        send(a/b)
   
           
if __name__ == "__main__":
    main()

# # receive a packet
# while True:
# 	packet = s.recvfrom(65565)
	
# 	#packet string from tuple
# 	packet = packet[0]
	
# 	#take first 20 characters for the ip header
# 	ip_header = packet[0:20]
	
# 	#now unpack them :)
# 	iph = unpack('!BBHHHBBH4s4s' , ip_header)
	
# 	version_ihl = iph[0]
# 	version = version_ihl &gt;&gt; 4
# 	ihl = version_ihl &amp; 0xF
	
# 	iph_length = ihl * 4
	
# 	ttl = iph[5]
# 	protocol = iph[6]
# 	s_addr = socket.inet_ntoa(iph[8]);
# 	d_addr = socket.inet_ntoa(iph[9]);
	
# 	print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + 
#         ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + 
#         ' Destination Address : ' + str(d_addr)

