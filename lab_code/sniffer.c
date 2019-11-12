#include <pcap.h>
#include <stdio.h>
#include <netinet/ip.h>
/* This function will be invoked by pcap for each captured packet.
We can process each packet inside the function.
*/

/* IP Header */
struct ipheader {
  unsigned char      iph_ihl:4, //IP header length
                     iph_ver:4; //IP version
  unsigned char      iph_tos; //Type of service
  unsigned short int iph_len; //IP Packet length (data + header)
  unsigned short int iph_ident; //Identification
  unsigned short int iph_flag:3, //Fragmentation flags
                     iph_offset:13; //Flags offset
  unsigned char      iph_ttl; //Time to Live
  unsigned char      iph_protocol; //Protocol type
  unsigned short int iph_chksum; //IP datagram checksum
  struct  in_addr    iph_sourceip; //Source IP address 
  struct  in_addr    iph_destip;   //Destination IP address 
};

void got_packet(u_char *args, const struct pcap_pkthdr *header,
const u_char *packet)
{
printf("Source IP Address: %d \n Destination IP Address: %d\n",iph_sourceip, iph_destip);
}

int main(){             
                
pcap_t *handle;
char errbuf[PCAP_ERRBUF_SIZE];
struct bpf_program fp;
char filter_exp[] = "ip proto icmp";
bpf_u_int32 net;
// Step 1: Open live pcap session on NIC with name eth3
//NIC is first argument
char* dev = "eth1";

// Students needs to change "eth3" to the name
// found on their own machines (using ifconfig).
handle = pcap_open_live("eth1", BUFSIZ, 1, 1000, errbuf);
if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);                                                                                                                                                          }                                                                                                                                                                           
// Step 2: Compile filter_exp into BPF psuedo-code
pcap_compile(handle, &fp, filter_exp, 0, net);
pcap_setfilter(handle, &fp);
// Step 3: Capture packets
pcap_loop(handle, -1, got_packet, NULL);
pcap_close(handle); //Close the handle
return 0;
