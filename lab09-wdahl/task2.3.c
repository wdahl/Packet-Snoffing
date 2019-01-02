#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

struct ipheader {

        unsigned char      iph_ihl:4, 
                           iph_ver:4;
        unsigned char      iph_tos;
        unsigned short int iph_len;
        unsigned short int iph_ident;
        unsigned short int iph_flags:3, iph_offset:13;
        unsigned char      iph_ttl;
        unsigned char      iph_protocol:IPPROTO_ICMP;
        unsigned short int iph_chksum;
        struct in_addr     iph_sourceip;
        struct in_addr     iph_destip;

};

struct icmpheader{
  unsigned char icmp_type;
  unsigned char icmp_code;
  unsigned short int icmp_chksum;
  unsigned short int icmp_id;
  unsigned short int icmp_seq;
};

unsigned short in_chksum(unsigned short *buf, int length){
  unsigned short *w = buf;
  int nleft = length;
  int sum = 0;
  unsigned short temp = 0;

  while(nleft > 1){
    sum += *w++;
    nleft -= 2;
  }

  if (nleft == 1){
    *(u_char *)(&temp) = *(u_char *)w;
    sum += temp;
  }

  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  return (unsigned short)(~sum);
}

void send_raw_ip_packet(struct ipheader* ip){
  struct sockaddr_in dest_info;
  int enable = 1;

  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

  setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

  dest_info.sin_family = AF_INET;
  dest_info.sin_addr = ip->iph_destip;

  sendto(sock, ip, ntohs(ip->iph_len), 0, (struct sockaddr *)&dest_info, sizeof(dest_info));
  close(sock);
}

void spoof(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
  struct ipheader *ip;
  ip = (struct ipheader *) packet;

  const char buffer[ntohs(ip->iph_len)];
  int ip_header_len = ip->iph_len * 4;
  struct icmpheader *icmp = (struct icmpheader *) ((u_char *)ip + ip_header_len);

  memset((char*)buffer, 0, ntohs(ip->iph_len));
  memcpy((char*)buffer, ip, ntohs(ip->iph_len));
  
  struct ipheader *newip = (struct ipheader *)buffer;
  struct icmpheader *newicmp = (struct icmpheader *)(buffer + sizeof(struct ipheader));
  newicmp->icmp_type = 0;

  icmp->icmp_chksum=0;
  icmp->icmp_chksum = in_chksum((unsigned short *)icmp, sizeof(struct icmpheader));

  newip->iph_ttl = 50;

  newip->iph_sourceip = ip->iph_destip;
  newip->iph_destip = ip->iph_sourceip;

  newip->iph_protocol = IPPROTO_ICMP;

  newip->iph_len = htons(sizeof(struct ipheader) + sizeof(struct icmpheader));

  send_raw_ip_packet(ip);
  printf("sent packet\n");
}

void main(){
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "ip proto icmp src 10.0.2.7\0";
  bpf_u_int32 net;

  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);

  pcap_compile(handle, &fp, filter_exp, 0, net);
  pcap_setfilter(handle, &fp);

  pcap_loop(handle, -1, spoof, NULL);

  pcap_close(handle);
}