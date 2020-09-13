#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <unistd.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <time.h>
#include <pcap.h>

#include "interface.h"
#include "common.h"
#include "packet.h"
#include "packet_handler.h"
#include "dhcp.h"

void dhcp_discover(struct packet *pkt, struct interface *iface){
  int size = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dhcp_packet);
  char *buf;
  //printf("DHCP DISCOVER\n");
  if((buf = malloc(size)) == NULL){
    perror("malloc");
  }
  struct packet *request;
  request = malloc(sizeof(struct packet));
  init_pkt(request);
  request->ethhdr  = (struct ethhdr *)buf;
  request->iphdr   = (struct iphdr *)(buf+sizeof(struct ethhdr));
  request->udphdr  = (struct udphdr *)(buf+sizeof(struct ethhdr)+sizeof(struct iphdr));
  request->dhcphdr = (struct dhcp_packet *)(buf+sizeof(struct ethhdr)+ sizeof(struct iphdr) + sizeof(struct udphdr));
  set_eth_header(request, pkt, iface);
  struct in_addr src, dst, subnetmask;
  inet_aton("255.255.255.255", &dst);
  set_ip_header(request, iface->ipaddr, &dst);
  int dhcp_mt = check_dhcp_message_type(pkt);
  if(strcmp(iface->name, "eth1"))
    inet_aton("192.168.56.10", &src);
  else
    inet_aton("192.168.57.10", &src);
  inet_aton("255.255.255.0", &subnetmask);
  int dport=68, sport=67;
  switch(dhcp_mt){
    case 1: 
      printf("OFFER\n");
      set_dhcp(request, 2, iface->ipaddr+(11*64*64*64*64), &src, &subnetmask, pkt, iface);
      break;
    case 3: 
      printf("ACK\n");
      set_dhcp(request, 5, iface->ipaddr+(11*64*64*64*64), &src, &subnetmask, pkt, iface);
      break;
    default: 
      printf("This message is not relevance to dhcp protocol");  
      set_dhcp(request, 5, iface->ipaddr+(11*64*64*64*64), &src, &subnetmask, pkt, iface);
      break;
  }
  set_udp_header(request, sport, dport, &src, &dst);
  print_pkt(request);
  if(send(iface->skfd, buf, size, 0) < 0){
    perror("SEND");
  }
  free(buf);
  free(request);
}

void set_eth_header(struct packet *request, struct packet *pkt, struct interface *iface){
  memcpy(request->ethhdr->h_source, iface->macaddr,  ETH_ALEN);
  memcpy(request->ethhdr->h_dest, pkt->ethhdr->h_source, ETH_ALEN);
  request->ethhdr->h_proto = pkt->ethhdr->h_proto;
}

void set_ip_header(struct packet *request,  u_int32_t src, struct in_addr *dst){
  //printf("SET IP HEADER\n");
  request->iphdr->version = 4;
  request->iphdr->ihl = 5;
  request->iphdr->tos = 16;
  request->iphdr->tot_len = htons(sizeof(struct iphdr)+sizeof(struct udphdr)+sizeof(struct dhcp_packet));
  request->iphdr->id = htons(0);
  request->iphdr->frag_off = htons(0);
  request->iphdr->ttl = 0x80;
  request->iphdr->protocol = IPPROTO_UDP;
  request->iphdr->saddr = src;
  request->iphdr->daddr = dst->s_addr;
  request->iphdr->check = 0;
  request->iphdr->check = calc_ip_cksum(request->iphdr);
  //ip->check = calc_ip_cksum((unsigned short *) (request+sizeof(struct ether_header)), ip->ihl*4);
}

void set_udp_header(struct packet *pkt, int sport, int dport, struct in_addr *src, struct in_addr *dst){
//    printf("udp test\n");
    struct udphdr *udp = pkt->udphdr;
    struct pseudo_header pse;
    udp->uh_sport = htons(sport);
    udp->uh_dport = htons(dport);
    udp->uh_ulen = htons(sizeof(struct udphdr)+sizeof(struct dhcp_packet));
    udp->uh_sum = 0;

    pse.saddr = src->s_addr;
    pse.daddr = dst->s_addr;
    pse.reserved = 0;
    pse.protocol = IPPROTO_UDP;
    pse.len = htons(sizeof(struct udphdr) + sizeof(struct dhcp_packet));

    char *pseudogram;
    int psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + sizeof(struct dhcp_packet);
    pseudogram = malloc(psize);
    memcpy(pseudogram , (char*) &pse , sizeof (struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), udp, sizeof(struct udphdr) + sizeof(struct dhcp_packet));
    udp->uh_sum = calc_udp_cksum(pkt->iphdr, udp);
    free(pseudogram);
}

void set_dhcp(struct packet *request, int dhcp_type, uint32_t dst, struct in_addr *siaddr, struct in_addr *subnetmask, struct packet *pkt, struct interface *iface){
  struct dhcp_packet *org_dhcp;
  //printf("SET DHCP HEADER\n");
  request->dhcphdr->op = 0x02;
  request->dhcphdr->htype = 0x01;
  request->dhcphdr->hlen = 0x06;
  request->dhcphdr->hops = 0x01;
  request->dhcphdr->xid = pkt->dhcphdr->xid;
  request->dhcphdr->secs = 0;
  request->dhcphdr->flags = 0;
  request->dhcphdr->ciaddr = (uint32_t)0;
  request->dhcphdr->yiaddr = (uint32_t)dst;
  request->dhcphdr->siaddr_nip = (uint32_t)0;
  request->dhcphdr->gateway_nip = (uint32_t)0;
  memcpy(request->dhcphdr->chaddr, iface->macaddr, ETH_ALEN);
  for(int i=0; i<64; i++) request->dhcphdr->sname[i] =0;
  for(int i=0; i<128; i++) request->dhcphdr->file[i] =0;
  /***set DHCP Message Type****/
  uint8_t cookie[4];
  cookie[0] = 99;
  cookie[1] = 130;
  cookie[2] = 83;
  cookie[3] = 99;

  uint8_t option_code[60];
  memset(option_code, 0, sizeof(option_code));
  /***set DHCP Message Type****/
  option_code[0] = 53;
  option_code[1] = 1; 
  option_code[2] = (uint8_t)dhcp_type;
  option_code[3] = 255;
  /***DHCP Server identifier***/
//  option_code[3] = 54;
  option_code[4] = 4; 
  memcpy(&option_code[5],&siaddr->s_addr,option_code[4]);
  /*** IP address lease time ***/
  int lease_time = 600;
  unsigned char* cp;
  option_code[9] = 51;
  option_code[10] = 4; 
  cp = (unsigned char *)&lease_time;
  for(int i=0;i<4;i++){
      option_code[14-i]=(uint8_t)(*cp++);
  }
  /*** Subnet Mask ***/
  option_code[15] = 1; 
  option_code[16] = 4; 
  memcpy(&option_code[17],&subnetmask->s_addr,option_code[16]);
  /*** Router ***/
  option_code[21] = 3; 
  option_code[22] = 4; 
  memcpy(&option_code[23],&siaddr->s_addr,option_code[22]);
  /*** domain name ***/
  char *domain="example.org"; 
  option_code[27] = 15; 
  option_code[28] = strlen(domain); 
  memcpy(&option_code[29],domain,option_code[28]);
  /**LAST**/
  option_code[29+strlen(domain)]=255;
  memcpy(&request->dhcphdr->cookie, &cookie, 4);
  memcpy(&request->dhcphdr->options, &option_code, 4);
}

int check_dhcp_message_type(struct packet *pkt){
  char ipstr[16];
  if(pkt->dhcphdr->options[2] ==  1){
    return 1;
  }
  else{
    return 3;
  }
}

