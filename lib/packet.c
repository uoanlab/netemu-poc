#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/time.h>
#include<netinet/ether.h>
#include<netinet/ip_icmp.h>
#include<netinet/tcp.h>
#include<netinet/udp.h>
#include<pthread.h>
#include<unistd.h>
#include <inttypes.h>

#include"interface.h"
#include"common.h"
#include"packet.h"

#define EXTEND_FOR_BUGGY_SERVERS 80
#define DHCP_OPTIONS_BUFSIZE    308

struct packet *free_pkt_queue = NULL;

void init_pkt(struct packet *pkt){
  pkt->size = 0;
  memset(pkt->buf, 0, PKT_BUF_SIZE);
  pkt->ethhdr   = NULL;
  pkt->arphdr   = NULL;
  pkt->iphdr    = NULL;
  pkt->icmphdr  = NULL;
  pkt->tcphdr   = NULL;
  pkt->udphdr   = NULL;
  pkt->dhcphdr  = NULL;
  pkt->payload  = NULL;
  pkt->paylen   = 0;
  pkt->is_rtns  = 0;
  pkt->diff_seq = 0;
  pkt->diff_ack = 0;
  memset(&pkt->timestamp, 0, sizeof(struct timeval));
  memset(&pkt->op, 0, sizeof(struct operation));
  pkt->next          = NULL;
}

void init_tcphdr(struct tcphdr *tcp){
  tcp->source=0;
  tcp->dest=0;
  tcp->seq=0;
  tcp->ack_seq=0;
  tcp->res1=0;
  tcp->doff=0;
  tcp->fin=0;
  tcp->syn=0;
  tcp->rst=0;
  tcp->psh=0;
  tcp->ack=0;
  tcp->urg=0;
  tcp->res2=0;
  tcp->doff=0;
  tcp->res1=0;
  tcp->res2=0;
  tcp->urg=0;
  tcp->ack=0;
  tcp->psh=0;
  tcp->rst=0;
  tcp->syn=0;
  tcp->fin=0;
  tcp->window=0;
  tcp->check=0;
  tcp->urg_ptr=0;
}

void init_iphdr(struct iphdr *ip){
  unsigned int ihl=4;
  unsigned int version=4;
  u_int8_t tos=60;
  u_int16_t tot_len=63;
  u_int16_t id=6;
  u_int16_t frag_off=0;
  u_int8_t ttl=0;
  u_int8_t protocol=6;
  u_int16_t check=0;
  u_int32_t saddr=0;
  u_int32_t daddr=0;
}

void init_ethhdr(struct ethhdr *eth){
  unsigned char h_dest[ETH_ALEN]="";
  unsigned char h_source[ETH_ALEN]="";
  unsigned short h_proto=0x0008;
}


struct packet *malloc_pkt(){
  struct packet *pkt;
  if(free_pkt_queue){
    pthread_mutex_lock(&mutex);
    pkt = free_pkt_queue;
    free_pkt_queue = free_pkt_queue->next;
    pthread_mutex_unlock(&mutex);
  }
  else{
    pkt = malloc(sizeof(struct packet));
  }
  init_pkt(pkt);
  return pkt;
}

void free_pkt(struct packet *pkt){
  pthread_mutex_lock(&mutex);
  pkt->next = free_pkt_queue;
  free_pkt_queue = pkt;
  pthread_mutex_unlock(&mutex);
}
void proc_pkt(struct packet *pkt){
  gettimeofday(&pkt->timestamp, NULL);

  u_char *hdr = pkt->buf;
  pkt->ethhdr = (struct ethhdr *)hdr;
  hdr+=ETHER_HDR_LEN;
  u_int16_t etype = ntohs(pkt->ethhdr->h_proto);
  switch(etype){
  case ETHERTYPE_ARP:
    pkt->arphdr = (struct arphdr *)hdr;
    break;
  case ETHERTYPE_IP:
    pkt->iphdr = (struct iphdr *)hdr;
    hdr+=(pkt->iphdr->ihl<<2);
    break;
  default:
    break;
  }
  if(pkt->iphdr){
    switch(pkt->iphdr->protocol){
    case IPPROTO_ICMP:
      pkt->icmphdr = (struct icmphdr *)hdr;
      break;
    case IPPROTO_TCP:
      pkt->tcphdr = (struct tcphdr *)hdr;
      hdr += (pkt->tcphdr->doff<<2);
      pkt->payload = hdr;
      pkt->paylen = ntohs(pkt->iphdr->tot_len)-(pkt->iphdr->ihl<<2)-(pkt->tcphdr->doff<<2);
      break;
    case IPPROTO_UDP:
      pkt->udphdr = (struct udphdr *)hdr;
      hdr+=(sizeof(struct udphdr));
      pkt->payload = hdr;
      pkt->paylen = ntohs(pkt->udphdr->len)-sizeof(struct udphdr);
      switch(ntohs(pkt->udphdr->uh_dport)){
        case 67:
        case 68:
          pkt->dhcphdr = (struct dhcp_packet *)pkt->payload;
          break;
      }
      break;
    default:
      break;
    }
  }
}
int copy_pkt(struct packet *copy, struct packet *origin){
  copy->size = origin->size;
  memcpy(copy->buf, origin->buf, PKT_BUF_SIZE);
  proc_pkt(copy);
  memcpy(&copy->timestamp, &origin->timestamp, sizeof(struct timeval));
  copy_operation(&copy->op, &origin->op);
  copy->is_rtns = origin->is_rtns;
  copy->diff_seq = origin->diff_seq;
  copy->diff_ack = origin->diff_ack;
  copy->next = NULL;
  return 1;
}

void print_ethhdr(struct ethhdr *ethhdr){
  char macstr[18];
  printf("======== ethernet header ========\n");
  u_char *smac = ethhdr->h_source;
  mactostr(smac, macstr);
  printf("Src Mac Addr -> %s\n", macstr);
  u_char *dmac = ethhdr->h_dest;
  mactostr(dmac, macstr);
  printf("Dst Mac Addr -> %s\n", macstr);
  printf("Type         -> 0x%04x", ntohs(ethhdr->h_proto));
  switch(ntohs(ethhdr->h_proto)){
  case ETHERTYPE_PUP:
    printf("(Xerox PUP)\n");
    break;
  case ETHERTYPE_IP:
    printf("(IP)\n");
    break;
  case ETHERTYPE_ARP:
    printf("(ARP)\n");
    break;
  case ETHERTYPE_REVARP:
    printf("(Reverse ARP)\n");
    break;
  case 0x86dd:
    printf("(IPv6)\n");
    break;
  default:
    printf("(Unknown)\n");
    break;
  }
}
void print_arphdr(struct arphdr *arphdr){
  static char *op[]={
    "undefined",
    "ARP request",
    "ARP reply",
    "RARP request",
    "RARP reply",
    "undefined",
    "undefined",
    "undefined",
    "InARP request",
    "InArp reply",
    "(ATM)ARP NAK",
  };
  char ipstr[16];
  char macstr[16];
  printf("========    arp header   ========\n");
  u_char *smac = (u_char *)arphdr+sizeof(struct arphdr);
  mactostr(smac, macstr);
  printf("Src Mac Addr -> %s\n", macstr);
  in_addr_t sip = *(in_addr_t *)(smac+arphdr->ar_hln);
  iptostr(sip, ipstr);
  printf("Src IP  Addr -> %s\n", ipstr);
  u_char *tmac = (smac+arphdr->ar_hln)+arphdr->ar_pln;
  mactostr(tmac, macstr);
  printf("Tgt Mac Addr -> %s\n", macstr);
  in_addr_t tip = *(in_addr_t *)(tmac+arphdr->ar_hln);
  iptostr(tip, ipstr);
  printf("Tgt IP  Addr -> %s\n", ipstr);
  u_short opcode = ntohs(arphdr->ar_op);
  printf("Opcode       -> %s\n", (opcode<=10)?op[opcode]:"undefined");
}
void print_iphdr(struct iphdr *iphdr){
  static char *proto[]={
    "undefined",
    "ICMP",
    "IGMP",
    "undefined",
    "IPIP",
    "undefined",
    "TCP",
    "undefined",
    "EGP",
    "undefined",
    "undefined",
    "undefined",
    "PUP",
    "undefined",
    "undefined",
    "undefined",
    "undefined",
    "UDP",
  };
  char ipstr[16];
  printf("========    ip header    ========\n");
  printf("Header Size -> %d bytes\n", (iphdr->ihl<<2));
  printf("Total  Size -> %d bytes\n", ntohs(iphdr->tot_len));
  printf("TTL         -> %d\n", iphdr->ttl);
  printf("Protocol    -> %d(%s)\n", iphdr->protocol, (iphdr->protocol<=17)?proto[iphdr->protocol]:"undefined");
  iptostr(iphdr->saddr, ipstr);
  printf("Src IP Addr -> %s\n", ipstr);
  iptostr(iphdr->daddr, ipstr);
  printf("Dst IP Addr -> %s\n", ipstr);
  printf("CheckSum    -> 0x%04x\n", iphdr->check);
}
void print_icmphdr(struct icmphdr *icmphdr){
  static char *type[]={
    "Echo Reply",
    "undefined",
    "undefined",
    "Destination Unreachable",
    "Source Quench",
    "Redirect",
    "undefined",
    "undefined",
    "Echo Request",
    "Router Adverisement",
    "Router Selection",
    "Time Exceeded for Datagram",
    "Parameter Problem on Datagram",
    "Timestamp Request",
    "Timestamp Reply",
    "Information Request",
    "Information Reply",
    "Address Mask Request",
    "Address Mask Reply",
  };
  printf("========   icmp header   ========\n");
  printf("Type -> %s", (icmphdr->type<=18)?type[icmphdr->type]:"undefined");
  printf("Code -> %d\n", icmphdr->code);
}
void print_mini_tcphdr(struct tcphdr *tcphdr){
  printf("=======  mini  tcp header =======\n");
  printf("Src Port   -> %d\n", ntohs(tcphdr->source));
  printf("Dst Port   -> %d\n", ntohs(tcphdr->dest));
  printf("Seq Number -> %u\n", ntohl(tcphdr->seq));
  printf("Ack Number -> %u\n", ntohl(tcphdr->ack_seq));
}
void print_tcphdr(struct tcphdr *tcphdr){
  printf("========    tcp header   ========\n");
  printf("Src Port   -> %d\n", ntohs(tcphdr->source));
  printf("Dst Port   -> %d\n", ntohs(tcphdr->dest));
  printf("Seq Number -> %u\n", ntohl(tcphdr->seq));
  printf("Ack Number -> %u\n", ntohl(tcphdr->ack_seq));
  char flags = (tcphdr->urg<<5)+(tcphdr->ack<<4)+(tcphdr->psh<<3)+(tcphdr->rst<<2)+(tcphdr->syn<<1)+(tcphdr->fin);
  printf("CheckSum   -> 0x%04x\n", tcphdr->check);
  printf("Flags      -> 0x%x\n",flags);
  printf("URG        -> %d\n", tcphdr->urg);
  printf("ACK        -> %d\n", tcphdr->ack);
  printf("PSH        -> %d\n", tcphdr->psh);
  printf("RST        -> %d\n", tcphdr->rst);
  printf("SYN        -> %d\n", tcphdr->syn);
  printf("FIN        -> %d\n", tcphdr->fin);
}
void print_udphdr(struct udphdr *udphdr){
  printf("========    udp header   ========\n");
  printf("Src Port -> %d\n", ntohs(udphdr->source));
  printf("Dst Port -> %d\n", ntohs(udphdr->dest));
  printf("Length   -> %d\n", ntohs(udphdr->len));
}
void print_payload(u_char *payload, int paylen){
  printf("========     payload     ========\n");
  int i;
  for(i=1;i<=paylen;i++){
    if(32<=(int)payload[i-1] && (int)payload[i-1]<=126)
      printf("%c ", payload[i-1]);
    else
      printf(". ");
    if(i%16==0) printf("\n");
  }
  printf("\n");
}
void print_pkt(struct packet *pkt){
  printf("++++++++++++ packet +++++++++++++\n");
  if(pkt->ethhdr)  print_ethhdr(pkt->ethhdr);
  if(pkt->arphdr)  print_arphdr(pkt->arphdr);
  if(pkt->iphdr)   print_iphdr(pkt->iphdr);
  if(pkt->icmphdr) print_icmphdr(pkt->icmphdr);
  if(pkt->tcphdr)  print_tcphdr(pkt->tcphdr);
  if(pkt->udphdr)  print_udphdr(pkt->udphdr);
  if(pkt->dhcphdr) print_dhcphdr(pkt->dhcphdr);
  if(pkt->payload) print_payload(pkt->payload, pkt->paylen);
  printf("+++++++++++++++++++++++++++++++++\n|\n|\n");
}
void print_buf(u_char *buf, int size){
  int i;
  for(i=1;i<=size;i++){
    if((i-1)%16==0) printf("%04x-> ", i-1);
    printf("%02x ", *(buf+i-1));
    if(i%16==0) printf("\n");
    else if(i%8==0) printf(" ");
  }
  printf("\n");
}
void enqueue(struct packet *queue, struct packet *pkt){
  pthread_mutex_lock(&mutex);
  pkt->next = queue->next;
  queue->next = pkt;
  pthread_mutex_unlock(&mutex);

}

struct packet *dequeue(struct packet *queue){
  struct packet *q;
  if(queue->next){
    pthread_mutex_lock(&mutex);
    struct packet *pkt_last;
    for(q=queue; q->next; q=q->next){
      pkt_last = q;
    }
    pkt_last->next = NULL;
    pthread_mutex_unlock(&mutex);
    return q;
  }
  else{
    return NULL;
  }
}
void push(struct packet **stack, struct packet *pkt){
  pthread_mutex_lock(&mutex);
  pkt->next = (*stack);
  (*stack) = pkt;
  pthread_mutex_unlock(&mutex);
}
struct packet *pop(struct packet **stack){
  if(*stack){
    struct packet *pkt;
    pthread_mutex_lock(&mutex);
    pkt = (*stack);
    (*stack) = (*stack)->next;
    pthread_mutex_unlock(&mutex);
  }
  else{
    return NULL;
  }
}
void repl_ethhdr(struct ethhdr *ethhdr, u_char *smac, u_char *dmac){
  memcpy(ethhdr->h_source, smac, ETH_ALEN);
  memcpy(ethhdr->h_dest  , dmac, ETH_ALEN);
}
u_int16_t calc_cksum(u_char *buf, int size){
  u_int32_t cksum = 0;
  int i;
  for(i=0;i<size;i+=2){
    cksum += *(u_int16_t *)(buf+i);
    if(cksum&0x000f0000) cksum = (cksum&0xffff)+(cksum>>16);
  }
  return ~cksum;
}
u_int16_t calc_ip_cksum(struct iphdr *iphdr){
  iphdr->check = 0;
  return calc_cksum((u_char *)iphdr, 20);
}
u_int16_t calc_tcp_cksum(struct iphdr *iphdr, struct tcphdr *tcphdr){
  tcphdr->check = 0;
  u_short len = ntohs(iphdr->tot_len)-(iphdr->ihl<<2);
  int cksize = ((len+12)%2) ? (len+12+1) : (len+12);
  u_char ckbuf[cksize];
  memset(ckbuf, 0, cksize);
  u_char *ptr = ckbuf;
  int IP_ADDR_LEN = sizeof(in_addr_t);
  memcpy(ptr, &iphdr->saddr, IP_ADDR_LEN);
  ptr+=IP_ADDR_LEN;
  memcpy(ptr, &iphdr->daddr, IP_ADDR_LEN);
  ptr+=IP_ADDR_LEN;
  memcpy(ptr, "\x00\x06", 2);
  ptr+=2;
  u_short nlen = htons(len);
  memcpy(ptr, &nlen, sizeof(u_short));
  ptr+=(sizeof(u_short));
  memcpy(ptr, (u_char *)tcphdr, len);

  return calc_cksum(ckbuf, cksize);
}
u_int16_t calc_udp_cksum(struct iphdr *iphdr, struct udphdr *udphdr){
  udphdr->check = 0;
  short len = ntohs(iphdr->tot_len)-(iphdr->ihl<<2);
  int cksize = ((len+12)%2) ? (len+12+1) : (len+12);
  u_char ckbuf[cksize];
  memset(ckbuf, 0, cksize);
  u_char *ptr = ckbuf;
  int IP_ADDR_LEN = sizeof(in_addr_t);
  memcpy(ptr, &iphdr->saddr, IP_ADDR_LEN);
  ptr+=IP_ADDR_LEN;
  memcpy(ptr, &iphdr->daddr, IP_ADDR_LEN);
  ptr+=IP_ADDR_LEN;
  memcpy(ptr, "\x00\x11", 2);
  ptr+=2;
  short nlen = htons(len);
  memcpy(ptr, &nlen, sizeof(short));
  ptr+=(sizeof(short));
  memcpy(ptr, (u_char *)udphdr, len);

  return calc_cksum(ckbuf, cksize);
}

unsigned short checksum(unsigned short *ptr,int nbytes) {
    register long sum;
    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        sum += *(u_int8_t *)ptr;
    }
    sum = (sum>>16)+(sum & 0xffff);
    sum = (sum>>16)+(sum & 0xffff);
    return ~sum;
}

void print_dhcphdr(struct dhcp_packet *dhcphdr){
  char ipstr[16];
  printf("========  dhcp header    ========   \n");
  printf("op         :%d\n", dhcphdr->op         );
  printf("htype      :%d\n", dhcphdr->htype      );
  printf("hlen       :%d\n", dhcphdr->hlen       );
  printf("hops       :%d\n", dhcphdr->hops       );
  printf("xid        :%"PRIx32"\n", dhcphdr->xid );
  printf("secs       :%d\n", dhcphdr->secs       );
  printf("secs       :%"PRIx16"\n", dhcphdr->secs);
  printf("flags      :%"PRIx16"\n",dhcphdr->flags);
  iptostr(dhcphdr->ciaddr, ipstr);
  printf("ciaddr     :%s\n", ipstr               );
  iptostr(dhcphdr->yiaddr, ipstr);
  printf("yiaddr     :%s\n", ipstr               );
  iptostr(dhcphdr->siaddr_nip, ipstr             );
  printf("siaddr_nip :%s\n", ipstr               );
  iptostr(dhcphdr->gateway_nip, ipstr            );
  printf("gateway_nip:%s\n", ipstr               );
  char macstr[16];
  mactostr(dhcphdr->chaddr+6, macstr);
  printf("chaddr     :%s\n", macstr);
//  printf("sname      :%s\n", dhcphdr->sname[64]  );
//  printf("file       :%s\n", dhcphdr->file[128]  );
}

void print_queue(struct packet *queue){
  struct packet *pkt;
  for(pkt = queue; pkt->next!=NULL; pkt = pkt->next)
    print_pkt(pkt);
}

int count_pkt_in_queue(struct packet *queue){
  int counter=0;
  struct packet *pkt;
  for(pkt=queue;pkt;pkt=pkt->next) counter++;
  return counter;
}