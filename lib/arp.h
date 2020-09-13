#pragma once
#define MACADDR_NONE      "\x00\x00\x00\x00\x00\x00"
#define MACADDR_BROADCAST "\xff\xff\xff\xff\xff\xff"

struct arpentry{
  u_char macaddr[6];
  in_addr_t ipaddr;
  struct arpentry *next;
};

//struct arpentry{
//  struct arpentry *entries;
//};


void init_arptbl(struct arpentry *arptbl);
void print_arptbl(struct arpentry *arptbl);
struct arpentry *make_arpentry(in_addr_t ipaddr, u_char *macaddr);
void add_arpentry(struct arpentry *arptbl, struct arpentry *entry);
void update_arpentry(struct arpentry *arptbl, struct arpentry *entry);
struct arpentry *search_arpentry(struct arpentry *arptbl, in_addr_t search_ip);
struct packet *make_arpreply(u_char *srcmac, in_addr_t srcip, u_char *dstmac, in_addr_t dstip);
void make_arprequest(struct packet *request, u_char *srcmac, in_addr_t srcip, in_addr_t tgtip);
void proc_arp(struct interface *iface, struct arphdr *arphdr);
