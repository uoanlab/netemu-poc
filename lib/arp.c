#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "interface.h" 
#include "arp.h"
#include "common.h"
#include "packet.h"

void proc_arp(struct interface *iface, struct arphdr *arphdr){
  uint16_t opcode = ntohs(arphdr->ar_op);
  u_char *smac = (u_char *)(arphdr+1);
  in_addr_t sip = *(in_addr_t *)(smac+arphdr->ar_hln);
  if(opcode == ARPOP_REPLY){
    struct arpentry *entry = make_arpentry(sip, smac);

    if(!search_arpentry(iface->arptbl, entry->ipaddr)){
      add_arpentry(iface->arptbl, entry);
    }
    else{
      update_arpentry(iface->arptbl, entry);
    }
  }
  else if(opcode == ARPOP_REQUEST){
    struct packet *reply = make_arpreply(iface->macaddr, iface->ipaddr, smac, sip);
    enqueue(iface->queue, reply);
  }
}

void print_arptbl(struct arpentry *arptbl){
  char ipstr[16];
  char macstr[16];
  printf("==== arp table ====\n");
  struct arpentry *e;

  for(e=arptbl->next; e; e=e->next){
    iptostr(e->ipaddr, ipstr);
    printf("ipaddr: %-15s,", ipstr);
    mactostr(e->macaddr, macstr);
    printf("macaddr: %s\n", macstr);
  }
  printf("===================\n");
}

struct arpentry *make_arpentry(in_addr_t ipaddr, u_char *macaddr){
  struct arpentry *entry = malloc(sizeof(struct arpentry));
  entry->ipaddr = ipaddr;
  memcpy(entry->macaddr, macaddr, ETHER_ADDR_LEN);
  return entry;
}

void add_arpentry(struct arpentry *arptbl, struct arpentry *entry){
  pthread_mutex_lock(&mutex);
  entry->next = arptbl->next;
  arptbl->next = entry;
  pthread_mutex_unlock(&mutex);
}

void update_arpentry(struct arpentry *arptbl, struct arpentry *entry){}

struct arpentry *search_arpentry(struct arpentry *arptbl, in_addr_t search_ip){
  struct arpentry *e;
  for(e=arptbl->next; e; e=e->next){
    if(e->ipaddr == search_ip){
      return e;
    }
  }
  return NULL;
}

struct packet * make_arpreply(u_char *srcmac, in_addr_t srcip, u_char *dstmac, in_addr_t dstip){
  struct packet *reply = malloc_pkt();
  /* make ether header */
  reply->ethhdr = (struct ethhdr *)reply->buf;
  memcpy(reply->ethhdr->h_source, srcmac, ETHER_ADDR_LEN);
  memcpy(reply->ethhdr->h_dest  , dstmac, ETHER_ADDR_LEN);
  reply->ethhdr->h_proto = htons(ETHERTYPE_ARP);
  reply->size += ETHER_HDR_LEN;
  /* make arp reply */
  reply->arphdr = (struct arphdr *)(reply->ethhdr+1);
  reply->arphdr->ar_hrd = htons(ARPHRD_ETHER);
  reply->arphdr->ar_pro = htons(ETHERTYPE_IP);
  reply->arphdr->ar_hln = ETHER_ADDR_LEN;
  reply->arphdr->ar_pln = sizeof(in_addr_t);
  reply->arphdr->ar_op  = htons(ARPOP_REPLY);
  u_char *smac, *sip, *tmac, *tip;
  smac = (u_char *)reply->arphdr+sizeof(struct arphdr);
  sip  = smac + reply->arphdr->ar_hln;
  tmac = sip  + reply->arphdr->ar_pln;
  tip  = tmac + reply->arphdr->ar_hln;
  memcpy(smac, srcmac, reply->arphdr->ar_hln);
  memcpy(sip , &srcip, reply->arphdr->ar_pln);
  memcpy(tmac, dstmac, reply->arphdr->ar_hln);
  memcpy(tip , &dstip, reply->arphdr->ar_pln);
  reply->size += (sizeof(struct arphdr)+2*(reply->arphdr->ar_hln+reply->arphdr->ar_pln));
  gettimeofday(&reply->timestamp, NULL);

  return reply;
}

void make_arprequest(struct packet *request, u_char *srcmac, in_addr_t srcip, in_addr_t tgtip){
  /* make ether header */
  request->ethhdr = (struct ethhdr *)request->buf;
  memcpy(request->ethhdr->h_source, srcmac           , ETHER_ADDR_LEN);
  memcpy(request->ethhdr->h_dest  , MACADDR_BROADCAST, ETHER_ADDR_LEN);
  request->ethhdr->h_proto = htons(ETHERTYPE_ARP);
  request->size = ETHER_HDR_LEN;
  /* make arp request */
  request->arphdr = (struct arphdr *)(request->ethhdr+1);
  request->arphdr->ar_hrd = htons(ARPHRD_ETHER);
  request->arphdr->ar_pro = htons(ETHERTYPE_IP);
  request->arphdr->ar_hln = ETHER_ADDR_LEN;
  request->arphdr->ar_pln = sizeof(in_addr_t);
  request->arphdr->ar_op  = htons(ARPOP_REQUEST);
  u_char *smac, *sip, *tmac, *tip;
  smac = ((u_char *)request->arphdr)+sizeof(struct arphdr);
  sip  = smac + request->arphdr->ar_hln;
  tmac = sip  + request->arphdr->ar_pln;
  tip  = tmac + request->arphdr->ar_hln;
  memcpy(smac, srcmac, request->arphdr->ar_hln);
  memcpy(sip , &srcip, request->arphdr->ar_pln);
  memcpy(tmac, MACADDR_NONE, request->arphdr->ar_hln);
  memcpy(tip , &tgtip      , request->arphdr->ar_pln);
  request->size+=(sizeof(struct arphdr)+2*(request->arphdr->ar_hln+request->arphdr->ar_pln));
  gettimeofday(&request->timestamp, NULL);
}


