#include<stdio.h>
#include<stdlib.h>
#include<arpa/inet.h>

#include"interface.h"
#include"routing.h"
#include"common.h"

void init_rtgtbl(struct routingentry *rtgtbl){
  rtgtbl->next = NULL;
}
//
void print_rtgtbl(struct routingentry *rtgtbl){
  printf("=========================== routing table ===========================\n");
  printf("|%-16s|%-16s|%-16s|%-16s|\n","ipaddr","netmask","nexthop", "interface");
  for(int i=0; i<4; i++)
    printf("|----------------");
  printf("|\n");
  struct routingentry *e;
  for(e = rtgtbl->next; e != NULL; e=e->next){
    char ipstr[16];
    iptostr(e->ipaddr, ipstr);
    printf("|%-16s|", ipstr);
    iptostr(e->ipmask, ipstr);
    printf("%-16s|", ipstr);
    iptostr(e->nexthop, ipstr);
    printf("%-16s|",ipstr);
    printf("%-16s|\n",e->iface->name);
  }
  for(int i=0; i<4; i++)
    printf("|----------------");
  printf("|\n");
}

struct routingentry *make_rtgentry(struct interface *iface){
  struct routingentry *entry = malloc(sizeof(struct routingentry));
  entry->ipaddr  = iface->ipaddr&iface->ipmask;
  entry->ipmask  = iface->ipmask;
  entry->nexthop = iface->ipaddr;
  entry->iface = iface;
  return entry;
}

void add_rtgentry(struct routingentry *rtgtbl, struct routingentry *entry){
  struct routingentry *e;
  for(e = rtgtbl; e->next != NULL; e=e->next){}
  entry->next = e->next;
  e->next = entry;
  printf("name: %s\n", entry->iface->name);
}

struct routingentry *search_route(struct routingentry *rtgtbl, in_addr_t ipaddr){
  /* ロンゲストマッチ未実装 */
  struct routingentry *e;
  for(e=rtgtbl->next; e!=NULL; e=e->next){
    if((ipaddr & e->ipmask) == (e->ipaddr & e->ipmask)){
/* debug print*/
      char ipstr[16];
      iptostr(e->ipaddr, ipstr);
//      printf("e->ipaddr:%s\n", ipstr);
      iptostr(e->ipmask, ipstr);
//      printf("e->ipmask:%s\n", ipstr);
      iptostr(ipaddr, ipstr);
//      printf("ipaddr   :%s\n", ipstr);
//      printf("\n");
//======================================
      return e;
    }
  }
  return NULL;
}
