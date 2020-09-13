#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netpacket/packet.h>
#include <pthread.h>


#include "common.h"
#include "connection.h"
#include "packet.h"

int modify_pkt(struct packet *pkt, char *before, int blen, char *after, int alen, struct connection *cnxtbl){
  pthread_mutex_lock(&mutex);
  if(pkt->icmphdr){}
  if(pkt->tcphdr){
//    struct connection *to = search_cnxentry(cnxtbl, pkt->iphdr->saddr, pkt->iphdr->daddr, pkt->iphdr->protocol, pkt->tcphdr->source, pkt->tcphdr->dest);
//    struct connection *from = search_cnxentry(cnxtbl, pkt->iphdr->daddr, pkt->iphdr->saddr, pkt->iphdr->protocol, pkt->tcphdr->dest, pkt->tcphdr->source);
// NEED CHANGE
    struct connection *to = search_cnxentry(cnxtbl, pkt);
    struct connection *from = search_cnxentry(cnxtbl, pkt);
    int i;
    int diff = alen-blen;
    int tot_diff = 0;
    for(i=0;i<(pkt->paylen-blen);i++){
    //test code
//      int r = xorshift()%100;
      int r = 0;
      if(0 <= r && r < (pkt->op.modify_per)){
    //test end
        if(memcmp(pkt->payload+i, before, blen) == 0){
          printf("size:%d\n", pkt->size);
          int size = pkt->paylen-i-blen;
          u_char tmp[size];
          memcpy(tmp, pkt->payload+i+blen, size);
          memcpy(pkt->payload+i, after, alen); memcpy(pkt->payload+i+alen, tmp, size);
        	pkt->size+=diff;
          pkt->iphdr->tot_len = htons(ntohs(pkt->iphdr->tot_len)+diff);
          pkt->paylen+=diff;
          i+=diff;
  	      tot_diff+=diff;
          printf("size:%d\n", pkt->size);
        }
      }
      if(!pkt->is_rtns){
        to->diff_seq+=tot_diff;
        from->diff_ack+=tot_diff;
      }
      pkt->tcphdr->check = calc_tcp_cksum(pkt->iphdr, pkt->tcphdr);
    }
  }
  if(pkt->udphdr){
    int i;
    int diff = alen-blen;
    for(i=0;i<(pkt->paylen-blen);i++){
      if(memcmp(pkt->payload+i, before, blen) == 0){
        int size = pkt->paylen-i-blen;
        u_char tmp[size];
        memcpy(tmp, pkt->payload+i+blen, size);
        memcpy(pkt->payload+i, after, alen);
        memcpy(pkt->payload+i+alen, tmp, size);
      	pkt->size+=diff;
        pkt->iphdr->tot_len = htons(ntohs(pkt->iphdr->tot_len)+diff);
        pkt->udphdr->len = htons(ntohs(pkt->udphdr->len)+diff);
        pkt->paylen+=diff;
        i+=diff;
      }
    }
    pkt->udphdr->check = calc_udp_cksum(pkt->iphdr, pkt->udphdr);
  }
  if(pkt->iphdr){
    pkt->iphdr->check = calc_ip_cksum(pkt->iphdr);
  }
  if(pkt->arphdr){}
  if(pkt->ethhdr){}
  pthread_mutex_unlock(&mutex);
  return 1;
}

