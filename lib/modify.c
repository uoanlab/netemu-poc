#include <stdio.h>
#include <stdlib.h>
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
#include "interface.h"
#include "modify.h"

int modify_pkt(struct packet *pkt, char *before, int blen, char *after, int alen, struct connection *cnxtbl, struct interface *iface){
  pthread_mutex_lock(&mutex);
  if(pkt->icmphdr){}
  if(pkt->tcphdr){
    struct connection *to = search_cnxentry(cnxtbl, pkt);
    struct connection *from = search_cnxentry(cnxtbl, pkt);
    int i;
    int diff = alen-blen;
    int tot_diff = 0;
    for(i=0;i<(pkt->paylen-blen);i++){
      int r = 0;
      if(0 <= r && r < (pkt->op.modify_per)){
        if(memcmp(pkt->payload+i, before, blen) == 0){
          int size = pkt->paylen-i-blen;
          u_char tmp[size];
          memcpy(tmp, pkt->payload+i+blen, size);
          memcpy(pkt->payload+i, after, alen);
          memcpy(pkt->payload+i+alen, tmp, size);
        	pkt->size+=diff;
          pkt->iphdr->tot_len = htons(ntohs(pkt->iphdr->tot_len)+diff);
          pkt->paylen+=diff;
          i+=diff;
  	      tot_diff+=diff;
        }
      }
    }
    struct packet *tmp_pkt = malloc(sizeof(struct packet));
    memcpy(tmp_pkt, pkt, sizeof(struct packet));
    tmp_pkt->tot_diff = tot_diff;

    if(tmp_pkt->tot_diff != 0){
      tmp_pkt->next = iface->seq_ack_controll_queue->next;
      iface->seq_ack_controll_queue->next = tmp_pkt;
    }

    pkt->tcphdr->check = calc_tcp_cksum(pkt->iphdr, pkt->tcphdr);
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

int chk_rtns(struct packet *queue, struct packet *pkt){
  /* 保存されている古いパケットはfreeする */
  struct packet *saved_pkt;
  for(saved_pkt=queue; saved_pkt; saved_pkt=saved_pkt->next){
    if((saved_pkt->tcphdr->seq == pkt->tcphdr->seq) &&
       (saved_pkt->tcphdr->ack_seq == pkt->tcphdr->ack_seq) &&
       (memcmp(saved_pkt->payload, pkt->payload, (saved_pkt->paylen<pkt->paylen)?pkt->paylen:saved_pkt->paylen) == 0)){
      pkt->is_rtns  = 1;
      pkt->diff_seq = saved_pkt->diff_seq;
      pkt->diff_ack = saved_pkt->diff_ack;
      copy_operation(&pkt->op, &saved_pkt->op);
      return 1;
    }
  }
  return 0;
}

int seq_ack_controll(struct interface *iface, struct packet *pkt){
  struct packet *seq_ack_queue = iface->seq_ack_controll_queue;
  for(seq_ack_queue = iface->seq_ack_controll_queue;
      seq_ack_queue->next!=NULL;
      seq_ack_queue = seq_ack_queue->next){
    //sequence NUMBER MATCH
    //acknowludge NUMBER MATCH
    struct packet *check_pkt = seq_ack_queue->next;
    if(pkt->tcphdr->seq == check_pkt->tcphdr->ack_seq){
    	pkt->tcphdr->ack_seq = htonl(ntohl(pkt->tcphdr->ack_seq) + check_pkt->tot_diff*(-1));
      seq_ack_queue->next = check_pkt->next;
      free(check_pkt);
      return 1;
    }
  }
  return 0;
}