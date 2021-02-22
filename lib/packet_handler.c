#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <math.h>
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
#include "routing.h"
#include "connection.h"
#include "modify.h"
#include "arp.h"
#include "packet_capture.h"
#include "pcapng.h"
#include "packet_handler.h"
#include "dhcp.h"
#include "delay.h"


void *send_loop(void *arg){
  struct interface *iface = (struct interface *)arg;
  struct packet *pkt;
/*  pcap file setting */
//  char *filename;
//  filename = (char *)malloc(strlen(iface->name) + 7);
//  strcpy(filename,iface->name);
//  strcat(filename,".pcapng");
//  free(filename);

  for(;;){
    for(pkt=dequeue(iface->queue); pkt; pkt=dequeue(iface->queue)){
     if(send(iface->skfd, pkt->buf, pkt->size, 0) < 0){
        perror("SEND");
      }
      else{
//        pcapng_send(pkt, iface->name);
      }
      free(pkt);
    }
//    usleep(100); /* sleep 0.1 ms in order to reduce CPU utilization */
  }
}

void *recv_loop(void *arg){
  struct interface *iface = (struct interface *)arg;
  struct sockaddr_ll sll;
  for(;;){
    struct packet *pkt = malloc(sizeof(struct packet));
    init_pkt(pkt);
    socklen_t len = sizeof(sll);
    if((pkt->size = recvfrom(iface->skfd, pkt->buf, PKT_BUF_SIZE, 0, (struct sockaddr *)&sll, &len)) < 0){
      printf("TEST1\n");
      perror("RECVFROM");
      free(pkt);
      continue;
    }

   if(sll.sll_pkttype == PACKET_OUTGOING){
      free(pkt);
      continue;
    }
    struct routingentry *route = NULL;
    struct arpentry *arpentry  = NULL;

    proc_pkt(pkt);
/* dhcp設定だけど多分必要ない*/
//dhcp setting
//    if(pkt->iphdr != NULL && pkt->iphdr->protocol == 17){
//      if(ntohs(pkt->udphdr->uh_dport) == 67 || ntohs(pkt->udphdr->uh_dport) == 68){
//        dhcp_discover(pkt, iface);
//        //print_pkt(pkt);
//      }
//    }
   if(pkt->arphdr){
      //printf("ARPHDR\n");
      proc_arp(iface, pkt->arphdr);
      free(pkt);
      continue;
    }
    else if(pkt->iphdr){
      //if(iface->mtu < ntohs(pkt->iphdr->tot_len)){
        //printf("TOT_LEN ERROR\n");
        //free(pkt);
        //continue;
      //}
      if(pkt->iphdr->daddr == iface->ipaddr){
        free(pkt);
        continue;
      }

      if(!(route = search_route(iface->rtgtbl, pkt->iphdr->daddr))){
        //printf("maybe set defalut gateway\n");
        //print_pkt(pkt);
        continue;
      }
      /* if the destination of a packet is a route interface, do nothing */
      if(pkt->iphdr->daddr == route->iface->ipaddr){
        //printf("DADDR  = IPADDR\n");
        //printf("DEST ADDR == route->iface->ipaddr\n");
        free(pkt);
        continue;
      }
      if(!(arpentry = search_arpentry(route->iface->arptbl, pkt->iphdr->daddr))){
        //printf("ADD ARP TABLE\n");
        struct packet *request;
        request = malloc(sizeof(struct packet));
        init_pkt(request);
        make_arprequest(request, route->iface->macaddr, route->iface->ipaddr, pkt->iphdr->daddr);
        enqueue(route->iface->queue, request);
        continue;
      }
//      pkt->iphdr->ttl-=1; pkt->iphdr->check+=1;
    }
    else{
      /* other protocols in a network layer do nothing */
      free(pkt);
      continue;
    }

    if(pkt->icmphdr){
      struct connection *conn;
      if((conn = search_cnxentry(iface->cnxtbl, pkt))){
        copy_operation(&pkt->op, &conn->op);
      }
    }

    else if(pkt->tcphdr){
      //printf("TCP RECV\n");
      struct connection *conn;
      if((conn = search_cnxentry(iface->cnxtbl, pkt))){
        copy_operation(&pkt->op, &conn->op);
      }
      //seq ack controll
    	if(!chk_rtns(conn->saved_pkt_queue, pkt)){
    	  pkt->diff_seq = conn->diff_seq;
    	  pkt->diff_ack = conn->diff_ack;
    	  copy_operation(&pkt->op, &conn->op);
    	  struct packet *copy = malloc_pkt();
    	  copy_pkt(copy, pkt);
    	  enqueue(conn->saved_pkt_queue, copy);
    	  if(10 < count_pkt_in_queue(conn->saved_pkt_queue)) {
    	    free_pkt(dequeue(conn->saved_pkt_queue));
    	  }
    	}
    }
    else if(pkt->udphdr){
      struct connection *conn;
      if((conn = search_cnxentry(iface->cnxtbl, pkt))){
        copy_operation(&pkt->op, &conn->op);
      }
    }
    else{
      free(pkt);
      continue;
    }
    repl_ethhdr(pkt->ethhdr, route->iface->macaddr, arpentry->macaddr);
    make_cnx(iface->cnxtbl, pkt);
    if(packet_handler(pkt, route, iface) == 1){
      free(pkt);
      continue;
    }
    else{
      enqueue(route->iface->queue, pkt);
    }
  }
}

int packet_handler(struct packet *pkt, struct routingentry *route, struct interface *iface){
  /* - - checking flags - - */
  if(pkt->op.modify){
    struct timeval before, after;
    gettimeofday(&before, NULL);
    modify_pkt(pkt, pkt->op.mset.before, pkt->op.mset.blen, pkt->op.mset.after, pkt->op.mset.alen, iface->cnxtbl);
    gettimeofday(&after, NULL);
    modify_log_output("test.log", before, after);
  }
  if(pkt->op.loss != 0.000000){
    if(loss_pkt(pkt)){
      return 1;
    }
  }
  if(pkt->op.delay){
    delay_pkt(route, pkt);
    return 1;
  }
  return 0;
}


void *delay_loop(void *arg){
  struct interface *iface = (struct interface *)arg;
  struct packet *pkt;
  for(;;){
    for(pkt=delay_dequeue(iface->delay_queue); pkt; pkt=delay_dequeue(iface->delay_queue)){
      if(send(iface->skfd, pkt->buf, pkt->size, 0) < 0){
        perror("SEND");
      }
      else{
//        continue;
      }
      free(pkt);
    }
    usleep(100); /* sleep 0.1 ms in order to reduce CPU utilization */
  }
}

void modify_log_output(char *filename, struct timeval before, struct timeval after){
  static int check_new = 0;
  FILE *outputfile;
  if(check_new == 0){
    check_new = 1;
    outputfile = fopen(filename, "w");
    fprintf(outputfile, "after.tv_sec, after.tv_usec, before.tv_sec, before.tv_usec\n");
    fclose(outputfile);
  }
  outputfile = fopen(filename, "a");
  if (outputfile == NULL) {
    printf("cannot open\n");
    exit(1);
  }
  fprintf(outputfile, "%lu, %lu, %lu, %lu\n", after.tv_sec, after.tv_usec, before.tv_sec, before.tv_usec);
  fclose(outputfile);
}
