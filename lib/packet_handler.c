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
  char *filename;
  filename = (char *)malloc(strlen(iface->name) + 7);
  strcpy(filename,iface->name);
  strcat(filename,".pcapng");
  free(filename);

  for(;;){
    for(pkt=dequeue(iface->queue); pkt; pkt=dequeue(iface->queue)){
     if(send(iface->skfd, pkt->buf, pkt->size, 0) < 0){
        perror("SEND");
      }
      else{
        pcapng_send(pkt, iface->name);
      }
      free(pkt);
    }
    usleep(100); /* sleep 0.1 ms in order to reduce CPU utilization */
  }
}

void *recv_loop(void *arg){
  struct interface *iface = (struct interface *)arg;
  for(;;){
    struct packet *pkt = malloc(sizeof(struct packet));
    init_pkt(pkt);
    struct sockaddr_ll sll;
    socklen_t len = sizeof(sll);
    if((pkt->size = recvfrom(iface->skfd, pkt->buf, PKT_BUF_SIZE, 0, (struct sockaddr *)&sll, &len)) < 0){
      perror("RECVFROM");
      free(pkt);
      continue;
    }

   if(sll.sll_pkttype == PACKET_OUTGOING){
      printf("PACKET OUTGOING\n");
      free(pkt);
      continue;
    }
    struct routingentry *route = NULL;
    struct arpentry *arpentry  = NULL;

    proc_pkt(pkt);
    //dhcp setting
    if(pkt->iphdr != NULL && pkt->iphdr->protocol == 17){
      if(ntohs(pkt->udphdr->uh_dport) == 67 || ntohs(pkt->udphdr->uh_dport) == 68){
        dhcp_discover(pkt, iface);
        //print_pkt(pkt);
      }
    }
   if(pkt->arphdr){
      //printf("ARPHDR\n");
      proc_arp(iface, pkt->arphdr);
      free(pkt);
      continue;
    }
    else if(pkt->iphdr){
      //printf("IPHDR\n");
      if(iface->mtu < ntohs(pkt->iphdr->tot_len)){
        //printf("TOT_LEN ERROR\n");
        free(pkt);
        continue;
      }
      if(pkt->iphdr->daddr == iface->ipaddr){
        //printf("DEST = ME\n");
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
//        print_arptbl(iface->arptbl);
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
      //printf("ICMP RECV\n");
      struct connection *conn;
      if((conn = search_cnxentry(iface->cnxtbl, pkt))){
        copy_operation(&pkt->op, &conn->op);
      }
    }

    else if(pkt->tcphdr){
      //printf("TCP RECV\n");
      struct connection *conn;
      if((conn = search_cnxentry(iface->cnxtbl, pkt))){
         //if(!chk_rtns(&conn->saved_pkt_queue, pkt)){
         pkt->diff_seq = conn->diff_seq;
         pkt->diff_ack = conn->diff_ack;
         copy_operation(&pkt->op, &conn->op);
         struct packet *copy = malloc_pkt();
         copy_pkt(copy, pkt);
//          if(100 < count_pkt_in_queue(conn->saved_pkt_queue)) {
//            free_pkt(dequeue(&conn->saved_pkt_queue));
//   //test         print_saved_pkt_queue(conn);
//          }
        //}
        pkt->tcphdr->seq     = htonl(ntohl(pkt->tcphdr->seq)    +pkt->diff_seq);
        pkt->tcphdr->ack_seq = htonl(ntohl(pkt->tcphdr->ack_seq)-pkt->diff_ack);
        pkt->tcphdr->check   = calc_tcp_cksum(pkt->iphdr, pkt->tcphdr);
      }
    }
    else if(pkt->udphdr){
      struct connection *conn;
      if((conn = search_cnxentry(iface->cnxtbl, pkt))){
        copy_operation(&pkt->op, &conn->op);
      }
    }
    else{
      /* other protocols in a transport layer do nothing */
      //printf("OTHER PROTOCOL RECV\n");
      free(pkt);
      continue;
    }

    repl_ethhdr(pkt->ethhdr, route->iface->macaddr, arpentry->macaddr);
    make_cnx(iface->cnxtbl, pkt);

    if(packet_handler(pkt, route, iface) == 1){
      continue;
    }
    enqueue(route->iface->queue, pkt);
  }
}

int packet_handler(struct packet *pkt, struct routingentry *route, struct interface *iface){
  /* - - checking flags - - */
  if(pkt->op.modify){
   modify_pkt(pkt, pkt->op.mset.before, pkt->op.mset.blen, pkt->op.mset.after, pkt->op.mset.alen, iface->cnxtbl);
  }
  if(pkt->op.loss){
   printf("loss\n");
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


/* TEST code */
//void *packet_handler(void *arg){
//  struct interface *iface = (struct interface *)arg;
//  for(;;){
//    struct packet *pkt = malloc(sizeof(struct packet));
//    init_pkt(pkt);
//    struct sockaddr_ll sll;
//    socklen_t len = sizeof(sll);
//    if((pkt->size = recvfrom(iface->skfd, pkt->buf, PKT_BUF_SIZE, 0, (struct sockaddr *)&sll, &len)) < 0){
//      perror("RECVFROM");
//      free(pkt);
//      continue;
//    }
//
//   if(sll.sll_pkttype == PACKET_OUTGOING){
//      free(pkt);
//      continue;
//    }
//    struct routingentry *route = NULL;
//    struct arpentry *arpentry  = NULL;
//
//    proc_pkt(pkt);
//    //dhcp setting
//    if(pkt->iphdr != NULL && pkt->iphdr->protocol == 17){
//      if(ntohs(pkt->udphdr->uh_dport) == 67 || ntohs(pkt->udphdr->uh_dport) == 68){
//        dhcp_discover(pkt, iface);
//        //print_pkt(pkt);
//      }
//    }
//   if(pkt->arphdr){
//      //printf("ARPHDR\n");
//      proc_arp(iface, pkt->arphdr);
//      free(pkt);
//      continue;
//    }
//    else if(pkt->iphdr){
//      //printf("IPHDR\n");
//      if(iface->mtu < ntohs(pkt->iphdr->tot_len)){
//        //printf("TOT_LEN ERROR\n");
//        free(pkt);
//        continue;
//      }
//      if(pkt->iphdr->daddr == iface->ipaddr){
//        //printf("DEST = ME\n");
//        free(pkt);
//        continue;
//      }
//
//      if(!(route = search_route(iface->rtgtbl, pkt->iphdr->daddr))){
//        //printf("maybe set defalut gateway\n");
//        //print_pkt(pkt);
//        continue;
//      }
//      /* if the destination of a packet is a route interface, do nothing */
//      if(pkt->iphdr->daddr == route->iface->ipaddr){
//        //printf("DEST ADDR == route->iface->ipaddr\n");
//        free(pkt);
//        continue;
//      }
//
//      if(!(arpentry = search_arpentry(route->iface->arptbl, pkt->iphdr->daddr))){
//        struct packet *request;
//        request = malloc(sizeof(struct packet));
//        init_pkt(request);
//        make_arprequest(request, route->iface->macaddr, route->iface->ipaddr, pkt->iphdr->daddr);
//        enqueue(route->iface->queue, request);
//        continue;
//      }
//    }
//    else{
//      /* other protocols in a network layer do nothing */
//      free(pkt);
//      continue;
//    }
//
//    if(pkt->icmphdr){
//      struct connection *conn;
//      if((conn = search_cnxentry(iface->cnxtbl, pkt))){
//        copy_operation(&pkt->op, &conn->op);
//      }
//    }
//
//    else if(pkt->tcphdr){
//      struct connection *conn;
//      if((conn = search_cnxentry(iface->cnxtbl, pkt))){
//         pkt->diff_seq = conn->diff_seq;
//         pkt->diff_ack = conn->diff_ack;
//         copy_operation(&pkt->op, &conn->op);
//         struct packet *copy = malloc_pkt();
//         copy_pkt(copy, pkt);
//        pkt->tcphdr->seq     = htonl(ntohl(pkt->tcphdr->seq)    +pkt->diff_seq);
//        pkt->tcphdr->ack_seq = htonl(ntohl(pkt->tcphdr->ack_seq)-pkt->diff_ack);
//        pkt->tcphdr->check   = calc_tcp_cksum(pkt->iphdr, pkt->tcphdr);
//      }
//    }
//    else if(pkt->udphdr){
//      struct connection *conn;
//      if((conn = search_cnxentry(iface->cnxtbl, pkt))){
//        copy_operation(&pkt->op, &conn->op);
//      }
//    }
//    else{
//      free(pkt);
//      continue;
//    }
//
//    repl_ethhdr(pkt->ethhdr, route->iface->macaddr, arpentry->macaddr);
//    make_cnx(iface->cnxtbl, pkt);
//
//    /* - - checking flags - - */
//    if(pkt->op.modify){
//       /* Segmentation fault occur  when  using -g option by controller command */
//      modify_pkt(pkt, pkt->op.mset.before, pkt->op.mset.blen, pkt->op.mset.after, pkt->op.mset.alen, iface->cnxtbl);
//      //}
//    }
//    if(pkt->op.loss){
//     printf("loss\n");
//      if(loss_pkt(pkt)) continue;
//      //}
//    }
//
//    /* << should change this implementation >> */
//    if(pkt->op.delay){
//      delay_pkt(route, pkt); 
//      continue;
//    }
//
//    /* link the packet to the transmission queue */
//    enqueue(route->iface->queue, pkt);
//  }
//}
//
//int chk_rtns(struct packet **queue, struct packet *pkt){
//  /* 保存されている古いパケットはfreeする */
//  struct packet *saved_pkt;
//  for(saved_pkt=(*queue);saved_pkt;saved_pkt=saved_pkt->next){
//    if((saved_pkt->tcphdr->seq == pkt->tcphdr->seq) &&
//       (saved_pkt->tcphdr->ack_seq == pkt->tcphdr->ack_seq) &&
//       (memcmp(saved_pkt->payload, pkt->payload, (saved_pkt->paylen<pkt->paylen)?pkt->paylen:saved_pkt->paylen) == 0)){
//      pkt->is_rtns  = 1;
//      pkt->diff_seq = saved_pkt->diff_seq;
//      pkt->diff_ack = saved_pkt->diff_ack;
//      copy_operation(&pkt->op, &saved_pkt->op);
//      return 1;
//    }
//  }
//  return 0;
//}
//

void *delay_loop(void *arg){
  struct interface *iface = (struct interface *)arg;
  struct packet *pkt;
/*  pcap file setting */
/*--------------------*/
//  char *filename;
//  filename = (char *)malloc(strlen(iface->name) + 7);
//  strcpy(filename,iface->name);
//  strcat(filename,".pcapng");
//  free(filename);
/*--------------------*/
  for(;;){
    for(pkt=delay_dequeue(iface->delay_queue); pkt; pkt=delay_dequeue(iface->delay_queue)){
     if(send(iface->skfd, pkt->buf, pkt->size, 0) < 0){
        perror("SEND");
      }
      else{
        continue;
      }
      free(pkt);
    }
    usleep(100); /* sleep 0.1 ms in order to reduce CPU utilization */
  }
}