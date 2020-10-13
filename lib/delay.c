#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netpacket/packet.h>
#include <pthread.h>


#include "common.h"
#include "routing.h"
#include "interface.h"
#include "connection.h"
#include "packet.h"
#include "delay.h"

void delay_enqueue(struct packet *queue, struct packet *pkt){
  struct packet *temp;
  pthread_mutex_lock(&mutex);
  for(temp=pkt; temp->next!=NULL; temp=temp->next){
    if(temp->timestamp.tv_sec >= pkt->timestamp.tv_sec){
      if(temp->timestamp.tv_usec >= pkt->timestamp.tv_usec+pkt->op.delay*1000){
//          printf("DELAY ENQUEUE\n");
//          print_pkt(pkt);
          printf("pkt\n");
          printf("%ld %06lu\n", pkt->timestamp.tv_sec, pkt->timestamp.tv_usec);
          printf("\n");
          pkt->next = temp->next;
          temp->next = pkt;
          pthread_mutex_unlock(&mutex);
          return;
      }
    }
  }

  pkt->next = queue->next;
  queue->next = pkt;
  pthread_mutex_unlock(&mutex);
  return;
}

struct packet *delay_dequeue(struct packet *queue){
  struct packet *q;
  if(queue->next){
    pthread_mutex_lock(&mutex);
    struct packet *pkt_last=queue;
    for(q=queue->next; q->next; q=q->next){
      pkt_last = q;
    }
    printf("q   :%p\n", q);
    printf("last:%p\n", pkt_last);
    struct timeval now;
    gettimeofday(&now, NULL); 

    printf("now\n");
    printf("%ld %06lu\n", now.tv_sec, now.tv_usec);
    printf("pkt\n");
    printf("%ld %06lu\n", q->timestamp.tv_sec, q->timestamp.tv_usec);
    printf("%d %d\n", (q->op.delay/1000), (q->op.delay%1000)*1000);
    printf("\n");
    if(now.tv_sec >= q->timestamp.tv_sec+(q->op.delay/1000)){
      if(now.tv_usec>=q->timestamp.tv_usec+(q->op.delay%1000)*1000 || now.tv_sec>q->timestamp.tv_sec+(q->op.delay/1000)){
        pkt_last->next = NULL;
        pthread_mutex_unlock(&mutex);
        return q;
      }
    }
    pthread_mutex_unlock(&mutex);
    return NULL;
  }
  else{
    pthread_mutex_unlock(&mutex);
    return NULL;
  }
}

void delay_pkt(struct routingentry *route, struct packet *pkt){
//    printf("timeval sec: %ld, usec%ld\n", pkt->timestamp.tv_sec, pkt->timestamp.tv_usec);
    delay_enqueue(route->iface->delay_queue, pkt);
}