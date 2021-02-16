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
    long judge_sec = pkt->timestamp.tv_sec+(pkt->op.delay/1000); 
    long judge_usec = pkt->timestamp.tv_usec+(pkt->op.delay%1000)*1000; 
    if(judge_usec/1000000 >= 1){
      judge_sec += 1;
      judge_usec = judge_usec%1000000;
    }

    if(temp->timestamp.tv_sec > judge_sec){
      pkt->next = temp->next;
      temp->next = pkt;
      pthread_mutex_unlock(&mutex);
      return;
    }
    else if(temp->timestamp.tv_sec == judge_sec && temp->timestamp.tv_usec >= judge_usec){
      pkt->next = temp->next;
      temp->next = pkt;
      pthread_mutex_unlock(&mutex);
      return;
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
    struct timeval now;
    gettimeofday(&now, NULL); 

    long judge_sec = q->timestamp.tv_sec+(q->op.delay/1000); 
    long judge_usec = q->timestamp.tv_usec+(q->op.delay%1000)*1000; 
    if(judge_usec/1000000 >= 1){
      judge_sec += 1;
      judge_usec = judge_usec%1000000;
    }
    if(now.tv_sec > judge_sec){
      pkt_last->next = NULL;
      pthread_mutex_unlock(&mutex);
      return q;
    }
    else if(now.tv_sec == judge_sec && now.tv_usec >= judge_usec){
      pkt_last->next = NULL;
      pthread_mutex_unlock(&mutex);
      return q;
    }
    pthread_mutex_unlock(&mutex);
    return NULL;
  }
  else{
    return NULL;
  }
}

void delay_pkt(struct routingentry *route, struct packet *pkt){
    delay_enqueue(route->iface->delay_queue, pkt);
}