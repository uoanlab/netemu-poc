#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <time.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netpacket/packet.h>
#include <pthread.h>


#include "common.h"
#include "connection.h"
#include "packet.h"

int loss_pkt(struct packet *pkt){
  int r = get_random(0, 100*10000);
  if(0 <= r && r < (pkt->op.loss)*10000){
    free_pkt(pkt);
    return 1;
  }
  return 0;
}