#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <linux/if_ether.h>
#include <net/if_arp.h>
#include <pthread.h>
#include <pcap.h>

#include "./lib/interface.h"
#include "./lib/routing.h"
#include "./lib/common.h"
#include "./lib/connection.h"
#include "./lib/arp.h"
#include "./lib/pcapng.h"
#include "./lib/packet_capture.h"
#include "./lib/packet_handler.h"
#include "./lib/insert.h"
#include "./lib/mongo.h"
#include "./lib/cmd_server.h"

int main(int argc, char *argv[]){
  if(argc-1 != 2){
    fprintf(stderr, "Usage: %s [INTERFACE1] [INTERFACE2]\n", argv[0]);
    exit(-1);
  }

  //number of interface
  int ifnum = argc-1;
/* init routingentry */
  struct routingentry *rtgtbl = malloc(sizeof(struct routingentry));
  struct connection *cnxtbl = malloc(sizeof(struct connection));
  init_rtgtbl(rtgtbl);
  init_cnxtbl(cnxtbl);

/* interface setting */
  struct interface *iface[2];
  for(int i=0; i<ifnum; i++){
    iface[i] = malloc(sizeof(struct interface));
    init_iface(iface[i], argv[i+1]);
    iface[i]->rtgtbl = rtgtbl;
    iface[i]->cnxtbl = cnxtbl;
    init_operation(iface[i]);
    char ipstr[16];
    iptostr(iface[i]->ipaddr, ipstr);
  }

  add_rtgentry(rtgtbl, make_rtgentry(iface[0]));
  add_rtgentry(rtgtbl, make_rtgentry(iface[1]));

  pthread_mutex_init(&mutex, NULL);
  pthread_t recver[2], sender[2];
  pthread_t delay[2];
//  pthread_t handler_loop[2];
  pthread_t capture[2];

  for(int i=0; i<ifnum; i++){
    pthread_create(&recver[i], NULL, &recv_loop, iface[i]);
    pthread_create(&sender[i], NULL, &send_loop, iface[i]);
    pthread_create(&delay[i] , NULL, &delay_loop, iface[i]);
//    pthread_create(&handler_loop[i] , NULL, &packet_handler, iface[i]);
    pthread_create(&capture[i], NULL, &pcapng_capture_loop, iface[i]);
  }

  pthread_t cmdsrv;
  pthread_create(&cmdsrv, NULL, &cmd_loop, cnxtbl);
  pthread_join(cmdsrv, NULL);

 return 0;
}
