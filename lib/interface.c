#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>

#include "interface.h"
#include "common.h"
#include "packet.h"
#include "arp.h"

void init_operation(struct interface *iface){
  iface->op = malloc(sizeof(struct operation));
  iface->op->loss = 0;
  iface->op->delay = 0;
  iface->op->delay_per = 0;
  iface->op->delay_ran = 0;
  iface->op->modify = 0;
  iface->op->modify_per = 0;
  iface->op->modify = 0;
}

void print_mac_to_str(u_char *macaddr){
  char str[18];
  snprintf(str, 18, "%02x:%02x:%02x:%02x:%02x:%02x",macaddr[0],macaddr[1],macaddr[2],macaddr[3],macaddr[4],macaddr[5]);
  printf("interface macaddr: %s\n", str);
}

void print_interface(struct interface *iface){
  printf("interface name: %s\n", iface->name);
  printf("interface skfd: %d\n", iface->skfd);
  printf("interface mtu: %d\n", iface->mtu);
  print_mac_to_str(iface->macaddr);
  char ipstr[16];
  iptostr(iface->ipaddr, ipstr);
  printf("ipaddr:%s\n", ipstr);
  iptostr(iface->ipmask, ipstr);
  printf("netmask:%s\n", ipstr);
  count_queue(iface);
  printf("\n");
}


void *init_iface(struct interface *iface, char *ifname){
  iface->name = malloc(strlen(ifname));

  if (iface->name == NULL){
    printf("malloc error: interface name %s\n", ifname);
    exit(-1);
  } 
  strcpy(iface->name, ifname);

//socket setting
  if((iface->skfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0){
    printf("socket error: interface name %s\n", iface->name);
    exit(-1);
  }

  struct ifreq ifreq;
  strncpy(ifreq.ifr_name, ifname, IFNAMSIZ);
  if(ioctl(iface->skfd, SIOCGIFINDEX, &ifreq) < 0){
    printf("valid interface name error: %s\n" ,iface->name);
    exit(-1);
  }

  /* set up link layer socket */
  struct sockaddr_ll sll;
  sll.sll_family = AF_PACKET;
  sll.sll_protocol = htons(ETH_P_ALL);
  sll.sll_ifindex = ifreq.ifr_ifindex;
  if(bind(iface->skfd, (struct sockaddr *)&sll, sizeof(struct sockaddr_ll)) < 0){
    printf("interface bind error: %s\n" ,iface->name);
    exit(-1);
  }

  /* get macaddr */
  if(ioctl(iface->skfd, SIOCGIFHWADDR, &ifreq) < 0){
    printf("get macaddr error: %s\n" ,iface->name);
    exit(-1);
  }
  memcpy(iface->macaddr, ifreq.ifr_hwaddr.sa_data, ETH_ALEN);

  /* get ipaddr */
  if(ioctl(iface->skfd, SIOCGIFADDR, &ifreq) < 0){
    perror("SIOCGIFADDR");
    exit(-1);
  }
  iface->ipaddr = ((struct sockaddr_in *)&ifreq.ifr_addr)->sin_addr.s_addr;

  /* get ipmask */
  if(ioctl(iface->skfd, SIOCGIFNETMASK, &ifreq) < 0){
    perror("SIOCGIFNETMASK");
    exit(-1);
  }
  iface->ipmask = ((struct sockaddr_in *)&ifreq.ifr_netmask)->sin_addr.s_addr;

  /* set MTU size */
  /* ifreq.ifr_mtu = 16110;// (16KB) */
  ifreq.ifr_mtu = 1500;
  if(ioctl(iface->skfd, SIOCSIFMTU, &ifreq) < 0){
    perror("SIOCSIFMTU");
    exit(-1);
  }

  /* get MTU size */
  if(ioctl(iface->skfd, SIOCGIFMTU, &ifreq) < 0){
    perror("SIOCGIFMTU");
    exit(-1);
  }
  iface->mtu = ifreq.ifr_mtu;

/* init queue */
  iface->queue = malloc(sizeof(struct packet));
  iface->queue->next = NULL;
  iface->delay_queue = malloc(sizeof(struct packet));
  iface->delay_queue->next = NULL;
/* init arptbl */
  iface->arptbl = malloc(sizeof(struct arpentry));
  iface->arptbl->next = NULL;

}

void count_queue(struct interface *iface){
  struct packet *q;
  int count=0;
  for(q = iface->queue->next; q; q=q->next){
    count++;
  }
  printf("queue pkt:%d\n",count);
}
