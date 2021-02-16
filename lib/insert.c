#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <linux/if_ether.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <pthread.h>
#include <pcap.h>
#include <arpa/inet.h>


#include "interface.h"
#include "routing.h"
#include "common.h"
#include "connection.h"
#include "arp.h"
#include "packet.h"
#include "pcapng.h"
#include "packet_capture.h"
#include "packet_handler.h"
#include "mongo.h"
#include "cmd_server.h"
#include "insert.h"

int flag_check(struct interface *iface, struct packet *pkt){
       if(pkt->op.headder.urg && pkt->tcphdr->urg){
        if(send(iface->skfd, pkt->buf, pkt->size, 0) < 0){
              perror("SEND");
        }
        free_pkt(pkt);
        return 0;//return 0 なら呼び出し先でcontinue
      }
       if(pkt->op.headder.psh && pkt->tcphdr->psh){
        if(send(iface->skfd, pkt->buf, pkt->size, 0) < 0){
              perror("SEND");
        }
        free_pkt(pkt);
        return 0;//return 0 なら呼び出し先でcontinue
      }
       if(pkt->op.headder.rst && pkt->tcphdr->rst){
        if(send(iface->skfd, pkt->buf, pkt->size, 0) < 0){
              perror("SEND");
        }
        free_pkt(pkt);
        return 0;//return 0 なら呼び出し先でcontinue
      }
       if(pkt->op.headder.syn && pkt->tcphdr->syn){
        if(send(iface->skfd, pkt->buf, pkt->size, 0) < 0){
              perror("SEND");
        }
        free_pkt(pkt);
        return 0;//return 0 なら呼び出し先でcontinue
      }
       if(pkt->op.headder.psh && pkt->tcphdr->psh){
       if(send(iface->skfd, pkt->buf, pkt->size, 0) < 0){
              perror("SEND");
        }
        free_pkt(pkt);
        return 0;//return 0 なら呼び出し先でcontinue
      }
      return 1;
}

void insert_tcppkt(int cnxid, void *arg, struct connection *cnxtbl){
  pass_insert *pass;
  pass = arg;
  printf("TCP flag:SYN\n");
  struct connection *c;
  int i=0;
  sleep(pass->difftime);
  pthread_t inserter;
  for(c=cnxtbl->next;c;c=c->next){
    if(c->id == cnxid){
      pass->c=c;
      if (c->proto == IPPROTO_TCP){
        for(int i=0; i<pass->thr; i++){
         pthread_create(&inserter, NULL, &insert_tcppkt_loop, pass);
        }
      }
      break;
    }
    i+=1;
  }
}

void *insert_tcppkt_loop(void *arg){
  int  flag=1;
  int  count=0;
  pass_insert *pass;
  pass = arg;
  int pkt_cnt=0;
  int t=1;
  time_t start = time(NULL);
  int seed =1;
  while(count < pass->n){
    seed+=1;
    struct interface *iface = pass->iface;
    struct connection *con = pass->c;
    struct arpentry *arpentry  = NULL;
    arpentry = search_arpentry(pass->iface->arptbl, con->daddr);
    char packet[1500];
    srand((unsigned int)time(NULL)*seed);
    int ip1 = rand()%255+1;
    int ip2 = rand()%255+1;
    int ip3 = rand()%255+1;
    int ip4 = rand()%255+1;
    char ip[15];
    sprintf(ip,"%d.%d.%d.%d",ip1,ip2,ip3,ip4);

    int dip1 = rand()%255+1;
    int dip2 = rand()%255+1;
    int dip3 = rand()%255+1;
    int dip4 = rand()%255+1;
    char dip[15];
    sprintf(dip,"%d.%d.%d.%d",dip1,dip2,dip3,dip4);
    //ether
    struct ethhdr *eth;
    eth=(struct ethhdr *)packet;
    eth->h_proto=htons(ETHERTYPE_IP);
    repl_ethhdr(eth, pass->iface->macaddr, arpentry->macaddr);

    //payload setting
    char *data;
    data = packet + sizeof(struct iphdr) + sizeof(struct ethhdr) + sizeof(struct tcphdr) ;
    if(pass->pay != NULL)strncpy(data, pass->pay,strlen(pass->pay));

    //ip
    struct iphdr *ih;
    ih = (struct iphdr *)(packet+sizeof(struct ethhdr));
    ih->version=4;
    ih->ihl=20/4;
    ih->tos=pass->tos;
    ih->tot_len=htons(sizeof(struct tcphdr)+sizeof(struct iphdr)+strlen(data));
    ih->id=htons(0);
    ih->frag_off=ntohs(pass->flag_off);
    ih->ttl=pass->ttl;
    ih->protocol=IPPROTO_TCP;
    ih->check=0;
    if(pass->ipflag == 1) inet_aton(pass->ip,(struct in_addr *)&ih->saddr);
    else if (pass->random==1) inet_aton(ip,(struct in_addr *)&ih->saddr);
    else ih->saddr=con->saddr;
    if(pass->dstipflag == 1) inet_aton(pass->dstip,(struct in_addr *)&ih->daddr);
    else if (pass->dstrandom==1) inet_aton(dip,(struct in_addr *)&ih->daddr);
    else ih->daddr=con->daddr;
    ih->check=tcp_checksum((u_char *)ih,sizeof(struct iphdr));

    //tcp
    struct pseudoTCPPacket pTCPPacket;
    char *pseudo_packet;
    struct tcphdr *th;
    th = (struct tcphdr *)(packet+sizeof(struct ethhdr)+sizeof(struct iphdr));
    th->source = (pass->sport)==0 ? con->sport : htons(pass->sport);
    th->dest = (pass->dport)==0 ? con->dport : htons(pass->dport);
    th->seq=htonl(pass->SEQ);
    th->ack_seq=htonl(pass->ACK);
    th->doff=pass->off;
    th->urg=pass->urg;
    th->ack=pass->ack;
    th->psh=pass->psh;
    th->rst=pass->rst;
    th->syn=pass->syn;
    th->fin=pass->fin;
    th->window=htons(pass->window);
    th->urg_ptr=0;
    // 擬似ヘッダの作成
    pseudo_packet = (char *)malloc((int) (sizeof(struct pseudoTCPPacket)+sizeof(struct tcphdr)+strlen(data)));
    memset(pseudo_packet, 0, sizeof(struct pseudoTCPPacket)+sizeof(struct tcphdr));
    pTCPPacket.srcAddr=ih->saddr;
    pTCPPacket.dstAddr=ih->daddr;
    pTCPPacket.zero=0;
    pTCPPacket.protocol=IPPROTO_TCP;
    pTCPPacket.TCP_len=htons(sizeof(struct tcphdr)+strlen(data));
    th->check=0x00;

    memcpy(pseudo_packet, (char *)&pTCPPacket, sizeof(struct pseudoTCPPacket));
    memcpy(pseudo_packet+sizeof(struct pseudoTCPPacket), th, sizeof(struct tcphdr)+strlen(data));

    // チェックサムの算出
    th->check=(tcp_checksum((u_char *)pseudo_packet, (int) (sizeof(struct pseudoTCPPacket)+sizeof(struct tcphdr)+strlen(data))));
    if(pass->bad_checksum!=0x0) th->check = ntohs(pass->bad_checksum);
    struct timeval pcap_time;
    gettimeofday(&pcap_time, NULL);
    int pcap_len = sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct tcphdr)+strlen(data);
    if(pass->pcap==1){
      FILE *file;
      file=fopen("eth1.pcap","ab");
      fwrite(&pcap_time.tv_sec,4,1,file);
      fwrite(&pcap_time.tv_usec,4,1,file);
      char temp2[4]={'\0'};
      u_int32_t pcap_len_hex=0x0;
      sprintf(temp2, "%x", pcap_len);
      sscanf(temp2,"%x",&pcap_len_hex);
      fwrite(&pcap_len_hex,4,1,file);
      fwrite(&pcap_len_hex,4,1,file);
      fwrite(packet,pcap_len,1,file);
      fclose(file);
    }

    if(pass->pcapng==1){
      if(!strcmp(pass->iface->name,"eth1"))
        pcapng_description_tcp("test1.pcapng",eth,ih,th,pcap_len);
      else
        pcapng_description_tcp("test2.pcapng",eth,ih,th,pcap_len);
    }
    if(send(iface->skfd,packet,pcap_len, 0) < 0){
      perror("INSERT SEND ERROR");
    }
    free(pseudo_packet);
    flag++;
    count+=1;
    pkt_cnt+=1;
    time_t end = time(NULL);
    if (end-start==1){
//      printf("%d %d\n",t,pkt_cnt);
      pkt_cnt=0;
      t+=1;
      start=end;
    }
    if(t >10) return 0;
//    time_t end= time(NULL);
//    if(end-start>=10){
//      printf("start %s", ctime(&end));
//      break;
//    }
  }
  free(pass->pay);
  return 0;
}

void insert_udppkt(int cnxid, void *arg, struct connection *cnxtbl){
  pass_insert *pass;
  pass = arg;
  struct connection *c;
  sleep(pass->difftime);
  printf("start udp\n");
  int i=0;
  for(c=cnxtbl->next;c;c=c->next){
    pthread_t inserter;
    if(c->id == cnxid){
      pass->c=c;
      //pass->iface=iface[i];
      //pass->len=strlen(data);
      //strncpy(pass.data,data,pass.dlen);
      //UDP version
      //
      static const unsigned char global[24] = {
        0xd4, 0xc3, 0xb2, 0xa1,
        0x02, 0x00,
        0x04, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x04, 0x01,
        0x01, 0x00, 0x00, 0x00
      };
      if(pass->pcap==1){
        //test.pcap 初期化
        FILE *file;
        file=fopen("insert_udp.pcap","wb");
        fwrite(global,sizeof(global),1,file);
        fclose(file);
        char filename[25] = {'\0'};
        sprintf(filename, "./test/udp_flood_count%d.txt",pass->thr);
        FILE *count;
        count=fopen(filename,"wb");
        fclose(count);
      }
      if (c->proto == IPPROTO_UDP)
        for(int i=0; i<pass->thr; i++) pthread_create(&inserter, NULL, &insert_udppkt_loop, pass);
      break;
    }
    i+=1;
  }
}


void *insert_udppkt_loop(void *arg){
  pass_insert *pass;
  pass = arg;
  int count = 0;
  int seed = 1;
  int pkt_cnt=0;
  int t=1;
  time_t start = time(NULL);
  char filename[25] = {'\0'};
  sprintf(filename, "./test/udp_flood_count%d.txt",pass->thr);
  while(count < pass->n){
    count++;
    struct interface *iface = pass->iface;
    struct connection *con = pass->c;
    struct arpentry *arpentry  = NULL;
    arpentry = search_arpentry(pass->iface->arptbl, con->daddr);
    char packet[1500];
    srand((unsigned int)time(NULL)*seed);
    int ip1 = rand()%255+1;
    int ip2 = rand()%255+1;
    int ip3 = rand()%255+1;
    int ip4 = rand()%255+1;
    char ip[15];
    sprintf(ip,"%d.%d.%d.%d",ip1,ip2,ip3,ip4);
    int dip1 = rand()%255+1;
    int dip2 = rand()%255+1;
    int dip3 = rand()%255+1;
    int dip4 = rand()%255+1;
    char dip[15];
    sprintf(dip,"%d.%d.%d.%d",dip1,dip2,dip3,dip4);

    //ether
    struct ethhdr *eth;
    eth=(struct ethhdr *)packet;
    eth->h_proto=htons(ETHERTYPE_IP);
    repl_ethhdr(eth, iface->macaddr, arpentry->macaddr);
    //data set
    char *data;
    data = packet + sizeof(struct iphdr) + sizeof(struct ethhdr) + sizeof(struct udphdr) ;
//    strncpy(data, pass->data, pass->dlen);
    if(pass->pay != NULL)strncpy(data, pass->pay,strlen(pass->pay));
    //ip
    struct iphdr *ih;
    ih = (struct iphdr *)(packet+sizeof(struct ethhdr));
    ih->version=4;
    ih->ihl=20/4;
    ih->tos=pass->tos;
    ih->tot_len=htons(sizeof(struct udphdr)+sizeof(struct iphdr)+strlen(data));
    ih->id=htons(0);
    ih->frag_off=ntohs(pass->flag_off);
    ih->ttl=pass->ttl;
    ih->protocol=IPPROTO_UDP;
    ih->check=0;
    if(pass->ipflag == 1)
      inet_aton(pass->ip,(struct in_addr *)&ih->saddr);
    else if (pass->random==1)
      inet_aton(ip,(struct in_addr *)&ih->saddr);
    else
      ih->saddr=con->saddr;
    if(pass->dstipflag == 1)
      inet_aton(pass->dstip,(struct in_addr *)&ih->daddr);
    else if (pass->dstrandom==1)
      inet_aton(dip,(struct in_addr *)&ih->daddr);
    else
      ih->daddr=con->daddr;
    ih->check=tcp_checksum((u_char *)ih,sizeof(struct iphdr));

    //udp
    srand((unsigned int) time(NULL));
    int ran_port = rand()%65535;
    struct udphdr *uh;
    uh = (struct udphdr *)(packet+sizeof(struct ethhdr)+sizeof(struct iphdr));
    uh->source = (pass->sport)==0 ? con->sport : htons(pass->sport);
    uh->dest = (pass->dport)==0 ? con->dport : htons(pass->dport);
    if(pass->random_dport)uh->dest = htons(ran_port);
    uh->len = htons(sizeof(struct udphdr)+strlen(data));
//test
//random port option test
    // 擬似ヘッダの作成
    struct pseudoTCPPacket pUDPPacket;
    char *pseudo_packet;
    pseudo_packet = (char *)malloc((int) (sizeof(struct pseudoTCPPacket)+sizeof(struct udphdr)+strlen(data)));
    memset(pseudo_packet, 0, sizeof(struct pseudoTCPPacket)+sizeof(struct udphdr));
    pUDPPacket.srcAddr=ih->saddr;
    pUDPPacket.dstAddr=ih->daddr;
    pUDPPacket.zero=0;
    pUDPPacket.protocol=IPPROTO_UDP;
    pUDPPacket.TCP_len=htons(sizeof(struct udphdr)+ strlen(data));
    uh->check=0x00;
    memcpy(pseudo_packet, (char *)&pUDPPacket, sizeof(struct pseudoTCPPacket));
    memcpy(pseudo_packet+sizeof(struct pseudoTCPPacket), uh, sizeof(struct udphdr)+strlen(data));

    // チェックサムの算出
    uh->check=(tcp_checksum((u_char *)pseudo_packet, (int) (sizeof(struct pseudoTCPPacket)+sizeof(struct udphdr)+strlen(data))));
    if(pass->pcap==1){
      printf("pcap test start \n");
      struct timeval pcap_time;
      gettimeofday(&pcap_time, NULL);
      FILE *file;
      file=fopen("insert_udp.pcap","ab");
      fwrite(&pcap_time.tv_sec,4,1,file);
      fwrite(&pcap_time.tv_usec,4,1,file);
      int pcap_len = sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct tcphdr)+strlen(data);
      char temp2[4]={'\0'};
      u_int32_t pcap_len_hex=0x0;
      sprintf(temp2, "%x", pcap_len);
      sscanf(temp2,"%x",&pcap_len_hex);
      printf("pcap_len:%d\n",pcap_len);
      printf("hex_len:%x\n",pcap_len_hex);
      fwrite(&pcap_len_hex,4,1,file);
      fwrite(&pcap_len_hex,4,1,file);
      fwrite(packet,pcap_len,1,file);
      fclose(file);
    }

    time_t end = time(NULL);
    pkt_cnt+=1;
    if(end-start==1){
      FILE *count;
      count=fopen(filename,"ab");
      fprintf(count,"%d %d\n",t,pkt_cnt);
      fclose(count);
      pkt_cnt=0;
      t+=1;
      start=end;
      printf("%ds %dp\n",t,pkt_cnt);
      pkt_cnt=0;
      t+=1;
      start=end;
    }




    if(send(iface->skfd,packet,sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct udphdr)+strlen(data), 0) < 0){
      perror("INSERT SEND ERROR");
    }
    free(pseudo_packet);
    seed+=1;
  }
  free(pass->pay);
  return 0;
}

void insert_icmppkt(int cnxid, void *arg, struct connection *cnxtbl){
  pass_insert *pass;
  pass = arg;
  struct connection *c;
  int i=0;
  sleep(pass->difftime);
  printf("start icmp\n");
  for(c=cnxtbl->next;c;c=c->next){
    pthread_t inserter;
    if(c->id == cnxid){
      pass->c=c;
//      pass->iface=iface[i];
//ICMP version
      static const unsigned char global[24] = {
        0xd4, 0xc3, 0xb2, 0xa1,
        0x02, 0x00,
        0x04, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x04, 0x01,
        0x01, 0x00, 0x00, 0x00
      };
      //test.pcap 初期化
      if(pass->pcap==1){
        FILE *file;
        file=fopen("insert_icmp.pcap","wb");
        fwrite(global,sizeof(global),1,file);
        fclose(file);
        char filename[30] = {'\0'};
        sprintf(filename, "./test/icmp_flood_count%d.txt",pass->thr);
        FILE *count;
        count=fopen(filename,"wb");
        fclose(count);
      }
      if (c->proto == IPPROTO_ICMP) for(int i=0; i<pass->thr; i++) pthread_create(&inserter, NULL, &insert_icmppkt_loop,pass);
      break;
    }
    i+=1;
  }
}

void *insert_icmppkt_loop(void *arg){
  int count=0;
  pass_insert *pass;
  pass = arg;
  int pkt_cnt=0;
  int t=1;
  time_t start = time(NULL);
  while(count < pass->n){
    count++;
    struct interface *iface = pass->iface;
    struct connection *con = pass->c;
    struct arpentry *arpentry  = NULL;
    arpentry = search_arpentry(iface->arptbl, con->daddr);
    char packet[1500];
    srand((unsigned int) time(NULL));
    int ip1 = rand()%255+1;
    int ip2 = rand()%255+1;
    int ip3 = rand()%255+1;
    int ip4 = rand()%255+1;
    char ip[15];
    sprintf(ip,"%d.%d.%d.%d",ip1,ip2,ip3,ip4);
    int dip1 = rand()%255+1;
    int dip2 = rand()%255+1;
    int dip3 = rand()%255+1;
    int dip4 = rand()%255+1;
    char dip[15];
    sprintf(dip,"%d.%d.%d.%d",dip1,dip2,dip3,dip4);

    //ether
    struct ethhdr *eth;
    eth=(struct ethhdr *)packet;
    eth->h_proto=htons(ETHERTYPE_IP);
    arpentry = search_arpentry(iface->arptbl, con->daddr);
    repl_ethhdr(eth, iface->macaddr, arpentry->macaddr);

    //data set
    char *data;
    data = packet + sizeof(struct iphdr) + sizeof(struct ethhdr) + 4 ;
    if(pass->pay != NULL)strncpy(data, pass->pay,strlen(pass->pay));
    //ip
    struct iphdr *ih;
    ih = (struct iphdr *)(packet+sizeof(struct ethhdr));
    ih->version=4;
    ih->ihl=20/4;
    ih->tos=pass->tos;
    ih->tot_len=htons(sizeof(struct icmphdr)+sizeof(struct iphdr)+strlen(data));
    ih->id=htons(0);
    ih->frag_off=ntohs(pass->flag_off);
    ih->ttl=pass->ttl;
    ih->protocol=IPPROTO_ICMP;
    ih->check=0;
    if(pass->ipflag == 1) inet_aton(pass->ip,(struct in_addr *)&ih->saddr);
    else if (pass->random==1) inet_aton(ip,(struct in_addr *)&ih->saddr);
    else ih->saddr=con->saddr;
    if(pass->dstipflag == 1)
      inet_aton(pass->dstip,(struct in_addr *)&ih->daddr);
    else if (pass->dstrandom==1)
      inet_aton(dip,(struct in_addr *)&ih->daddr);
    else
      ih->daddr=con->daddr;
    ih->check=tcp_checksum((u_char *)ih,sizeof(struct iphdr));

    //icmp
    struct icmphdr *ich;
    ich = (struct icmphdr *)(packet+sizeof(struct ethhdr)+sizeof(struct iphdr));
    //option change
    switch(pass->type){
      case 0:
        ich->type = ICMP_ECHOREPLY;
        ich->code = htons(0);
        ich->un.echo.id = htons(pass->ic_id);
        ich->un.echo.sequence = htons(pass->ic_seq);
        break;
      case 3:
        ich->type = ICMP_DEST_UNREACH;
        ich->code = htons(0);
        ich->un.echo.id = htons(pass->ic_id);
        ich->un.echo.sequence = htons(pass->ic_seq);
        break;
      case 4:
        ich->type = ICMP_SOURCE_QUENCH;
        ich->code = htons(0);
        ich->un.echo.id = htons(pass->ic_id);
        ich->un.echo.sequence = htons(pass->ic_seq);
        break;
      case 5:
        ich->type = ICMP_REDIRECT;
        ich->code = htons(0);
        ich->un.echo.id = htons(pass->ic_id);
        ich->un.echo.sequence = htons(pass->ic_seq);
        break;
      case 8:
        ich->type = ICMP_ECHO;
        ich->code = htons(0);
        ich->un.echo.id = htons(pass->ic_id);
        ich->un.echo.sequence = htons(pass->ic_seq);
        break;
      case 9:  ich->code = htons(9);  break;
      case 10: ich->code = htons(10); break;
      case 11:
        ich->type = ICMP_TIME_EXCEEDED;
        ich->code = htons(0);
        ich->un.echo.id = htons(pass->ic_id);
        ich->un.echo.sequence = htons(pass->ic_seq);
        break;
      case 17:
        ich->type = ICMP_ADDRESSREPLY;
        ich->code = htons(0);
        ich->un.echo.id = htons(pass->ic_id);
        ich->un.echo.sequence = htons(pass->ic_seq);
        break;
      case 18:
        ich->type = NR_ICMP_TYPES;
        ich->code = htons(0);
        ich->un.echo.id = htons(pass->ic_id);
        ich->un.echo.sequence = htons(pass->ic_seq);
        break;
    }
    ich->checksum = 0;
    ich->checksum=tcp_checksum((u_char *)ich,sizeof(struct icmphdr)+strlen(data));
    if(pass->pcap==1){
      struct timeval pcap_time;
      gettimeofday(&pcap_time, NULL);
      FILE *file;
      file=fopen("insert_icmp.pcap","ab");
      fwrite(&pcap_time.tv_sec,4,1,file);
      fwrite(&pcap_time.tv_usec,4,1,file);
      int pcap_len = sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct icmphdr)+strlen(data);
      char temp2[4]={'\0'};
      u_int32_t pcap_len_hex=0x0;
      sprintf(temp2, "%x", pcap_len);
      sscanf(temp2,"%x",&pcap_len_hex);
      fwrite(&pcap_len_hex,4,1,file);
      fwrite(&pcap_len_hex,4,1,file);
      fwrite(packet,pcap_len,1,file);
      fclose(file);
    }

    time_t end = time(NULL);
    pkt_cnt+=1;
    if(end-start==1){
      printf("%ds %dp\n",t,pkt_cnt);
      pkt_cnt=0;
      t+=1;
      start=end;
    }
    if(send(iface->skfd,packet,sizeof(struct ethhdr)+sizeof(struct iphdr)+sizeof(struct icmphdr)+strlen(data), 0) < 0){
      perror("INSERT SEND ERROR");
    }
  }
  free(pass->pay);
  return 0;
}

u_int16_t tcp_checksum(u_char *data,int len)
{
  register u_int32_t  sum;
  register u_int16_t  *ptr;
  register int        c;
    sum=0;
    ptr=(u_int16_t *)data;
    for(c=len;c>1;c-=2){
      sum+=(*ptr);
      if(sum&0x80000000){
        sum=(sum&0xFFFF)+(sum>>16);
      }
     //printf("%#x\n",*ptr);
      ptr++;
    }

    if(c==1){
      u_int16_t       val;
      val=0;
      memcpy(&val,ptr,sizeof(u_int8_t));
      sum+=val;
    }
    while(sum>>16){
      sum=(sum&0xFFFF)+(sum>>16);
    }
    //printf("sum:%#x\n",~sum);
    return(~sum);
}
