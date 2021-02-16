#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netpacket/packet.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "common.h"
#include "packet.h"
#include "interface.h"
#include "pcapng.h"

void got_pcapng(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
  FILE *file;
  char *filename;
  filename = (char *)malloc(strlen(args) + 7);
  strcpy(filename,args);
  strcat(filename,".pcapng");
  file=fopen(filename,"ab");
  free(filename);
  struct ethhdr *ethernet;
  struct iphdr *ip;
  struct tcphdr *tcp;
  struct udphdr *udp;
  struct icmphdr *icmp;
  const char *payload;
  int size_ip;
  int size_tcp;
  int size_payload;
  unsigned char blocktype[4] = {0x06,0x00,0x00,0x00};
  unsigned char block_option[2] = {0x00,0x00};
  unsigned char iid[4] = {0x00,0x00,0x00,0x00};
  unsigned char op[2] = {0x00,0x00};
  ethernet = (struct ethhdr*)(packet);
  ip = (struct iphdr*)(packet + sizeof(struct ethhdr));
  switch(ip->protocol) {
    case IPPROTO_TCP:
      tcp = (struct tcphdr*)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
      size_ip = ip->ihl * 4;
      size_tcp = tcp->doff * 4;
      size_payload = ntohs(ip->tot_len) - (size_ip + size_tcp);
    //write enhanced block
      //block type
      int block_len=34+sizeof(struct ethhdr)+ntohs(ip->tot_len);
      fwrite(blocktype,sizeof(blocktype),1,file);
      fwrite(&block_len,4,1,file);
      fwrite(iid,sizeof(iid),1,file);
      fwrite(&header->ts.tv_sec,4,1,file);
      fwrite(&header->ts.tv_usec,4,1,file);
      fwrite(&header->caplen,4,1,file);
      fwrite(&header->len,4,1,file);
      //option
      fwrite(packet,sizeof(struct ethhdr)+ntohs(ip->tot_len),1,file);
      //block length
      fwrite(op,sizeof(op),1,file);
      fwrite(&block_len,4,1,file);
      break;

    case IPPROTO_UDP:
//      printf("udp\n");
      udp = (struct udphdr*)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
      int size_ip = ip->ihl * 4;
      int size_udp = ntohs(udp->uh_ulen);
      int size_payload = ntohs(udp->uh_ulen)-sizeof(struct udphdr) ;
    //write enhanced block
      //block type
      fwrite(blocktype,sizeof(blocktype),1,file);
      //block length
      int tempu=44+sizeof(struct ethhdr)+ntohs(ip->tot_len);
      u_int32_t block_udplength;
      char tempu2[4]={'\0'};
      sprintf(tempu2, "%x", tempu);
      sscanf(tempu2,"%hx",&block_udplength);
      fwrite(&block_udplength,sizeof(block_udplength),1,file);
      //block interface id
      fwrite(iid,sizeof(iid),1,file);
      sizeof(struct ethhdr)+ntohs(ip->tot_len);
      fwrite(&header->ts.tv_sec,4,1,file);
      fwrite(&header->ts.tv_usec,4,1,file);
      //padding func
      fwrite(&header->caplen,4,1,file);
      fwrite(&header->len,4,1,file);
      fwrite(packet,sizeof(struct ethhdr)+ntohs(ip->tot_len),1,file);
      unsigned char padding[12]={
        0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00
      };
      fwrite(padding,sizeof(padding),1,file);
      //block length
      fwrite(&block_udplength,sizeof(block_udplength),1,file);
      break;

    case IPPROTO_ICMP:
      icmp = (struct icmphdr*)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
//      printf("icmp\n");
      //block type
      fwrite(blocktype,sizeof(blocktype),1,file);
      //block length
      u_int32_t block_icmplength=34+sizeof(struct ethhdr)+ntohs(ip->tot_len);
      fwrite(&block_icmplength,sizeof(block_icmplength),1,file);
      //block interface id
      fwrite(iid,sizeof(iid),1,file);
      fwrite(&header->ts.tv_sec,4,1,file);
      fwrite(&header->ts.tv_usec,4,1,file);
      fwrite(&header->caplen,4,1,file);
      fwrite(&header->len,4,1,file);
      fwrite(packet,sizeof(struct ethhdr)+ntohs(ip->tot_len),1,file);
      fwrite(op,sizeof(op),1,file);
      //block length
      fwrite(&block_icmplength,sizeof(block_icmplength),1,file);
      break;
    case IPPROTO_IP:
      fwrite(&header->ts.tv_sec,4,1,file);
      fwrite(&header->ts.tv_usec,4,1,file);
      fwrite(&header->caplen,4,1,file);
      fwrite(&header->len,4,1,file);
      fwrite(packet,sizeof(struct ethhdr)+ntohs(ip->tot_len),1,file);
      break;
    default:
      break;
  }
  fclose(file);
  return;
}


void* pcapng_capture_loop(void *argv)
{
  struct interface *iface = (struct interface *)argv;
  char *dev = NULL;
  dev =(char *)malloc(strlen(iface->name));
  strcpy(dev,iface->name);
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle;
  char filter_exp[] = "ip";
  struct bpf_program fp;
  bpf_u_int32 mask;
  bpf_u_int32 net;
  int num_packets = -1;

  //Section Header Block
  static const unsigned char shb[28] = {
    0x0a, 0x0d, 0x0d, 0x0a,//block type,
    0x1c, 0x00, 0x00, 0x00,//block length
    0x4d, 0x3c, 0x2b, 0x1a,//byte order magic
    0x01, 0x00, 0x00, 0x00,//version
    0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff,
    0x1c, 0x00, 0x00, 0x00 //block length
  };

  //Interface Description Block
  static const unsigned char idb[20] = {
    0x01, 0x00, 0x00, 0x00,//block type,
    0x14, 0x00, 0x00, 0x00,//block length
    0x01, 0x00,            //link type
    0x00, 0x00,            //reserved
    0x00, 0x00, 0x04, 0x00,//snap length
    0x14, 0x00, 0x00, 0x00 //block length
  };
  //test.pcap 初期化
  FILE *file;
  char *filename;
  filename = (char *)malloc(strlen(iface->name) + 7);
  strncpy(filename,iface->name,strlen(iface->name));
  strcat(filename,".pcapng");
  file=fopen(filename,"wb");
  fwrite(shb,sizeof(shb),1,file);
  fwrite(idb,sizeof(idb),1,file);
  free(filename);
  fclose(file);

  if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
    fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
        dev, errbuf);
    net = 0;
    mask = 0;
  }
  handle = pcap_open_live(dev, 200000, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    exit(EXIT_FAILURE);
  }
  if (pcap_datalink(handle) != DLT_EN10MB) {
    fprintf(stderr, "%s is not an Ethernet\n", dev);
    exit(EXIT_FAILURE);
  }
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n",
        filter_exp, pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }
  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n",
        filter_exp, pcap_geterr(handle));
    exit(EXIT_FAILURE);
  }
  free(dev);
  pcap_loop(handle, num_packets, got_pcapng, iface->name);
  pcap_freecode(&fp);
  pcap_close(handle);
  return 0;
}

void pcapng_global_header(char *str)
{
  //Section Header Block
  static const unsigned char shb[28] = {
    0x0a, 0x0d, 0x0d, 0x0a,//block type,
    0x1c, 0x00, 0x00, 0x00,//block length
    0x4d, 0x3c, 0x2b, 0x1a,//byte order magic
    0x01, 0x00, 0x00, 0x00,//version
    0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff,
    0x1c, 0x00, 0x00, 0x00 //block length
  };

  //Interface Description Block
  static const unsigned char idb[20] = {
    0x01, 0x00, 0x00, 0x00,//block type,
    0x14, 0x00, 0x00, 0x00,//block length
    0x01, 0x00,            //link type
    0x00, 0x00,            //reserved
    0x00, 0x00, 0x04, 0x00,//snap length
    0x14, 0x00, 0x00, 0x00 //block length
  };

  //test.pcapng 初期化
  FILE *file;
  file=fopen(str,"wb");
  fwrite(shb,sizeof(shb),1,file);
  fwrite(idb,sizeof(idb),1,file);
  fclose(file);
}

void pcapng_description_tcp(char *str, struct ethhdr *ethernet, struct iphdr *ip, struct tcphdr *tcp, int pcap_len)
{
  FILE *file;
  file=fopen(str,"ab");
  struct udphdr *udp;
  struct icmphdr *icmp;
  const char *payload;
  int size_ip;
  int size_tcp;
  int size_payload;
  unsigned char blocktype[4] = {0x06,0x00,0x00,0x00};
  unsigned char block_option[2] = {0x00,0x00};
  unsigned char iid[4] = {0x00,0x00,0x00,0x00};
  unsigned char op[2] = {0x00,0x00};
  //ethernet = (struct ethhdr*)(packet);
  //ip = (struct iphdr*)(packet + sizeof(struct ethhdr));
  switch(ip->protocol) {
    case IPPROTO_TCP:
  //    tcp = (struct tcphdr*)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
      size_ip = ip->ihl * 4;
      size_tcp = tcp->doff * 4;
      size_payload = ntohs(ip->tot_len) - (size_ip + size_tcp);
      //write enhanced block
      //block type
      fwrite(blocktype,sizeof(blocktype),1,file);
      //block length
      int block_length=34+sizeof(struct ethhdr)+ntohs(ip->tot_len)+16;
      u_int16_t block_tcplength;
      fwrite(&block_length,4,1,file);
      //block interface id
      fwrite(iid,sizeof(iid),1,file);
      sizeof(struct ethhdr)+ntohs(ip->tot_len);
      struct timeval pcap_time;
      gettimeofday(&pcap_time, NULL);
      fwrite(&pcap_time.tv_sec,4,1,file);
      fwrite(&pcap_time.tv_usec,4,1,file);
      char temp2[4]={'\0'};
      u_int32_t tes=pcap_len;
      fwrite(&tes,4,1,file);
      fwrite(&tes,4,1,file);
      fwrite(ethernet,pcap_len,1,file);
      //option
  //    fwrite(packet,sizeof(struct ethhdr)+ntohs(ip->tot_len),1,file);
      //block length
      fwrite(op,sizeof(op),1,file);
      unsigned char comment[2] = {0x01,0x00};
      unsigned char length[2] = {0x06,0x00};
      unsigned char word[6] = {0x69,0x6e,0x73,0x65,0x72,0x74};
      fwrite(comment,2,1,file);
      fwrite(length,2,1,file);
      fwrite(word,6,1,file);
      fwrite(op,sizeof(op),1,file);
      fwrite(op,sizeof(op),1,file);
      fwrite(op,sizeof(op),1,file);
      fwrite(&block_length,4,1,file);
      break;
//    case IPPROTO_UDP:
//      printf("udp\n");
  //    udp = (struct udphdr*)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
//      int size_ip = ip->ihl * 4;
//      int size_udp = ntohs(udp->uh_ulen);
//      int size_payload = ntohs(udp->uh_ulen)-sizeof(struct udphdr) ;
//    //write enhanced block
//      //block type
//      fwrite(blocktype,sizeof(blocktype),1,file);
//      //block length
//      int tempu=44+sizeof(struct ethhdr)+ntohs(ip->tot_len);
//      u_int32_t block_udplength;
//      char tempu2[4]={'\0'};
//      sprintf(tempu2, "%x", tempu);
//      sscanf(tempu2,"%hx",&block_udplength);
//      fwrite(&block_udplength,sizeof(block_udplength),1,file);
//      //block interface id
//      fwrite(iid,sizeof(iid),1,file);
//      sizeof(struct ethhdr)+ntohs(ip->tot_len);
//      fwrite(&header->ts.tv_sec,4,1,file);
//      fwrite(&header->ts.tv_usec,4,1,file);
//      //padding func
//      fwrite(&header->caplen,4,1,file);
//      fwrite(&header->len,4,1,file);
//  //    fwrite(packet,sizeof(struct ethhdr)+ntohs(ip->tot_len),1,file);
//      unsigned char padding[12]={
//        0x00,0x00,0x00,0x00,
//        0x00,0x00,0x00,0x00,
//        0x00,0x00,0x00,0x00
//      };
//      fwrite(padding,sizeof(padding),1,file);
//      //block length
//      fwrite(&block_udplength,sizeof(block_udplength),1,file);
//      break;
//
//    case IPPROTO_ICMP:
//  //    icmp = (struct icmphdr*)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
////      printf("icmp\n");
//      //block type
//      fwrite(blocktype,sizeof(blocktype),1,file);
//      //block length
//      int tempi=34+sizeof(struct ethhdr)+ntohs(ip->tot_len);
//      u_int32_t block_icmplength=0x0;
//      char tempi2[4]={'\0'};
//      sprintf(tempi2, "%x", tempi);
//      sscanf(tempi2,"%hx",&block_icmplength);
//      fwrite(&block_icmplength,sizeof(block_icmplength),1,file);
//      //block interface id
//      fwrite(iid,sizeof(iid),1,file);
//      sizeof(struct ethhdr)+ntohs(ip->tot_len);
//      fwrite(&header->ts.tv_sec,4,1,file);
//      fwrite(&header->ts.tv_usec,4,1,file);
//      fwrite(&header->caplen,4,1,file);
//      fwrite(&header->len,4,1,file);
//  //    fwrite(packet,sizeof(struct ethhdr)+ntohs(ip->tot_len),1,file);
//      fwrite(op,sizeof(op),1,file);
//      //block length
//      fwrite(&block_icmplength,sizeof(block_icmplength),1,file);
//      break;
//    case IPPROTO_IP:
//      fwrite(&header->ts.tv_sec,4,1,file);
//      fwrite(&header->ts.tv_usec,4,1,file);
//      fwrite(&header->caplen,4,1,file);
//      fwrite(&header->len,4,1,file);
//  //    fwrite(packet,sizeof(struct ethhdr)+ntohs(ip->tot_len),1,file);
//      break;
//    default:
//      break;
  }
  fclose(file);
}

void pcapng_send(struct packet *pkt, char *str){
  char *filename;
//  filename = (char *)malloc(strlen(str) + 7);
//  strcpy(filename,str);
//  strcat(filename,".pcapng");
  if(!strcmp(str,"eth1"))
    filename="test1.pcapng";
  else
    filename="test2.pcapng";
  struct ethhdr *ethernet;
  struct iphdr *ip;
  struct tcphdr *tcp;
  struct icmphdr *icmp;
  int size_ip;
  int size_tcp;
  int size_payload;
  unsigned char blocktype[4] = {0x06,0x00,0x00,0x00};
  unsigned char block_option[2] = {0x00,0x00};
  unsigned char iid[4] = {0x00,0x00,0x00,0x00};
  unsigned char op[2] = {0x00,0x00};
  unsigned char pad1[1] = {0x00};
  unsigned char pad2[2] = {0x00,0x00};
  unsigned char pad3[3] = {0x00,0x00,0x00};
  unsigned char pad4[4] = {0x00,0x00,0x00,0x00};

  if(pkt->arphdr){}
  else if(pkt->iphdr){
    if(pkt->iphdr->protocol == IPPROTO_TCP){
      //case IPPROTO_TCP:
      FILE *file;
      file=fopen(filename,"ab");
      size_ip = pkt->iphdr->ihl * 4;
      size_tcp = pkt->tcphdr->doff * 4;
      size_payload = ntohs(pkt->iphdr->tot_len) - (size_ip + size_tcp);
    //write enhanced block
      //block type
      //block length
      int pcap_len = sizeof(struct ethhdr)+size_ip+size_tcp;
      int block_length=34+pcap_len+strlen(pkt->payload);
      int pad_size = 0;
      while((block_length+pad_size)%4!=0)
        pad_size=pad_size+1;
      block_length+=pad_size;
      u_int32_t tes=pcap_len+strlen(pkt->payload)+pad_size;
      if(pkt->op.delay)
        block_length+=16;
      else if(pkt->op.modify)
        block_length+=16;
      else if(pkt->op.loss)
        block_length+=16;
      fwrite(blocktype,4,1,file);
      fwrite(&block_length,4,1,file);
      fwrite(iid,4,1,file);
      fwrite(&pkt->timestamp.tv_sec,4,1,file);
      fwrite(&pkt->timestamp.tv_usec,4,1,file);

      fwrite(&tes,4,1,file);
      fwrite(&tes,4,1,file);
      fwrite(pkt->ethhdr,sizeof(struct ethhdr),1,file);
      fwrite(pkt->iphdr,size_ip,1,file);
      fwrite(pkt->tcphdr,size_tcp,1,file);
        for(int i=0; i<pad_size; i++){
          fwrite(pad1,1,1,file);
        }
      fwrite(pkt->payload,strlen(pkt->payload),1,file);
      fwrite(op,2,1,file);
      //block length
      if(pkt->op.delay){
        printf("delay\n");
        unsigned char comment[2] = {0x01,0x00};
        unsigned char length[2] = {0x06,0x00};
        unsigned char word[6] = {0x64,0x65,0x6c,0x61,0x79,0x3a};
        fwrite(comment,2,1,file);
       fwrite(length,2,1,file);
        fwrite(word,6,1,file);
        fwrite(pad1,1,1,file);
        fwrite(pad1,1,1,file);
        fwrite(pad4,4,1,file);
      }
      else if(pkt->op.modify){
        unsigned char comment[2] = {0x01,0x00};
        unsigned char length[2] = {0x06,0x00};
        unsigned char word[6] = {0x6d,0x6f,0x64,0x69,0x66,0x79};
        fwrite(comment,2,1,file);
        fwrite(length,2,1,file);
        fwrite(word,6,1,file);
        fwrite(pad1,1,1,file);
        fwrite(pad1,1,1,file);
        fwrite(pad4,4,1,file);
      }
      else if(pkt->op.loss){
        unsigned char comment[2] = {0x01,0x00};
        unsigned char length[2] = {0x06,0x00};
        unsigned char word[6] = {0x64,0x72,0x6f,0x70,0x3a,0x3a};
        fwrite(comment,2,1,file);
        fwrite(length,2,1,file);
        fwrite(word,6,1,file);
        fwrite(pad1,1,1,file);
        fwrite(pad1,1,1,file);
        fwrite(pad4,4,1,file);
      }
      fwrite(&block_length,4,1,file);
      fclose(file);
    }
    else if(pkt->iphdr->protocol == IPPROTO_UDP){
      FILE *file;
      file=fopen(filename,"ab");
      struct udphdr *udp;
      struct iphdr *ip;
      udp = pkt->udphdr;
      ip = pkt->iphdr;
      unsigned char padding[12]={
        0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00
      };
      int size_ip = ip->ihl * 4;
      int size_udp = ntohs(udp->uh_ulen);
      int size_payload = ntohs(udp->uh_ulen)-sizeof(struct udphdr);
      int pcap_len = sizeof(struct ethhdr)+size_ip+size_udp;
      //write enhanced block
      //block type
      fwrite(blocktype,sizeof(blocktype),1,file);
      //block length
      int block_udplength=32+sizeof(struct ethhdr)+size_ip+size_udp+6;
      u_int32_t hdr_len=pcap_len+strlen(pkt->payload);
      int pad_size=0;
      while((block_udplength+pad_size)%4!=0)
        pad_size+=1;
      block_udplength+=pad_size;
//      u_int32_t block_udplength;
      fwrite(&block_udplength,4,1,file);
      //block interface id
      fwrite(iid,sizeof(iid),1,file);
      fwrite(&pkt->timestamp.tv_sec,4,1,file);
      fwrite(&pkt->timestamp.tv_usec,4,1,file);
      fwrite(&hdr_len,4,1,file);
      fwrite(&hdr_len,4,1,file);
      fwrite(pkt->ethhdr,sizeof(struct ethhdr),1,file);
      fwrite(pkt->iphdr,size_ip,1,file);
      fwrite(pkt->udphdr,size_udp,1,file);
      fwrite(pkt->payload,strlen(pkt->payload),1,file);
      fwrite(padding,pad_size,1,file);
      //block length
      fwrite(&block_udplength,sizeof(block_udplength),1,file);
      fclose(file);
    }
    // ICMP出力はやっていない。おそらく動くと思うけどテストはしていない
//    else if(pkt->iphdr->protocol == IPPROTO_ICMP){
//      FILE *file;
//      file=fopen(filename,"ab");
//      ip = pkt->iphdr;
//      icmp = pkt->icmphdr;
//      //block type
//      fwrite(blocktype,sizeof(blocktype),1,file);
//      //block length
//      int block_icmplength=34+sizeof(struct ethhdr)+ntohs(pkt->iphdr->tot_len);
//      //block length
//      fwrite(&block_icmplength,sizeof(block_icmplength),1,file);
//      fwrite(iid,sizeof(iid),1,file);
//      fwrite(&pkt->timestamp.tv_sec,4,1,file);
//      fwrite(&pkt->timestamp.tv_usec,4,1,file);
//      fwrite(pkt->ethhdr,sizeof(struct ethhdr),1,file);
//      fwrite(ip,ip->ihl*4,1,file);
//      printf("dbg4:%d\n",ip->tot_len);
//      fwrite(icmp,ip->tot_len-ip->ihl*4-strlen(pkt->payload),1,file);
//      printf("dbg3\n");
//      fwrite(pkt->payload,strlen(pkt->payload),1,file);
//      fwrite(op,sizeof(op),1,file);
//      //block length
//      fwrite(&block_icmplength,sizeof(block_icmplength),1,file);
//      fclose(file);
    else if(pkt->iphdr->protocol == IPPROTO_IP){
      FILE *file;
      file=fopen(filename,"ab");
      u_int32_t block_length = sizeof(struct ethhdr) + pkt->iphdr->tot_len+34;
      int pad_size = 0;
      while((block_length+pad_size)%4!=0)
        pad_size=pad_size+1;
      block_length+=pad_size;
      u_int32_t ip_length = sizeof(struct ethhdr) + pkt->iphdr->tot_len+pad_size;
      fwrite(&block_length,4,1,file);
      fwrite(iid,sizeof(iid),1,file);
      fwrite(&pkt->timestamp.tv_sec,4,1,file);
      fwrite(&pkt->timestamp.tv_usec,4,1,file);
      fwrite(&ip_length,4,1,file);
      fwrite(&ip_length,4,1,file);
      fwrite(pkt->ethhdr,sizeof(struct ethhdr),1,file);
      fwrite(pkt->iphdr,pkt->iphdr->tot_len-strlen(pkt->payload),1,file);
      for(int i=0; i<pad_size; i++)
        fwrite(pad1,1,1,file);
      fwrite(pkt->payload,strlen(pkt->payload),1,file);
      fwrite(&block_length,4,1,file);
      fclose(file);
    }
    else{}
  }
//      break;
  return;
}
