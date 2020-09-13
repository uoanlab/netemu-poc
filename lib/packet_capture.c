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
#include "interface.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
  FILE *file;
  char *filename;
  filename = (char *)malloc(strlen(args) + 5);
  strcpy(filename,args);
  strcat(filename,".pcap");
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
  ethernet = (struct ethhdr*)(packet);
  ip = (struct iphdr*)(packet + sizeof(struct ethhdr));
  switch(ip->protocol) {
    case IPPROTO_TCP:
      tcp = (struct tcphdr*)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
      size_ip = ip->ihl * 4;
      size_tcp = tcp->doff * 4;
      size_payload = ntohs(ip->tot_len) - (size_ip + size_tcp);
      fwrite(&header->ts.tv_sec,4,1,file);
      fwrite(&header->ts.tv_usec,4,1,file);
      fwrite(&header->caplen,4,1,file);
      fwrite(&header->len,4,1,file);
      fwrite(packet,sizeof(struct ethhdr)+ntohs(ip->tot_len),1,file);
      break;
    case IPPROTO_UDP:
      udp = (struct udphdr*)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
      int size_ip = ip->ihl * 4;
      int size_udp = ntohs(udp->uh_ulen);
      int size_payload = ntohs(udp->uh_ulen)-sizeof(struct udphdr) ;
      fwrite(&header->ts.tv_sec,4,1,file);
      fwrite(&header->ts.tv_usec,4,1,file);
      fwrite(&header->caplen,4,1,file);
      fwrite(&header->len,4,1,file);
      fwrite(packet,sizeof(struct ethhdr)+ntohs(ip->tot_len),1,file);
      return;
    case IPPROTO_ICMP:
      icmp = (struct icmphdr*)(packet + sizeof(struct ethhdr) + sizeof(struct iphdr));
      //pcap hdeadr
      fwrite(&header->ts.tv_sec,4,1,file);
      fwrite(&header->ts.tv_usec,4,1,file);
      fwrite(&header->caplen,4,1,file);
      fwrite(&header->len,4,1,file);
      fwrite(packet,sizeof(struct ethhdr)+ntohs(ip->tot_len),1,file);
      return;
    case IPPROTO_IP:
      fwrite(&header->ts.tv_sec,4,1,file);
      fwrite(&header->ts.tv_usec,4,1,file);
      fwrite(&header->caplen,4,1,file);
      fwrite(&header->len,4,1,file);
      fwrite(packet,sizeof(struct ethhdr)+ntohs(ip->tot_len),1,file);
      return;
    default:
      return;
  }
  fclose(file);
  return;
}

void* capture_loop(void *argv)
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
  FILE *file;
  char *filename;
  filename = (char *)malloc(strlen(iface->name) + 5);
  strncpy(filename,iface->name,strlen(iface->name));
  strcat(filename,".pcap");
  file=fopen(filename,"wb");
  fwrite(global,sizeof(global),1,file);
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
  pcap_loop(handle, num_packets, got_packet, iface->name);
  pcap_freecode(&fp);
  pcap_close(handle);
  return 0;
}

