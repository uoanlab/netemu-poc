#pragma once
void got_pcapng(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void *pcapng_capture_loop(void *argv);
void pcapng_global_header(char *str);
void pcapng_description_tcp(char *str, struct ethhdr *eh, struct iphdr *ih, struct tcphdr *th, int pcap_len);
void pcapng_send(struct packet *pkt, char *str);
