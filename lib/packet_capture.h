#pragma once
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void *capture_loop(void *argv);
