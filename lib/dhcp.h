#pragma once

void dhcp_discover(struct packet *pkt, struct interface *iface);
void set_eth_header(struct packet *rep_buf,  struct packet *pkt , struct interface *iface);
void set_ip_header(struct packet *rep_buf,  u_int32_t src, struct in_addr *dst);
void set_udp_header(struct packet *rep_buf, int sport, int dport, struct in_addr *src, struct in_addr *dst);
void set_dhcp(struct packet *rep_buf, int dhcp_type, uint32_t dst, struct in_addr *siaddr, struct in_addr *subnetmask, struct packet *pkt, struct interface *iface);
int check_dhcp_message_type(struct packet *pkt);