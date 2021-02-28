#pragma once
struct interface{
  char *name;
  int skfd;
  int mtu;
  u_char macaddr[6];
  in_addr_t ipaddr;
  in_addr_t ipmask;
  struct operation *op;
  struct packet *queue;
  struct packet *delay_queue;
  struct packet *seq_ack_controll_queue;
  struct routingentry *rtgtbl;
  struct connection *cnxtbl;
  struct arpentry *arptbl;
};


void *init_iface(struct interface *iface, char *ifname);
void print_interface(struct interface *iface);
void print_mac_to_str(u_char *macaddr);
void init_operation(struct interface *iface);
void count_queue(struct interface *iface);
