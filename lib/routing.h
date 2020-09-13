#pragma once
struct routingentry{
  in_addr_t ipaddr;
  in_addr_t ipmask;
//  in_addr_t gateway;
  in_addr_t nexthop;
  struct interface *iface;
  struct routingentry *next;
};

void init_rtgtbl(struct routingentry *rtgtbl);
void print_rtgtbl(struct routingentry *rtgtbl);
struct routingentry *make_rtgentry(struct interface *iface);
void add_rtgentry(struct routingentry *rtgtbl, struct routingentry *entry);
struct routingentry *search_route(struct routingentry *rtgtbl, in_addr_t ipaddr);
