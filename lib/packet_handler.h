#pragma once

void *send_loop(void *arg);
void *recv_loop(void *arg);
//void *packet_handler(void *arg);
int packet_handler(struct packet *pkt, struct routingentry *route, struct interface *iface);
void *delay_loop(void *arg);

static u_int32_t xorshift();
int loss_pkt(struct packet *pkt);
void modify_log_output(char *filename, struct timeval before, struct timeval after);