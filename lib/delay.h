#pragma once

void delay_enqueue(struct packet *queue, struct packet *pkt);
void delay_pkt(struct routingentry *route, struct packet *pkt);
struct packet *delay_dequeue(struct packet *queue);