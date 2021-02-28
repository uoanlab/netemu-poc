#pragma once
int modify_pkt(struct packet *pkt, char *before, int blen, char *after, int alen, struct connection *cnxtbl, struct interface *iface);
int chk_rtns(struct packet *queue, struct packet *pkt);
int seq_ack_controll(struct interface *iface, struct packet *pkt);