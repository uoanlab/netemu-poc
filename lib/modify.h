#pragma once
int modify_pkt(struct packet *pkt, char *before, int blen, char *after, int alen, struct connection *cnxtbl);
int chk_rtns(struct packet *queue, struct packet *pkt);