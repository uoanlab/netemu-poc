#pragma once
int modify_pkt(struct packet *pkt, char *before, int blen, char *after, int alen, struct connection *cnxtbl);
