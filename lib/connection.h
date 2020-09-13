#pragma once
struct connection{
  int id;
  in_addr_t saddr;
  in_addr_t daddr;
  u_int8_t  proto;
  u_int16_t sport;
  u_int16_t dport;
  struct operation op;
  struct connection *next;
  int diff_seq;
  int diff_ack;

  struct packet *saved_pkt_stack;
  struct packet *saved_pkt_queue;
  //test code
  struct packet *saved_pkt_queue_delay;
};


void init_cnxtbl(struct connection *cnxtbl);
void print_cnxtbl(struct connection *cnxtbl);
int get_cnxtbl(struct connection *cnxtbl, char *buf, int size);

void init_cnxentry(struct connection *entry);
struct connection *malloc_cnxentry(void);
void free_cnxentry(struct connection *entry);
struct connection *make_cnxentry(in_addr_t  saddr, in_addr_t daddr, u_int8_t proto, u_int16_t sport, u_int16_t dport);
void add_cnxentry(struct connection *cnxtbl, struct connection *entry);
void del_cnxentry(struct connection *cnxtbl, int id, in_addr_t saddr, in_addr_t daddr, u_int8_t proto, u_int16_t sport, u_int16_t dport);
void clear_cnxtbl(struct connection *cnxtbl);
void update_cnxentry(struct connection *cnxtbl, struct connection *entry);
//struct connection *search_cnxentry(struct connection *cnxtbl ,in_addr_t saddr, in_addr_t daddr, u_int8_t protocol, u_int16_t sport, u_int16_t dport);
struct connection *search_cnxentry(struct connection *cnxtbl , struct packet *pkt);

int set_all(struct connection *cnxtbl, int id, int loss, int delay, char *before, int blen, char *after, int alen);
int unset_all(struct connection *cnxtbl, int id);
int set_loss(struct connection *cnxtbl, int id, int loss, int difftime);
int unset_loss(struct connection *cnxtbl, int id);
int set_delay(struct connection *cnxtbl, int id, int delay, int delay_per, int difftime);
int unset_delay(struct connection *cnxtbl, int id);
int set_modify(struct connection *cnxtbl, int id, char *before, int blen, char *after, int alen, int per,int difftime);
int unset_modify(struct connection *cnxtbl, int id);
int set_flag(struct connection *cnxtbl, int id, char *flag, int flen);
void print_cnx(struct connection *cnx);
void print_saved_pkt_queue(struct connection *cnx);
int make_cnx(struct connection *cnxtbl, struct packet *pkt);
struct connection *generate_cnxentry(struct connection *cnxtbl ,in_addr_t saddr, in_addr_t daddr, u_int8_t proto, u_int16_t sport, u_int16_t dport);
