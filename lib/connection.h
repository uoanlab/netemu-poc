struct ip_mask{
  in_addr_t addr;
  in_addr_t mask;
  struct ip_mask *next;
};

struct ipmask_root{
  struct ip_mask *positive_tree;
  struct ip_mask *denial_tree;
  int any_flag;
};

struct port_tree{
  struct ports *positive_tree;
  struct ports *denial_tree;
  int any_flag;
};

struct ports{
  u_int16_t lower_port;
  u_int16_t higher_port;
  struct ports *next;
};

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
  //test code
  struct ip_mask *ipmask_saddr;
  struct ip_mask *ipmask_daddr;
  int saddr_any_flag;
  int daddr_any_flag;
  struct port_tree *sport_tree;
  struct port_tree *dport_tree;

  struct ipmask_root *ipmask_saddr_root;
  struct ipmask_root *ipmask_daddr_root;
};

void init_cnxtbl(struct connection *cnxtbl);
void print_cnxtbl(struct connection *cnxtbl);
int get_cnxtbl(struct connection *cnxtbl, char *buf, int size);

void init_cnxentry(struct connection *entry);
struct connection *malloc_cnxentry(void);
void free_cnxentry(struct connection *entry);
struct connection *make_cnxentry(in_addr_t saddr, in_addr_t daddr, u_int8_t proto, struct port_tree *sport_tree, struct port_tree *dport_tree, struct ipmask_root *saddr_mask, struct ipmask_root *daddr_mask);
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
struct connection *generate_cnxentry(struct connection *cnxtbl ,in_addr_t saddr, in_addr_t daddr, u_int8_t proto, struct port_tree *sport_tree, struct port_tree *dport_tree, struct ip_mask *saddr_mask, struct ip_mask *daddr_mask, int saddr_any_flag, int daddr_any_flag);
void init_ports(struct ports *port_tree);
void add_port_tree(struct ports *port_tree, struct ports *node);
void print_port(struct port_tree *port_tree);
int string_to_port(char* port_str, u_int16_t *lower_port, u_int16_t *higher_port);

int search_port_tree(u_int16_t port, struct port_tree *port_tree);
void free_tree(struct port_tree *port_tree);
void init_port_tree(struct port_tree *port_tree);
struct port_tree *array_port_parse(char *arr);
int string_to_ipmask(char *ipmask, in_addr_t *ip, in_addr_t *mask);
struct ipmask_root *array_ip_parse(char *arr);
void print_ipmask(struct ip_mask *ip_mask);
void add_ipmask(struct ip_mask *ip_mask, struct ip_mask *node);
void init_ipmask(struct ip_mask *ip_mask);
struct ip_mask *search_ipmask(in_addr_t saddr, struct ip_mask *ip_mask);
void init_ipmask_tree(struct ipmask_root *ip_mask_tree);
int exec_operation(struct packet *pkt, struct connection *conn);
struct connection *search_cnxentry_no_exec(struct connection *cnxtbl, struct packet *pkt);