#pragma once
#define PKT_BUF_SIZE 1024*80
#define EXTEND_FOR_BUGGY_SERVERS 80
#define DHCP_OPTIONS_BUFSIZE    308

struct packet{
  int size;
  u_char buf[PKT_BUF_SIZE];
  struct ethhdr       *ethhdr;
  struct arphdr       *arphdr;
  struct iphdr        *iphdr;
  struct icmphdr      *icmphdr;
  struct tcphdr       *tcphdr;
  struct udphdr       *udphdr;
  struct dhcp_packet  *dhcphdr;
  u_char              *payload;
  int                  paylen;
  struct timeval       timestamp;
  struct operation     op;
  int                  is_rtns;
  /* test code */
  int                  diff_seq;
  int                  diff_ack;
  /* test code */
  struct packet        *next;
};

/* See RFC 2131 */
struct dhcp_packet {
  uint8_t op;
  uint8_t htype;
  uint8_t hlen;
  uint8_t hops;
  uint32_t xid;
  uint16_t secs;
  uint16_t flags;
  uint32_t ciaddr;
  uint32_t yiaddr;
  uint32_t siaddr_nip;
  uint32_t gateway_nip;
  u_char chaddr[16];
  uint8_t sname[64];
  uint8_t file[128];
  uint8_t cookie[4];
  uint8_t options[DHCP_OPTIONS_BUFSIZE + EXTEND_FOR_BUGGY_SERVERS];
} __attribute__((packed));

struct pseudo_header{
  uint32_t saddr;
  uint32_t daddr;
  uint8_t  reserved;
  uint8_t  protocol;
  uint16_t len;
}__attribute__((__packed__));
 

void init_pkt(struct packet *pkt);
void init_tcphdr(struct tcphdr *tcp);
void init_ethhdr(struct ethhdr *eth);
struct packet *malloc_pkt(void);
void free_pkt(struct packet *pkt);
void proc_pkt(struct packet *pkt);
int  copy_pkt(struct packet *copy, struct packet *origin);
void print_ethhdr(struct ethhdr *ethhdr);
void print_arphdr(struct arphdr *arphdr);
void print_iphdr(struct iphdr *iphdr);
void print_icmphdr(struct icmphdr *icmphdr);
void print_mini_tcphdr(struct tcphdr *tcphdr);
void print_tcphdr(struct tcphdr *tcphdr);
void print_udphdr(struct udphdr *udphdr);
void print_dhcphdr(struct dhcp_packet *dhcphdr);
void print_payload(u_char *payload, int paylen);
void print_pkt(struct packet *pkt);
void print_buf(u_char *buf, int size);
void enqueue(struct packet *queue, struct packet *pkt);
struct packet *dequeue(struct packet *queue);
void push(struct packet **stack, struct packet *pkt);
struct packet *pop(struct packet **stack);
void repl_ethhdr(struct ethhdr *ethhdr, u_char *smac, u_char *dmac);
u_int16_t calc_cksum(u_char *buf, int size);
u_int16_t calc_ip_cksum(struct iphdr *iphdr);
u_int16_t calc_tcp_cksum(struct iphdr *iphdr, struct tcphdr *tcphdr);
u_int16_t calc_udp_cksum(struct iphdr *iphdr, struct udphdr *udphdr);
unsigned short checksum(unsigned short *ptr,int nbytes);
void print_queue(struct packet *queue);
