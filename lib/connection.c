#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<pthread.h>
#include<arpa/inet.h>
#include<netinet/ether.h>
#include<netinet/ip_icmp.h>
#include<netinet/tcp.h>
#include<netinet/udp.h>

#include"common.h"
#include"packet.h"
#include"connection.h"

struct connection *free_cnxentry_queue = NULL;

void init_cnxtbl(struct connection *cnxtbl){
  cnxtbl->next = NULL;
}
void print_cnxtbl(struct connection *cnxtbl){
  struct connection *c;
  char ipstr[16];
  printf("======================================== Connection  Table =======================================\n");
  printf("|id| source ipaddr |  dest ipaddr  |proto|sport|dport|                   flag                    |\n");
  printf("--------------------------------------------------------------------------------------------------\n");
  for(c=cnxtbl->next;c;c=c->next){
    printf("|%2d", c->id);
    iptostr(c->saddr, ipstr);
    printf("|%15s", ipstr);
    iptostr(c->daddr, ipstr);
    printf("|%15s", ipstr);
    printf("|");
    if(c->proto == IPPROTO_TCP)       printf(" TCP ");
    else if(c->proto == IPPROTO_UDP)  printf(" UDP ");
    else if(c->proto == IPPROTO_ICMP) printf(" ICMP");
    else printf("Other");
    printf("|%5d", ntohs(c->sport));
    printf("|%5d", ntohs(c->dport));
    printf("| loss : ");
    (c->op.loss) ? printf("%3d%%", c->op.loss) : printf("  x ");
    printf("| delay : ");
    (c->op.delay) ? printf("%6dms %3d%%", c->op.delay, c->op.delay_per) : printf("           x ");
    printf("| modify : ");
    (c->op.modify) ? printf("%s to %s ", c->op.mset.before, c->op.mset.after) : printf("x ");
    printf("|\n");
  }
  printf("===================================================================================================\n");
  print_saved_pkt_queue(cnxtbl);
}
int get_cnxtbl(struct connection *cnxtbl, char *buf, int size){
  int ret_len=0;
  int len;
  len = snprintf(buf,
		 size,
		 "=========================================== Connection  Table ==========================================\n" \
		 "| id| source ipaddr |  dest ipaddr  |proto|sport|dport|                      flag                      |\n" \
		 "--------------------------------------------------------------------------------------------------------\n");
  buf+=len; size-=len;
  ret_len += len;

  char ipstr[16];
  char ipstr2[16];
  struct connection *c;
  for(c=cnxtbl->next;(c && 0<(size/100)-1);c=c->next){
    len = snprintf(buf,
		   size,
		   "|%3d|%15s|%15s|%5s|%5d|%5d",
		   c->id,
		   ((iptostr(c->saddr, ipstr), ipstr)),
		   ((iptostr(c->daddr, ipstr2), ipstr2)),
		   (c->proto == IPPROTO_TCP)  ? " TCP " :
		   (c->proto == IPPROTO_UDP)  ? " UDP " :
		   (c->proto == IPPROTO_ICMP) ? " ICMP" : "Other",
		   ntohs(c->sport),
		   ntohs(c->dport)
		   );
    buf+=len; size-=len;
    ret_len += len;
    len = (c->op.loss) ?
      snprintf(buf, size, "| loss : %3d%%", c->op.loss) :
      snprintf(buf, size, "| loss : %4s", "x");
    buf+=len; size-=len;
    ret_len += len;
    len = (c->op.delay) ?
      sprintf(buf, "| delay : %6dms %3d%%", c->op.delay, c->op.delay_per) :
      sprintf(buf, "| delay : %8s", "x");
    buf+=len; size-=len;
    ret_len += len;
    len = (c->op.modify) ?
      sprintf(buf, "| modify :       o|\n") :
      sprintf(buf, "| modify :       x|\n");
    buf+=len; size-=len;
    ret_len += len;
    if(c->op.modify){
      len = snprintf(buf, size, "| %45s to %46s |\n", c->op.mset.before, c->op.mset.after);
      buf+=len; size-=len;
      ret_len += len;
    }
    if(c->proto == IPPROTO_TCP){
    len = snprintf(buf, size, "|   |       TCP flag|urg:%d ack:%d psh:%d rst:%d syn:%d fin:%d                                               |\n", c->op.headder.urg, c->op.headder.ack, c->op.headder.psh, c->op.headder.rst, c->op.headder.syn, c->op.headder.fin );
      buf+=len; size-=len;
      ret_len += len;
    }
  }
  len = snprintf(buf, size, "========================================================================================================\n");
  ret_len += len;
//  print_saved_pkt_queue(cnxtbl);
  return ret_len;
}
void init_cnxentry(struct connection *entry){
  entry->id          = 1;
  entry->saddr       = 0;
  entry->daddr       = 0;
  entry->proto       = 0;
  entry->sport       = 0;
  entry->dport       = 0;
  entry->op.loss   = 0;
  entry->op.delay  = 0;
  entry->op.modify = 0;
  memset(&entry->op.mset, 0, sizeof(struct modify_set));
  entry->next        = NULL;
  entry->diff_seq    = 0;
  entry->diff_ack    = 0;
  entry->saved_pkt_stack = NULL;
  entry->saved_pkt_queue = NULL;
  //test code
  entry->saved_pkt_queue_delay = NULL;
}
struct connection *malloc_cnxentry(){
  struct connection *entry;
  pthread_mutex_lock(&mutex);
  if(free_cnxentry_queue){
    entry = free_cnxentry_queue;
    free_cnxentry_queue = free_cnxentry_queue->next;
  }
  else{
    entry = malloc(sizeof(struct connection));
  }
  pthread_mutex_unlock(&mutex);

  init_cnxentry(entry);

  return entry;
}
void free_cnxentry(struct connection *entry){
  struct packet *free;
  for(free=pop(&entry->saved_pkt_queue);free;free=pop(&entry->saved_pkt_stack)) free_pkt(free);
  entry->saved_pkt_queue = NULL;
  pthread_mutex_lock(&mutex);
  entry->next = free_cnxentry_queue;
  free_cnxentry_queue = entry;
  pthread_mutex_unlock(&mutex);
}
void add_cnxentry(struct connection *cnxtbl,struct connection *entry){
  struct connection *c;
  for(c=cnxtbl; c->next!=NULL; c=c->next) 
    entry->id++;
  c->next = entry;
}
void del_cnxentry(struct connection *cnxtbl, int id, in_addr_t saddr, in_addr_t daddr, u_int8_t proto, u_int16_t sport, u_int16_t dport){
  struct connection *c;
  for(c=cnxtbl;c->next;){
    if((id == c->next->id) ||
       ((saddr == c->next->saddr || c->next->saddr == 0) &&
        (daddr == c->next->daddr || c->next->daddr == 0) &&
        (proto == c->next->proto || c->next->proto == 0) &&
        (sport == c->next->sport || c->next->sport == 0) &&
        (dport == c->next->dport || c->next->dport == 0))){
      struct connection *free = c->next;
      c->next = c->next->next;
      free_cnxentry(free);
      continue;
    }
    c=c->next;
  }
}
void clear_cnxtbl(struct connection *cnxtbl){
  struct connection *c;
  for(c=cnxtbl;c->next;){
    struct connection *free = c->next;
    c->next = c->next->next;
    free_cnxentry(free);
  }
}

void update_cnxentry(struct connection *cnxtbl, struct connection *entry){}

struct connection *search_cnxentry(struct connection *cnxtbl, struct packet *pkt){
  in_addr_t saddr = pkt->iphdr->saddr;
  in_addr_t daddr = pkt->iphdr->daddr; 
  u_int8_t proto  = pkt->iphdr->protocol;
  u_int16_t sport;
  u_int16_t dport;
  if(pkt->tcphdr){
    sport = pkt->tcphdr->source;
    dport = pkt->tcphdr->dest;
  }
  else if(pkt->udphdr){
    sport = pkt->udphdr->source;
    dport = pkt->udphdr->dest;
  }
  else if(pkt->icmphdr){
    sport = 0;
    dport = 0;
  }
  else{
    sport = 0;
    dport = 0; 
  }
                    
  struct connection *c;
  for(c=cnxtbl->next;c;c=c->next){
//    test
    if((saddr == c->saddr || c->saddr == 0) &&
       (daddr == c->daddr || c->daddr == 0) &&
       (proto == c->proto || c->proto == 0) &&
      ((sport == c->sport || c->sport == 0) ||
       (dport == c->dport || c->dport == 0)
      )
      ){
        copy_operation(&pkt->op, &c->op);
        return c;
    }
  }
  return NULL;
}
int set_all(struct connection *cnxtbl, int id, int loss, int delay, char *before, int blen, char *after, int alen){
  struct connection *c;
  for(c=cnxtbl->next;c;c=c->next){
    if(c->id == id){
      c->op.loss   = loss;
      c->op.delay  = delay;
      c->op.modify = 1;
      memset(c->op.mset.before, 0, c->op.mset.blen);
      c->op.mset.blen = blen;
      memcpy(c->op.mset.before, before, blen);
      memset(c->op.mset.after, 0, c->op.mset.alen);
      c->op.mset.alen = alen;
      memcpy(c->op.mset.after,  after,  alen);
      return 1;
    }
  }
  return 0;
}
int unset_all(struct connection *cnxtbl, int id){
  struct connection *c;
  for(c=cnxtbl->next;c;c=c->next){
    if(c->id == id){
      c->op.loss   = 0;
      c->op.delay  = 0;
      c->op.modify = 0;
      memset(&c->op.mset, 0, sizeof(struct modify_set));
      return 1;
    }
  }
  return 0;
}
int set_loss(struct connection *cnxtbl, int id, int loss, int difftime){
  struct connection *c;
  printf("SET LOSS connection.c\n");
  for(c=cnxtbl->next;c;c=c->next){
    printf("test\n");
    if(c->id == id){
      c->op.loss = loss;
      c->op.loss_start = time(NULL);
      c->op.loss_difftime = difftime;
      printf("start loss id :%d\n",c->id);
      printf("start loss :%d\n",c->op.loss);
      return 1;
    }
  }
  return 0;
}
int unset_loss(struct connection *cnxtbl, int id){
  return set_loss(cnxtbl, id, 0, 0);
}
int set_delay(struct connection *cnxtbl, int id, int delay, int delay_per, int difftime){
  struct connection *c;
  for(c=cnxtbl->next;c;c=c->next){
    if(c->id == id){
      c->op.delay = delay;
      c->op.delay_per = delay_per;
      c->op.delay_start = time(NULL);
      printf("start:%ld\n",c->op.delay_start);
      c->op.delay_difftime = difftime;
      return 1;
    }
  }
  return 0;
}
int unset_delay(struct connection *cnxtbl, int id){
  return set_delay(cnxtbl, id, 0, 0, 0);
}
int set_modify(struct connection *cnxtbl, int id, char *before, int blen, char *after, int alen, int per, int difftime){
  struct connection *c;
  for(c=cnxtbl->next;c;c=c->next){
    if(c->id == id){
      c->op.modify = 1;
      c->op.modify_per=per;
      memset(c->op.mset.before, 0, c->op.mset.blen);
      c->op.mset.blen = blen;
      memcpy(c->op.mset.before, before, blen);
      memset(c->op.mset.after , 0, c->op.mset.alen);
      c->op.mset.alen = alen;
      memcpy(c->op.mset.after,  after,  alen);
      c->op.modify_start = time(NULL);
      printf("start:%ld\n",c->op.modify_start);
      c->op.modify_difftime = difftime;
      return 1;
    }
  }
  return 0;
}
int unset_modify(struct connection *cnxtbl, int id){
  struct connection *c;
  for(c=cnxtbl->next;c;c=c->next){
    if(c->id == id){
      c->op.modify = 0;
      c->op.mset.blen = 0;
      memset(c->op.mset.before, 0, MODIFY_BUF_SIZE);
      c->op.mset.alen = 0;
      memset(c->op.mset.after , 0, MODIFY_BUF_SIZE);
      return 1;
    }
  }
  return 0;
}
int set_flag(struct connection *cnxtbl, int id, char *flag, int flen){
  struct connection *c;
  for(c=cnxtbl->next;c;c=c->next){
    if(c->id == id){
      if(memcmp("urg",flag,flen)==0)c->op.headder.urg=1;
      if(memcmp("ack",flag,flen)==0)c->op.headder.ack=1;
      if(memcmp("psh",flag,flen)==0)c->op.headder.psh=1;
      if(memcmp("rst",flag,flen)==0)c->op.headder.rst=1;
      if(memcmp("syn",flag,flen)==0)c->op.headder.syn=1;
      if(memcmp("fin",flag,flen)==0)c->op.headder.fin=1;
      printf("%d\n",c->op.headder.urg);
      return 1;
    }
  }
  return 0;
}
void print_cnx(struct connection *cnx){
  char ipstr[16];
  printf("======================================== Connection  Table =======================================\n");
  printf("|id| source ipaddr |  dest ipaddr  |proto|sport|dport|                   flag                    |\n");
  printf("--------------------------------------------------------------------------------------------------\n");
    printf("|%2d", cnx->id);
    iptostr(cnx->saddr, ipstr);
    printf("|%15s", ipstr);
    iptostr(cnx->daddr, ipstr);
    printf("|%15s", ipstr);
    printf("|");
    if(cnx->proto == IPPROTO_TCP)       printf(" TCP ");
    else if(cnx->proto == IPPROTO_UDP)  printf(" UDP ");
    else if(cnx->proto == IPPROTO_ICMP) printf(" ICMP");
    else printf("Other");
    printf("|%5d", ntohs(cnx->sport));
    printf("|%5d", ntohs(cnx->dport));
    printf("| loss : ");
    (cnx->op.loss) ? printf("%3d%%", cnx->op.loss) : printf("  x ");
    printf("| delay : ");
    (cnx->op.delay) ? printf("%6dms", cnx->op.delay) : printf("      x ");
    printf("| modify : ");
    (cnx->op.modify) ? printf("%s to %s ", cnx->op.mset.before, cnx->op.mset.after) : printf("x ");
    printf("|\n");
  printf("==================================================================================================\n");
  print_saved_pkt_queue(cnx);
}
void print_saved_pkt_queue(struct connection *cnx){
  char ipstr[16];
  struct packet *pkt;
  for(pkt=cnx->saved_pkt_queue; pkt!=NULL; pkt=cnx->saved_pkt_queue){
    printf("change\n");
    printf("++++++++++++ packet +++++++++++++\n");
    if(pkt->ethhdr)  print_ethhdr(pkt->ethhdr);
    if(pkt->arphdr)  print_arphdr(pkt->arphdr);
    if(pkt->iphdr)   print_iphdr(pkt->iphdr);
    if(pkt->icmphdr) print_icmphdr(pkt->icmphdr);
    if(pkt->tcphdr)  print_tcphdr(pkt->tcphdr);
    if(pkt->udphdr)  print_udphdr(pkt->udphdr);
    if(pkt->payload) print_payload(pkt->payload, pkt->paylen);
    printf("+++++++++++++++++++++++++++++++++\n|\n|\n");
  }
}

struct connection *make_cnxentry(in_addr_t saddr, in_addr_t daddr, u_int8_t proto, u_int16_t sport, u_int16_t dport){
  struct connection *entry = malloc_cnxentry();
  entry->saddr = saddr;
  entry->daddr = daddr;
  entry->proto = proto;
  entry->sport = sport;
  entry->dport = dport;
  entry->next = NULL;
  return entry;
}

int make_cnx(struct connection *cnxtbl, struct packet *pkt){
  struct connection *find;
  if(!(find = search_cnxentry(cnxtbl, pkt))){
    struct connection *entry = malloc_cnxentry();
    entry->saddr = pkt->iphdr->saddr;
    entry->daddr = pkt->iphdr->daddr;
    entry->proto = pkt->iphdr->protocol;

    if(pkt->icmphdr){
      entry->sport = 0;
      entry->dport = 0;
    }
    else if(pkt->tcphdr){
      entry->sport = pkt->tcphdr->source;
      entry->dport = pkt->tcphdr->dest;
    }
    else if(pkt->udphdr){
      entry->sport = pkt->udphdr->source;
      entry->dport = pkt->udphdr->dest;
    }
    else{
      entry->sport = 0;
      entry->dport = 0;
    }
    add_cnxentry(cnxtbl, entry);
    return 1;
    /*for test*/
//    set_delay(cnxtbl, tid, tdelay);
//    set_loss(cnxtbl, tid, tloss);
//    set_modify(cnxtbl, 1, tbefore, tblen, tafter, talen);
//    set_modify(cnxtbl, tid, tbefore, tblen, tafter, talen);

  }
  return 0;
}

struct connection *generate_cnxentry(struct connection *cnxtbl ,in_addr_t saddr, in_addr_t daddr, u_int8_t proto, u_int16_t sport, u_int16_t dport){
  struct connection *c;
  for(c=cnxtbl->next;c;c=c->next){
//    test
    if((saddr == c->saddr || c->saddr == 0) &&
       (daddr == c->daddr || c->daddr == 0) &&
       (proto == c->proto || c->proto == 0) &&
      ((sport == c->sport || c->sport == 0) ||
       (dport == c->dport || c->dport == 0)
      )
      ){
//    if((saddr == c->saddr ) &&
//       (daddr == c->daddr ) &&
//       (proto == c->proto ) &&
//       (sport == c->sport ) &&
//       (dport == c->dport )){
      return c;
    }
  }
  return NULL;
}

