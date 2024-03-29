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
#include"cmd_server.h"
#include"connection.h"
#include"loss.h"

struct connection *free_cnxentry_queue = NULL;

void init_cnxtbl(struct connection *cnxtbl){
  cnxtbl->ipmask_saddr = malloc(sizeof(struct ip_mask));
  cnxtbl->ipmask_daddr = malloc(sizeof(struct ip_mask));
  cnxtbl->sport_tree = malloc(sizeof(struct port_tree));
  cnxtbl->dport_tree = malloc(sizeof(struct port_tree));

  cnxtbl->ipmask_saddr_root = malloc(sizeof(struct ipmask_root));
  cnxtbl->ipmask_daddr_root = malloc(sizeof(struct ipmask_root));

  init_ipmask_tree(cnxtbl->ipmask_saddr_root);
  init_ipmask_tree(cnxtbl->ipmask_daddr_root);

  init_ipmask(cnxtbl->ipmask_saddr);
  init_ipmask(cnxtbl->ipmask_daddr);
  init_port_tree(cnxtbl->sport_tree);
  init_port_tree(cnxtbl->dport_tree);
  cnxtbl->next = NULL;
}

void print_cnxtbl(struct connection *cnxtbl){
  struct connection *c;
  char ipstr[16];
//  printf("======================================== Connection  Table =======================================\n");
//  printf("|id| source ipaddr |  dest ipaddr  |proto|sport|dport|                   flag                    |\n");
//  printf("--------------------------------------------------------------------------------------------------\n");
  for(c=cnxtbl->next;c;c=c->next){
 //   printf("|%2d", c->id);
 //   iptostr(c->saddr, ipstr);
 //   printf("|%15s", ipstr);
 //   iptostr(c->daddr, ipstr);
 //   printf("|%15s", ipstr);
 //   printf("|");
 //   if(c->proto == IPPROTO_TCP)       printf(" TCP ");
 //   else if(c->proto == IPPROTO_UDP)  printf(" UDP ");
 //   else if(c->proto == IPPROTO_ICMP) printf(" ICMP");
 //   else printf("Other");
 //   printf("|%5d", ntohs(c->sport));
 //   printf("|%5d", ntohs(c->dport));
 //   printf("| loss : ");
 //   (c->op.loss) ? printf("%3d%%", c->op.loss) : printf("  x ");
 //   printf("| delay : ");
 //   (c->op.delay) ? printf("%6dms %3d%%", c->op.delay, c->op.delay_per) : printf("           x ");
 //   printf("| modify : ");
 //   (c->op.modify) ? printf("%s to %s ", c->op.mset.before, c->op.mset.after) : printf("x ");
 //   printf("|\n");
    printf("|%2d", c->id);
    printf("\n");
  }
 // printf("===================================================================================================\n");
//  print_saved_pkt_queue(cnxtbl);
}
int get_cnxtbl(struct connection *cnxtbl, char *buf, int size){
  int ret_len=0;
  int len;
  struct connection *c;
  for(c=cnxtbl->next;(c && 0<(size/100)-1);c=c->next){
    len = snprintf(buf, size, "===========================================\n");
    buf+=len; size-=len;
    ret_len += len;
    len = snprintf(buf, size, "%d:\n", c->id);
    buf+=len; size-=len;
    ret_len += len;
    len = snprintf(buf, size, "sip psitive\n");
    buf+=len; size-=len;
    ret_len += len;
    for(struct ip_mask *tmp = c->ipmask_saddr_root->positive_tree->next; tmp != NULL; tmp = tmp->next){
      char ipstr[16];
      iptostr(tmp->addr, ipstr);
      len = snprintf(buf, size, "ipaddr: %s\t", ipstr);
      buf+=len; size-=len;
      ret_len += len;
      iptostr(tmp->mask, ipstr);
      len = snprintf(buf, size, "mask: %s\n", ipstr);
      buf+=len; size-=len;
      ret_len += len;
    }

    len = snprintf(buf, size, "source ip denial\n");
    buf+=len; size-=len;
    ret_len += len;
    for(struct ip_mask *tmp = c->ipmask_saddr_root->denial_tree->next; tmp != NULL; tmp = tmp->next){
      char ipstr[16];
      iptostr(tmp->addr, ipstr);
      len = snprintf(buf, size, "ipaddr: %s\t", ipstr);
      buf+=len; size-=len;
      ret_len += len;
      iptostr(tmp->mask, ipstr);
      len = snprintf(buf, size, "mask: %s\n", ipstr);
      buf+=len; size-=len;
      ret_len += len;
    }
 
    len = snprintf(buf, size, "\n");
    buf+=len; size-=len;
    ret_len += len;

    len = snprintf(buf, size, "dest ip positive\n");
    buf+=len; size-=len;
    ret_len += len;
    for(struct ip_mask *tmp = c->ipmask_daddr_root->positive_tree->next; tmp != NULL; tmp = tmp->next){
      char ipstr[16];
      iptostr(tmp->addr, ipstr);
      len = snprintf(buf, size, "ipaddr: %s\t", ipstr);
      buf+=len; size-=len;
      ret_len += len;
      iptostr(tmp->mask, ipstr);
      len = snprintf(buf, size, "mask: %s\n", ipstr);
      buf+=len; size-=len;
      ret_len += len;
    }
    len = snprintf(buf, size, "\n");
    buf+=len; size-=len;
    ret_len += len;

    len = snprintf(buf, size, "dest ip denial\n");
    buf+=len; size-=len;
    ret_len += len;
    for(struct ip_mask *tmp = c->ipmask_daddr_root->denial_tree->next; tmp != NULL; tmp = tmp->next){
      char ipstr[16];
      iptostr(tmp->addr, ipstr);
      len = snprintf(buf, size, "ipaddr: %s\t", ipstr);
      buf+=len; size-=len;
      ret_len += len;
      iptostr(tmp->mask, ipstr);
      len = snprintf(buf, size, "mask: %s\n", ipstr);
      buf+=len; size-=len;
      ret_len += len;
    }
    len = snprintf(buf, size, "\n");
    buf+=len; size-=len;
    ret_len += len;

    len = snprintf(buf, size, "sport\n");
    buf+=len; size-=len;
    ret_len += len;

    struct port_tree *tree = c->sport_tree;
    if(tree->any_flag == 1){
      len = snprintf(buf, size, "any\n");
      buf+=len; size-=len;
      ret_len += len;
    }
    else{
      struct ports *tmp;
      len = snprintf(buf, size, "\tpositive\n");
      buf+=len; size-=len;
      ret_len += len;
      for(struct ports *tmp = tree->positive_tree->next; tmp!=NULL; tmp=tmp->next){
        len = snprintf(buf, size, "\t\tlower:%d\thigher:%d\n", ntohs(tmp->lower_port), ntohs(tmp->higher_port));
        buf+=len; size-=len;
        ret_len += len;
      }
      len = snprintf(buf, size, "\tdenial\n");
      buf+=len; size-=len;
      ret_len += len;
      for(struct ports *tmp = tree->denial_tree->next; tmp!=NULL; tmp=tmp->next){
        len = snprintf(buf, size, "\t\tlower:%d\thigher:%d\n", ntohs(tmp->lower_port), ntohs(tmp->higher_port));
        buf+=len; size-=len;
        ret_len += len;
      }
    }
    len = snprintf(buf, size, "\n");
    buf+=len; size-=len;
    ret_len += len;

    len = snprintf(buf, size, "dport\n");
    buf+=len; size-=len;
    ret_len += len;

    tree = c->dport_tree;
    if(tree->any_flag == 1){
      len = snprintf(buf, size, "any\n");
      buf+=len; size-=len;
      ret_len += len;
    }
    else{
      struct ports *tmp;
      len = snprintf(buf, size, "\tpositive\n");
      buf+=len; size-=len;
      ret_len += len;
      for(struct ports *tmp = tree->positive_tree->next; tmp!=NULL; tmp=tmp->next){
        len = snprintf(buf, size, "\t\tlower:%d\thigher:%d\n", ntohs(tmp->lower_port), ntohs(tmp->higher_port));
        buf+=len; size-=len;
        ret_len += len;
      }
      len = snprintf(buf, size, "\tdenial\n");
      buf+=len; size-=len;
      ret_len += len;
      for(struct ports *tmp = tree->denial_tree->next; tmp!=NULL; tmp=tmp->next){
        len = snprintf(buf, size, "\t\tlower:%d\thigher:%d\n", ntohs(tmp->lower_port), ntohs(tmp->higher_port));
        buf+=len; size-=len;
        ret_len += len;
      }
    }
    len = snprintf(buf, size, "\n");
    buf+=len; size-=len;
    ret_len += len;


  }
  len = snprintf(buf, size, "===========================================\n");
  buf+=len; size-=len;
  ret_len += len;
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
      free_tree(c->sport_tree);
      free_tree(c->dport_tree);
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
  struct connection *return_cnx = NULL;
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
  int a = 0;
  for(c=cnxtbl->next;c!=NULL;c=c->next){
    a++;
    struct ip_mask *sipcheck, *dipcheck;
    sipcheck = search_ipmask(saddr, c->ipmask_saddr_root->denial_tree);
    if(sipcheck != NULL){
      continue;
    }
    sipcheck = search_ipmask(saddr, c->ipmask_saddr_root->positive_tree);
    if(sipcheck == NULL){
      continue;
    }
    dipcheck = search_ipmask(daddr, c->ipmask_daddr_root->denial_tree);
    if(dipcheck != NULL){
      continue;
    }
    dipcheck = search_ipmask(daddr, c->ipmask_daddr_root->positive_tree);
    if(dipcheck == NULL){
      continue;
    }
    if(!(pkt->icmphdr) && search_port_tree(sport, c->sport_tree) == 0){
      continue;
    } 
    if(!(pkt->icmphdr) && search_port_tree(dport, c->dport_tree) == 0){
      continue;
    } 
    if(proto != c->proto || c->proto == 252){
      continue;
    } 
    exec_operation(pkt, c);
    return_cnx = c;
  }
  return return_cnx;
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
int set_loss(struct connection *cnxtbl, int id, double loss, int difftime){
  struct connection *c;
  for(c=cnxtbl->next;c;c=c->next){
    if(c->id == id){
      c->op.loss = loss;
      c->op.loss_start = time(NULL);
      c->op.loss_difftime = difftime;
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

struct connection *make_cnxentry(in_addr_t saddr, in_addr_t daddr, u_int8_t proto, struct port_tree *sport_tree, struct port_tree *dport_tree, struct ipmask_root *saddr_mask, struct ipmask_root *daddr_mask){
  struct connection *entry = malloc_cnxentry();
  entry->saddr = saddr;
  entry->daddr = daddr;
  entry->proto = proto;
//  entry->sport = sport;
//  entry->dport = dport;
  entry->sport_tree = sport_tree;
  entry->dport_tree = dport_tree;
  entry->ipmask_saddr_root = saddr_mask;
  entry->ipmask_daddr_root = daddr_mask;
  entry->next = NULL;
  return entry;
}

int make_cnx(struct connection *cnxtbl, struct packet *pkt){
  struct connection *find;
  if(!(find = search_cnxentry_no_exec(cnxtbl, pkt))){
//    struct connection *entry = malloc_cnxentry();
//    entry->saddr = pkt->iphdr->saddr;
//    entry->daddr = pkt->iphdr->daddr;
//    entry->proto = pkt->iphdr->protocol;
    u_int16_t sport, dport;
    if(pkt->icmphdr){
      sport = 0;
      dport = 0;
    }
    else if(pkt->tcphdr){
      sport = pkt->tcphdr->source;
      dport = pkt->tcphdr->dest;
    }
    else if(pkt->udphdr){
      sport = pkt->udphdr->source;
      dport = pkt->udphdr->dest;
    }
    else{
      sport = 0;
      dport = 0;
    }
    struct connection *entry;

    struct ip_mask *saddr_mask, *daddr_mask;
    saddr_mask = malloc(sizeof(struct ip_mask));
    daddr_mask = malloc(sizeof(struct ip_mask));
    init_ipmask(saddr_mask);
    init_ipmask(daddr_mask);

    struct ipmask_root *saddr_mask_root, *daddr_mask_root;
    saddr_mask_root = malloc(sizeof(struct ipmask_root));
    daddr_mask_root = malloc(sizeof(struct ipmask_root));
    init_ipmask_tree(saddr_mask_root);
    init_ipmask_tree(daddr_mask_root);

    char ipstr[16];
    iptostr(pkt->iphdr->saddr, ipstr);
    saddr_mask_root = array_ip_parse(ipstr);
    iptostr(pkt->iphdr->daddr, ipstr);
    daddr_mask_root = array_ip_parse(ipstr);

    struct port_tree *sport_tree, *dport_tree;
    sport_tree = malloc(sizeof(struct port_tree));
    dport_tree = malloc(sizeof(struct port_tree));
    init_port_tree(sport_tree);
    init_port_tree(dport_tree);
    char str[10]; 
    sprintf(str,"%d", sport);
    sport_tree = array_port_parse(str);
    sprintf(str,"%d", dport);
    dport_tree = array_port_parse(str);

    entry = make_cnxentry(pkt->iphdr->saddr, pkt->iphdr->daddr, pkt->iphdr->protocol, sport_tree, dport_tree, saddr_mask_root, daddr_mask_root);

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

void init_ports(struct ports *port_tree){
    port_tree->next = NULL;
    port_tree->lower_port = -1;
    port_tree->higher_port = -1;
    return;
}

void add_port_tree(struct ports *port_tree, struct ports *node){
    struct ports *tmp;
    for(tmp = port_tree; tmp->next != NULL; tmp = tmp->next){}
    tmp->next = node; 
}

void print_port(struct port_tree *port_tree){
    struct ports *tmp;
    if(port_tree->any_flag == 1){
        printf("any\n");
    }
    else{
        for(tmp = port_tree->positive_tree->next; tmp != NULL; tmp = tmp->next){
            printf("low_port  : %d\n", tmp->lower_port);
            printf("high_port : %d\n", tmp->higher_port);
            printf("\n");
        }

        for(tmp = port_tree->denial_tree->next; tmp != NULL; tmp = tmp->next){
            printf("low_port  : %d\n", tmp->lower_port);
            printf("high_port : %d\n", tmp->higher_port);
            printf("\n");
        }
    }
}

int string_to_port(char* port_str, u_int16_t *lower_port, u_int16_t *higher_port){
  char *colon;
  char *bikkuri = strchr(port_str, '!');
  int return_flag = 0;
  if(bikkuri != NULL){
    port_str += 1;
    return_flag = 1;
  }
	colon = strchr(port_str, ':');
  if(colon == NULL){
    *lower_port = atoi(port_str);
    *higher_port = atoi(port_str);
  }
  else if(port_str == colon){
    *lower_port = 0;
    *higher_port = atoi(colon+1);
  }
  else if(*(colon+1) == ':' || *(colon+1) == ']' || *(colon+1) == '\0'){
    *colon = '\0';
    *lower_port = atoi(port_str);
    *higher_port = 65534;
  }
  else{
    *colon = '\0';
    *lower_port = atoi(port_str);
    *higher_port = atoi(colon+1);
  }
    return return_flag;
}

int search_port_tree(u_int16_t port, struct port_tree *port_tree){
    struct ports *tmp;
    if(port_tree->any_flag == 1){
        return 1;
    }
    for(tmp=port_tree->denial_tree->next; tmp!=NULL; tmp=tmp->next){
        if(tmp->lower_port == port && port == tmp->higher_port){
            return 0;
        }
    }
    for(tmp=port_tree->positive_tree->next; tmp!=NULL; tmp=tmp->next){
        if(tmp->lower_port <= port && port <= tmp->higher_port){
            return 1;
        }
    }
    return 0;
}

void free_tree(struct port_tree *port_tree){
    struct ports *tmp;
    struct ports *tmp2;
    for(tmp = port_tree->positive_tree->next; tmp != NULL; tmp = tmp2){
        tmp2 = tmp->next;
        free(tmp);
    }

    for(tmp = port_tree->denial_tree->next; tmp != NULL; tmp = tmp2){
        tmp2 = tmp->next;
        free(tmp);
    }
    free(port_tree);
    return;
}

void init_port_tree(struct port_tree *port_tree){
    port_tree->positive_tree = malloc(sizeof(struct ports));
    port_tree->denial_tree = malloc(sizeof(struct ports));
    port_tree->any_flag = 0;
//    port_tree->positive_tree = NULL;
//    port_tree->denial_tree = NULL;
    init_ports(port_tree->positive_tree);
    init_ports(port_tree->denial_tree);
}

struct port_tree *array_port_parse(char *arr){
    struct port_tree *port_tree; 
    port_tree = malloc(sizeof(struct port_tree));

    struct ports *positive_tree; 
    struct ports *denial_tree; 
    positive_tree = malloc(sizeof(struct ports));
    denial_tree = malloc(sizeof(struct ports));
    init_ports(positive_tree);
    init_ports(denial_tree);
    port_tree->positive_tree = positive_tree;
    port_tree->denial_tree = denial_tree;

	char *open_braket, *close_braket;
    open_braket = strchr(arr, '[');
    close_braket = strchr(arr, ']');
    if(strcmp(arr, "any") == 0 ){
        port_tree->any_flag = 1;
    }
    else if(open_braket!=NULL){
        *close_braket = '\0';
        char *wordfirst = open_braket+1;
        char *comma = strtok(wordfirst, ",");
        while(1){
            int flag = 0;
            if(comma == NULL) break;
            struct ports *node; 
            node = malloc(sizeof(struct ports));
            init_ports(node);
            flag = string_to_port(comma, &node->lower_port, &node->higher_port);
            if(flag != 0){
                add_port_tree(positive_tree, node);
            }
            else{
                add_port_tree(denial_tree, node);
            }
            comma = strtok(NULL, ",");
        }
    }
    else{
        int flag = 0;
        struct ports *node; 
        node = malloc(sizeof(struct port_tree));
        init_ports(node);
        flag = string_to_port(arr, &node->lower_port, &node->higher_port);
        if(flag == 0){
            add_port_tree(positive_tree, node);
        }
        else if(flag == 1){
            add_port_tree(denial_tree, node);
        }
    }
    port_tree->positive_tree = positive_tree;
    port_tree->denial_tree = denial_tree;
    return port_tree;
}

void init_ipmask(struct ip_mask *ip_mask){
    ip_mask->addr = 0;
    ip_mask->mask = 0;
    ip_mask->next = NULL;
    return ;
}

void add_ipmask(struct ip_mask *ip_mask, struct ip_mask *node){
    struct ip_mask *tmp;
    for(tmp = ip_mask; tmp->next != NULL; tmp = tmp->next){}
    tmp->next = node; 
}

void print_ipmask(struct ip_mask *ip_mask){
    struct ip_mask *tmp;
    for(tmp = ip_mask->next; tmp != NULL; tmp = tmp->next){
        printf("ip  : ");
        print_ip(tmp->addr);
        printf("mask: ");
        print_ip(tmp->mask);
    }
}



int string_to_ipmask(char *ipmask, in_addr_t *ip, in_addr_t *mask){
	char *slash;
  char *bikkuri = strchr(ipmask, '!');
  if(bikkuri != NULL){
    printf("%s\n", bikkuri);
  }
  int return_flag = 0;
  if(bikkuri != NULL){
    ipmask += 1;
    return_flag = 1;
  }
	
	slash = strchr(ipmask, '/');
    if(slash == NULL){
        *ip = inet_addr(ipmask);
        *mask = 4294967295;
        return return_flag;
    }
    else{
	    char *dot;
	    dot = strchr(slash+1, '.');
        *slash = '\0';
        if(dot == NULL){
            // CIDR
            *ip  = inet_addr(ipmask);
            int cidr = atoi(slash+1);
            switch(cidr%8){
            case(1):
                *mask = 128;
                break;
            case(2):
                *mask = 192;
                break;
            case(3):
                *mask = 224;
                break;
            case(4):
                *mask = 240;
                break;
            case(5):
                *mask = 248;
                break;
            case(6):
                *mask = 252;
                break;
            case(7):
                *mask = 254;
                break;
            }

            *mask = *mask << 8;
            for(int i=1; 8*i<=cidr; i++){
                if(i!=1) *mask = *mask << 8;
                *mask += 255;
            }
            return return_flag;
        }
        else{
            // 255.255.255.0
            *ip = inet_addr(ipmask);
            *mask = inet_addr(slash+1);
            in_addr_t test;
            test = inet_addr(slash+1);
        }
        return return_flag;
    }
}

struct ipmask_root *array_ip_parse(char *arr){
    struct ipmask_root *addr_mask_root;
    addr_mask_root = malloc(sizeof(struct ipmask_root));
    init_ipmask_tree(addr_mask_root);

    struct ip_mask *ip_mask; 
    struct ip_mask *denial_ip_mask; 
    ip_mask = malloc(sizeof(struct ip_mask));
    denial_ip_mask = malloc(sizeof(struct ip_mask));
    init_ipmask(ip_mask);
    init_ipmask(denial_ip_mask);
	  char *open_braket, *close_braket;
    open_braket = strchr(arr, '[');
    close_braket = strchr(arr, ']');
    if(open_braket!=NULL){
        *close_braket = '\0';
        char *wordfirst = open_braket+1;
        char *comma = strtok(wordfirst, ",");
        while(1){
            in_addr_t ip;
            int mask;
            if(comma == NULL) break;
            struct ip_mask *node; 
            node = malloc(sizeof(struct ip_mask));
            init_ipmask(node);
            int return_flag = string_to_ipmask(comma, &node->addr, &node->mask);
            if(return_flag == 0)
              add_ipmask(denial_ip_mask, node);
            else if(return_flag == 1)
              add_ipmask(ip_mask, node);
            comma = strtok(NULL, ",");
        }
    }
    else{
        struct ip_mask *node; 
        node = malloc(sizeof(struct ip_mask));
        init_ipmask(node);
        int return_flag = string_to_ipmask(arr, &node->addr, &node->mask);
        if(return_flag == 1)
          add_ipmask(denial_ip_mask, node);
        else if(return_flag == 0)
          add_ipmask(ip_mask, node);
    }
    addr_mask_root->positive_tree = ip_mask;
    addr_mask_root->denial_tree = denial_ip_mask;
    return addr_mask_root;
}

struct ip_mask *search_ipmask(in_addr_t addr, struct ip_mask *ip_mask){
    struct ip_mask *tmp;
    for(tmp = ip_mask->next; tmp!=NULL; tmp=tmp->next){
        if((addr&tmp->mask) == (tmp->addr&tmp->mask)){
            return tmp;
        }
    }
    return NULL;
}

void init_ipmask_tree(struct ipmask_root *ip_mask_tree){
  ip_mask_tree->positive_tree = malloc(sizeof(struct ip_mask)); 
  ip_mask_tree->denial_tree = malloc(sizeof(struct ip_mask)); 
  init_ipmask(ip_mask_tree->positive_tree);
  init_ipmask(ip_mask_tree->denial_tree);
  ip_mask_tree->any_flag = -1;
}

//lossした場合return 1
//それ以外    return 0
int exec_operation(struct packet *pkt, struct connection *conn){
  if(conn->op.delay >= 0){
    pkt->op.delay += conn->op.delay;
  }
  if(conn->op.loss != 0.000000){
    pkt->op.loss = conn->op.loss;
    int ret_value;
    ret_value = loss_pkt(pkt);
    if(ret_value == 1){
      return 1;
    }
  }
  return 0;
}

struct connection *search_cnxentry_no_exec(struct connection *cnxtbl, struct packet *pkt){
  struct connection *return_cnx = NULL;
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
  int a = 0;
  for(c=cnxtbl->next;c!=NULL;c=c->next){
    a++;
    struct ip_mask *sipcheck, *dipcheck;
    sipcheck = search_ipmask(saddr, c->ipmask_saddr_root->denial_tree);
    if(sipcheck != NULL){
      continue;
    }
    sipcheck = search_ipmask(saddr, c->ipmask_saddr_root->positive_tree);
    if(sipcheck == NULL){
      continue;
    }
    dipcheck = search_ipmask(daddr, c->ipmask_daddr_root->denial_tree);
    if(dipcheck != NULL){
      continue;
    }
    dipcheck = search_ipmask(daddr, c->ipmask_daddr_root->positive_tree);
    if(dipcheck == NULL){
      continue;
    }
    if(!(pkt->icmphdr) && search_port_tree(sport, c->sport_tree) == 0){
      continue;
    } 
    if(!(pkt->icmphdr) && search_port_tree(dport, c->dport_tree) == 0){
      continue;
    } 
    if(proto != c->proto || c->proto == 252){
      continue;
    } 
    return_cnx = c;
  }
  return return_cnx;
}