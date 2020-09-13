#pragma once
#define MODIFY_BUF_SIZE 1024

struct modify_set{
  int blen;
  char before[MODIFY_BUF_SIZE];
  int alen;
  char after[MODIFY_BUF_SIZE];
};

struct flag_headder{
  int urg;
  int ack;
  int psh;
  int rst;
  int syn;
  int fin;
};

struct operation{
  int loss;
  int delay;
  int delay_per;
  int delay_ran;
  int modify;
  //test code
  int modify_per;
  struct flag_headder  headder;
  //
  struct modify_set mset;
  time_t loss_start;
  int loss_difftime;
  time_t delay_start;
  int delay_difftime;
  time_t modify_start;
  int modify_difftime;
};


pthread_mutex_t mutex;

void iptostr(in_addr_t ip, char *ipstr);
void mactostr(u_char *mac, char *macstr);
int copy_operation(struct operation *copy, struct operation *origin);
void print_ip(in_addr_t ip);

int get_random(int min,int max);