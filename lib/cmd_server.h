/**
 * @file cmd_server.h
 * @brief コマンドサーバについての設定:基本的にエミュレータのパケット操作に関するパラメータはこれから操作される。
**/

/**
 * コマンドサーバのメイン処理.
 * @param argc arg
**/
void *cmd_loop(void *arg);
void proc_cmd(int csk, char *cmd, struct connection *cnxtbl);

typedef struct{
  struct interface *iface;
  int ifaceid;
  struct connection *c;
  int fin;
  int syn;
  int ack;
  int rst;
  int psh;
  int urg;
  char *data;
  int dlen;
  int sport;
  int dport;
  u_int16_t bad_checksum;
  u_int32_t SEQ;
  u_int32_t ACK;
  int off;
  int window;
  int id;
  int thr;
  int n;
  char ip[15];
  char dstip[15];
  int ipflag;
  int dstipflag;
  int random;
  int dstrandom;
  int random_dport;
  u_int16_t ttl;
  u_int16_t flag_off;
  int tos;
  char *pay;
  int type;
  int code;
  u_int16_t ic_id;
  u_int16_t ic_seq;
  FILE *fp;
  FILE *fp2;
  time_t insert_start;
  int difftime;
  int pcap;
  int pcapng;
} pass_insert;

void init_pass(void *arg);
