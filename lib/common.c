/**
 * @file common.c
 * @brief いろいろな所から呼ばれそうな関数
**/

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<arpa/inet.h>
#include <time.h>

#include "interface.h"
#include "common.h"

/**
 * ipを出力する関数
 * @param ip 出力したいip
**/
void print_ip(in_addr_t ip){
      char ipstr[16];
      iptostr(ip, ipstr);
      printf("ipaddr   :%s\n", ipstr);
      printf("\n");
}

/**
 * ipをchar[]に変更する関数
 * @param ip castしたいip
 * @param ipstr 格納する文字ポインタ
**/
void iptostr(in_addr_t ip, char *ipstr){
  inet_ntop(AF_INET, &ip, ipstr, 16);
}

/**
 * macをchar[]に変更する関数
 * @param mac castしたいmac
 * @param macstr 格納する文字ポインタ
**/
void mactostr(u_char *mac, char *macstr){
  snprintf(macstr, 18, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/**
 * パケット操作のためのパラメータをコピーする関数 
 * @param copy copy元
 * @param origin copy先
 * @return 正常終了で１を返す
**/

int copy_operation(struct operation *copy, struct operation *origin){
  copy->loss   = origin->loss;
  copy->delay  = origin->delay;
  copy->delay_per  = origin->delay_per;
  copy->modify = origin->modify;
  copy->modify_per = origin->modify_per;
  copy->headder.urg = origin->headder.urg;
  copy->headder.ack = origin->headder.ack;
  copy->headder.psh = origin->headder.psh;
  copy->headder.rst = origin->headder.rst;
  copy->headder.syn = origin->headder.syn;
  copy->headder.fin = origin->headder.fin;
  copy->delay_start  = origin->delay_start;
  copy->delay_difftime  = origin->delay_difftime;
  copy->modify_start  = origin->modify_start;
  copy->modify_difftime  = origin->modify_difftime;
  copy->loss_start  = origin->loss_start;
  copy->loss_difftime  = origin->loss_difftime;
  int blen = origin->mset.blen;
  copy->mset.blen = blen;
  memcpy(copy->mset.before, origin->mset.before, blen);
  int alen = origin->mset.alen;
  copy->mset.alen = alen;
  memcpy(copy->mset.after , origin->mset.after , alen);
  return 1;
}

/**
 * 乱数を返す関数
 * @param min 生成したい下限
 * @param max 生成したい上限
 * @return 生成した乱数
**/
int get_random(int min,int max){
  static int flag;
  if (flag == 0) {
    srand((unsigned int)time(NULL));
    flag = 1;
  }
  return min + (int)(rand()*(max-min+1.0)/(1.0+RAND_MAX));
}
