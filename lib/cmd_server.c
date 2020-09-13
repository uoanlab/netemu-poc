#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#include "common.h"
#include "pcap.h"
#include "connection.h"
#include "cmd_server.h"

void *cmd_loop(void  *arg){
  struct connection *cnxtbl = (struct connection *)arg;
  /* recieve commands from controller */
  int ssk; /* server socket */
  struct sockaddr_in server;
  int port = 55555;
  server.sin_family      = AF_INET;
  server.sin_port        = htons(port);
  server.sin_addr.s_addr = inet_addr("127.0.0.1");

  if((ssk=socket(AF_INET, SOCK_STREAM, 0)) < 0){
    perror("SOCKET");
    exit(-1);
  }
  int yes = 1;
  if(setsockopt(ssk, SOL_SOCKET, SO_REUSEADDR, (const char *)&yes, sizeof(yes)) < 0){
    perror("SETSOCKOPT");
    exit(-1);
  }
  if(bind(ssk, (struct sockaddr *)&server, sizeof(server)) < 0){
    perror("BIND");
    exit(-1);
  }
  if(listen(ssk, 5) < 0){
    perror("LISTEN");
    exit(-1);
  }

  int csk; /* client socket */
  struct sockaddr_in client;
  socklen_t len = sizeof(client);

  for(;;){
    if((csk = accept(ssk, (struct sockaddr *)&client, &len)) < 0){
      perror("ACCEPT");
    }
    for(;;){
      char cmd[256];
      if(recv(csk, cmd, 256, 0) <= 0)
       break;
      proc_cmd(csk, cmd, cnxtbl);
      memset(cmd, '\0', sizeof(cmd));
    }
  }
}


void proc_cmd(int csk, char *cmd, struct connection *cnxtbl){
  char *flag = strtok(cmd, " ");
  int len;
  printf("DEBUG: cmd ->[%s]\n", flag);
  if(strcmp(flag, "print") == 0){
    printf("Print Connection Table\n");
    char result[60401];
    len = get_cnxtbl(cnxtbl, result, (sizeof(result)/sizeof(result[0])));
    send(csk, result, len+1, 0);
  }
  else if(strcmp(flag, "clear") == 0){
    printf("Clear Connection Table\n");
    clear_cnxtbl(cnxtbl);
  }
  else if(strcmp(flag, "generate") == 0){
    printf("Generate Connection Entry\n");
    in_addr_t saddr = inet_addr(strtok(NULL, " "));
    in_addr_t daddr = inet_addr(strtok(NULL, " "));

    char *protonm = strtok(NULL, " ");
    u_int8_t proto = 0;
    if(strcmp(protonm, "TCP") == 0) proto = IPPROTO_TCP;
    else if(strcmp(protonm, "UDP") == 0) proto = IPPROTO_UDP;
    else if(strcmp(protonm, "ICMP") == 0) proto = IPPROTO_ICMP;
    u_int16_t sport = htons(atoi(strtok(NULL, " ")));
    u_int16_t dport = htons(atoi(strtok(NULL, " ")));
    struct connection *find;
    if(!(find = generate_cnxentry(cnxtbl, saddr, daddr, proto, sport, dport))){
      print_ip(saddr);
      print_ip(daddr);
      printf("sport:%d\n", sport);
      printf("dport:%d\n", dport);
      struct connection *entry = make_cnxentry(saddr, daddr, proto, sport, dport);
      add_cnxentry(cnxtbl, entry);
    }
  }
  else if(strcmp(flag, "delete") == 0){
    int id = atoi(strtok(NULL,  ""));
    printf("Delete Connection %d\n", id);
    del_cnxentry(cnxtbl, id, 0, 0, 0, 0, 0);
  }
  else if(strcmp(flag, "setloss") == 0){
    int id   = atoi(strtok(NULL, " "));
    int loss = atoi(strtok(NULL, " "));
    int difftime = atoi(strtok(NULL, " "));
    printf("%d: Set loss %d%% difftime:%d\n", id, loss, difftime);
    set_loss(cnxtbl, id, loss, difftime);
  }
  else if(strcmp(flag, "unsetloss") == 0){
    int id = atoi(strtok(NULL, " "));
    printf("%d: Unset loss\n", id);
    unset_loss(cnxtbl, id);
  }
  else if(strcmp(flag, "setdelay") == 0){
    int id    = atoi(strtok(NULL, " "));
    int delay = atoi(strtok(NULL, " "));
    int per = atoi(strtok(NULL, " "));
    int difftime = atoi(strtok(NULL, " "));
    printf("%d: Set delay %dms delay_per %dper diff_time:%d\n", id, delay, per, difftime);
    set_delay(cnxtbl, id, delay, per, difftime);
  }
  else if(strcmp(flag, "unsetdelay") == 0){
    int id = atoi(strtok(NULL, " "));
    printf("%d: Unset delay\n", id);
    unset_delay(cnxtbl, id);
  }
  else if(strcmp(flag, "setmodify") == 0){
    int id = atoi(strtok(NULL, " "));
    char *before = strtok(NULL, " ");
    int blen = strlen(before);
    char *after = strtok(NULL, " ");
    int alen = strlen(after);
    int per = atoi(strtok(NULL, " "));
    int difftime = atoi(strtok(NULL, " "));
    printf("%d: Set modify before %s after:%s per:%d, difftime:%d\n", id, before, after, per, difftime);
    set_modify(cnxtbl, id, before, blen, after, alen, per, difftime);
  }
  else if(strcmp(flag, "unsetmodify") == 0){
    int id = atoi(strtok(NULL, " "));
    printf("%d: Unset Modify\n", id);
    unset_modify(cnxtbl, id);
  }
  else if(strcmp(flag, "setflag") == 0){
    int id = atoi(strtok(NULL, " "));
    char *flag = strtok(NULL, " ");
    int flen = strlen(flag);
    printf("%d: set flag %s \n", id, flag);
    set_flag(cnxtbl, id, flag,flen);
  }
  else if(strcmp(flag, "insert") == 0){
    int count =0;
    pass_insert pass;
    init_pass((void *)&pass);
    int id = atoi(strtok(NULL, " "));
    pass.difftime=atoi(strtok(NULL, " "));
    printf("difftime:%d\n",pass.difftime);
    char *pro = strtok(NULL, " ");
    if (strcmp(pro,"tcp")==0){
      while(1){
        char *opt = strtok(NULL, " ");
//        printf("%s\n",opt);
        if(opt == NULL) break;
        if(strcmp(opt,"A")==0)      pass.ack    =1;
        else if(strcmp(opt,"F")==0) pass.fin    =1;
        else if(strcmp(opt,"P")==0) pass.psh    =1;
        else if(strcmp(opt,"R")==0) pass.rst    =1;
        else if(strcmp(opt,"U")==0) pass.urg    =1;
        else if(strcmp(opt,"S")==0) pass.syn    =1;
        else if(strcmp(opt,"Z")==0) pass.sport  =atoi(strtok(NULL, " "));
        else if(strcmp(opt,"D")==0) pass.dport  =atoi(strtok(NULL, " "));
        else if(strcmp(opt,"W")==0) pass.window =atoi(strtok(NULL, " "));
        else if(strcmp(opt,"O")==0) pass.off    =atoi(strtok(NULL, " "));
        else if(strcmp(opt,"Q")==0){}
        //check sumに合わせた型変換
        else if(strcmp(opt,"B")==0){
          int temp = atoi(strtok(NULL," "));
          char temp2[4]={'\0'};
          sprintf(temp2, "%x", temp);
          sscanf(temp2,"%hx",&pass.bad_checksum);
        }
        else if(strcmp(opt,"M")==0){
          int temp = atoi(strtok(NULL," "));
          char temp2[8]={'\0'};
          sprintf(temp2, "%x", temp);
          sscanf(temp2,"%x",&pass.SEQ);
        }
        else if(strcmp(opt,"L")==0){
          int temp = atoi(strtok(NULL," "));
          char temp2[8]={'\0'};
          sprintf(temp2, "%x", temp);
          sscanf(temp2,"%x",&pass.ACK);
        }
        else if(strcmp(opt,"T")==0) pass.thr = atoi(strtok(NULL, " "));
        else if(strcmp(opt,"N")==0) pass.n = atoi(strtok(NULL, " "));
        else if(strcmp(opt,"s")==0){
          strcpy(pass.ip,strtok(NULL, " "));
          pass.ipflag=1;
        }
        else if(strcmp(opt,"r")==0) pass.random = 1;
        else if(strcmp(opt,"t")==0){
          int temp = atoi(strtok(NULL," "));
          char temp2[8]={'\0'};
          sprintf(temp2, "%x", temp);
          sscanf(temp2,"%hx",&pass.ttl);
        }
        else if(strcmp(opt,"f")==0){
          int temp = atoi(strtok(NULL," "));
          char temp2[8]={'\0'};
          sprintf(temp2, "%x", temp);
          sscanf(temp2,"%hx",&pass.flag_off);
        }
        else if(strcmp(opt,"o")==0) pass.tos = atoi(strtok(NULL, " "));
        else if(strcmp(opt,"d")==0){
          char *payload = strtok(NULL, " ");
          pass.pay = (char *)malloc(strlen(payload));
          strncpy(pass.pay,payload,strlen(payload));
        }
        else if(strcmp(opt,"pcap")==0){
          pass.pcap=1;
          printf("pass.pcap:%d\n",pass.pcap);
        }
        else if(strcmp(opt,"pcapng")==0){
          pass.pcapng=1;
          printf("pass.pcap:%d\n",pass.pcap);
        }
        else if(strcmp(opt,"j")==0){
          strcpy(pass.dstip,strtok(NULL, " "));
          pass.dstipflag=1;
        }
        else if(strcmp(opt,"J")==0) pass.dstrandom = 1;
      }
//      insert_tcppkt(id, &pass);
      count+=1;
    }
    else if (strcmp(pro,"udp")==0){
      while(1){
        char *opt = strtok(NULL, " ");
        if(opt == NULL) break;
        if(strcmp(opt,"Z")==0) pass.sport  =atoi(strtok(NULL, " "));
        else if(strcmp(opt,"D")==0) pass.dport  =atoi(strtok(NULL, " "));
        else if(strcmp(opt,"W")==0) pass.window =atoi(strtok(NULL, " "));
        //check sumに合わせた型変換
        else if(strcmp(opt,"B")==0){
          int temp = atoi(strtok(NULL," "));
          char temp2[4]={'\0'};
          sprintf(temp2, "%x", temp);
          sscanf(temp2,"%hx",&pass.bad_checksum);
        }
        else if(strcmp(opt,"T")==0) pass.thr = atoi(strtok(NULL, " "));
        else if(strcmp(opt,"N")==0) pass.n = atoi(strtok(NULL, " "));
        else if(strcmp(opt,"s")==0){
          strcpy(pass.ip,strtok(NULL, " "));
          pass.ipflag=1;
        }
        else if(strcmp(opt,"r")==0) pass.random = 1;
        else if(strcmp(opt,"t")==0){
          int temp = atoi(strtok(NULL," "));
          char temp2[8]={'\0'};
          sprintf(temp2, "%x", temp);
          sscanf(temp2,"%hx",&pass.ttl);
        }
        else if(strcmp(opt,"f")==0){
          int temp = atoi(strtok(NULL," "));
          char temp2[8]={'\0'};
          sprintf(temp2, "%x", temp);
          sscanf(temp2,"%hx",&pass.flag_off);
        }
        else if(strcmp(opt,"o")==0) pass.tos = atoi(strtok(NULL, " "));
        else if(strcmp(opt,"E")==0) pass.random_dport = 1;
        else if(strcmp(opt,"d")==0){
          char *payload = strtok(NULL, " ");
          pass.pay = (char *)malloc(strlen(payload));
          strncpy(pass.pay,payload,strlen(payload));
        }
        else if(strcmp(opt,"pcap")==0){
          pass.pcap=1;
          printf("pass.pcap:%d\n",pass.pcap);
        }
        else if(strcmp(opt,"pcapng")==0){
          pass.pcapng=1;
        }
        else if(strcmp(opt,"j")==0){
          strcpy(pass.dstip,strtok(NULL, " "));
          pass.dstipflag=1;
        }
        else if(strcmp(opt,"J")==0) pass.dstrandom = 1;
//      char *data = strtok(NULL, " ");
//      int dlen = strlen(data);
//      int thread_size = atoi(strtok(NULL, " "));
//      int dport = atoi(strtok(NULL, " "));
      }
//      insert_udppkt(id,&pass);
    }
    else if (strcmp(pro,"icmp")==0){
      printf("%d:insert icmp method start\n", id);
      while(1){
        char *opt = strtok(NULL, " ");
        if(opt == NULL) break;
        //set sender port
        if(strcmp(opt,"Z")==0) pass.sport  =atoi(strtok(NULL, " "));
        //set dest port
        else if(strcmp(opt,"D")==0) pass.dport  =atoi(strtok(NULL, " "));
        //set window size
        else if(strcmp(opt,"W")==0) pass.window =atoi(strtok(NULL, " "));
        //check sum を直接代入
        else if(strcmp(opt,"B")==0){
          int temp = atoi(strtok(NULL," "));
          char temp2[4]={'\0'};
          sprintf(temp2, "%x", temp);
          sscanf(temp2,"%hx",&pass.bad_checksum);
        }
        //set thread size
        else if(strcmp(opt,"T")==0) pass.thr = atoi(strtok(NULL, " "));
        //set sending packet number
        else if(strcmp(opt,"N")==0) pass.n = atoi(strtok(NULL, " "));
        //set ip spoof (choice)
        else if(strcmp(opt,"s")==0){
          strcpy(pass.ip,strtok(NULL, " "));
          pass.ipflag=1;
        }
        //set ip spoof (random)
        else if(strcmp(opt,"r")==0) pass.random = 1;
        //set ttl
        else if(strcmp(opt,"t")==0){
          int temp = atoi(strtok(NULL," "));
          char temp2[8]={'\0'};
          sprintf(temp2, "%x", temp);
          sscanf(temp2,"%hx",&pass.ttl);
        }
        //set flag offset
        else if(strcmp(opt,"f")==0){
          int temp = atoi(strtok(NULL," "));
          char temp2[8]={'\0'};
          sprintf(temp2, "%x", temp);
          sscanf(temp2,"%hx",&pass.flag_off);
        }
        //set flag tos
        else if(strcmp(opt,"o")==0) pass.tos = atoi(strtok(NULL, " "));
        //set random dport flag
        else if(strcmp(opt,"E")==0) pass.random_dport = 1;
        //set payload
        else if(strcmp(opt,"d")==0){
          char *payload = strtok(NULL, " ");
          pass.pay = (char *)malloc(strlen(payload));
          strncpy(pass.pay,payload,strlen(payload));
        }
        else if(strcmp(opt,"Y")==0){
          pass.type = atoi(strtok(NULL," "));
        }
        else if(strcmp(opt,"C")==0){
          pass.code = atoi(strtok(NULL," "));
        }
        else if(strcmp(opt,"I")==0){
          int temp = atoi(strtok(NULL," "));
          char temp2[8]={'\0'};
          sprintf(temp2, "%x", temp);
          sscanf(temp2,"%hx",&pass.ic_id);
        }
        else if(strcmp(opt,"S")==0){
          int temp = atoi(strtok(NULL," "));
          char temp2[8]={'\0'};
          sprintf(temp2, "%x", temp);
          sscanf(temp2,"%hx",&pass.ic_seq);
        }
        else if(strcmp(opt,"pcap")==0){
          pass.pcap=1;
          printf("pass.pcap:%d\n",pass.pcap);
        }
        else if(strcmp(opt,"pcapng")==0){
          pass.pcapng=1;
        }
        else if(strcmp(opt,"j")==0){
          strcpy(pass.dstip,strtok(NULL, " "));
          pass.dstipflag=1;
        }
        else if(strcmp(opt,"J")==0) pass.dstrandom = 1;
//      char *data = strtok(NULL, " ");
//      int dlen = strlen(data);
//      int thread_size = atoi(strtok(NULL, " "));
//      int dport = atoi(strtok(NULL, " "));
      }
//      insert_icmppkt(id,&pass);
    }
  }
  else{
    printf("BAD INSTRUCTION\n");
  }
}
void init_pass(void *arg){
  pass_insert *pass;
  pass = arg;
  pass->fin=0;
  pass->syn=0;
  pass->ack=0;
  pass->rst=0;
  pass->psh=0;
  pass->urg=0;
  pass->dlen=0;
  pass->sport=0;
  pass->dport=0;
  pass->bad_checksum=0x0;
  pass->SEQ=0x0;
  pass->ACK=0x0;
  pass->off=5;
  pass->window=64;
  pass->thr=1;
  pass->n=1;
  pass->random=0;
  pass->random_dport=0;
  pass->ttl=0x40;
  pass->flag_off=0x00;
  pass->tos=0;
  pass->type=0;
  pass->code=0;
}
