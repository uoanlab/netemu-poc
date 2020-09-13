#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <json-c/json.h>


//#include "mongo.h"

void usage(void){
  printf("== USAGE ==\n");
  printf(">> genereate a connection entry\n");
  printf("-g(--generate) <src ip> <dst ip> <protocol> <src port> <dst port>\n");
  printf(">> print a connection table\n");
  printf("-p(--print)\n");
  printf(">> clear a connection table\n");
  printf("-p(--clear)\n");
  printf(">> delete a connection by id\n");
  printf("--delete <connection id>\n");
  printf(">> modify a packets (need to specify -i option)\n");
  printf("-i <connection id> -m(--modify) <beofre> <after> <percentage>\n");
  printf(">> delay packets (need to specify -i option)\n");
  printf("-i <connection id> -d(--delay) <mili seconds> <percentage> <diff_time>\n");
  printf(">> loss packets (need to specify -i option)\n");
  printf("-i <connection id> -l(--loss) <percentage>\n");
  printf(">> drop all packets (need to specify -i option)\n");
  printf("-i <connection id> --drop\n");
  printf(">> set TCP flag \n");
  printf("-i <connection id> -a <tcp flag or no>\n");
}



int main(int argc, char *argv[]){
  printf("START CONTROLLER\n");
  int sk;
  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port   = htons(55555);
  addr.sin_addr.s_addr = inet_addr("127.0.0.1");

  if((sk = socket(AF_INET, SOCK_STREAM, 0)) < 0){
    perror("SOCKET");
    usage();
    exit(-1);
  }
  if(connect(sk, (struct sockaddr *)&addr, sizeof(addr)) < 0){
    //perror("CONNECT");
    fprintf(stderr, "ERROR: nwsimulator isn't running!\n");
    exit(-1);
  }

  /* エラー処理をする必要あり */
  int opt;
  int longindex;
  opterr = 0;
  struct option longopts[] = {
    {"id",        required_argument, NULL, 'i'},
    {"print",     no_argument,       NULL, 'p'},
    {"clear",     no_argument,       NULL, 'c'},
    {"delete",    required_argument, NULL,  2 },
    {"generate",  required_argument, NULL, 'g'},
    {"delay",     required_argument, NULL, 'd'},
    {"loss",      required_argument, NULL, 'l'},
    {"modify",    required_argument, NULL, 'm'},
    {"setflag",   required_argument, NULL, 'f'},
    {"drop",      no_argument,       NULL,  1 },
    {"unset",     required_argument, NULL, 'u'},
    {"help",      no_argument,       NULL, 'h'},
    {"insert",    required_argument, NULL, 'a'},
    {"ACK",       required_argument, NULL, 'A'},
    {"URG",       required_argument, NULL, 'U'},
    {"PSH",       required_argument, NULL, 'P'},
    {"SYN",       required_argument, NULL, 'S'},
    {"FIN",       required_argument, NULL, 'F'},
    {"RST",       required_argument, NULL, 'R'},
    {"sport",     required_argument, NULL, 'z'},
    {"dport",     required_argument, NULL, 'D'},
    {"setwindow", required_argument, NULL, 'W'},
    {"setcheck",  required_argument, NULL, 'B'},
    {"setSEQ",    required_argument, NULL, 'M'},
    {"setACK",    required_argument, NULL, 'L'},
    {"thread",    required_argument, NULL, 'T'},
    {"times",     required_argument, NULL, 'N'},
    {"setdoff",   required_argument, NULL, 'O'},
    {"pcap",      required_argument, NULL, 'X'},
    {"pcapng",    required_argument, NULL, 'G'},
    {"destip",    required_argument, NULL, 'j'},
    {"destip ran",required_argument, NULL, 'J'},
    {0,          0,                 0,     0 },
  };


  for(;;){
    char cmd[256];
    printf("mode list\n");
    printf("====================================\n");
    printf("1. print connection table\n");
    printf("2. clear connection table\n");
    printf("3. generate connection table\n");
    printf("4. delete connection\n");
    printf("5. packet manipulate setting\n");
    printf("6. using scenario manipulate setting\n");
    printf("7. output pcap log\n");
    printf("8. output pcapng log\n");
    printf("====================================\n");
    printf("\n");
    printf("input mode id:");

    int i;
    scanf("%d",&i);
    /* print connection table */
    if(i == 1){
      sprintf(cmd, "print");
      send(sk, cmd, sizeof(cmd), 0);
      char buf[65536];
      recv(sk, buf , sizeof(buf), 0);
      printf("%s\n\n", buf);
    }
    /* clear connection table */
    else if(i == 2){
      sprintf(cmd, "clear");
      send(sk, cmd, sizeof(cmd), 0);
      close(sk);
    }
    else if(i == 3){
      printf("input Connection table id\n");
      printf("example:\n");
      printf("[source ip] [dest ip] [TCP] [sport] [dport]\n");
      char source_ip[15], dest_ip[15], proto[15], sport[15], dport[15];  
      scanf("%s%s%s%s%s", source_ip, dest_ip, proto, sport, dport);
      printf("generate %s %s %s %s %s",source_ip, dest_ip, proto, sport, dport);
      sprintf(cmd, "generate %s %s %s %s %s", source_ip, dest_ip, proto, sport, dport);
      send(sk, cmd, sizeof(cmd), 0);
    }
    else if(i == 4){
      printf("input delete id\n");
      int id;
      scanf("%d",&id);
      if(id <= 0){
        fprintf(stderr, "Invalid ID\n");
        exit(0);
      }
      sprintf(cmd, "delete %d", id);
      send(sk, cmd, sizeof(cmd), 0);
    }
    else if(i == 5){
      printf("manipulate list\n");
      printf("1. loss\n");
      printf("2. delay\n");
      printf("3. modify\n");
      printf("4. insert\n");
      printf("\n");

      printf("input number\n");
      int manipulate_id;
      scanf("%d",&manipulate_id);
      if(manipulate_id <= 0 && 5 <= manipulate_id){
        fprintf(stderr, "Invalid manipulate_id\n");
        exit(0);
      }
      /* loss setting*/
      if(manipulate_id == 1)
        printf("test\n");
      /* delay setting*/
      if(manipulate_id == 2)
        printf("input delay param\n");
        printf("[connection_table_id] [delay_time] [percentage ]\n");
        int connection_table_id, delay_time, percentage ;
        scanf("%d%d%d", &connection_table_id, &delay_time, &percentage);
        sprintf(cmd, "setdelay %d %d %d 0", connection_table_id, delay_time, percentage);
        send(sk, cmd, sizeof(cmd), 0);
        
      /* modify setting*/
      if(manipulate_id == 3)
        printf("test\n");
      /* insert setting*/
      if(manipulate_id == 4)
        printf("test\n");
    }
    else if(i == 6){
//      get_scenariolist();
//      printf("input scenario_name:");
//      char scenario_name[20];
//      scanf("%s", scenario_name);
//      mongo_search(scenario_name);
    }





//    if((opt = getopt_long(argc, argv, "i:pcg:d:l:m:u:", longopts, &longindex)) != -1){
//      int id = 0;
//      switch(opt){
//      case 'i':
//        if((id = atoi(optarg)) <= 0){
//          fprintf(stderr, "Invalid ID\n");
//          exit(0);
//        }
//        break;
//      case 'p':
//        sprintf(cmd, "print");
//        send(sk, cmd, sizeof(cmd), 0);
//        char buf[65536];
//        recv(sk, buf , sizeof(buf), 0);
//        printf("%s", buf);
//        close(sk);
//        return 0;
//        break;
//      case 'c':
//        sprintf(cmd, "clear");
//        send(sk, cmd, sizeof(cmd), 0);
//        close(sk);
//        break;
//      case 2:
//        if((id = atoi(optarg)) <= 0){
//          fprintf(stderr, "Invalid ID\n");
//          exit(0);
//        }
//        sprintf(cmd, "delete %d", id);
//        send(sk, cmd, sizeof(cmd), 0);
//        close(sk);
//        break;
//      case 'g':
//        if(argv[optind] && argv[optind+1] && argv[optind+2] && argv[optind+3]){
//          sprintf(cmd, "generate %s %s %s %s %s", optarg, argv[optind], argv[optind+1], argv[optind+2], argv[optind+3]);
//          send(sk, cmd, sizeof(cmd), 0);
//        }
//        else{
//          fprintf(stderr, "The argument isn't enough\n");
//          usage();
//        }
//        close(sk);
//        return 0;
//        break;
//      case 'h':
//        usage();
//        close(sk);
//        return 0;
//        break;
//      default:
//        usage();
//        close(sk);
//        return 0;
//        break;
//      }
//  
//
//      while((opt = getopt_long(argc, argv, "i:pcg:d:d:l:f:a:m:u", longopts, &longindex)) != -1){
//        switch(opt){
//        case 'd':
//          if(atoi(optarg) < 0 || 9999999 < atoi(optarg)){
//          fprintf(stderr, "Input 0 - 999999ms\n");
//          exit(0);
//        }
//        sprintf(cmd, "setdelay %d %s %s %s", id, optarg,argv[optind],argv[optind+1]);
//        break;
//        case 'l':
//          if(atoi(optarg) < 0 || 100 < atoi(optarg)){
//          fprintf(stderr, "Input 0 - 100%\n");
//          exit(0);
//        }
//        //setloss <id> <loss_per> <loss_difftime>
//        sprintf(cmd, "setloss %d %s %s", id, optarg, argv[optind]);
//        break;
//        case 'f':
//          sprintf(cmd, "setflag %d %s", id, optarg);
//          break;
//        case 'a' :
//          if (strcmp(argv[optind],"tcp")==0){
//            //insert id protocol flag thr
//            sprintf(cmd, "insert %d %s %s", id, optarg,argv[optind]);
//            while((opt = getopt_long(argc, argv, "srtfmoAFSPURZDWOQBMLTNXGjJ", longopts, &longindex)) != -1){
//              switch(opt){
//                /*IP option list*/
//                case 's':
//                  strcat(cmd," s");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                case 'r':
//                  strcat(cmd," r");
//                  break;
//                case 't':
//                  strcat(cmd," t");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                case 'f':
//                  strcat(cmd," f");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                case 'm':
//                  strcat(cmd," m");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                case 'o':
//                  strcat(cmd," o");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                /*TCP option list*/
//                case 'A':
//                  strcat(cmd," A");
//                  break;
//                case 'F':
//                  strcat(cmd," F");
//                  break;
//                case 'S':
//                  strcat(cmd," S");
//                  break;
//                case 'P':
//                  strcat(cmd," P");
//                  break;
//                case 'U':
//                  strcat(cmd," U");
//                  break;
//                case 'R':
//                  strcat(cmd," R");
//                  break;
//                //送信ポートを指定する /sport
//                case 'Z':
//                  strcat(cmd," Z");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                //宛先ポートを指定する /dport
//                case 'D':
//                  strcat(cmd," D");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                //window サイズを指定する デフォルトは64
//                case 'W':
//                  strcat(cmd," W");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                //TCPオフセットを偽装する デフォルトは64
//                case 'O':
//                  strcat(cmd," O");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                //シーケンス番号を集めるためのオプション実装が難しいから後回し
//                case 'Q':
//                  strcat(cmd," Q");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                //間違ったチェックサムを送信パケットに設定する
//                case 'B':
//                  strcat(cmd," B");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                //TCPシーケンス番号(SEQ)を設定する
//                case 'M':
//                  strcat(cmd," M");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                //TCP確認応答番号(ACK)を設定する
//                case 'L':
//                  strcat(cmd," L");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                //thread size
//                 case 'T':
//                  strcat(cmd," T");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                //thread size
//                 case 'N':
//                  strcat(cmd," N");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                  //payload 空白を認識できない
//                 case 'd':
//                  strcat(cmd," d");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                 case 'X':
//                  strcat(cmd," pcap");
//                  break;
//                 case 'G':
//                  strcat(cmd," pcapng");
//                  break;
//                case 'j':
//                  strcat(cmd," s");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                case 'J':
//                  strcat(cmd," J");
//                  break;
//              }
//            }
//          }
//  //controller -i <id> -a <udp> <data(not space)> <thread_size> <if(port==0) ramdom>
//          else if(strcmp(argv[optind],"udp")==0){
//            sprintf(cmd, "insert %d %s %s", id, optarg, argv[optind]);
//            while((opt = getopt_long(argc, argv, "srtfmoZDBTNdEXGjJ", longopts, &longindex)) != -1){
//              switch(opt){
//              /*IP option list*/
//                //ip spoof (choice)
//                case 's':
//                  strcat(cmd," s");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                //ip spoof (random)
//                case 'r':
//                  strcat(cmd," r");
//                  break;
//                //ttl
//                case 't':
//                  strcat(cmd," t");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                //flag offset
//                case 'f':
//                  strcat(cmd," f");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                //mtu
//                case 'm':
//                  strcat(cmd," m");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                //tos
//                case 'o':
//                  strcat(cmd," o");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//              //udp option
//                //送信ポートを指定する /sport
//                case 'Z':
//                  strcat(cmd," Z");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                //宛先ポートを指定する /dport
//                case 'D':
//                  strcat(cmd," D");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                //間違ったチェックサムを送信パケットに設定する
//                case 'B':
//                  strcat(cmd," B");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                //thread size
//                 case 'T':
//                  strcat(cmd," T");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                //packet数を指定する
//                 case 'N':
//                  strcat(cmd," N");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                  //payload 空白を認識できない
//                 case 'd':
//                  strcat(cmd," d");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                 case 'X':
//                  strcat(cmd," pcap");
//                  break;
//                 case 'G':
//                  strcat(cmd," pcapng");
//                  break;
//                case 'j':
//                  strcat(cmd," s");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                case 'J':
//                  strcat(cmd," J");
//                  break;
//              }
//            }
//          }
//          else if (strcmp(argv[optind],"icmp")==0){
//            sprintf(cmd, "insert %d %s %s", id, optarg, argv[optind]);
//            while((opt = getopt_long(argc, argv, "srtfmoZDBTNdECYISXGjJ", longopts, &longindex)) != -1){
//              switch(opt){
//                /*IP option list*/
//                //ip spoof (choice)
//                case 's':
//                  strcat(cmd," s");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                //ip spoof (random)
//                case 'r':
//                  strcat(cmd," r");
//                  break;
//                //ttl
//                case 't':
//                  strcat(cmd," t");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                //flag offset
//                case 'f':
//                  strcat(cmd," f");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                //mtu
//                case 'm':
//                  strcat(cmd," m");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                //tos
//                case 'o':
//                  strcat(cmd," o");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//              //udp
//                //送信ポートを指定する /sport
//                case 'Z':
//                  strcat(cmd," Z");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                //宛先ポートを指定する /dport
//                case 'D':
//                  strcat(cmd," D");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                //間違ったチェックサムを送信パケットに設定する
//                case 'B':
//                  strcat(cmd," B");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                //thread size
//                 case 'T':
//                  strcat(cmd," T");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                //packet数を指定する
//                 case 'N':
//                  strcat(cmd," N");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                  //payload 空白を認識できない
//                 case 'd':
//                  strcat(cmd," d");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                case 'E':
//                  strcat(cmd," E");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                  //icmp type set
//                case 'Y':
//                  strcat(cmd," Y");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                  //icmp code set
//                case 'C':
//                  strcat(cmd," C");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                  //icmp identifier set
//                case 'I':
//                  strcat(cmd," I");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                  //icmp sequence set
//                case 'S':
//                  strcat(cmd," S");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                 case 'X':
//                  strcat(cmd," pcap");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                 case 'G':
//                  strcat(cmd," pcapn");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                case 'j':
//                  strcat(cmd," s");
//                  strcat(cmd," ");
//                  strcat(cmd,argv[optind]);
//                  break;
//                case 'J':
//                  strcat(cmd," J");
//                  break;
//              }
//            }
//  
//          }
//          break;
//        case 'm':
//          sprintf(cmd, "setmodify %d %s %s %s %s", id, optarg, argv[optind], argv[optind+1], argv[optind+2]);
//          break;
//        case  1 :
//          sprintf(cmd, "setloss %d 100", id);
//          break;
//        case 'u':
//          if(strcmp(optarg, "loss") == 0) sprintf(cmd, "unsetloss %d", id);
//          else if(strcmp(optarg, "delay") == 0) sprintf(cmd, "unsetdelay %d", id);
//          else if(strcmp(optarg, "modify") == 0) sprintf(cmd, "unsetmodify %d", id);
//          break;
//        derault:
//          printf("test code\n");
//          usage();
//          return 1;
//          break;
//        }
//        send(sk, cmd, sizeof(cmd), 0);
//      }
//    }
  }
  close(sk);
  return 0;
}
