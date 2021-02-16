// 擬似パケットの構造体を定義。
struct pseudoTCPPacket {
  uint32_t        srcAddr;
  uint32_t        dstAddr;
  uint8_t         zero;
  uint8_t         protocol;
  uint16_t        TCP_len;
};

int flag_check(struct interface *iface, struct packet *pkt);
void insert_tcppkt(int cnxid, void *arg, struct connection *cnxtbl);
void *insert_tcppkt_loop(void *arg);
void insert_udppkt(int cnxid, void *arg, struct connection *cnxtbl);
void *insert_udppkt_loop(void *arg);
void insert_icmppkt(int cnxid,void *arg, struct connection *cnxtbl);
void *insert_icmppkt_loop(void *arg);
u_int16_t tcp_checksum(u_char *data,int len);