CC=gcc
CFLAGS = -I/usr/local/include/libmongoc-1.0 -I/usr/local/include/libbson-1.0 -L/usr/local/lib -lmongoc-1.0 -lbson-1.0

#nwsimulator: nwsimulator.o ./lib/interface.o ./lib/routing.o ./lib/common.o ./lib/packet_handler.o ./lib/packet.o ./lib/arp.o ./lib/connection.o ./lib/modify.o ./lib/loss.o  ./lib/pcapng.o ./lib/packet_capture.o ./lib/mongo.o ./lib/cmd_srver.o ./lib/insert.o
#	gcc -Wall -pthread ./lib/interface.o ./lib/routing.o ./lib/common.o ./lib/packet.o ./lib/packet_handler.o ./lib/arp.o nwsimulator.o ./lib/connection.o ./lib/modify.o ./lib/loss.o ./lib/pcapng.o ./lib/packet_capture.o ./lib/mongo.o ./lib/cmd_server.o ./lib/insert.o -o nwsimulator -lpcap $(CFLAGS)
nwsimulator: nwsimulator.o ./lib/interface.o ./lib/routing.o ./lib/common.o ./lib/packet_handler.o ./lib/packet.o ./lib/arp.o ./lib/connection.o ./lib/modify.o ./lib/loss.o  ./lib/pcapng.o ./lib/packet_capture.o ./lib/mongo.o ./lib/cmd_server.o ./lib/dhcp.o ./lib/delay.o ./lib/insert.o
	gcc -Wall -pthread ./lib/interface.o ./lib/routing.o ./lib/common.o ./lib/packet.o ./lib/packet_handler.o ./lib/arp.o nwsimulator.o ./lib/connection.o ./lib/modify.o ./lib/loss.o ./lib/pcapng.o ./lib/packet_capture.o ./lib/mongo.o ./lib/cmd_server.o ./lib/dhcp.o ./lib/delay.o ./lib/insert.o -o nwsimulator -lpcap $(CFLAGS)
	rm nwsimulator.o ./lib/*.o

nwsimulator.o: nwsimulator.c
	gcc -c nwsimulator.c
interface.o: ./lib/interface.c
	gcc -c interface.c
routing.o: ./lib/routing.c
	gcc -c routing.c
common.o: ./lib/common.c
	gcc -c common.c
packet.o: ./lib/packet.c
	gcc -c packet.c
packet_handler.o: ./lib/packet_handler.c
	gcc -c packet_handler.c
arp.o: ./lib/arp.c
	gcc -c arp.c
modify.o: ./lib/modify.c
	gcc -c modify.c
loss.o: ./lib/loss.c
	gcc -c loss.c
pcapng.o: ./lib/pcapng.c
	gcc -c pcapng.c
packet_capture.o: ./lib/packet_capture.c
	gcc -c packet_capture.c
mongo.o: ./lib/mongo.c
	gcc -c mongo.c $(CFLAGS)
cmd_server.o: ./lib/cmd_server.c
	gcc -c cmd_server.c
dhcp.o: ./lib/dhcp.c
	gcc -c dhcp.c
delay.o: ./lib/delay.c
	gcc -c delay.c
insert.o: ./lib/insert.c
	gcc -c insert.c
#insert.o: ./lib/insert.c
#	gcc -c insert.c
clean:
	rm nwsimulator
