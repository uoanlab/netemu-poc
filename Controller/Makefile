CC=gcc
CFLAGS = -I/usr/local/include/libmongoc-1.0 -I/usr/local/include/libbson-1.0 -L/usr/local/lib -lmongoc-1.0 -lbson-1.0
CFLAGS += $(shell pkg-config --cflags json-c)
LDFLAGS += $(shell pkg-config --libs json-c)

#controller: controller.o mongo.o
controller: controller.o
	gcc -g -Wall controller.o -o controller ${CFLAGS} ${LDFLAGS}
	rm controller.o
#mongo.o: mongo.c
#	gcc -c mongo.c ${CFLAGS}
