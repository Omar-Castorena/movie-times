CC := gcc
LDFLAGS := -lssl -lcrypto
UNAME := $(shell uname)

ifeq ($(UNAME), Darwin)
CFLAGS := -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib
MYSQLFLAG := `mysql_config --cflags --libs`
endif

all: ssl-client ssl-server-tier1 ssl-server-tier2

ssl-client: ssl-client.o client-tools.o
	$(CC) $(CFLAGS) -o ssl-client ssl-client.o client-tools.o $(LDFLAGS)

ssl-client.o: ssl-client.c client-tools.c
	$(CC) $(CFLAGS) -c ssl-client.c client-tools.c

ssl-server-tier1: ssl-server-tier1.o server-tools.o client-tools.o
	$(CC) $(CFLAGS) -o ssl-server-tier1 ssl-server-tier1.o server-tools.o client-tools.o $(LDFLAGS)

ssl-server-tier1.o: ssl-server-tier1.c server-tools.c client-tools.c
	$(CC) $(CFLAGS) -c ssl-server-tier1.c server-tools.c client-tools.c

ssl-server-tier2: ssl-server-tier2.o server-tools.o
	$(CC) $(CFLAGS) -o ssl-server-tier2 ssl-server-tier2.o server-tools.o `mysql_config --cflags --libs` $(LDFLAGS)

ssl-server-tier2.o: ssl-server-tier2.c server-tools.c
	$(CC) $(CFLAGS) -c ssl-server-tier2.c server-tools.c `mysql_config --cflags --libs`
clean:
	rm -f ssl-server-tier1 ssl-server-tier1.o ssl-server-tier2 ssl-server-tier2.o server-tools.o ssl-client ssl-client.o client-tools.o
