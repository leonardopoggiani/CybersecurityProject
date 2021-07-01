CC = g++

CFLAGS  = -g -Wall -Wformat-zero-length
PROTOCOL  = -D PROTOCOL_DEBUG
VERBOSE  = -D VERBOSE_LEVEL

all : client server

client : client.cpp crypto.cpp
	$(CC) $(CFLAGS) -o client client.cpp crypto.cpp -lpthread -lcrypto

server : server.cpp crypto.cpp
	$(CC) $(CFLAGS) -o server server.cpp crypto.cpp -lpthread -lcrypto

verbose : client_verbose server_verbose

client_verbose : client.cpp crypto.cpp
	$(CC) $(CFLAGS) $(PROTOCOL) $(VERBOSE) -o client client.cpp crypto.cpp -lpthread -lcrypto

server_verbose : server.cpp crypto.cpp
	$(CC) $(CFLAGS) $(PROTOCOL) $(VERBOSE) -o server server.cpp crypto.cpp -lpthread -lcrypto

clean : 
	$(RM) *.o client server