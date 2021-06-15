TARGET= client server 
CC= g++
CFLAGS= -Wall -lcrypto -g

normal: $(TARGET)
client: client.cpp
	$(CC) $(CFLAGS) client.cpp -o client
server: server.cpp
	$(CC) $(CFLAGS) server.cpp -o server
clean:
	$(RM) $(TARGET)

CPPFLAGS="-I/usr/local/opt/openssl@1.1/include"
LDFLAGS="-L/usr/local/opt/openssl@1.1/lib"