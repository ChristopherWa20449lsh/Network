CC = g++
CFLAGS = -std=c++11
OPENSSL_INCLUDE = /opt/homebrew/opt/openssl@1.1/include
OPENSSL_LIB = /opt/homebrew/opt/openssl@1.1/lib

all: client server

client: client.cpp
	$(CC) $(CFLAGS) -I$(OPENSSL_INCLUDE) -L$(OPENSSL_LIB) -o client client.cpp -lssl -lcrypto

server: server.cpp
	$(CC) $(CFLAGS) -I$(OPENSSL_INCLUDE) -L$(OPENSSL_LIB) -o server server.cpp -lssl -lcrypto

.PHONY: clean

clean:
	rm -f client server
	rm -f *.crt *.key *.pem *.csr *.srl