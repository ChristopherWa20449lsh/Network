# Generated automatically from Makefile.in by configure.
CC = g++

OPENSSL_INCLUDE_MAC = /opt/homebrew/opt/openssl@1.1/include
OPENSSL_LIB_MAC = /opt/homebrew/opt/openssl@1.1/lib
# OPENSSL_MAC = /opt/homebrew/opt/openssl@1.1/bin/openssl
OPENSSL_INCLUDE_LINUX_NORMAL = /usr/local/openssl-1.1.1f/include
OPENSSL_LIB_LINUX_NORMAL = /usr/local/openssl-1.1.1f/lib
# OPENSSL_LINUX_NORMAL = /usr/local/openssl-1.1.1f/bin/openssl
OPENSSL_INCLUDE_LINUX_HEARTBLEED = /usr/local/openssl-1.0.1c/include
OPENSSL_LIB_LINUX_HEARTBLEED = /usr/local/openssl-1.0.1c/lib
# OPENSSL_LINUX_HEARTBLEED = /usr/local/openssl-1.0.1c/bin/openssl

CFLAGS=-g -I$(OPENSSL_INCLUDE) -Wall
LD=-L$(OPENSSL_LIB) -lssl -lcrypto -ldl -lpthread -lsqlite3

.PHONY: clean Key server client

common.o: common.cpp common.h
	$(CC) $(CFLAGS) -c common.cpp

HttpProtocol.o: HttpProtocol.cpp HttpProtocol.h
	$(CC) $(CFLAGS) -std=c++11 -c HttpProtocol.cpp

server.o: server.cpp
	$(CC) $(CFLAGS) -c server.cpp

server: common.o server.o HttpProtocol.o
	$(CC) $(CFLAGS) common.o server.o HttpProtocol.o -o server $(LD)

client: client.cpp
	$(CC) $(CFLAGS) -std=c++11 client.cpp -o client $(LD)

mac:
	OPENSSL_INCLUDE=$(OPENSSL_INCLUDE_MAC) OPENSSL_LIB=$(OPENSSL_LIB_MAC) $(MAKE) Key server client

normal:
	OPENSSL_INCLUDE=$(OPENSSL_INCLUDE_LINUX_NORMAL) OPENSSL_LIB=$(OPENSSL_LIB_LINUX_NORMAL) $(MAKE) Key server client

heartbleed:
	OPENSSL_INCLUDE=$(OPENSSL_INCLUDE_LINUX_HEARTBLEED) OPENSSL_LIB=$(OPENSSL_LIB_LINUX_HEARTBLEED) $(MAKE) Key server client

Key:
	chmod +x keygen.sh
	./keygen.sh

clean:
	rm -rf client.dSYM
	rm -f *.o server client
	rm -f *.crt *.key *.pem *.csr *.srl
