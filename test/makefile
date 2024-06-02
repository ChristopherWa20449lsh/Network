CC = g++

OPENSSL_INCLUDE_MAC = /opt/homebrew/opt/openssl@1.1/include
OPENSSL_LIB_MAC = /opt/homebrew/opt/openssl@1.1/lib
OPENSSL_MAC = /opt/homebrew/opt/openssl@1.1/bin/openssl
OPENSSL_INCLUDE_LINUX_NORMAL = /usr/local/openssl-1.1.1f/ssl/include
OPENSSL_LIB_LINUX_NORMAL = /usr/local/openssl-1.1.1f/ssl/lib
OPENSSL_LINUX_NORMAL = /usr/local/openssl-1.1.1f/bin/openssl
OPENSSL_INCLUDE_LINUX_HEARTBLEED = /usr/local/openssl-1.0.1c/ssl/include
OPENSSL_LIB_LINUX_HEARTBLEED = /usr/local/openssl-1.0.1c/ssl/lib
OPENSSL_LINUX_HEARTBLEED = /usr/local/openssl-1.0.1c/bin/openssl

CFLAGS=-g -I$(OPENSSL_INCLUDE) -Wall
LD=-L$(OPENSSL_LIB) -lssl -lcrypto -ldl -lpthread

mac:
	$(CC) -g -I$(OPENSSL_INCLUDE_MAC) test.cpp -o test -L$(OPENSSL_LIB_MAC) -lssl -lcrypto -ldl -lpthread

normal:
	$(CC) -g -I$(OPENSSL_INCLUDE_LINUX_NORMAL) test.cpp -o test -L$(OPENSSL_LIB_LINUX_NORMAL) -lssl -lcrypto -ldl -lpthread

heartbleed:
	$(CC) -g -I$(OPENSSL_INCLUDE_LINUX_HEARTBLEED) test.cpp -o test -L$(OPENSSL_LIB_LINUX_HEARTBLEED) -lssl -lcrypto -ldl -lpthread