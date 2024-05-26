CC = g++
CFLAGS = -std=c++11
OPENSSL_INCLUDE = /opt/homebrew/opt/openssl@1.1/include
OPENSSL_LIB = /opt/homebrew/opt/openssl@1.1/lib

generate: generate.cpp
	$(CC) $(CFLAGS) -o generate generate.cpp

normal: normal.cpp
	$(CC) $(CFLAGS) -o normal normal.cpp

buffer: buffer.cpp
	$(CC) $(CFLAGS) -I$(OPENSSL_INCLUDE) -L$(OPENSSL_LIB) -o buffer buffer.cpp -lssl -lcrypto

test: test.cpp
	$(CC) $(CFLAGS) -o test test.cpp

compare:
	./generate
	./normal
	./buffer