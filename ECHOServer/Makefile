CC = g++
CFLAGS = -std=c++11

all: client server

client: client.cpp
	$(CC) $(CFLAGS) -o client client.cpp

server: server.cpp
	$(CC) $(CFLAGS) -o server server.cpp

.PHONY: clean

clean:
	rm -f client server