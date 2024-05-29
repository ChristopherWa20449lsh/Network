# Generated automatically from Makefile.in by configure.
CC = g++
OPENSSL_INCLUDE = /opt/homebrew/opt/openssl@1.1/include
OPENSSL_LIB = /opt/homebrew/opt/openssl@1.1/lib
CFLAGS=-g -I$(OPENSSL_INCLUDE) -Wall
LD=-L$(OPENSSL_LIB) -lssl -lcrypto -ldl -lpthread
DISTDIR=Test

DIST=common.cpp \
	common.h \
	HttpProtocol.cpp \
	HttpProtocol.h \
	MyWebServer.cpp \

common.o: common.cpp common.h
	$(CC) $(CFLAGS) -c common.cpp

HttpProtocol.o: HttpProtocol.cpp HttpProtocol.h
	$(CC) $(CFLAGS) -c HttpProtocol.cpp

MyWebServer.o: MyWebServer.cpp
	$(CC) $(CFLAGS) -c MyWebServer.cpp

MyWebServer: common.o MyWebServer.o HttpProtocol.o
	$(CC) $(CFLAGS) common.o MyWebServer.o HttpProtocol.o -o MyWebServer $(LD)

Client: Client.cpp
	$(CC) $(CFLAGS) Client.cpp -o Client $(LD)

clean:
	rm -f *.o MyWebServer Client
	rm -f *.crt *.key *.pem *.csr *.srl
dist:
	rm -rf ${DISTDIR}; mkdir ${DISTDIR}
	cp ${DIST} ${DISTDIR}
	rm -f ${DISTFILE}
	tar cf - ${DISTDIR} | gzip > ${DISTFILE}
