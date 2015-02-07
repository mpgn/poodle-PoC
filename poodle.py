import SocketServer
import ssl
import argparse
import socket
import sys
import threading
import select
from struct import *
from pyfancy import *
from pprint import pprint

class SecureTCPHandler(SocketServer.BaseRequestHandler):
  def handle(self):
    self.request = ssl.wrap_socket(self.request, keyfile="cert/localhost.pem", certfile="cert/localhost.pem", server_side=True, ssl_version=ssl.PROTOCOL_SSLv3, cert_reqs=ssl.CERT_NONE)

    #loop to avoid broken pipe
    while True:
        try:
            data = self.request.recv(1024)
            if data == '':
                break
            print(pyfancy.LIGHTGREEN + 'The paquet is securely received: {}'.format(repr(data)) + pyfancy.END)
            self.request.send(b'OK')
        except ssl.SSLError as e:
            print('The server encountered an error with SSL: {}'.format(str(e)))
            break
    return

class SpyTCPHandler(SocketServer.BaseRequestHandler):

    def handle(self):
        # server choose by the spy. The spy can generate request from the client to this server
        server = socket.create_connection((SERVER_HOST, SERVER_PORT))
        # Sockets from which we expect to read
        inputs = [server, self.request]
        running = True
        while running:

            readable = select.select(inputs, [], [])[0]
            for source in readable:
                if source is server:
                    print pyfancy.PINK + "Client " + pyfancy.END + " <----- " + pyfancy.BLUE +"Server" + pyfancy.END
                    data = server.recv(4096)
                    if len(data) == 0:
                        running = False
     
                    # poodle attack here !
                    
                    # we send data to the client
                    self.request.send(data)

                elif source is self.request:
                    print pyfancy.PINK + "Client " + pyfancy.END + " -----> " + pyfancy.BLUE + "Server" + pyfancy.END
                    
                    data = self.request.recv(4096)
                    if len(data) == 0:
                        running = False
     
                    # poodle attack here !
                    
                    # we send data to the server
                    server.send(data)
        return

class Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port

    def connection(self):
        SocketServer.TCPServer.allow_reuse_address = True
        httpd = SocketServer.TCPServer((self.host, self.port), SecureTCPHandler)
        server = threading.Thread(target=httpd.serve_forever)
        server.daemon=True
        server.start()
        print('Server is serving HTTPS on {!r} port {}'.format(self.host, self.port))
        self.httpd = httpd

    def disconnect(self):
        print('Server stop serving HTTPS on {!r} port {}'.format(self.host, self.port))
        self.httpd.shutdown()

class Client:

    def __init__(self, host, port):
        self.host = host
        self.port = port

    def connection(self):
        print('Client connected to host {!r} and port {}\n'.format(self.host, self.port))

        purpose = ssl.Purpose.SERVER_AUTH
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv3)

        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_sock = context.wrap_socket(raw_sock, server_hostname=self.host)

        ssl_sock.connect((self.host, self.port))
        self.socket = ssl_sock
    
    def send_request(self, path=0):
        print('\nCliend send request...')
        srt_path = ''
        for x in range(0,path):
            srt_path += 'A'
        self.socket.sendall(b"HEAD /"+ srt_path +" HTTP/1.0\r\nHost: "+ self.host +"\r\n\r\n")
        msg = "".join([str(i) for i in self.socket.recv(1024).split(b"\r\n")])
        print("[" + pyfancy.GREEN + msg + pyfancy.END + "] Client received confirmation ")

    def disconnect(self):
        print("\nClient disconnect")
        self.socket.close()
        
class Spy:

    def __init__(self, host, port):
        self.host = host
        self.port = port

    def connection(self):
        SocketServer.TCPServer.allow_reuse_address = True
        httpd = SocketServer.TCPServer((self.host, self.port), SpyTCPHandler)
        spy = threading.Thread(target=httpd.serve_forever)
        spy.daemon=True
        spy.start()
        print('Spy is serving HTTPS on {!r} port {}'.format(self.host, self.port))
        self.spy = httpd

    def disconnect(self):
        print('Spy stop serving HTTPS on {!r} port {}'.format(self.host, self.port))
        self.spy.shutdown()

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Connection with SSLv3')
    parser.add_argument('host', help='hostname or IP address')
    parser.add_argument('port', type=int, help='TCP port number')
    parser.add_argument('-v', help='debug mode', action="store_true")
    args = parser.parse_args()

    SERVER_HOST = args.host
    SERVER_PORT = args.port

    server = Server(args.host, args.port)
    server.connection()

    spy = Spy(args.host, args.port+1)
    spy.connection()

    client = Client(args.host, args.port+1)
    client.connection()

    client.send_request()
    client.send_request(2)

    client.disconnect()
    spy.disconnect()
    server.disconnect()
    
