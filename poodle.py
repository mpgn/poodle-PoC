import SocketServer
import ssl
import argparse
import socket
import sys
import threading
from pyfancy import *
from pprint import pprint

class SecureTCPHandler(SocketServer.BaseRequestHandler):
  def handle(self):
    self.request = ssl.wrap_socket(self.request, keyfile="cert/localhost.pem", certfile="cert/localhost.pem", server_side=True, ssl_version=ssl.PROTOCOL_SSLv3, cert_reqs=ssl.CERT_NONE)
    while True:
        try:
            data = self.request.recv(1024)
            if data == '':
                break
            print('The paquet is securly received: %s' % repr(data))
            self.request.send(b'OK')
        except ssl.SSLError as e:
            print('The server encountered an error with SSL: %s' % str(e))
            break
    return

class Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port

    def connection(self):
        SocketServer.TCPServer.allow_reuse_address = True
        httpd = SocketServer.TCPServer((self.host, self.port), SecureTCPHandler)
        server = threading.Thread(target=httpd.serve_forever)
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
        purpose = ssl.Purpose.SERVER_AUTH
        context = ssl.SSLContext(ssl.PROTOCOL_SSLv3)

        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_sock = context.wrap_socket(raw_sock, server_hostname=self.host)

        ssl_sock.connect((self.host, self.port))
        print('Connected to host {!r} and port {}\n'.format(self.host, self.port))
        self.socket = ssl_sock
    
    def send_request(self, path=0):
        print('Cliend send request...')
        srt_path = ''
        for x in range(0,path):
            srt_path += 'A'
        self.socket.sendall(b"HEAD /"+ srt_path +" HTTP/1.0\r\nHost: "+ self.host +"\r\n\r\n")
        msg = "".join([str(i) for i in self.socket.recv(1024).split(b"\r\n")])
        print("Client received confirmation")
        print("[" + pyfancy.GREEN + msg + pyfancy.END + "]")

    def disconnect(self):
        print("\nClient disconnect")
        self.socket.close()
        

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Connection with SSLv3')
    parser.add_argument('host', help='hostname or IP address')
    parser.add_argument('port', type=int, help='TCP port number')
    parser.add_argument('-v', help='debug mode', action="store_true")
    args = parser.parse_args()

    server = Server(args.host, args.port)
    server.connection()
    client = Client(args.host, args.port)
    client.connection()
    client.send_request()
    client.send_request(3)
    client.send_request()
    client.send_request()

    client.disconnect()
    server.disconnect()
