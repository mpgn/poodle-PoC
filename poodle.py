import http.server
import http.client
import socketserver
import ssl
import argparse
import socket
import sys
import threading
sys.path.append('tests/')
from testClient import open_ssl
from pprint import pprint

CRLF = "\r\n\r\n"

class MyTCPHandler(socketserver.BaseRequestHandler):
    """
    The RequestHandler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """

    def handle(self):
        httpd.socket = ssl.wrap_socket (httpd.socket,ssl_version=ssl.PROTOCOL_SSLv3, certfile='cert/localhost.pem', server_side=True, cert_reqs=ssl.CERT_NONE)
        while True:
            try:
                data = httpd.socket.recv(1024)
                if data == '':
                    break
                httpd.socket.send(b'200')
            except ssl.SSLError as e:
                print("Error SSL")
                break
        return


class Client():

    def connection(host, port):
        ssl_socket = socket.create_connection((host,port))
        ssl_socket= ssl.wrap_socket(ssl_socket, server_side=False, ssl_version=ssl.PROTOCOL_SSLv3, cert_reqs=ssl.CERT_NONE)
        
        print('Client is ready on host {!r} and port {}\n'.format(host, port))
        return ssl_socket

    def request(ssl_sock, path=0):
        print('Cliend send request...')
        ssl_sock.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        pprint.pprint(conn.recv(1024).split(b"\r\n"))

    def closeSession(client):
        print('Client close the connection')
        client.close()

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Connection with SSLv3')
    parser.add_argument('host', help='hostname or IP address')
    parser.add_argument('port', type=int, help='TCP port number')
    parser.add_argument('-v', help='debug mode', action="store_true")
    args = parser.parse_args()

    httpd = socketserver.TCPServer((args.host, args.port), MyTCPHandler)
    server = threading.Thread(target=httpd.serve_forever)

    server.start()
    print('Server is serving HTTPS on {!r} port {}'.format(args.host, args.port))

    client = Client.connection(args.host, args.port)

    Client.request(client)
    Client.request(client)

    Client.closeSession(client)
    init_server.shutdown()

    
