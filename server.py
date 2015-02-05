import http.server
import socketserver
import ssl
import argparse
import socket

def connection(host, port):
    Handler = http.server.SimpleHTTPRequestHandler
    httpd = socketserver.TCPServer((host, port), Handler)
    httpd.socket = ssl.wrap_socket (httpd.socket,ssl_version=ssl.PROTOCOL_SSLv3, certfile='cert/localhost.pem', server_side=True)

    print('Serving HTTPS on {!r} port {} \n'.format(host, port))
    try:
        httpd.serve_forever()

    except KeyboardInterrupt:
        pass
    httpd.server_close()


if __name__ == '__main__':
    
    parser = argparse.ArgumentParser(description='Connection with SSLv3')
    parser.add_argument('host', help='hostname or IP address')
    parser.add_argument('port', type=int, help='TCP port number')
    args = parser.parse_args()

    connection(args.host, args.port)

