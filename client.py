import argparse
import ssl
import sys
sys.path.append('tests/')
from testClient import open_ssl
import http.client

def connection(host, port):

    conn = http.client.HTTPSConnection(host, port,context=context) 

    print('Connected to host {!r} and port {}'.format(host, port))
    conn.request("GET", '/', 'sdfsdfsdfd')
    r1 = conn.getresponse()
    print(r1.status, r1.reason)
    conn.close()

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Connection with SSLv3')
    parser.add_argument('host', help='hostname or IP address')
    parser.add_argument('port', type=int, help='TCP port number')
    parser.add_argument('-v', help='debug mode', action="store_true")
    args = parser.parse_args()

    purpose = ssl.Purpose.SERVER_AUTH
    context = ssl.create_default_context(purpose, cafile='cert/ca.crt')
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv3)

    if args.v:
        print("\n============ Handshake =============\n")
        ssl_sock = open_ssl(args.host, args.port, context)
        print("\n============ Handshake =============\n\n")

    connection(args.host, args.port)