import argparse, socket, ssl, sys, textwrap, httplib
import ctypes
from pprint import pprint

def open_ssl(host, port, cafile=None):
    say('Address we want to talk to', (host, port))
    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.connect((host, port))
    return context.wrap_socket(raw_sock)

def say(title, *words):
    print(fill(title.ljust(36, '.') + ' ' + ' '.join(str(w) for w in words)))

def fill(text):
    return textwrap.fill(text, subsequent_indent='    ',
                         break_long_words=False, break_on_hyphens=False)

def describe(ssl_sock, hostname):
    cert = ssl_sock.getpeercert()
    if cert is None:
        say('Peer certificate', 'none')
    else:
        say('Peer certificate', 'provided')
        subject = cert.get('subject', [])
        names = [name for names in subject for (key, name) in names
                 if key == 'commonName']
        if 'subjectAltName' in cert:
            names.extend(name for (key, name) in cert['subjectAltName']
                         if key == 'DNS')

        say('Name(s) on peer certificate', *names or ['none'])
        if names:
            try:
                ssl.match_hostname(cert, hostname)
            except ssl.CertificateError as e:
                message = str(e)
            else:
                message = 'Yes'
            say('Whether name(s) match the hostname', message)
        for category, count in sorted(context.cert_store_stats().items()):
            say('Certificates loaded of type {}'.format(category), count)

    cipher, version, bits = ssl_sock.cipher()
    compression = ssl_sock.compression()

    say('Cipher chosen for this connection', cipher)
    say('Cipher defined in TLS version', version)
    say('Cipher key has this many bits', bits)
    say('Compression algorithm in use', compression or 'none')

    return cert

def connection(host, port, cafile=None):

    try:
        conn = httplib.HTTPSConnection(host, port,context=context) 
    except (httplib.HTTPException, socket.error) as er:
        print "Error: %s" % er
        sys.exit(errno.EACCES)

    print('Connected to host {!r} and port {}'.format(host, port))
    conn.request("HEAD", '/index.html')
    r1 = conn.getresponse()
    print(r1.status, r1.reason)
    conn.close()

parser = argparse.ArgumentParser(description='Connection with SSLv3')
parser.add_argument('host', help='hostname or IP address')
parser.add_argument('port', type=int, help='TCP port number')
parser.add_argument('-v', help='debug mode', action="store_true")
args = parser.parse_args()

purpose = ssl.Purpose.SERVER_AUTH
context = ssl.create_default_context(purpose, cafile=None)
context = ssl.SSLContext(ssl.PROTOCOL_SSLv3)

if args.v:
    print("\n============ Handshake =============\n")
    ssl_sock = open_ssl(args.host, args.port)
    describe(ssl_sock, args.host)
    ssl_sock.close()
    print("\n============ Handshake =============\n\n")

connection(args.host, args.port)