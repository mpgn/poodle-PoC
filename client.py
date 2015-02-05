import argparse
import socket
import ssl
import sys
import textwrap
import ctypes
import http.client
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

class PySSLSocket(ctypes.Structure):
    """The first few fields of a PySSLSocket (see Python's Modules/_ssl.c)."""

    _fields_ = [('ob_refcnt', ctypes.c_ulong), ('ob_type', ctypes.c_void_p),
                ('Socket', ctypes.c_void_p), ('ssl', ctypes.c_void_p)]

def SSL_get_version(ssl_sock):
    """Reach behind the scenes for a socket's TLS protocol version."""

    lib = ctypes.CDLL(ssl._ssl.__file__)
    lib.SSL_get_version.restype = ctypes.c_char_p
    address = id(ssl_sock._sslobj)
    struct = ctypes.cast(address, ctypes.POINTER(PySSLSocket)).contents
    version_bytestring = lib.SSL_get_version(struct.ssl)
    return version_bytestring.decode('ascii')

def lookup(prefix, name):
    if not name.startswith(prefix):
        name = prefix + name
    try:
        return getattr(ssl, name)
    except AttributeError:
        matching_names = (s for s in dir(ssl) if s.startswith(prefix))
        message = 'Error: {!r} is not one of the available names:\n {}'.format(
            name, ' '.join(sorted(matching_names)))
        print(fill(message), file=sys.stderr)
        sys.exit(2)


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

    try:
        protocol_version = SSL_get_version(ssl_sock)
    except Exception:
        if debug:
            raise
    else:
        say('Protocol version negotiated', protocol_version)

    cipher, version, bits = ssl_sock.cipher()
    compression = ssl_sock.compression()

    say('Cipher chosen for this connection', cipher)
    say('Cipher defined in TLS version', version)
    say('Cipher key has this many bits', bits)
    say('Compression algorithm in use', compression or 'none')

    return cert

def connection(host, port):

    conn = http.client.HTTPSConnection(host, port,context=context) 

    print('Connected to host {!r} and port {}'.format(host, port))
    conn.request("GET", '/', 'sdfsdfsdfd')
    r1 = conn.getresponse()
    print(r1.status, r1.reason)
    conn.close()

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
    ssl_sock = open_ssl(args.host, args.port)
    describe(ssl_sock, args.host)
    ssl_sock.close()
    print("\n============ Handshake =============\n\n")

connection(args.host, args.port)