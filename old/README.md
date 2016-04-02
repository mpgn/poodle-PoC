**Update 2016**: this is my first work for the Poodle PoC, unfortunately SSLv3 is disabled by default on OpenSSL, you cannot launch the python script unless your OpenSSL is not udpate. This poc is still working but i made another one `poodle-poc.py` without SSLv3 to show the cryptography behind the attack.

#Poodle attack
A sample application of the **Poddle** (*Padding Oracle On Downgraded Legacy Encryption*) attack with a Man on the Middle exploit to demonstrate the vunlerability of the protocole SSLv3.

## How the exploit work ?

The attack will be explain regarding the implementation made in this repository. There are four components to make this exploit possible include in the file `poodle.py`:  a client, a proxy, a server, an attacker.

#### Situation

The diagram below represents the situation: 

    +--------------------+         +---------------------+          +--------------------+
    |     - Client -     +-------> |       - Proxy -     +--------> |    -  Server -     |
    |   sends requests   |         |       intercept     |          |       Oracle       |
    |                    | <-------+ read server response| <--------+                    |
    +--------------------+         +-----+--------+------+          +--------------------+
                 ^                         |        |                               
                 |                         |        |                               
                 |                   +-----v--------+------+                        
                 +--------+----------+     - Attacker -    |
                                     |   alter, decipher   |                        
                 inject javascript   +---------------------+ 

- **Server** :
It's a perfect secure server ready to make handshake with a client using the protocol SSLv3 and receive encrypted requests from the client through is handler. The server response will be used as **Oracle** by the attacker. <br />
Class: `Server()` -  Important functions : `connection()`, `SecureTCPHandler.handle()`, `disconnect()`

- **Client** :
A sample client, can be related to a web browser. The client makes requests to a server with a cookie inside. <br />
Class: `Client()` -  Important functions : `connection()`, `request(...)`, `disconnect()` <br />
Example request :
```
GET / HTTP/1.1\r\nCookie: UpVP0rDn5SoHoiX9\r\n\r\n
```

- **Proxy** :
The proxy is our man in the middle, he is completely passive. He intercepts encrypted requests from the client to the server and lets the attacker alter them. He also intercepts the data from the server to the client and gets the header response status. <br />
Class: `Proxy()` -  Important functions : `ProxyTCPHandler.handle()`

- **Attacker** : He can make ask to the client to generate a request to a secure server with a cookie inside. In real case, it can be done by injecting some javascript into the a web page visited by the client.
He also alters client's requests regarding the proxy interception. Finally he can decipher one byte of the client's request. <br />
Class: `Poodle(Client)` -  Important functions : `exploit()`, `decipher(...)`, `find_plaintext_byte(...)`, `choosing_block(...)`, `alter(...)`

###Exploit

The attack starts with the function `Poddle.run()`.
By hypothesis the requests are encrypted  with [CBC](http://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29), so the first move of the attacker is to determine the length of a block with the function `size_of_block()`.
Once he have the length the exploit can start !

The attacker reads all the encrypted block except the first one (VI is unknown) byte by byte. At each byte of each block the function `find_plaintext_byte(...)` is launched. This function ask to the client to send an infinite number of requests to the server after make a new handshake between the client and the server to change the encryption of the request. 
Each request is altered and the loop finish when the server's response is not an error MAC.
At this point the attacker can run the function `decipher(...)` and make a simple XOR operation to find a plain text byte.

The request will be deciphered byte by byte of each block.
At the end we will have the final request made by the client.

##Run it !

Require python version `2.7.*` and openssl 0.9.8 to launch this exploit. Then just run:
```
python poodle.py localhost 1111
```

**Warning** OpenSSL > 1.0 no longer support SSLv3 protocole, you may have this error:
```
AttributeError: 'module' object has no attribute 'PROTOCOL_SSLv3'
```

The Poodle attack cannot be run on updated machine (good things, but bad for the PoC) 

Video demo :

[![Poodle-PoC](http://mpgn.fr/poodle.png)](https://sendvid.com/1wjwn1qz)

##Ressources

- https://blog.cloudflare.com/padding-oracles-and-the-decline-of-cbc-mode-ciphersuites/
- http://en.wikipedia.org/wiki/POODLE
- https://www.imperialviolet.org/2014/10/14/poodle.html
- http://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29
- http://wiki.wireshark.org/SSL


