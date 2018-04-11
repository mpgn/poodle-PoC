# Poodle PoC

A proof of concept of the Poodle Attack (Padding Oracle On Downgraded Legacy Encryption) :

> a man-in-the-middle exploit which takes advantage of Internet and security software clients' fallback to SSL 3.0

The Poodle attack allow you to retrieve encrypted data send by a client to a server if the Transport Layer Security used is SSLv3. It does not allow you to retrieve the private key used to encrypt the message or the request HTTP. 

![imgonline-com-ua-twotoone-luefsrwi2n8iqy](https://user-images.githubusercontent.com/5891788/38616224-81b01940-3d93-11e8-9d59-e825e7ff6f4b.jpg)

#### SSLv3 and CBC cipher mode

SSLv3 is a protocol to encrypt/decrypt and secure your data. In our case, he uses the [CBC cipher mode chainning](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29) . The plaintext is divided into block regarding the encryption alogithm (AES,DES, 3DES) and the length is a mulitple of 8 or 16. If the plaintext don't fill the length, a [padding](https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7) is added at the end to complete the missing space. I strongly advice you to open this images of [encryption](https://upload.wikimedia.org/wikipedia/commons/thumb/8/80/CBC_encryption.svg/601px-CBC_encryption.svg.png) and [decryption](https://upload.wikimedia.org/wikipedia/commons/thumb/2/2a/CBC_decryption.svg/601px-CBC_decryption.svg.png) to read this readme.


Encryption | Decryption
--- | --- 
C<sub>i</sub> = E<sub>k</sub>(P<sub>i</sub> ⊕ C<sub>i-1</sub>), and C<sub>0</sub> = IV | P<sub>i</sub> = D<sub>k</sub>(C<sub>i</sub>) ⊕ C<sub>i-1</sub>, and C<sub>0</sub> = IV
 
Basically this is just some simple XOR, you can also watch this video (not me) https://www.youtube.com/watch?v=0D7OwYp6ZEc.

A request send over HTTPS using SSLv3 will be ciphered with AES/DES and the mode CBC. The particularity of SSlv3 over TLS1.x is the padding. In SSLv3 the padding is fill with random bytes except the last byte equal to the length of the padding.

Example:

`T|E|X|T|0xab|0x10|0x02` where `0xab|0x10|0x02` is the padding. <br />
`T|E|X|T|E|0x5c|0x01`    where `0x5c|0x01` is the padding.

Also the last block can be fill with a full block of padding meaning the last block can be full a random byte except the last byte.

`T|E|X|T|E|0x5c|0x01|0x3c|0x09|0x5d|0x08|0x04|0x07`    where `|0x5c|0x01|0x3c|0x09|0x5d|0x08|0x04|0x07` is the padding on only the `0x07` is know by the attacker. So if an attacker is able to influence the padding block, he will be able to know that the last byte of the last block is equal to the length of a block.

#### Influence the padding

An attacker must be able to make the victim send requests (using javascript by exploiting an XSS for example). Then he can control the path and the data of each request: 

Example: adding "A" byte to the path of the request
```
GET / HTTP/1.1\r\nSECRET COOKIE\r\n\r\n
GET /AAA HTTP/1.1\r\nSECRET COOKIE\r\n\r\nDATA
```

With this technique he can influence the padding.

#### HMAC

SSLv3 also use [HMAC](https://en.wikipedia.org/wiki/Hash-based_message_authentication_code) to check the integrity and authenticate of the plaintext.

> keyed-hash message authentication code (HMAC) is a specific type of message authentication code (MAC) involving a cryptographic hash function (hence the 'H') in combination with a secret cryptographic key

With this an attacker can't intercept and alter the request then send it back. If the server encounter a problem, he will send an HMAC error.

#### MAC-then-encrypt

The protocl SSLv3 use the following routine: he receives the data from the client, decrypt the data, check the integrity with the HMAC.

> MAC-then-Encrypt:
> Does not provide any integrity on the ciphertext, since we have no way of knowing until we decrypt the message whether it was indeed authentic or spoofed.
> Plaintext integrity.
> If the cipher scheme is malleable it may be possible to alter the message to appear valid and have a valid MAC. This is a theoretical point, of course, since practically speaking the MAC secret > should provide protection.
> Here, the MAC cannot provide any information on the plaintext either, since it is encrypted.

https://crypto.stackexchange.com/questions/202/should-we-mac-then-encrypt-or-encrypt-then-mac

This mean that we can alter the ciphered text without the server knowing it. this is great, really :)

### Cryptography

First the last block need to be full of padding, like we see previously the attacker use path of the request and check the length of the request. 

* He saves the length of the original cipher
* He adds one byte in the path and check the length. 
	- If the length doesn't change he adds another byte etc.
	- Else : the length of the cipher request change, he knows the last block is full of padding. 

Since the last block except the last byte is full of random bytes he can replace this last block C<sub>n</sub> by the block he wants to decrypt C<sub>i</sub>. The altered request is send to the server.

The server :
* remove the padding regarding the length of the last byte
* get the hmac from the request = HMAC
* get the plaintext
* compare hmac(plaintext) and HMAC
	- if equal => good padding
	- else => bad padding


By replacing the last block the attacker also changes the the last byte of the last block (the length of the padding). There is 1/256 the last byte replace in the padding block is the same than the orginal, in this case there will be no padding error and the attacker can use this XOR operation to retrieve the last byte of the block C<sub>i</sub> by following this operation :

P<sub>n</sub> = D<sub>k</sub>(C<sub>n</sub>) ⊕ C<sub>n-1</sub><br />
P<sub>n</sub> = D<sub>k</sub>(C<sub>i</sub>) ⊕ C<sub>n-1</sub><br />
P<sub>n</sub> = D<sub>k</sub>(C<sub>i</sub>) ⊕ C<sub>n-1</sub><br />
xxxxxxx7	  = D<sub>k</sub>(C<sub>i</sub>) ⊕ C<sub>n-1</sub><br />
D<sub>k</sub>(C<sub>i</sub>) = xxxxxxx7 ⊕ C<sub>n-1</sub><br />
P<sub>i</sub> ⊕ C<sub>i-1</sub> = xxxxxxx7 ⊕ C<sub>n-1</sub><br />
P<sub>i</sub> = C<sub>i-1</sub> ⊕ xxxxxxx7 ⊕ C<sub>n-1</sub><br />

(xxxxxxx7 or xxxxxxx15 and x random byte)

The last byte of the block can be retrieve P<sub>i</sub>[7] = C<sub>i-1</sub>[7] ⊕ xxxxxxx7 ⊕ C<sub>n-1</sub>[7]
In case of padding the attacker need to close the SSL session to make another handshake (new AES key) and get new cipher then replace the last block etc. (generaly +300 handshake needed)

Once one byte is retrieve he will get all the other byte of the block by adding a byte in the path and remove one byte in the data :


| Request to retrieve  byte E,I,K,O |
|---|
| GET /a SECRET_COOKIE dataazerty PADDING_7 |
| GET /aa SECRET_COOKIE dataazert PADDING_7 |
| GET /aaa SECRET_COOKIE dataazer PADDING_7 |
| GET /aaaa SECRET_COOKIE dataaze PADDING_7 |


#### About TLS1.0

> Even though TLS specifications require servers to check the padding, some implementations fail to validate it properly, which makes some servers vulnerable to POODLE even if they disable SSL 3.0

TLS is normaly safe against Poodle, but some implementations don't check the padding, it's like if we used SSLv3, this is why some TLS version are vulnerable.

### Start the attack

#### The poodle-poc.py file

This poc explore the cryptography behind the attack. This file allow us to understand how the attack works in a simple way.

```bash
python3 poodle-poc.py
```

The file `parallelization-poodle.py` is a project, and idea :) check https://github.com/mpgn/poodle-PoC/issues/1
```bash
python3 parallelization-poodle.py
```

[![asciicast](https://asciinema.org/a/cuj891xnb8djk5luiwilr9igk.png)](https://asciinema.org/a/cuj891xnb8djk5luiwilr9igk)


#### The poodle-exploit.py file

This is the real exploit. Really usefull with you want to make a proof a concept about the Poodle Attack for a client during a pentest if he used old server and browser. Just put the ip of your malicious proxy into the config browser with the correct port, the proxy will take care of the rest.

requirement:
- make sure the client and the browser can communicate with the protocol SSLv3, use the tool [testssl.sh](https://testssl.sh/) for example

```
$> python3 poodle-exploit.py
	usage: poodle-exploit.py [-h] [--start-block START_BLOCK]
							[--stop-block STOP_BLOCK]
							proxy port server rport
	poodle-exploit.py: error: the following arguments are required: proxy, port, server, rport

$> python3 test.py 192.168.13.1 4443 192.168.13.133 443 --start-block 46 --stop-block 50
```
Choosing a block: if you don't specify the block option, all the block will be decrypted but this can take a long time. I strongly advise you 'know' how the request will be formated and use the script `request-splitter.py` to know the block you want to decrypt (idealy the cookie block ! :)

Then insert the javascript malicious code (`poodle.js`) into the vulnerable website using an XSS for example. Launch the python script and type `help`, then `search`, and finaly `active`. During that time, only two interactions with the javascript will be needed (search and active command).

[![asciicast](https://asciinema.org/a/174901.png)](https://asciinema.org/a/174901)


## Contributor

[mpgn](https://github.com/mpgn) 

### Licence

[licence MIT](https://github.com/mpgn/poodle-PoC/blob/master/LICENSE)

## References

* https://en.wikipedia.org/wiki/POODLE
* https://www.openssl.org/~bodo/ssl-poodle.pdf
