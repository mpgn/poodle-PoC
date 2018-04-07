'''
    Poodle  attack implementation
    Author: mpgn <martial.puygrenier@gmail.com>
    Created: 03/2018 - Python3
    License: MIT
    
    This script allow you to see in which block the sensitive data will be
'''

BLOCK_LENGTH = 8

def split_len(seq, length):
        return [seq[i:i+length] for i in range(0, len(seq), length)]

data = """POST /aaaaa

Host: 192.168.13.133
User-Agent: Mozilla/5.0 (Windows NT 5.1; rv:33.0) Gecko/20100101 Firefox/33.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: fr,fr-fr;q=0.8,en-us;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Referer: https://192.168.13.133/
Content-Length: 62
Content-Type: text/plain; charset=UTF-8
Cookie: auth-token=@Quokkalight
Connection: keep-alive
Pragma: no-cache
Cache-Control: no-cache


bbbbbbbbbbbbbbb"""

s = split_len(data,BLOCK_LENGTH)

for block in range(0,len(s)):
    print(str(block) +" -> ["+repr(s[block])+"]")



