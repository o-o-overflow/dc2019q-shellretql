# chall-shellretQL

A shellcoding web challenge.

This challenge builds on the shellQL challenge from 2018 by moving the flag to the file `/flag` and placing a proxy in between the webserver and database. The proxy contained a buffer overflow vulnerability.  Even though the input was limited to 1,000 bytes, the buffer overflow could be triggered by returning results that exceeded the buffer.  The proxy process had the access to read to the `/flag` file. 

The intended solution used two requests.  The first request leaks a stack address (saved EBP). The second request uses the leaked address to predict the location of their injected shellcode that would read the flag.  
  
Coming to the intended solution required a few discoveries. First, it was necessary to realize that long results were being cut off. Which leads to the question of how many bytes must be returned before the results were cut off. After some expirimentation, the results start cutting off when 1370 or more characters are returned by a query (however it is important to note this depends on how many characters the initial query contains).  

At this point, the **crux** of the challenge was to realize that the last line of the results contained a leaked stack address, which was the saved RBP value for the current function.  For example, after sending the SQL query `SELECT concat(repeat("A",1260),"CCCCDDDD");` results in the following:  
```00000000: 01 00 00 01 01 3A 00 00  02 03 64 65 66 00 00 00  .....:....def...
00000010: 24 63 6F 6E 63 61 74 28  72 65 70 65 61 74 28 22  $concat(repeat("
00000020: 41 22 2C 20 31 32 36 30  29 2C 22 43 43 43 43 44  A", 1260),"CCCCD
00000030: 44 44 44 22 29 00 0C 08  00 F4 04 00 00 FD 00 00  DDD")...........
00000040: 1F 00 00 05 00 00 03 FE  00 00 02 00 F7 04 00 04  ................
00000050: FC F4 04 41 41 41 41 41  41 41 41 41 41 41 41 41  ...AAAAAAAAAAAAA
...
00000530: 41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 43  AAAAAAAAAAAAAAAC
00000540: 43 43 43 44 44 44 44 05  50 05 00 00 00 00 00 00  CCCDDDD.P.......
00000550: C0 AF FF ED A8 7F 00 00  00 00 00 00 00 00 00 00  ...;............
```
After finding the saved RBP, the next hurdle was to realize that saved RBP was changing in a predictable way. For example, running the same query three times in a row returned the values `0x7FA8ED7F9FC0, 0x7FA8ECFF8FC0, and 0x7FA8EC7F7FC0` and the offset between each of the values was 0x801000. Thus, after saved EBP in one request it is then possible to send predict the value of EBP in the next request. 

In the same way as last year, the php scripts were running as `cgi-bin`, which means that the output must start with `Content-type: text/html\n\n` (as defined by the cgi-bin format), otherwise the server would return a `500`.

Check out [exploit.py](interaction/exploit.py) and [shellcode.template](interaction/shellcode.template).

`interaction` has an exploit Dockerfile and exploit scripts.

`service` has the Dockerfile for the service and the associated binaries and sources for the service. 

You can use `./tester launch` to launch the service container.

TAGS: web, shellcode

LEVEL: hard

STATUS: ready

AUTHOR: adamd and trickE

TESTED BY: nobody. 

