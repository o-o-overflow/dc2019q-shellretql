# chall-shellretQL

A shellcoding web challenge.

The intended solution is to write two shellcodes:
 - The first leaks a memory location on the stack 
 - The second uses that location to run a shellcode that exists within the query and sends the flag over the open socket.

One complication is that the php scripts are running as `cgi-bin`, which means that your output must follow the cgi-bin format, otherwise no output for you (500).

So you must send `Content-type: text/html\n\n` first, then the output.

Check out [exploit.py](interaction/exploit.py) and [shellcode.template](interaction/shellcode.template).

`interaction` has Dockerfile and exploit scripts.

`service/src` has the source for the extension and the php files.

You can use `./tester launch` to launch the service container.

TAGS: web, shellcode

LEVEL: hard
Dockerfile and exploit scripts
STATUS: ready

You can use `./tester launch` to launch the service container.

AUTHOR: adamd and trickE

TESTED BY: nobody. 

