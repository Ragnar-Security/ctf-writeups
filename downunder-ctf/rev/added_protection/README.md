# Added Protection

If you have not already, follow us on Twitter for updates and content! [@RagnarSecurity](https://twitter.com/ragnarsecurity)


This was a "hard" reverse engineering challenge (it was actually pretty easy to figure it out, even though it was considered hard). 

If we run the program, it returns this to STDIN:

```
WittsEnd2@ubuntu:[~/Documents/ctf-writeups/downunder-ctf/rev/added_protection]
$ ./added_protection 
size of code: 130
Can u find the flag? 
```

Nothing particularly useful. Lets open Ghidra and start exploring the contents. It seems like symbols were still present so we could easily go to main.

```C
undefined8 main(void)

{
  ushort *puVar1;
  code *__dest;
  ulong local_10;
  
  fprintf(stderr,"size of code: %zu\n",0x82);
  local_10 = 0;
  while (local_10 < 0x41) {
    puVar1 = (ushort *)(code + local_10 * 2);
    *puVar1 = *puVar1 ^ 0xbeef;
    if (*puVar1 < 0x2a) {
      *puVar1 = *puVar1 - 0x2b;
    }
    else {
      *puVar1 = *puVar1 - 0x2a;
    }
    local_10 = local_10 + 1;
  }
  __dest = (code *)mmap((void *)0x0,0x82,7,0x22,-1,0);
  if (__dest == (code *)0xffffffffffffffff) {
    perror("mmap");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  memcpy(__dest,code,0x82);
  (*__dest)();
  return 0;
}
```

What stood out to me immediately was the lines here: 
```c
  __dest = (code *)mmap((void *)0x0,0x82,7,0x22,-1,0);
  if (__dest == (code *)0xffffffffffffffff) {
    perror("mmap");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
```

I knew this immediately could be useful because it was a function pointer being called in an if statement. This is something that `I have used` when creating challenges. 

This trick I learned from the book[Programming Anti-Revsersing Techniques](https://leanpub.com/anti-reverse-engineering-linux) by Jacob Baines. I highly recommend reading it. 

Moving on, since we cannot read directly what that function pointer is doing, I decided to pull up our good ol' friend GDB and to debug it. 

There is just one catch to this...we can't set a breakpoint at code. So like any other good reverser, I took a look at how `code` was being called, and see if the data has anythignginteresting.
```
$ gdb-peda added_protection

Reading symbols from added_protection...
(No debugging symbols found in added_protection)

gdb-peda$ b *main+299
Breakpoint 1 at 0x12a0

gdb-peda$ r

Starting program: /home/mwittner/Documents/ctf-writeups/downunder-ctf/rev/added_protection/added_protection 
size of code: 130
[----------------------------------registers-----------------------------------]
RAX: 0x0 
RBX: 0x5555555552b0 (<__libc_csu_init>:	push   r15)
RCX: 0x7ffff7ed98b6 (<__GI___mmap64+38>:	cmp    rax,0xfffffffffffff000)
RDX: 0x7ffff7ffb000 --> 0x49e1894864ec8348 
RSI: 0x555555558060 --> 0x49e1894864ec8348 
RDI: 0x7ffff7ffb000 --> 0x49e1894864ec8348 
RBP: 0x7fffffffde70 --> 0x0 
RSP: 0x7fffffffde30 --> 0x7fffffffdf68 --> 0x7fffffffe289 ("/home/mwittner/Documents/ctf-writeups/downunder-ctf/rev/added_protection/added_protection")
RIP: 0x5555555552a0 (<main+299>:	call   rdx)
R8 : 0xffffffff 
R9 : 0x0 
R10: 0x55555555446c --> 0x73007970636d656d ('memcpy')
R11: 0x7ffff7f4c4e0 (<__memmove_avx_unaligned_erms>:	endbr64)
R12: 0x555555555090 (<_start>:	xor    ebp,ebp)
R13: 0x7fffffffdf60 --> 0x1 
R14: 0x0 
R15: 0x0
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x555555555293 <main+286>:	mov    QWORD PTR [rbp-0x20],rax
   0x555555555297 <main+290>:	mov    rdx,QWORD PTR [rbp-0x20]
   0x55555555529b <main+294>:	mov    eax,0x0
=> 0x5555555552a0 <main+299>:	call   rdx
   0x5555555552a2 <main+301>:	mov    eax,0x0
   0x5555555552a7 <main+306>:	leave  
   0x5555555552a8 <main+307>:	ret    
   0x5555555552a9:	nop    DWORD PTR [rax+0x0]
No argument
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffde30 --> 0x7fffffffdf68 --> 0x7fffffffe289 ("/home/mwittner/Documents/ctf-writeups/downunder-ctf/rev/added_protection/added_protection")
0008| 0x7fffffffde38 --> 0x1555552f5 
0016| 0x7fffffffde40 --> 0x7ffff7faefc8 --> 0x0 
0024| 0x7fffffffde48 --> 0x5555555580e0 --> 0x820000050f 
0032| 0x7fffffffde50 --> 0x7ffff7ffb000 --> 0x49e1894864ec8348 
0040| 0x7fffffffde58 --> 0x7ffff7ffb000 --> 0x49e1894864ec8348 
0048| 0x7fffffffde60 --> 0x82 
0056| 0x7fffffffde68 --> 0x41 ('A')
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x00005555555552a0 in main ()


gdb-peda$ x/40xi $rdx
   0x7ffff7ffb000:	sub    rsp,0x64
   0x7ffff7ffb004:	mov    rcx,rsp
   0x7ffff7ffb007:	movabs r8,0x64617b4654435544
   0x7ffff7ffb011:	movabs r9,0x6e456465636e3476
   0x7ffff7ffb01b:	movabs r10,0x5364337470797263
   0x7ffff7ffb025:	movabs r11,0x65646f436c6c6568
   0x7ffff7ffb02f:	movabs r12,0x662075206e61437d
   0x7ffff7ffb039:	movabs r13,0x2065687420646e69
   0x7ffff7ffb043:	movabs r14,0x2020203f67616c66
   0x7ffff7ffb04d:	mov    r15d,0xa
   0x7ffff7ffb053:	push   r15
   0x7ffff7ffb055:	push   r14
   0x7ffff7ffb057:	push   r13
   0x7ffff7ffb059:	push   r12
   0x7ffff7ffb05b:	push   r11
   0x7ffff7ffb05d:	push   r10
   0x7ffff7ffb05f:	push   r9
   0x7ffff7ffb061:	push   r8
   0x7ffff7ffb063:	mov    eax,0x1
   0x7ffff7ffb068:	mov    edi,0x1
   0x7ffff7ffb06d:	lea    rsi,[rcx-0x1f]
   0x7ffff7ffb071:	mov    edx,0x3a
   0x7ffff7ffb076:	syscall 
   0x7ffff7ffb078:	xor    rbx,rbx
   0x7ffff7ffb07b:	mov    eax,0x3c
   0x7ffff7ffb080:	syscall 
   0x7ffff7ffb082:	add    BYTE PTR [rax],al
   0x7ffff7ffb084:	add    BYTE PTR [rax],al
   0x7ffff7ffb086:	add    BYTE PTR [rax],al
   0x7ffff7ffb088:	add    BYTE PTR [rax],al
   0x7ffff7ffb08a:	add    BYTE PTR [rax],al
   0x7ffff7ffb08c:	add    BYTE PTR [rax],al
   0x7ffff7ffb08e:	add    BYTE PTR [rax],al
   0x7ffff7ffb090:	add    BYTE PTR [rax],al
   0x7ffff7ffb092:	add    BYTE PTR [rax],al
   0x7ffff7ffb094:	add    BYTE PTR [rax],al
   0x7ffff7ffb096:	add    BYTE PTR [rax],al
   0x7ffff7ffb098:	add    BYTE PTR [rax],al
   0x7ffff7ffb09a:	add    BYTE PTR [rax],al
   0x7ffff7ffb09c:	add    BYTE PTR [rax],al
gdb-peda$ 
```
Hmm These look interesting

```
   0x7ffff7ffb007:	movabs r8,0x64617b4654435544
   0x7ffff7ffb011:	movabs r9,0x6e456465636e3476
   0x7ffff7ffb01b:	movabs r10,0x5364337470797263
   0x7ffff7ffb025:	movabs r11,0x65646f436c6c6568
   0x7ffff7ffb02f:	movabs r12,0x662075206e61437d
   0x7ffff7ffb039:	movabs r13,0x2065687420646e69
   0x7ffff7ffb043:	movabs r14,0x2020203f67616c66
```
Lets see what's in them:

Line 1) `da{FTCUD`

This seemed reversed, lets unreverse it. 

Line 1) `DUCTF{ad`

If we continue, we get the full flag: `DUCTF{adv4ncedEncrypt3dShellCode}`