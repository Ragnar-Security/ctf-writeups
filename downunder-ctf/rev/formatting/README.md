# Formatting 

If you have not already, follow us on Twitter for updates and content! [@RagnarSecurity](https://twitter.com/ragnarsecurity)


This is a beginner challenge in the Reverse Engineering category. This is great for people new to the tools that reversers use.

First, lets run the binary 
```
$ ./formatting 
haha its not that easy}
```

Okay, nothing useful. Lets open it up in Ghidra. Here is the main function:

```c

undefined8 main(void)

{
  int iVar1;
  char acStack146 [17];
  undefined local_81;
  undefined local_80;
  long local_28;
  undefined4 local_20;
  undefined4 local_1c;
  
  local_1c = 0x66;
  local_20 = 0x6c;
  local_80 = 0;
  local_81 = (undefined)brac1;
  iVar1 = sprintf(acStack146,fmt,"d1d_You_Just_ltrace_",(ulong)this,(ulong)crap,(ulong)is,(ulong)too
                  ,(ulong)easy,(ulong)what,(ulong)the,(ulong)heck);
  local_28 = (long)iVar1;
  acStack146[local_28] = (char)brac1;
  puts(flag + 6);
  return 0;
}
```

Huh, it says `d1d_You_Just_ltrace_`. Looks like it is part of a flag. Lets ltrace the binary and see if we get more. 

```
$ ltrace ./formatting
sprintf("d1d_You_Just_ltrace_296faa2990ac"..., "%s%02x%02x%02x%02x%02x%02x%02x%0"..., "d1d_You_Just_ltrace_", 0x29, 0x6f, 0xaa, 0x29, 0x90, 0xac, 0xbc, 0x36) = 37
puts("haha its not that easy}"haha its not that easy}
)                                                                                   = 24
+++ exited (status 0) +++
```

Looks like there is more to the flag. Looks like it requires some hex at the end of it too. If we take all of the hex values alone with `d1d_You_Just_ltrace`, you get the flag.

`DUCTF{d1d_You_Just_ltrace_96faa2990acbc36}` - Note, ltrace didn't totally dump the flag, it missed bc and 36. 