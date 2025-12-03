**采用性价比最高方案，我是wsl2+windows主机**

# 1.WSL2 Kali桥接
[安装WSL kali过程_哔哩哔哩_bilibili](https://www.bilibili.com/video/BV1ZC4y1U73Y/?spm_id_from=333.1391.0.0)
wsl2的桥接模式可以看老大的视频

# 2.Kali安装clash

[nelvko/clash-for-linux-install： 😼 优雅地使用基于 clash/mihomo 的代理环境](https://github.com/nelvko/clash-for-linux-install?tab=readme-ov-file)

这个一键安装脚本很好，可以直接嗦了

# 3.Kali设置代理以及ipv6

## openvpn配置文件设置代理


```bash
┌──(root㉿MJ)-[~]
└─# cat /etc/openvpn/labs_z_2.ovpn
client
dev tun
http-proxy 127.0.0.1 7890       主要添加这一行其他不变，走clash的代理，不然延迟会高
```


## kali转发端口设置http以及socks5代理

这里采用的gost代理方式

```bash
创建文件
vim /etc/systemd/system/gost.service


[Unit]
Description=GO Simple Tunnel (gost) Service
After=network.target

[Service]
# 使用 User= 或 Group= 确保服务不以 root 权限运行，提高安全性
# 例如：User=nobody
# 假设您的 gost 可执行文件在 /usr/local/bin/gost
ExecStart=/usr/local/bin/gost -L http://:8080 -L socks5://:1080 -F http://127.0.0.1:7890
Restart=always
# 避免使用 Type=forking，systemd 推荐使用 Type=simple
Type=simple

[Install]
WantedBy=multi-user.target
```

开机自启动
```bash

sudo systemctl daemon-reload
sudo systemctl enable gost.service
```

## ipv6

```bash
vim /etc/sysctl.d/99-ipv6.conf

# 启用 IPv6 (net.ipv6.conf.all.disable_ipv6=0) net.ipv6.conf.all.disable_ipv6 = 0 net.ipv6.conf.default.disable_ipv6 = 0 net.ipv6.conf.eth0.disable_ipv6 = 0


sudo sysctl -p /etc/sysctl.d/99-ipv6.conf

sudo systemctl restart networking

```

**设置完windows用firefox走kali的代理就可以放问htb的内网，不过目前bp抓包以及tscan等工具设置代理发现一样不能用，后续可能会改进，不过这样设置可以满足基本需求了**

