```
nmap -sC -sV -p- 192.168.173.112
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-02 08:42 CDT
Nmap scan report for 192.168.173.112
Host is up (0.043s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f0856165d388ad496b38f4ac5b904f2d (RSA)
|   256 05809092ff9ed60e2f70376d8676db05 (ECDSA)
|_  256 c35735b98aa5c0f8b1b2e97309adc79a (ED25519)
80/tcp    open  http     Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Cookie Cutter Coming Soon!
|_http-server-header: Apache/2.4.29 (Ubuntu)
50000/tcp open  ibm-db2?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 107.34 seconds
                                                                                                                    
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sU 192.168.173.112
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-02 08:47 CDT
Nmap scan report for 192.168.173.112
Host is up (0.041s latency).
Not shown: 997 closed udp ports (port-unreach)
PORT      STATE    SERVICE
363/udp   filtered rsvp_tunnel
1072/udp  filtered cardax
29823/udp filtered unknown

Nmap done: 1 IP address (1 host up) scanned in 1086.58 seconds
                                                                  
```