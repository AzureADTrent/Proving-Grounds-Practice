```
nmap -sC -sV -p- 192.168.235.170
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-31 08:44 CDT
Nmap scan report for 192.168.235.170
Host is up (0.047s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c1994b952225ed0f8520d363b448bbcf (RSA)
|   256 0f448badad95b8226af036ac19d00ef3 (ECDSA)
|_  256 32e12a6ccc7ce63e23f4808d33ce9b3a (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Under Maintainence
|_http-server-header: nginx/1.18.0 (Ubuntu)
5132/tcp open  unknown
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, NULL: 
|     Enter Username:
|   GenericLines, GetRequest, HTTPOptions, RTSPRequest: 
|     Enter Username: Enter OTP: Incorrect username or password
|   Help: 
|     Enter Username: Enter OTP:
|   RPCCheck: 
|     Enter Username: Traceback (most recent call last):
|     File "/opt/depreciated/messaging/messages.py", line 100, in <module>
|     main()
|     File "/opt/depreciated/messaging/messages.py", line 82, in main
|     username = input("Enter Username: ")
|     File "/usr/lib/python3.8/codecs.py", line 322, in decode
|     (result, consumed) = self._buffer_decode(data, self.errors, final)
|     UnicodeDecodeError: 'utf-8' codec can't decode byte 0x80 in position 0: invalid start byte
|   SSLSessionReq: 
|     Enter Username: Traceback (most recent call last):
|     File "/opt/depreciated/messaging/messages.py", line 100, in <module>
|     main()
|     File "/opt/depreciated/messaging/messages.py", line 82, in main
|     username = input("Enter Username: ")
|     File "/usr/lib/python3.8/codecs.py", line 322, in decode
|     (result, consumed) = self._buffer_decode(data, self.errors, final)
|     UnicodeDecodeError: 'utf-8' codec can't decode byte 0xd7 in position 13: invalid continuation byte
|   TerminalServerCookie: 
|     Enter Username: Traceback (most recent call last):
|     File "/opt/depreciated/messaging/messages.py", line 100, in <module>
|     main()
|     File "/opt/depreciated/messaging/messages.py", line 82, in main
|     username = input("Enter Username: ")
|     File "/usr/lib/python3.8/codecs.py", line 322, in decode
|     (result, consumed) = self._buffer_decode(data, self.errors, final)
|_    UnicodeDecodeError: 'utf-8' codec can't decode byte 0xe0 in position 5: invalid continuation byte
8433/tcp open  http    Werkzeug httpd 2.0.2 (Python 3.8.10)
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
|_http-server-header: Werkzeug/2.0.2 Python/3.8.10
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5132-TCP:V=7.93%I=7%D=7/31%Time=64C7BB28%P=x86_64-pc-linux-gnu%r(NU
SF:LL,10,"Enter\x20Username:\x20")%r(GenericLines,3A,"Enter\x20Username:\x
SF:20Enter\x20OTP:\x20Incorrect\x20username\x20or\x20password\n")%r(GetReq
SF:uest,3A,"Enter\x20Username:\x20Enter\x20OTP:\x20Incorrect\x20username\x
SF:20or\x20password\n")%r(HTTPOptions,3A,"Enter\x20Username:\x20Enter\x20O
SF:TP:\x20Incorrect\x20username\x20or\x20password\n")%r(RTSPRequest,3A,"En
SF:ter\x20Username:\x20Enter\x20OTP:\x20Incorrect\x20username\x20or\x20pas
SF:sword\n")%r(RPCCheck,1CD,"Enter\x20Username:\x20Traceback\x20\(most\x20
SF:recent\x20call\x20last\):\n\x20\x20File\x20\"/opt/depreciated/messaging
SF:/messages\.py\",\x20line\x20100,\x20in\x20<module>\n\x20\x20\x20\x20mai
SF:n\(\)\n\x20\x20File\x20\"/opt/depreciated/messaging/messages\.py\",\x20
SF:line\x2082,\x20in\x20main\n\x20\x20\x20\x20username\x20=\x20input\(\"En
SF:ter\x20Username:\x20\"\)\n\x20\x20File\x20\"/usr/lib/python3\.8/codecs\
SF:.py\",\x20line\x20322,\x20in\x20decode\n\x20\x20\x20\x20\(result,\x20co
SF:nsumed\)\x20=\x20self\._buffer_decode\(data,\x20self\.errors,\x20final\
SF:)\nUnicodeDecodeError:\x20'utf-8'\x20codec\x20can't\x20decode\x20byte\x
SF:200x80\x20in\x20position\x200:\x20invalid\x20start\x20byte\n")%r(DNSVer
SF:sionBindReqTCP,10,"Enter\x20Username:\x20")%r(DNSStatusRequestTCP,10,"E
SF:nter\x20Username:\x20")%r(Help,1B,"Enter\x20Username:\x20Enter\x20OTP:\
SF:x20")%r(SSLSessionReq,1D5,"Enter\x20Username:\x20Traceback\x20\(most\x2
SF:0recent\x20call\x20last\):\n\x20\x20File\x20\"/opt/depreciated/messagin
SF:g/messages\.py\",\x20line\x20100,\x20in\x20<module>\n\x20\x20\x20\x20ma
SF:in\(\)\n\x20\x20File\x20\"/opt/depreciated/messaging/messages\.py\",\x2
SF:0line\x2082,\x20in\x20main\n\x20\x20\x20\x20username\x20=\x20input\(\"E
SF:nter\x20Username:\x20\"\)\n\x20\x20File\x20\"/usr/lib/python3\.8/codecs
SF:\.py\",\x20line\x20322,\x20in\x20decode\n\x20\x20\x20\x20\(result,\x20c
SF:onsumed\)\x20=\x20self\._buffer_decode\(data,\x20self\.errors,\x20final
SF:\)\nUnicodeDecodeError:\x20'utf-8'\x20codec\x20can't\x20decode\x20byte\
SF:x200xd7\x20in\x20position\x2013:\x20invalid\x20continuation\x20byte\n")
SF:%r(TerminalServerCookie,1D4,"Enter\x20Username:\x20Traceback\x20\(most\
SF:x20recent\x20call\x20last\):\n\x20\x20File\x20\"/opt/depreciated/messag
SF:ing/messages\.py\",\x20line\x20100,\x20in\x20<module>\n\x20\x20\x20\x20
SF:main\(\)\n\x20\x20File\x20\"/opt/depreciated/messaging/messages\.py\",\
SF:x20line\x2082,\x20in\x20main\n\x20\x20\x20\x20username\x20=\x20input\(\
SF:"Enter\x20Username:\x20\"\)\n\x20\x20File\x20\"/usr/lib/python3\.8/code
SF:cs\.py\",\x20line\x20322,\x20in\x20decode\n\x20\x20\x20\x20\(result,\x2
SF:0consumed\)\x20=\x20self\._buffer_decode\(data,\x20self\.errors,\x20fin
SF:al\)\nUnicodeDecodeError:\x20'utf-8'\x20codec\x20can't\x20decode\x20byt
SF:e\x200xe0\x20in\x20position\x205:\x20invalid\x20continuation\x20byte\n"
SF:);
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 187.86 seconds

```

```
<!--commenting the code until we fix the whole application-->
   <!--<div class="row">-->
      <!--<div class="col-lg-4 col-sm-offset-2">-->
         <!--<div class="panel panel-primary">-->
            <!--<div class="panel-heading">Login</div>-->
            <!--<div class="panel-body">-->
               <!--<div class="col-md-6">-->
		       <!--<form method="post" action="http://127.0.0.1:8433/graphql?query={login(username:$uname, password:$pswd)}" enctype="multipart/form-data">-->
                     <!--<div class="form-group">-->
                        <!--<label for="uname">Username</label>-->
                        <!--<input type="text" placeholder="username" name="uname" class="form-control"><br>-->
                        <!--<label for="pswd">Password</label>-->
                        <!--<input type="text" placeholder="password" name="pswd" class="form-control"><br>-->
                        <!--<button class="btn btn-primary" type="submit">Submit</button>-->
```

https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/graphql

`query={__schema{types{name,fields{name}}}}` gave me a full list so I could search. Ran listusers and the one below to get access.

![[Pasted image 20230731153043.png]]

Connected with netcat.

![[Pasted image 20230731153258.png]]

One message mentioned password. Opened that to get the password.

Once in, I checked out the application and saw it was owned by root which means it is running as it.

The code mentions being able to attach files. It has to copy the file first to the user, so we can attach it and review it in the folder.
![[Pasted image 20230731143332.png]]

Attached the msg.json file to see if any other messages like passwords are mentioned.

![[Pasted image 20230731153351.png]]

It sent. So it was time to read it in opt.

![[Pasted image 20230731153438.png]]

Root password is in the last message.

The other was is using pwnkit as it is vulnerable.