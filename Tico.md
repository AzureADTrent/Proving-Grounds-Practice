```
nmap -sC -sV -p- 192.168.173.143
Starting Nmap 7.93 ( https://nmap.org ) at 2023-08-02 12:11 CDT
Nmap scan report for 192.168.173.143
Host is up (0.046s latency).
Not shown: 65428 filtered tcp ports (no-response), 101 closed tcp ports (conn-refused)
PORT      STATE SERVICE    VERSION
21/tcp    open  ftp        vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 ftp      ftp          4096 Feb 01  2021 pub
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 192.168.45.216
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp    open  ssh        OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8535fbcab34b30d8e58eb325586c6e70 (RSA)
|   256 de67a232d5ff566e825b6a177de244ac (ECDSA)
|_  256 3aa3203b32cd836fdc23a266f90fc6d3 (ED25519)
80/tcp    open  http       nginx 1.14.0 (Ubuntu)
|_http-title: Markdown Editor
|_http-server-header: nginx/1.14.0 (Ubuntu)
8080/tcp  open  http-proxy
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     X-DNS-Prefetch-Control: off
|     X-Frame-Options: SAMEORIGIN
|     X-Download-Options: noopen
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     Referrer-Policy: strict-origin-when-cross-origin
|     X-Powered-By: NodeBB
|     set-cookie: _csrf=n11yKpyDG1dgVxA-pIH6umze; Path=/
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 15431
|     ETag: W/"3c47-MAHPkDGWjRz5Agdw4kVh8sU0dHw"
|     Vary: Accept-Encoding
|     Date: Wed, 02 Aug 2023 17:13:47 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en-GB" data-dir="ltr" style="direction: ltr;" >
|     <head>
|     <title>Not Found | NodeBB</title>
|     <meta name="viewport" content="width&#x3D;device-width, initial-scale&#x3D;1.0" />
|     <meta name="content-type" content="text/html; charset=UTF-8" />
|     <meta name="apple-mobile-web-app-capable" content="yes" />
|     <meta name="mobile-web-app-capable" content="yes" />
|     <meta property="og:site_name"
|   GetRequest: 
|     HTTP/1.1 200 OK
|     X-DNS-Prefetch-Control: off
|     X-Frame-Options: SAMEORIGIN
|     X-Download-Options: noopen
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     Referrer-Policy: strict-origin-when-cross-origin
|     X-Powered-By: NodeBB
|     set-cookie: _csrf=BSr3GGqEG5syOjyyXiTh0S4I; Path=/
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 24233
|     ETag: W/"5ea9-90w1O0yiUcr2C1JDIx95asAKUDw"
|     Vary: Accept-Encoding
|     Date: Wed, 02 Aug 2023 17:13:47 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en-GB" data-dir="ltr" style="direction: ltr;" >
|     <head>
|     <title>Home | NodeBB</title>
|     <meta name="viewport" content="width&#x3D;device-width, initial-scale&#x3D;1.0" />
|     <meta name="content-type" content="text/html; charset=UTF-8" />
|     <meta name="apple-mobile-web-app-capable" content="yes" />
|     <meta name="mobile-web-app-capable" content="yes" />
|     <meta property="og:site_name" content="No
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     X-DNS-Prefetch-Control: off
|     X-Frame-Options: SAMEORIGIN
|     X-Download-Options: noopen
|     X-Content-Type-Options: nosniff
|     X-XSS-Protection: 1; mode=block
|     Referrer-Policy: strict-origin-when-cross-origin
|     X-Powered-By: NodeBB
|     Allow: GET,HEAD
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 8
|     ETag: W/"8-ZRAf8oNBS3Bjb/SU2GYZCmbtmXg"
|     Vary: Accept-Encoding
|     Date: Wed, 02 Aug 2023 17:13:47 GMT
|     Connection: close
|     GET,HEAD
|   RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|_    Connection: close
| http-robots.txt: 3 disallowed entries 
|_/admin/ /reset/ /compose
|_http-title: Home | NodeBB
11211/tcp open  memcached  Memcached 1.5.6 (uptime 3764 seconds; Ubuntu)
27017/tcp open  mongodb    MongoDB
| mongodb-databases: 
|   errmsg = command listDatabases requires authentication
|   codeName = Unauthorized
|   code = 13
|_  ok = 0.0
| fingerprint-strings: 
|   FourOhFourRequest, GetRequest: 
|     HTTP/1.0 200 OK
|     Connection: close
|     Content-Type: text/plain
|     Content-Length: 85
|     looks like you are trying to access MongoDB over HTTP on the native driver port.
|   mongodb: 
|     errmsg
|     command serverStatus requires authentication
|     code
|     codeName
|_    Unauthorized
| mongodb-info: 
|   MongoDB Build info
|     maxBsonObjectSize = 16777216
|     openssl
|       running = OpenSSL 1.1.1  11 Sep 2018
|       compiled = OpenSSL 1.1.1  11 Sep 2018
|     bits = 64
|     versionArray
|       0 = 4
|       1 = 0
|       2 = 22
|       3 = 0
|     ok = 1.0
|     debug = false
|     allocator = tcmalloc
|     storageEngines
|       0 = devnull
|       1 = ephemeralForTest
|       2 = mmapv1
|       3 = wiredTiger
|     modules
|     buildEnvironment
|       ccflags = -fno-omit-frame-pointer -fno-strict-aliasing -ggdb -pthread -Wall -Wsign-compare -Wno-unknown-pragmas -Winvalid-pch -Werror -O2 -Wno-unused-local-typedefs -Wno-unused-function -Wno-deprecated-declarations -Wno-unused-but-set-variable -Wno-missing-braces -fstack-protector-strong -fno-builtin-memcmp
|       linkflags = -pthread -Wl,-z,now -rdynamic -Wl,--fatal-warnings -fstack-protector-strong -fuse-ld=gold -Wl,--build-id -Wl,--hash-style=gnu -Wl,-z,noexecstack -Wl,--warn-execstack -Wl,-z,relro
|       distmod = ubuntu1804
|       target_arch = x86_64
|       target_os = linux
|       cxx = /opt/mongodbtoolchain/v2/bin/g++: g++ (GCC) 5.4.0
|       cxxflags = -Woverloaded-virtual -Wno-maybe-uninitialized -std=c++14
|       cc = /opt/mongodbtoolchain/v2/bin/gcc: gcc (GCC) 5.4.0
|       distarch = x86_64
|     javascriptEngine = mozjs
|     gitVersion = 1741806fb46c161a1d42870f6e98f5100d196315
|     sysInfo = deprecated
|     version = 4.0.22
|   Server status
|     errmsg = command serverStatus requires authentication
|     codeName = Unauthorized
|     code = 13
|_    ok = 0.0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8080-TCP:V=7.93%I=7%D=8/2%Time=64CA8EAE%P=x86_64-pc-linux-gnu%r(Get
SF:Request,34B2,"HTTP/1\.1\x20200\x20OK\r\nX-DNS-Prefetch-Control:\x20off\
SF:r\nX-Frame-Options:\x20SAMEORIGIN\r\nX-Download-Options:\x20noopen\r\nX
SF:-Content-Type-Options:\x20nosniff\r\nX-XSS-Protection:\x201;\x20mode=bl
SF:ock\r\nReferrer-Policy:\x20strict-origin-when-cross-origin\r\nX-Powered
SF:-By:\x20NodeBB\r\nset-cookie:\x20_csrf=BSr3GGqEG5syOjyyXiTh0S4I;\x20Pat
SF:h=/\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Length:\
SF:x2024233\r\nETag:\x20W/\"5ea9-90w1O0yiUcr2C1JDIx95asAKUDw\"\r\nVary:\x2
SF:0Accept-Encoding\r\nDate:\x20Wed,\x2002\x20Aug\x202023\x2017:13:47\x20G
SF:MT\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"e
SF:n-GB\"\x20data-dir=\"ltr\"\x20style=\"direction:\x20ltr;\"\x20\x20>\n<h
SF:ead>\n\t<title>Home\x20\|\x20NodeBB</title>\n\t<meta\x20name=\"viewport
SF:\"\x20content=\"width&#x3D;device-width,\x20initial-scale&#x3D;1\.0\"\x
SF:20/>\n\t<meta\x20name=\"content-type\"\x20content=\"text/html;\x20chars
SF:et=UTF-8\"\x20/>\n\t<meta\x20name=\"apple-mobile-web-app-capable\"\x20c
SF:ontent=\"yes\"\x20/>\n\t<meta\x20name=\"mobile-web-app-capable\"\x20con
SF:tent=\"yes\"\x20/>\n\t<meta\x20property=\"og:site_name\"\x20content=\"N
SF:o")%r(HTTPOptions,1BF,"HTTP/1\.1\x20200\x20OK\r\nX-DNS-Prefetch-Control
SF::\x20off\r\nX-Frame-Options:\x20SAMEORIGIN\r\nX-Download-Options:\x20no
SF:open\r\nX-Content-Type-Options:\x20nosniff\r\nX-XSS-Protection:\x201;\x
SF:20mode=block\r\nReferrer-Policy:\x20strict-origin-when-cross-origin\r\n
SF:X-Powered-By:\x20NodeBB\r\nAllow:\x20GET,HEAD\r\nContent-Type:\x20text/
SF:html;\x20charset=utf-8\r\nContent-Length:\x208\r\nETag:\x20W/\"8-ZRAf8o
SF:NBS3Bjb/SU2GYZCmbtmXg\"\r\nVary:\x20Accept-Encoding\r\nDate:\x20Wed,\x2
SF:002\x20Aug\x202023\x2017:13:47\x20GMT\r\nConnection:\x20close\r\n\r\nGE
SF:T,HEAD")%r(RTSPRequest,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnec
SF:tion:\x20close\r\n\r\n")%r(FourOhFourRequest,34B2,"HTTP/1\.1\x20404\x20
SF:Not\x20Found\r\nX-DNS-Prefetch-Control:\x20off\r\nX-Frame-Options:\x20S
SF:AMEORIGIN\r\nX-Download-Options:\x20noopen\r\nX-Content-Type-Options:\x
SF:20nosniff\r\nX-XSS-Protection:\x201;\x20mode=block\r\nReferrer-Policy:\
SF:x20strict-origin-when-cross-origin\r\nX-Powered-By:\x20NodeBB\r\nset-co
SF:okie:\x20_csrf=n11yKpyDG1dgVxA-pIH6umze;\x20Path=/\r\nContent-Type:\x20
SF:text/html;\x20charset=utf-8\r\nContent-Length:\x2015431\r\nETag:\x20W/\
SF:"3c47-MAHPkDGWjRz5Agdw4kVh8sU0dHw\"\r\nVary:\x20Accept-Encoding\r\nDate
SF::\x20Wed,\x2002\x20Aug\x202023\x2017:13:47\x20GMT\r\nConnection:\x20clo
SF:se\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en-GB\"\x20data-dir=\"ltr
SF:\"\x20style=\"direction:\x20ltr;\"\x20\x20>\n<head>\n\t<title>Not\x20Fo
SF:und\x20\|\x20NodeBB</title>\n\t<meta\x20name=\"viewport\"\x20content=\"
SF:width&#x3D;device-width,\x20initial-scale&#x3D;1\.0\"\x20/>\n\t<meta\x2
SF:0name=\"content-type\"\x20content=\"text/html;\x20charset=UTF-8\"\x20/>
SF:\n\t<meta\x20name=\"apple-mobile-web-app-capable\"\x20content=\"yes\"\x
SF:20/>\n\t<meta\x20name=\"mobile-web-app-capable\"\x20content=\"yes\"\x20
SF:/>\n\t<meta\x20property=\"og:site_name\"");
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 189.95 seconds
                                                              
```