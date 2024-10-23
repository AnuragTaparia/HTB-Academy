# Enumerating & Retrieving Password Policies
## Enumerating the Password Policy - from Linux - Credentialed
- As stated in the previous section, we can pull the domain password policy in several ways, depending on how the domain is configured and whether or not we have valid domain credentials. With valid domain credentials, the password policy can also be obtained remotely using tools such as [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) or `rpcclient`
```shell-session
AnuragTaparia@htb[/htb]$ crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol
```

## Enumerating the Password Policy - from Linux - SMB NULL Sessions
- Without credentials, we may be able to obtain the password policy via an SMB NULL session or LDAP anonymous bind.
- SMB NULL sessions allow an unauthenticated attacker to retrieve information from the domain, such as a complete listing of users, groups, computers, user account attributes, and the domain password policy. 
- SMB NULL session misconfigurations are often the result of legacy Domain Controllers being upgraded in place, ultimately bringing along insecure configurations, which existed by default in older versions of Windows Server.

- When creating a domain in earlier versions of Windows Server, anonymous access was granted to certain shares, which allowed for domain enumeration. An SMB NULL session can be enumerated easily. For enumeration, we can use tools such as `enum4linux`, `CrackMapExec`, `rpcclient`, etc.
- We can use [rpcclient](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html) to check a Domain Controller for SMB NULL session access.
- Once connected, we can issue an RPC command such as `querydominfo` to obtain information about the domain and confirm NULL session access.
```shell-session
AnuragTaparia@htb[/htb]$ rpcclient -U "" -N 172.16.5.5
```

```shell-session
rpcclient $> querydominfo
rpcclient $> getdompwinfo
```


- Let's try this using [enum4linux](https://labs.portcullis.co.uk/tools/enum4linux). `enum4linux` is a tool built around the [Samba suite of tools](https://www.samba.org/samba/docs/current/man-html/samba.7.html) `nmblookup`, `net`, `rpcclient` and `smbclient` to use for enumeration of windows hosts and domains.
- Here are some common enumeration tools and the ports they use:

| Tool      | Ports                                             |
| --------- | ------------------------------------------------- |
| nmblookup | 137/UDP                                           |
| nbtstat   | 137/UDP                                           |
| net       | 139/TCP, 135/TCP, TCP and UDP 135 and 49152-65535 |
| rpcclient | 135/TCP                                           |
| smbclient | 445/TCP                                           |
#### Using enum4linux
```shell-session
AnuragTaparia@htb[/htb]$ enum4linux -P 172.16.5.5
```

- The tool [enum4linux-ng](https://github.com/cddmp/enum4linux-ng) is a rewrite of `enum4linux` in Python, but has additional features such as the ability to export data as YAML or JSON files which can later be used to process the data further or feed it to other tools. It also supports colored output, among other features
```shell-session
AnuragTaparia@htb[/htb]$ enum4linux-ng -P 172.16.5.5 -oA ilfreight
```


## Enumerating Null Session - from Windows
- It is less common to do this type of null session attack from Windows, but we could use the command `net use \\host\ipc$ "" /u:""` to establish a null session from a windows machine and confirm if we can perform more of this type of attack.
#### Establish a null session from windows
```cmd-session
C:\htb> net use \\DC01\ipc$ "" /u:""
```

- We can also use a username/password combination to attempt to connect. Let's see some common errors when trying to authenticate:

## Enumerating the Password Policy - from Linux - LDAP Anonymous Bind
- [LDAP anonymous binds](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/anonymous-ldap-operations-active-directory-disabled) allow unauthenticated attackers to retrieve information from the domain, such as a complete listing of users, groups, computers, user account attributes, and the domain password policy. 
- This is a legacy configuration, and as of Windows Server 2003, only authenticated users are permitted to initiate LDAP requests. 
- We still see this configuration from time to time as an admin may have needed to set up a particular application to allow anonymous binds and given out more than the intended amount of access, thereby giving unauthenticated users access to all objects in AD.
- With an LDAP anonymous bind, we can use LDAP-specific enumeration tools such as `windapsearch.py`, `ldapsearch`, `ad-ldapdomaindump.py`, etc., to pull the password policy.
#### Using ldapsearch
```shell-session
AnuragTaparia@htb[/htb]$ ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
```

## Enumerating the Password Policy - from Windows
- If we can authenticate to the domain from a Windows host, we can use built-in Windows binaries such as `net.exe` to retrieve the password policy. 
- We can also use various tools such as PowerView, CrackMapExec ported to Windows, SharpMapExec, SharpView, etc.
- Using built-in commands is helpful if we land on a Windows system and cannot transfer tools to it, or we are positioned on a Windows system by the client, but have no way of getting tools onto it. One example using the built-in net.exe binary is:
#### Using net.exe
```cmd-session
C:\htb> net accounts
```
#### Using PowerView
```powershell-session
PS C:\htb> import-module .\PowerView.ps1
PS C:\htb> Get-DomainPolicy
```

## Analyzing the Password Policy

The default password policy when a new domain is created is as follows, and there have been plenty of organizations that never changed this policy:

| Policy                                      | Default Value |
| ------------------------------------------- | ------------- |
| Enforce password history                    | 24 days       |
| Maximum password age                        | 42 days       |
| Minimum password age                        | 1 day         |
| Minimum password length                     | 7             |
| Password must meet complexity requirements  | Enabled       |
| Store passwords using reversible encryption | Disabled      |
| Account lockout duration                    | Not set       |
| Account lockout threshold                   | 0             |
| Reset account lockout counter after         | Not set       |


# Password Spraying - Making a Target User List
## Detailed User Enumeration
- To mount a successful password spraying attack, we first need a list of valid domain users to attempt to authenticate with. There are several ways that we can gather a target list of valid users:
	- By leveraging an SMB NULL session to retrieve a complete list of domain users from the domain controller
	- Utilizing an LDAP anonymous bind to query LDAP anonymously and pull down the domain user list
	- Using a tool such as `Kerbrute` to validate users utilizing a word list from a source such as the [statistically-likely-usernames](https://github.com/insidetrust/statistically-likely-usernames) GitHub repo, or gathered by using a tool such as [linkedin2username](https://github.com/initstring/linkedin2username) to create a list of potentially valid users
	- Using a set of credentials from a Linux or Windows attack system either provided by our client or obtained through another means such as LLMNR/NBT-NS response poisoning using `Responder` or even a successful password spray using a smaller wordlist
- Regardless of the method we choose, and if we have the password policy or not, we must always keep a log of our activities, including, but not limited to:
	- The accounts targeted
	- Domain Controller used in the attack
	- Time of the spray
	- Date of the spray
	- Password(s) attempted
- This will help us ensure that we do not duplicate efforts. If an account lockout occurs or our client notices suspicious logon attempts, we can supply them with our notes to crosscheck against their logging systems and ensure nothing nefarious was going on in the network.
## SMB NULL Session to Pull User List
- If you are on an internal machine but don’t have valid domain credentials, you can look for SMB NULL sessions or LDAP anonymous binds on Domain Controllers. Either of these will allow you to obtain an accurate list of all users within Active Directory and the password policy
- Some tools that can leverage SMB NULL sessions and LDAP anonymous binds include [enum4linux](https://github.com/portcullislabs/enum4linux), [rpcclient](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html), and [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec), among others.
#### Using enum4linux
```shell-session
AnuragTaparia@htb[/htb]$ enum4linux -U 172.16.5.5  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
```
#### Using rpcclient
```shell-session
AnuragTaparia@htb[/htb]$ rpcclient -U "" -N 172.16.5.5

rpcclient $> enumdomusers 
```
#### Using CrackMapExec --users Flag
- This is a useful tool that will also show the `badpwdcount` (invalid login attempts), so we can remove any accounts from our list that are close to the lockout threshold. 
- It also shows the `baddpwdtime`, which is the date and time of the last bad password attempt, so we can see how close an account is to having its `badpwdcount` reset.
```shell-session
AnuragTaparia@htb[/htb]$ crackmapexec smb 172.16.5.5 --users
```

## Gathering Users with LDAP Anonymous
- We can use various tools to gather users when we find an LDAP anonymous bind. Some examples include [windapsearch](https://github.com/ropnop/windapsearch) and [ldapsearch](https://linux.die.net/man/1/ldapsearch).
#### Using ldapsearch
```shell-session
AnuragTaparia@htb[/htb]$ ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "
```
#### Using windapsearch
```shell-session
AnuragTaparia@htb[/htb]$ ./windapsearch.py --dc-ip 172.16.5.5 -u "" -U
```

## Enumerating Users with Kerbrute
- This tool uses [Kerberos Pre-Authentication](https://ldapwiki.com/wiki/Wiki.jsp?page=Kerberos%20Pre-Authentication), which is a much faster and potentially stealthier way to perform password spraying. 
- This method does not generate Windows event ID [4625: An account failed to log on](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625), or a logon failure which is often monitored for. 
- The tool sends TGT requests to the domain controller without Kerberos Pre-Authentication to perform username enumeration. If the KDC responds with the error `PRINCIPAL UNKNOWN`, the username is invalid. Whenever the KDC prompts for Kerberos Pre-Authentication, this signals that the username exists, and the tool will mark it as valid. This method of username enumeration does not cause logon failures and will not lock out accounts. 
- However, once we have a list of valid users and switch gears to use this tool for password spraying, failed Kerberos Pre-Authentication attempts will count towards an account's failed login accounts and can lead to account lockout, so we still must be careful regardless of the method chosen.
```shell-session
AnuragTaparia@htb[/htb]$  kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt 
```

- We've checked over 48,000 usernames in just over 12 seconds and discovered 50+ valid ones. Using Kerbrute for username enumeration will generate event ID [4768: A Kerberos authentication ticket (TGT) was requested](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4768). 
- This will only be triggered if [Kerberos event logging](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/enable-kerberos-event-logging) is enabled via Group Policy. Defenders can tune their SIEM tools to look for an influx of this event ID, which may indicate an attack. 
- If we are successful with this method during a penetration test, this can be an excellent recommendation to add to our report.

- If we are unable to create a valid username list using any of the methods highlighted above, we could turn back to external information gathering and search for company email addresses or use a tool such as [linkedin2username](https://github.com/initstring/linkedin2username) to mash up possible usernames from a company's LinkedIn page.

## Credentialed Enumeration to Build our User List
- With valid credentials, we can use any of the tools stated previously to build a user list. A quick and easy way is using CrackMapExec.
#### Using CrackMapExec with Valid Credentials
```shell-session
AnuragTaparia@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u htb-student.txt -p Academy_student_AD! --users
```
