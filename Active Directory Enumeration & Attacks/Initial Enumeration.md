# External Recon and Enumeration Principles
Before kicking off any pentest, it can be beneficial to perform `external reconnaissance` of your target. This can serve many different functions, such as:

- Validating information provided to you in the scoping document from the client
- Ensuring you are taking actions against the appropriate scope when working remotely
- Looking for any information that is publicly accessible that can affect the outcome of your test, such as leaked credentials
## What Are We Looking For?
The table below highlights the "`What`" in what we would be searching for during this phase of our engagement.

|**Data Point**|**Description**|
|---|---|
|`IP Space`|Valid ASN for our target, netblocks in use for the organization's public-facing infrastructure, cloud presence and the hosting providers, DNS record entries, etc.|
|`Domain Information`|Based on IP data, DNS, and site registrations. Who administers the domain? Are there any subdomains tied to our target? Are there any publicly accessible domain services present? (Mailservers, DNS, Websites, VPN portals, etc.) Can we determine what kind of defenses are in place? (SIEM, AV, IPS/IDS in use, etc.)|
|`Schema Format`|Can we discover the organization's email accounts, AD usernames, and even password policies? Anything that will give us information we can use to build a valid username list to test external-facing services for password spraying, credential stuffing, brute forcing, etc.|
|`Data Disclosures`|For data disclosures we will be looking for publicly accessible files ( .pdf, .ppt, .docx, .xlsx, etc. ) for any information that helps shed light on the target. For example, any published files that contain `intranet` site listings, user metadata, shares, or other critical software or hardware in the environment (credentials pushed to a public GitHub repo, the internal AD username format in the metadata of a PDF, for example.)|
|`Breach Data`|Any publicly released usernames, passwords, or other critical information that can help an attacker gain a foothold.|

We have addressed the `why` and `what` of external reconnaissance; let's dive into the `where` and `how`.

## Where Are We Looking?
The table below lists a few potential resources and examples that can be used.

| **Resource**                     | **Examples**                                                                                                                                                                                                                                                                                                                                                                                                                             |
| -------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ASN / IP registrars`            | [IANA](https://www.iana.org/), [arin](https://www.arin.net/) for searching the Americas, [RIPE](https://www.ripe.net/) for searching in Europe, [BGP Toolkit](https://bgp.he.net/)                                                                                                                                                                                                                                                       |
| `Domain Registrars & DNS`        | [Domaintools](https://www.domaintools.com/), [PTRArchive](http://ptrarchive.com/), [ICANN](https://lookup.icann.org/lookup), manual DNS record requests against the domain in question or against well known DNS servers, such as `8.8.8.8`.                                                                                                                                                                                             |
| `Social Media`                   | Searching Linkedin, Twitter, Facebook, your region's major social media sites, news articles, and any relevant info you can find about the organization.                                                                                                                                                                                                                                                                                 |
| `Public-Facing Company Websites` | Often, the public website for a corporation will have relevant info embedded. News articles, embedded documents, and the "About Us" and "Contact Us" pages can also be gold mines.                                                                                                                                                                                                                                                       |
| `Cloud & Dev Storage Spaces`     | [GitHub](https://github.com/), [AWS S3 buckets & Azure Blog storage containers](https://grayhatwarfare.com/), [Google searches using "Dorks"](https://www.exploit-db.com/google-hacking-database)                                                                                                                                                                                                                                        |
| `Breach Data Sources`            | [HaveIBeenPwned](https://haveibeenpwned.com/) to determine if any corporate email accounts appear in public breach data, [Dehashed](https://www.dehashed.com/) to search for corporate emails with cleartext passwords or hashes we can try to crack offline. We can then try these passwords against any exposed login portals (Citrix, RDS, OWA, 0365, VPN, VMware Horizon, custom applications, etc.) that may use AD authentication. |
# Initial Enumeration of the Domain

Below are some of the key data points that we should be looking for at this time and noting down into our notetaking tool of choice and saving scan/tool output to files whenever possible.
#### Key Data Points

| **Data Point**                  | **Description**                                                                                                                 |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `AD Users`                      | We are trying to enumerate valid user accounts we can target for password spraying.                                             |
| `AD Joined Computers`           | Key Computers include Domain Controllers, file servers, SQL servers, web servers, Exchange mail servers, database servers, etc. |
| `Key Services`                  | Kerberos, NetBIOS, LDAP, DNS                                                                                                    |
| `Vulnerable Hosts and Services` | Anything that can be a quick win. ( a.k.a an easy host to exploit and gain a foothold)                                          |
## TTPs
- We will start with `passive` identification of any hosts in the network, followed by `active` validation of the results to find out more about each host (what services are running, names, potential vulnerabilities, etc.).
-  Once we know what hosts exist, we can proceed with probing those hosts, looking for any interesting data we can glean from them. 
- After we have accomplished these tasks, we should stop and regroup and look at what info we have.
- At this time, we'll hopefully have a set of credentials or a user account to target for a foothold onto a domain-joined host or have the ability to begin credentialed enumeration from our Linux attack host.
- Let's look at a few tools and techniques to help us with this enumeration.
### Identifying Hosts
- First, let's take some time to listen to the network and see what's going on. We can use `Wireshark` and `TCPDump` to "put our ear to the wire" and see what hosts and types of network traffic we can capture.  This is particularly helpful if the assessment approach is "black box."
- We can notice some [ARP](https://en.wikipedia.org/wiki/Address_Resolution_Protocol) requests and replies, [MDNS](https://en.wikipedia.org/wiki/Multicast_DNS), and other basic [layer two](https://www.juniper.net/documentation/us/en/software/junos/multicast-l2/topics/topic-map/layer-2-understanding.html) packets (since we are on a switched network, we are limited to the current broadcast domain).
#### Start Wireshark on ea-attack01
```shell-session
┌─[htb-student@ea-attack01]─[~]
└──╼ $sudo -E wireshark
```

- If we are on a host without a GUI (which is typical), we can use [tcpdump](https://linux.die.net/man/8/tcpdump), [net-creds](https://github.com/DanMcInerney/net-creds), and [NetMiner](https://www.netminer.com/en/product/netminer.php), etc., to perform the same functions. We can also use tcpdump to save a capture to a .pcap file, transfer it to another host, and open it in Wireshark.
#### Tcpdump Output
```shell-session
AnuragTaparia@htb[/htb]$ sudo tcpdump -i ens224 
```

- Depending on the host you are on, you may already have a network monitoring tool built-in, such as `pktmon.exe`, which was added to all editions of Windows 10. 

```
As a note for testing, it's always a good idea to save the PCAP traffic you capture. You can review it again later to look for more hints, and it makes for great additional information to include while writing your reports.
```

- Our first look at network traffic pointed us to a couple of hosts via `MDNS` and `ARP`. Now let's utilize a tool called `Responder` to analyze network traffic and determine if anything else in the domain pops up.
- [Responder](https://github.com/lgandx/Responder-Windows) is a tool built to listen, analyze, and poison `LLMNR`, `NBT-NS`, and `MDNS` requests and responses.
- This time we will passively listen to the network and not send any poisoned packets. We'll cover this tool more in-depth in later sections
#### Starting Responder
```bash
sudo responder -I ens224 -A
```


- Our passive checks have given us a few hosts to note down for a more in-depth enumeration. Now let's perform some active checks starting with a quick ICMP sweep of the subnet using `fping`.
- [Fping](https://fping.org/) provides us with a similar capability as the standard ping application in that it utilizes ICMP requests and replies to reach out and interact with a host. 
- Where fping shines is in its ability to issue ICMP packets against a list of multiple hosts at once and its scriptability. 
- Also, it works in a round-robin fashion, querying hosts in a cyclical manner instead of waiting for multiple requests to a single host to return before moving on. 
- These checks will help us determine if anything else is active on the internal network. ICMP is not a one-stop-shop, but it is an easy way to get an initial idea of what exists. Other open ports and active protocols may point to new hosts for later targeting.
#### FPing Active Checks
- Here we'll start `fping` with a few flags: 
	- `a` to show targets that are alive, 
	- `s` to print stats at the end of the scan, 
	- `g` to generate a target list from the CIDR network, and 
	- `q` to not show per-target results.

```shell-session
AnuragTaparia@htb[/htb]$ fping -asgq 172.16.5.0/23
```
- The command above validates which hosts are active in the `/23` network and does it quietly instead of spamming the terminal with results for each IP in the target list.

#### Nmap Scanning
- Now that we have a list of active hosts within our network, we can enumerate those hosts further. 
- We are looking to determine what services each host is running, identify critical hosts such as `Domain Controllers` and `web servers`, and identify potentially vulnerable hosts to probe later. 
- With our focus on AD, after doing a broad sweep, it would be wise of us to focus on standard protocols typically seen accompanying AD services, such as DNS, SMB, LDAP, and Kerberos name a few.
```bash
sudo nmap -v -A -iL hosts.txt -oN /home/htb-student/Documents/host-enum
```
- The [-A (Aggressive scan options)](https://nmap.org/book/man-misc-options.html) scan will perform several functions. One of the most important is a quick enumeration of well-known ports to include web services, domain services, etc. 
- For our hosts.txt file, some of our results from Responder and fping overlapped (we found the name and IP address), so to keep it simple, just the IP address was fed into hosts.txt for the scan.
- As weird as it sounds to have hosts running legacy software or end-of-life operating systems, it is still common in large enterprise environments. 
- You will often have some process or equipment such as a production line or the HVAC built on the older OS and has been in place for a long time. Taking equipment like that offline is costly and can hurt an organization, so legacy hosts are often left in place. 
- They will likely try to build a hard outer shell of Firewalls, IDS/IPS, and other monitoring and protection solutions around those systems. If you can find your way into one, it is a big deal and can be a quick and easy foothold. 
```
Before exploiting legacy systems, however, we should alert our client and get their approval in writing in case an attack results in system instability or brings a service or the host down. They may prefer that we just observe, report, and move on without actively exploiting the system.
```
- Be sure to use the `-oA` flag as a best practice when performing Nmap scans. This will ensure that we have our scan results in several formats for logging purposes and formats that can be manipulated and fed into other tools.

## Identifying Users
 - If our client does not provide us with a user to start testing with (which is often the case), we will need to find a way to establish a foothold in the domain by either obtaining clear text credentials or an NTLM password hash for a user, a SYSTEM shell on a domain-joined host, or a shell in the context of a domain user account. 
 - Obtaining a valid user with credentials is critical in the early stages of an internal penetration test. This access (even at the lowest level) opens up many opportunities to perform enumeration and even attacks. 
 - Let's look at one way we can start gathering a list of valid users in a domain to use later in our assessment.
### Kerbrute - Internal AD Username Enumeration
- [Kerbrute](https://github.com/ropnop/kerbrute) can be a stealthier option for domain account enumeration. It takes advantage of the fact that Kerberos pre-authentication failures often will not trigger logs or alerts.
-  We will use Kerbrute in conjunction with the `jsmith.txt` or `jsmith2.txt` user lists from [Insidetrust](https://github.com/insidetrust/statistically-likely-usernames). This repository contains many different user lists that can be extremely useful when attempting to enumerate users when starting from an unauthenticated perspective.
#### Enumerating Users with Kerbrute
```shell-session
AnuragTaparia@htb[/htb]$ kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o valid_ad_users
```

## Identifying Potential Vulnerabilities
- The [local system](https://docs.microsoft.com/en-us/windows/win32/services/localsystem-account) account `NT AUTHORITY\SYSTEM` is a built-in account in Windows operating systems. It has the highest level of access in the OS and is used to run most Windows services.
- It is also very common for third-party services to run in the context of this account by default.
- A `SYSTEM` account on a `domain-joined` host will be able to enumerate Active Directory by impersonating the computer account, which is essentially just another kind of user account. Having SYSTEM-level access within a domain environment is nearly equivalent to having a domain user account.
- By gaining SYSTEM-level access on a domain-joined host, you will be able to perform actions such as, but not limited to:
	- Enumerate the domain using built-in tools or offensive tools such as BloodHound and PowerView.
	- Perform Kerberoasting / ASREPRoasting attacks within the same domain.
	- Run tools such as Inveigh to gather Net-NTLMv2 hashes or perform SMB relay attacks.
	- Perform token impersonation to hijack a privileged domain user account.
	- Carry out ACL attacks.

