- The most important things to do when landing on a host for the first time is to check our
	- privilege level
	- network connections
	- potential VPN or other remote access software
	- If a host has more than one network adapter, we can likely use it to move to a different network segment
- Pivoting is essentially the idea of moving to other networks through a compromised host to find more targets on different network segments.
- Tunneling, on the other hand, is a subset of pivoting. Tunneling encapsulates network traffic into another protocol and routes traffic through it.
	- Typical applications like VPNs or specialized browsers are just another form of tunneling network traffic.

## Lateral Movement, Pivoting, and Tunneling Compared
#### Lateral Movement
- Lateral movement can be described as a technique used to further our access to additional hosts, applications, and services within a network environment.
- Lateral Movement often enables privilege escalation across hosts
- [Palo Alto Network's Explanation](https://www.paloaltonetworks.com/cyberpedia/what-is-lateral-movement)
- [MITRE's Explanation](https://attack.mitre.org/tactics/TA0008/)
- One practical example of `Lateral Movement` would be:
	- During an assessment, we gained initial access to the target environment and were able to gain control of the local administrator account. We performed a network scan and found three more Windows hosts in the network. We attempted to use the same local administrator credentials, and one of those devices shared the same administrator account. We used the credentials to move laterally to that other device, enabling us to compromise the domain further.
- **Lateral movement** occurs within the same network or domain, aiming to gain broader control.
#### Pivoting
-  Utilizing multiple hosts to cross `network` boundaries you would not usually have access to.
- **Pivoting** involves moving from one network segment to another through a compromised system that provides access to previously unreachable networks.

---

To summarize, we should look at these tactics as separate things. Lateral Movement helps us spread wide within a network, elevating our privileges, while Pivoting allows us to delve deeper into the networks accessing previously unreachable environments.

---

#### Tunneling
- We often find ourselves using various protocols to shuttle traffic in/out of a network where there is a chance of our traffic being detected.
- A **tunnel** is created by encapsulating one protocol within another. For example, using SSH tunneling to encapsulate application traffic (HTTP, SMB, etc.) within SSH.
- Example: SSH Tunneling, VPN
- One practical example of `Tunneling` would be:
	- One way we used Tunneling was to craft our traffic to hide in HTTP and HTTPS. This is a common way we maintained Command and Control (C2) of the hosts we had compromised within a network. We masked our instructions inside GET and POST requests that appeared as normal traffic and, to the untrained eye, would look like a web request or response to any old website. If the packet were formed properly, it would be forwarded to our Control server. If it were not, it would be redirected to another website, potentially throwing off the defender checking it out.

-  In the context of pivoting, we need to be mindful of what networks a host we land on can reach, so documenting as much IP addressing information as possible on an engagement can prove helpful.

