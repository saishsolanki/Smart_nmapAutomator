# Smart_nmapAutomator

A script you can run in the background!
  
![nmapAutomator](https://i.imgur.com/3cMJIPr.gif)
  
## Summary

The main goal for this script is to automate the process of enumeration & recon that is run every time, and instead focus our attention on real pentesting.  

This will ensure two things:  
1. Automate nmap scans. 
2. Always have some recon running in the background. 

Once initial ports are found '*in 5-10 seconds*', we can start manually looking into those ports, and let the rest run in the background with no interaction from our side whatsoever.  

## Features

### Scans
1. **Network** : Shows all live hosts in the host's network (~15 seconds)
2. **Port**    : Shows all open ports (~15 seconds)
3. **Script**  : Runs a script scan on found ports (~5 minutes)
4. **Full**    : Runs a full range port scan, then runs a thorough scan on new ports (~5-10 minutes)
5. **UDP**     : Runs a UDP scan "requires sudo" (~5 minutes)
6. **Vulns**   : Runs CVE scan and nmap Vulns scan on all found ports (~5-15 minutes)
7. **Recon**   : Suggests recon commands, then prompts to automatically run them
8. **All**     : Runs all the scans (~20-30 minutes)

*Note: This is a reconnaissance tool, and it does not perform any exploitation.*

### Automatic Recon & Tool Checks
With the `recon` option, nmapAutomator will automatically recommend and run the best recon tools for each found port.  
If a recommended tool or required wordlist is missing from your machine, nmapAutomator will warn you at startup and suggest how to install it. Missing recon commands will be skipped.

### In-Depth Enumeration
Recon recommendations now include many more tools and protocols, including NetExec for SMB, SSH, LDAP, FTP, WMI, WINRM, RDP, VNC, MSSQL, and NFS. The script also checks for the presence of all these tools and required wordlists before running.

### Runs on any shell
nmapAutomator is 100% POSIX compatible, so it can run on any `sh` shell, and on any unix-based machine (*even a 10 YO router!*), which makes nmapAutomator ideal for lateral movement recon.

If you want to run nmapAutomator on a remote machine, simply download a static nmap binary from [this link](https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/nmap), or with [static-get](https://github.com/minos-org/minos-static), and transfer it to the remote machine. You can then use `-s/--static-nmap` to specify the path to the static nmap binary.

### Remote Mode (Beta)
With the `-r/--remote` flag nmapAutomator will run in Remote Mode, which is designed to run using POSIX shell commands only, without relying on any external tools.  
Remote Mode is still under development. Only following scans currently work with `-r`:
- [x] Network Scan (currently ping only)
- [ ] Port Scan
- [ ] Full Scan
- [ ] UDP Scan
- [ ] Recon Scan

### Output
nmapAutomator saves the output of each type of scan into a separate file, under the output directory.  
The entire script output is also saved, which you can view with `less -r outputDir/nmapAutomator_host_type.txt`, or you can simply `cat` it.

-----
  
## Requirements:

nmapAutomator will check for all required tools and wordlists at startup and warn you if any are missing. Recon commands for missing tools will be skipped.

**Core tools:**
- nmap, host, awk, sed, grep, sort, uniq, cut, tee, cat, printf, mkdir, cd, rm, sleep, stty, jobs, wait, expr

**Recon tools:**
- smtp-user-enum, swaks, dnsrecon, dig, fierce, sslscan, nikto, whatweb, wafw00f, ffuf, gobuster, joomscan, wpscan, droopescan, snmp-check, snmpwalk, onesixtyone, ldapsearch, smbmap, smbclient, crackmapexec, enum4linux, hydra, showmount, odat, NetExec, sqsh

**Wordlists/files:**
- users.txt, passwords.txt, /usr/share/wordlists/metasploit/unix_users.txt, /usr/share/onesixtyone/names, accounts/accounts-multiple.txt

*If any recon recommended tools or wordlists are missing, you will be warned at startup and the relevant recon commands will be skipped.*

**To install ffuf:**
```bash
sudo apt update
sudo apt install ffuf -y
```

**Or Gobuster (v3.0 or higher):**
```bash
sudo apt update
sudo apt install gobuster -y
```

**Other recon tools used within the script include:**
|[nmap Vulners](https://github.com/vulnersCom/nmap-vulners)|[sslscan](https://github.com/rbsec/sslscan)|[nikto](https://github.com/sullo/nikto)|[joomscan](https://github.com/rezasp/joomscan)|[wpscan](https://github.com/wpscanteam/wpscan)|
|:-:|:-:|:-:|:-:|:-:|
|[droopescan](https://github.com/droope/droopescan)|[smbmap](https://github.com/ShawnDEvans/smbmap)|[enum4linux](https://github.com/portcullislabs/enum4linux)|[dnsrecon](https://github.com/darkoperator/dnsrecon)|[odat](https://github.com/quentinhardy/odat)|
|[smtp-user-enum](https://github.com/pentestmonkey/smtp-user-enum)|snmp-check|snmpwalk|ldapsearch|[NetExec](https://github.com/Pennyw0rth/NetExec)|

Most of these should be installed by default in [Parrot OS](https://www.parrotsec.org) and [Kali Linux](https://www.kali.org).  
*If any recon recommended tools or wordlists are found to be missing, they will be automatically omitted, and the user will be notified.*

## Installation:
```bash
git clone https://github.com/21y4d/nmapAutomator.git
sudo ln -s $(pwd)/nmapAutomator/nmapAutomator.sh /usr/local/bin/
```

-----

## Usage:
```
./nmapAutomator.sh -h
Usage: nmapAutomator.sh -H/--host <TARGET-IP> -t/--type <TYPE>
Optional: [-r/--remote <REMOTE MODE>] [-d/--dns <DNS SERVER>] [-o/--output <OUTPUT DIRECTORY>] [-s/--static-nmap <STATIC NMAP PATH>]

Scan Types:
	Network : Shows all live hosts in the host's network (~15 seconds)
	Port    : Shows all open ports (~15 seconds)
	Script  : Runs a script scan on found ports (~5 minutes)
	Full    : Runs a full range port scan, then runs a thorough scan on new ports (~5-10 minutes)
	UDP     : Runs a UDP scan "requires sudo" (~5 minutes)
	Vulns   : Runs CVE scan and nmap Vulns scan on all found ports (~5-15 minutes)
	Recon   : Suggests recon commands, then prompts to automatically run them
	All     : Runs all the scans (~20-30 minutes)
```

**Example scans**:
```
./nmapAutomator.sh --host 10.1.1.1 --type All
./nmapAutomator.sh -H 10.1.1.1 -t Basic
./nmapAutomator.sh -H academy.htb -t Recon -d 1.1.1.1
./nmapAutomator.sh -H 10.10.10.10 -t network -s ./nmap
```

------

## Additional Features
- Checks for all required tools and wordlists at startup and warns if any are missing.
- Configurable parallelism for ping jobs via `MAX_PING_JOBS` environment variable (default: 25).
- Checks exit codes for nmap and recon tools, warning if a scan fails.
- Recon recommendations now include NetExec and many more protocols.

## Upcoming Features


**Feel free to send your pull requests :)**  
*For any pull requests, please try to follow these [Contributing Guidelines](CONTRIBUTING.md).*
