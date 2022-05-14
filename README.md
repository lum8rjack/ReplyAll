# ReplyAll
ReplyAll is a LLMNR, NBT-NS and MDNS poisoner written in Go. It is based off of the commonly used [Responder](https://github.com/lgandx/Responder) tool. Unlike Responder, this tool does not have the servers (SMB, MSSQL, etc.) implemented. To use this tool in a similar way as Responder, you should first start Responder (analyze mode) or [Impacket's](https://github.com/SecureAuthCorp/impacket) SMB server. Then run this tool and specify the IP address of the server.

Why use this if it doesn't have the servers implement? This gives you the ability to have a compiled binary that could be dropped on a compromised machine during a pentest or red team engagement. The compromise machine would not need to have Python installed. 


## Installation

You will need Go version 1.9+ and libpcap for Linux/Mac or WinPcap for Windows. Currently, it has only been tested on Linux.

### Go Modules Needed:
- github.com/google/gopacket
- github.com/google/gopacket/layers
- github.com/google/gopacket/pcap


 ### Linux Setup:
```bash
apt install libpcap-dev
git clone https://github.com/lum8rjack/ReplyAll
cd ReplyAll
make linux
```

## Usage

Options
```bash
Usage: ReplyAll -interface eth0
  -A	Analyze mode. This option allows you to see NBT-NS, BROWSER, LLMNR requests without responding. (default false)
  -interface string
    	Network interface to use and listen on
  -ip string
    	IP address to respond with (defaults to the IP of the interface you specify)
```

Running the tool in analyze mode only:
```bash
ReplyAll.bin -interface eth0 -A
```

Running the tool to respond to requests and specify the IP of 10.10.10.25:
```bash
ReplyAll.bin -interface eth0 -ip 10.10.10.25
```

## Future Improvements
- Build and test on ARM and Winddows
- Cross compile / Docker build
- Implement authentication servers (HTTP/SMB/MSSQL/FTP/LDAP)
- Possibly reduce the binary size to make it easier to use on IoT devices


## References
- https://www.cynet.com/attack-techniques-hands-on/llmnr-nbt-ns-poisoning-and-credential-access-using-responder/
- https://www.youtube.com/watch?v=APDnbmTKjgM
- https://www.devdungeon.com/content/packet-capture-injection-and-analysis-gopacket
- https://blog.apnic.net/2021/05/12/programmatically-analyse-packet-captures-with-gopacket/

