#ipscanner2
Multithreaded IP scanner application which determines IPs dead or alive for given between two IPs for A, B, C network classes.

Written by EA & AME 2015 - 2024
App Types: python

## Features
| Module                    | Feature
| ------                    | -------
|sources/ipscan2.py         | Main application
|sources/gui_main.py        | Grafik User Interface
|sources/pyicmp/__init__.py | pyicmp package definer
|sources/pyicmp/handler.py  | IP ping handler
|sources/pyicmp/ip.py       | IP header string unpacker
|sources/pyicmp/messages.py | ICMP messages handler
|sources/pyicmp/ping.py     | Ping module

| Config file            | Feature
| -----------            | -------
|config/ipscan2.cfg      | Intialized paramaters file
|IP1=www.xxx.yyy.zzz     | First ip (v4) in subnet  
|IP2=www.xxx.yyy.zzz     | Second ip (v4) in subnet 
|TTL=64 # Time To Live   | The amount of time or “hops” that a packet is set to exist inside a network before being discarded by a router
|CONSOLE=                | Replacce "#" ICMP info to output to console
|DUMP=/file_path-        | Create ip dumpfile (.csv)
## Usage/Examples  
~~~python3
cd ../ipscanner2/sources  
$ sudo python3 ipscan2.py

 ~~~

