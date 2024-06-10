#ipscanner2
Multithreaded IP scanner application which determines IPs dead or alive for given between two IPs for A, B, C network classes.

Written by EA & AME 2015 - 2024
App Types: python

## Features
sources/ipscan2.py         | Main application
sources/gui_main.py        | Grafik User Interface
sources/pyicmp/__init__.py | pyicmp package definer
sources/pyicmp/handler.py  | IP ping handler
sources/pyicmp/ip.py       | IP header string unpacker
sources/pyicmp/messages.py | ICMP messages handler
sources/pyicmp/ping.py     | Ping module
config/ipscan2.cfg         | Intialized paramaters file
|IP1=155.223.128.1
|IP2=155.223.128.32
|TTL=64 # Time To Live
|CONSOLE=
|DUMP=/Users/alimuratergin/Desktop/ipscan- # create ip dumpfile (.csv)
