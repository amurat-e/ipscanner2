﻿#!/usr/bin/env python3
# requires superuser privileges
# EA 2015 Ege University
# Updated by AME 2022, 2024
# readfromconffile() ipscan.cfg -> ipscan2.cfg

import sys
import pyicmp, socket, struct
from pyicmp.handler import Handler as icmp
import ctypes, os
import threading, concurrent
from concurrent import futures
from concurrent.futures import *
import gui_main, tkinter
import console_main
 
ThreadLimit = 64


# socket libraries and pyicmp expects IP addresses be strings
def inet4toint(ip): # string to integer
    (x,) = struct.unpack("!L", socket.inet_aton(ip))
    return x

def inttoinet4(ip): # integer to string
    return socket.inet_ntoa(struct.pack ("!L", ip))

def genlistofipaddrs(ip, cls=None): # classful assumption with single IP
    # some sound cls values (24:a-class,20:b-class,16:c-class,8:d-class)
    if cls is None:
        if not ( ip & 0x80000000 ):
            cls = 24
        elif not ( ip & 0xb0000000 ) :
            cls = 16
        else:
            cls = 8 
    # generate list of addresses
    return [( ( ip + i ) & (2 ** 32 -1) ) for i in range(0, (2 ** cls - 1 )) 
            if ( ( ip + i ) & (2 ** 32 -1) ) & 0xff != 0 and 
            ( ( ip + i ) & (2 ** 32 -1) ) & 0xff != 0xff ]

def genaddr_classless(ip1, ip2): # classless or explicit range
    return [ ip for ip in range(min(ip1,ip2), max(ip1,ip2)) ]

def amiadmin(): # sending ICMP messages requires superuser privileges
    try:
        # unix type superuser?
        is_admin = os.getuid() == 0
    except AttributeError:
        # windows type superuser?
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        is_admin = True
    return is_admin

def readfromconffile():
    # config file values will also be defaults for GUI
    env_base = "../config"
    print('ipsscan2.cfg base: ',env_base)
    config = open(env_base+'/ipscan2.cfg')
    # config = open('ipscan.cfg')
    cfgs = config.readlines()
    cfgs = [ cfg for cfg in cfgs if cfg[0]!="#" ]
    cfgd = dict(cc.split('=') for cc in cfgs)
    return cfgd

def main():
    # superuser check
    try:
        if not amiadmin():
            raise PermissionError
        cfgd = readfromconffile()
        if ('CONSOLE' not in cfgd) :
            print(sys.argv[0] + ' is running GUI mode. \nIf you prefer CONSOLE mode, remove the \'#\' at the beginning of the CONSOLE= line in the \'ipscan 2.cfg\' file.')
            TK = tkinter.Tk()
            gui_handle = gui_main.IPScannerApp(master=TK,handler=icmp(0),cfgd=cfgd)
            TK.mainloop()
        else:
            print(sys.argv[0] + ' is running CONSOLE mode. \nIf you prefer GUI mode, put \'#\' at the beginning of CONSOLE= line in \'ipscan2.cfg\' file.')
            console_handle = console_main.Console(handler=icmp(0),cfgd=cfgd)
            console_handle.ip_scan()
            
    except PermissionError as e:
            print ("Needs administrator/root privilege for creating OS Socket.")
            print ("sudo python3 "+sys.argv[0])
            exit()

def IPScanner(handler, ip, ttl, file, lock, console):
    ping_result = handler.do_ping(ip, ttl)
    # Future function for actual IP scanning task
    # for simplicity, screen and file I/O uses the same lock here
    # Console print thread
    if (file is not None):
        # Writing .csv file thread if DUMP is not None from ipscan2.cfg  file
        d = DumpFileThread(file, ping_result, lock)
        d.start()
    return ping_result

class DumpFileThread(threading.Thread):
# this is responsible for outputting dump thread
    result = None
    file = None
    def __init__(self, file, result, lock):
        threading.Thread.__init__(self, name="fileio")
        self.result = result
        self.file = file
        self.lock = lock

    def run(self):
        flag = False # try until succcessful, do at most once
        while not flag:
            with self.lock:
                tmp = str(self.result['ip']+';'+ str(self.result['on']) + ';\"' 
                      + str(self.result['responses']).replace(";", " ") + '"')
                self.file.writelines(tmp + "\n")
                self.file.flush()
                flag = True

if __name__=="__main__": main ()
