#!/usr/bin/env python3
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
        is_admin = os.getuid() == 0
    except AttributeError:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
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
            #pass 
            
            raise PermissionError
        cfgd = readfromconffile()
        TK = tkinter.Tk()
        gui_handle = gui_main.IPScannerApp(master=TK,handler=icmp(0),cfgd=cfgd)
        TK.mainloop()
    except PermissionError as e:
        print ("Needs administrator/root privilege for creating OS Socket.")
        print ("sudo python3 "+sys.argv[0])
        exit()

def IPScanner(handler, ip, ttl, file, lock, console):

    ping_result = handler.do_ping(ip, ttl)

    # Future function for actual IP scanning task
    # for simplicity, screen and file I/O uses the same lock here
    # Console print thread
    if (console):
        t = PrintThread(ping_result, lock)
        t.start()

    if (file is not None):
        # Writing .csv file thread if DUMP is not None from ipscan2.cfg  file
        d = DumpFileThread(file, ping_result, lock)
        d.start()
    return ping_result

class PrintThread(threading.Thread):
# screen messages
    def __init__(self, res, lock):
        threading.Thread.__init__(self, name="screen")
        self.res = res
        self.lock = lock
    
    def run(self):
        flag = False # try until successful, do at most once
        while not flag: 
            with self.lock:
                stat = '\x1b[92mAlive\x1b[0m' if self.res['on'] else '\x1b[91mDead\x1b[0m'
                respt = str(self.res['avg_time']/1000)+'ms' if self.res['on'] else ''
                print(self.res['ip']+':('+str(self.res['hostname'])+') :'+respt +' -> '+ stat)
                flag = True

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
