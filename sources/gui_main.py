#!/usr/bin/env python3
# requires superuser privileges
# EA 2015 Ege University
# Updated by AME 2022, 2024
# readfromconffile() ipscan.cfg -> ipscan2.cfg

from ipscan2 import *
from concurrent.futures import *
import threading
import tkinter
import tkinter.ttk
import tkinter.scrolledtext
import datetime


class IPScannerApp(tkinter.Frame):
    
    def __init__(self, master=None, handler=None, cfgd=None):
        tkinter.Frame.__init__(self, master)
        self.master.geometry("800x600")
        self.treeview = False
        self.cfgs=cfgd
        self.dumpfile=None
        self.filename=None
        self.console=False
        self.fileiolock = threading.RLock()

        if (self.cfgs['TTL'] !='' and self.cfgs['TTL'] !='\n') :
            print('TTL Set:',self.cfgs['TTL'], end='')
            ttl = self.cfgs['TTL']

        if ('CONSOLE' in self.cfgs) :
            print('CONSOLE Set:',self.cfgs['CONSOLE'], end='')
            self.console = True

        if (self.cfgs['DUMP'] !='' and self.cfgs['DUMP'] !='\n') :
                self.filename = self.cfgs['DUMP'].replace('\n','') + str(int(datetime.datetime.timestamp(datetime.datetime.now()))) + ".csv"
                self.dumpfile = open(self.filename, mode='w')
                print('Dump File Set:',self.filename)

      
        self.resultsbox = tkinter.scrolledtext.ScrolledText(self, state=tkinter.DISABLED, wrap = tkinter.WORD,  
                                      width = 80,  
                                      height = 25,  
                                      font = ("Consolas", 
                                              15))
        ip0 = inet4toint(self.cfgs['IP1'])
        if (self.cfgs['IP2'] is not None):
            ip1 = inet4toint(self.cfgs['IP2'])
        # reverse conversion from integers
        ip0 = inttoinet4(ip0)
        ip1 = inttoinet4(ip1)
        print("Python IPScanner version 2.1")
        self.master.title("IP Scanner using ICMP")
        # window setup
        self.fname = tkinter.StringVar(self, self.filename)
        self.ttl = tkinter.IntVar(self, ttl)
        self.wait = tkinter.Label(self, text="")
        self.parm = tkinter.Label(self, text="")
        self.ip0str = tkinter.StringVar(self, ip0)
        if ip1:
            self.ip1str = tkinter.StringVar(self, ip1)
        else: 
            self.ip1str = tkinter.StringVar(self, "")
        self.ip0 = tkinter.Entry(textvariable=self.ip0str)
        self.ip1 = tkinter.Entry(textvariable=self.ip1str)
        self.scan_button = tkinter.Button(self, text="Scan", command=self.ip_scan)
        self.ip0.pack(anchor=tkinter.N)
        self.ip1.pack(anchor=tkinter.N)
        self.scan_button.pack(anchor=tkinter.S)
        self.resultsbox.pack(anchor=tkinter.S)
        self.pack()
        self.handler = handler

    def ip_scan(self):
        self.resultsbox.delete("1.0",tkinter.END)
        ttl = self.ttl.get()
        if self.ip1str.get() != "":
            ips = genaddr_classless(inet4toint(self.ip0str.get()),
                                    inet4toint(self.ip1str.get()))
        else:
            ips = genlistofipaddrs(inet4toint(self.ip0str.get()), 8)
        ips_converted = [inttoinet4(ip) for ip in ips]
        futs = []
        self.wait['text'] = "Wait..."
        self.wait.pack()
        flbl = ""
        if self.fname.get() != '': flbl = " File: " + self.fname.get()
        self.parm['text'] = " ICMP with TTL="+str(self.ttl.get())+ flbl
        self.parm.pack()
        self.update()
        executor = ThreadPoolExecutor (max_workers=ThreadLimit)
        results = dict()
        ping_result = []
        # send promises to future executor
        with executor:
            futs = [ executor.submit(IPScanner, self.handler, ip, ttl, self.dumpfile, self.fileiolock,self.console) for ip in ips_converted ]
        # get results as completed
        for ex in concurrent.futures.as_completed(futs):
            ping_result = ex.result()
            if ping_result is None: break
            results[inet4toint(ping_result['ip'])] = (ping_result['on'],
                                                      ping_result['avg_time']/1000)
        # ip to integer and back, again
        for host in sorted(results):
            tmp = inttoinet4(host)
            tmp += (": alive" if results[host][0] else ": dead") 
            tmp += (("(" + str(results[host][1]) + "ms)") if results[host][0]
                                                          else "") + "\n"
            self.resultsbox.configure(state=tkinter.NORMAL)
            self.resultsbox.insert(tkinter.END,bytes(tmp, 'utf-8'))
            self.resultsbox.configure(state=tkinter.DISABLED)
        self.wait['text']="All completed"
        self.resultsbox.configure(state=tkinter.NORMAL)
        self.resultsbox.pack()
        self.pack()
        self.update()
