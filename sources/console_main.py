from concurrent.futures import *
import threading
import socket
import datetime
import struct
import concurrent
# CONSOLE
class Console():
    
    def __init__(self, master=None, handler=None, cfgd=None):
        self.treeview = False
        self.cfgs=cfgd
        self.dumpfile=None
        self.filename=None
        self.console=False
        self.fileiolock = threading.RLock()

        if (self.cfgs['TTL'] !='' and self.cfgs['TTL'] !='\n') :
            print('TTL Set:',self.cfgs['TTL'], end='')
            self.ttl = self.cfgs['TTL']

        if ('CONSOLE' in self.cfgs) :
            print('CONSOLE Set:',self.cfgs['CONSOLE'], end='')
            self.console = True

        if (self.cfgs['DUMP'] !='' and self.cfgs['DUMP'] !='\n') :
                self.filename = self.cfgs['DUMP'].replace('\n','') + str(int(datetime.datetime.timestamp(datetime.datetime.now()))) + ".csv"
                self.dumpfile = open(self.filename, mode='w')
                print('Dump File Set:',self.filename)
      
        print("Python IPScanner version 2.2 Console")        
        self.ip0 = Console.inet4toint(self.cfgs['IP1'])
        self.ip1 = Console.inet4toint(self.cfgs['IP2'])
        # reverse conversion from integers
        self.ip0s = Console.inttoinet4(self.ip0)
        self.ip1s = Console.inttoinet4(self.ip1)

        # window setup

        self.handler = handler
    def inet4toint(ip): # string to integer
        try:
            (x,) = struct.unpack("!L", socket.inet_aton(ip))
            return x
        except OSError as e:
            print(e)
            exit()

    def inttoinet4(ip): # integer to string
        return socket.inet_ntoa(struct.pack ("!L", ip))
    
    def genaddr_classless(ip1, ip2): # classless or explicit range
        return [ ip for ip in range(min(ip1,ip2), max(ip1,ip2)) ]
    
    def IPScanner(handler, ip, ttl, file, lock, console):
        ping_result = handler.do_ping(ip, ttl)
        # Future function for actual IP scanning task
        # for simplicity, screen and file I/O uses the same lock here
        # Console print thread
        #t = PrintThread(ping_result, lock)
        #t.start()
        if (file is not None):
            # Writing .csv file thread if DUMP is not None from ipscan2.cfg  file
            d = DumpFileThread(file, ping_result, lock)
            d.start()
        return ping_result

    def ip_scan(self):
        print("If you won't to change IPs press ENTER")
        in1 = input("Current IP1:{} New? ".format(self.cfgs['IP1'].replace('\n',''))) 
        in2 = input("Current IP2:{} New? ".format(self.cfgs['IP2'].replace('\n',''))) 
        ip_1 = self.cfgs['IP1'] if in1 == '' else in1
        ip_2 = self.cfgs['IP2'] if in2 == '' else in2
        ips = Console.genaddr_classless(Console.inet4toint(ip_1),
                                    Console.inet4toint(ip_2))
        ips_converted = [Console.inttoinet4(ip) for ip in ips]
        futs = []
        executor = ThreadPoolExecutor (max_workers=64)
        results = dict()
        ping_result = []
        # send promises to future executor
        with executor:
            futs = [ executor.submit(Console.IPScanner, self.handler, ip, self.ttl, self.dumpfile, self.fileiolock,True) for ip in ips_converted ]
        # get results as completed
        for ex in concurrent.futures.as_completed(futs):
            ping_result = ex.result()
            if ping_result is None: break
            results[Console.inet4toint(ping_result['ip'])] = (ping_result['on'],
                                                      ping_result['avg_time']/1000)
        # ip to integer and back, again
        for host in sorted(results):
            tmp = Console.inttoinet4(host)
            tmp += (": \x1b[92mAlive\x1b[0m" if results[host][0] else ": \x1b[91mDead\x1b[0m") 
            tmp += (("(" + str(results[host][1]) + "ms)") if results[host][0]
                                                          else "") 
            print(tmp)
            
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