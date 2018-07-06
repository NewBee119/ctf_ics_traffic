#!/usr/bin/python
#coding:utf-8
import dpkt
import sys

def middler_check(pcap):
    counts = 0
    tcp_tmp = ''  
    for (ts,buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                #print('Non IP Packet type not supported %s' % eth.data.__class__.__name__)
                continue
            ip = eth.data
            if not isinstance(ip.data, dpkt.tcp.TCP):
                #print "Not tcp Packet" 
                continue                     
            tcp = ip.data
            if counts == 0:
                tcp_tmp = tcp
                counts = 1
                continue
            if tcp.flags == tcp_tmp.flags == 0x18:

                if tcp.seq == tcp_tmp.seq and tcp.ack ==tcp_tmp.ack:
                    #print "repeat packets..."
                    if tcp.data != tcp_tmp.data:
                        print "original packets>>%s" % tcp_tmp.data.encode('hex')
                        print "original packet length:%d" % len(tcp_tmp.data)
                        print "modified packets>>%s" % tcp.data.encode('hex')
                        print "modified packet length:%d" % len(tcp.data)
            
            tcp_tmp = tcp       
        except Exception,err:
            print "[error] %s" % err 
    
if __name__ == '__main__':
    if len(sys.argv) != 2:
        print "usage: python check_middler.py pcapfile"
    try:
        f = open(sys.argv[1])
        pcap = dpkt.pcapng.Reader(f)
    except:
        print "it is not pcapng format..."
        f.close()
        f = open(sys.argv[1])
        pcap = dpkt.pcap.Reader(f)            
    middler_check(pcap)
    f.close()
