# -*- coding: UTF-8 -*-
import dpkt
import socket
import sys
from optparse import OptionParser

def viewflowinfor(pcap):
    countFlowLength = [0]*1000
    flowLength = [0]*1000
    counts = 0
    isFlag = 0
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
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)

            #print ip.len
            if ip.data.dport != 502:
                continue
            if counts == 0:
                flowLength[0] = ip.len
                countFlowLength[0] = 1
                counts = counts + 1
                continue

            for i in range(0, counts):
                if ip.len == flowLength[i]:
                    countFlowLength[i] = countFlowLength[i] + 1
                    isFlag = 1
                    break
                else:
                    isFlag = 0
                    continue

            if i == counts - 1 and isFlag == 0:
                flowLength[counts] = ip.len
                countFlowLength[counts] = 1
                counts = counts + 1

            isFlag = 0
        except Exception,err:
            print "[error] %s" % err 

    for j in range(0, counts):
        print "[+] length: %d, with %d packets" % (flowLength[j], countFlowLength[j])




def filterAflow(pcap, srcip, srcport, dstip, dstport, outputfile):
    pcw = dpkt.pcap.Writer(open(outputfile, 'wb'))
    counts = 0
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
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            
            tcp = ip.data


            if srcip == src and srcport==tcp.sport and dstip == dst and dstport==tcp.dport: 
                pcw.writepkt(eth,ts)
                counts = counts + 1

        except Exception,err:
            print "[error] %s" % err 

    print "the flow saved into %s, wtih %d packets" % (outputfile, counts)
    pcw.close 

def printPcap(pcap):
    flowList = [[] for i in range(1000)]
    counts = 0
    countFlow = [0]*1000
    isFlag = 0
    
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
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            
            tcp = ip.data
            if tcp.dport != 502:
                continue
            if counts == 0 :
                flowList[0].append(src) 
                flowList[0].append(tcp.sport) 
                flowList[0].append(dst) 
                flowList[0].append(tcp.dport)
                counts = counts + 1
                countFlow[0] = 1
                continue
                #print flowList[0][0],flowList[0][1],flowList[0][2],flowList[0][3]

            for i in range(0, counts):
                if flowList[i][0] == src and  flowList[i][1] == tcp.sport and flowList[i][2] == dst and flowList[i][3] == tcp.dport:
                    countFlow[i] = countFlow[i] + 1
                    isFlag = 1
                    break
                else:
                    isFlag = 0
                    continue
            if i == counts - 1 and isFlag == 0:
                flowList[counts].append(src) 
                flowList[counts].append(tcp.sport) 
                flowList[counts].append(dst) 
                flowList[counts].append(tcp.dport)
                countFlow[counts] = 1
                counts = counts + 1 
            isFlag = 0    
        except Exception,err:
            print "[error] %s" % err 
    for j in range(0, counts):
        print "[%d] Src:%s:%d -->Dst:%s:%d  counts: %d "% (j, flowList[j][0], flowList[j][1], flowList[j][2], flowList[j][3], countFlow[j])   
            
def main():
    pcap_path = "./t1.pcapng" '''None'''
    outputfile = "./sampleflow.pcap"
    srcip = None
    srcport = None
    dstip = None
    dstport = None
    parser = OptionParser()  
    parser.add_option(
        "--pcapfile", dest="pcapfile",
        action='store', type='string',
        help="special the pcap file path",
        default=pcap_path
    )

    parser.add_option(
        "--srcip", dest="srcip",
        action='store', type='string',
        help="special the srcip for search, e.x. 10.0.0.4,10.0.0.5",
        default=srcip
    )

    parser.add_option(
        "--srcport", dest="srcport",
        action='store', type='int',
        help="special the srcport for search, e.x. 80,443 ",
        default=srcport                                     
    )

    parser.add_option(
        "--dstip", dest="dstip",
        action='store', type='string',
        help="special the dstip for search, e.x. 10.0.0.4,10.0.0.5",
        default=dstip
    )

    parser.add_option(
        "--dstport", dest="dstport",
        action='store', type='int',
        help="special the dstport for search, e.x. 80,443 ",
    )   

    parser.add_option(
        "--outputfile", dest="outputfile",
        action='store', type='string',
        help="save flow into a pcapfile ",
        default=outputfile                                     
    )

    parser.add_option(
        "-v", "--view", action="store_true", 
        help="view basic flow information",
        dest="view", default=False
    )

    parser.add_option(
        "-f", "--filter", action="store_true", 
        help="filter a flow and save as a pcap",
        dest="filter", default=False
    )

    parser.add_option(
        "-i", "--flowinfor", action="store_true", 
        help="view a flow's imformation",
        dest="flowinfor", default=False
    )
  
    (options, args) = parser.parse_args() 

    '''print options.pcapfile
    print options.outputfile
    print options.srcip
    print options.srcport
    print options.dstip
    print options.dstport'''
    
    if options.pcapfile is None:
        print "please input the pcap file path..."
        sys.exit(0)

    #sys.exit(0)

    try:
        f = open(options.pcapfile)
        pcap = dpkt.pcapng.Reader(f)
    except:
        print "it is not pcapng format..."
        f.close()
        f = open(options.pcapfile)
        pcap = dpkt.pcap.Reader(f)  

    if options.view:
        printPcap(pcap)
        sys.exit(0)

    if options.filter:
        if (options.outputfile and options.srcip and options.srcport and options.dstip and options.dstport) is None:
            print "Make sure do not miss: srcip, srcport, dstip, dstport"
            sys.exit(0)
        else:
            filterAflow(pcap, options.srcip, options.srcport, options.dstip, options.dstport, options.outputfile)
            sys.exit(0)

    if options.flowinfor:
        viewflowinfor(pcap)
        length = input("choose packets length >>")
        f.close

        try:
            f = open(options.pcapfile)
            pcap = dpkt.pcapng.Reader(f)
        except:
            print "it is not pcapng format..."
            f.close()
            f = open(options.pcapfile)
            pcap = dpkt.pcap.Reader(f)  

        fout = open("out_%d.txt"%length, "wb")
        counts = 0 

        pcw = dpkt.pcap.Writer(open('Packets_%d.pcap'%length, 'wb'))
        '''
        tmp1 = 0.0 
        tmp2 = 0.0
        tmp3 = 0.0
        tmp4 = 0.0
        tmp5 = 0.0
        tmp6 = 0.0
        '''

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
                if tcp.dport != 502:   #filter 502 or 102
                    continue              
                if ip.len == length:
                    '''
                    if counts%4 == 0 and counts < 4:
                        print >>fout, ">>%s,  %f" % (tcp.data.encode('hex'), ts)
                        tmp1 = ts
                    if counts%4 == 1 and counts < 4:
                        print >>fout, ">>%s,  %f" % (tcp.data.encode('hex'), ts)
                        tmp2 = ts
                    if counts%4 == 2 and counts < 4:
                        print >>fout, ">>%s,  %f" % (tcp.data.encode('hex'), ts)
                        tmp3 = ts
                    if counts%4 == 3 and counts < 4:
                        print >>fout, ">>%s,  %f" % (tcp.data.encode('hex'), ts)
                        tmp4 = ts
                    
                    if counts%4 == 0 and counts >= 4:
                        print >>fout, ">>%s,  %f,  %f" % (tcp.data.encode('hex'), ts, (ts-tmp1))
                        tmp1 = ts
                    if counts%4 == 1 and counts > 4:
                        print >>fout, ">>%s,  %f,  %f" % (tcp.data.encode('hex'), ts, (ts-tmp2))
                        tmp2 = ts
                    if counts%4 == 2 and counts > 4:
                        print >>fout, ">>%s,  %f,  %f" % (tcp.data.encode('hex'), ts, (ts-tmp3))
                        tmp3 = ts
                    if counts%4 == 3 and counts > 4:
                        print >>fout, ">>%s,  %f,  %f" % (tcp.data.encode('hex'), ts, (ts-tmp4))
                        tmp4 = ts
                    '''
                    print >>fout, ">>%s,  %f" % (tcp.data.encode('hex'), ts)
                    print ">>%s" % tcp.data.encode('hex')
                    counts = counts + 1
                    pcw.writepkt(eth,ts)
            except Exception,err:
                print "[error] %s" % err 

        print "save %d packets information into out_%d.txt" % (counts, length)
        print "save %d packets into packets_%d.pcap" % (counts, length)

        f.close
        fout.close
        pcw.close 
            


if __name__ == '__main__':
    main()
