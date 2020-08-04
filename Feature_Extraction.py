from scapy.all import *

def flows_from_pcap(filePath) :
    flows = {}
    fpcap = rdpcap(filePath)
    c = 0
    i = 0
    for pkt in fpcap :
        srcAddr, dstAddr, sport, dport, proto = '', '', '', '', ''
        tcp_close = False
        if 'Ethernet' in pkt :
            eth = pkt['Ethernet']
            if eth.type == 2048 :
                ip = pkt['IP']
                plen = ip.len
                proto = ip.proto
                srcAddr = ip.src
                dstAddr = ip.dst
                if proto == 17 :
                    sport = pkt['UDP'].sport
                    dport = pkt['UDP'].dport
                elif proto == 6 :
                    sport = pkt['TCP'].sport
                    dport = pkt['TCP'].dport
                    tcp_close = ('F' in pkt['TCP'].flags) or ('R' in pkt['TCP'].flags)
        tuple5 = (srcAddr, sport, dstAddr, dport, proto, True)
        if tuple5 in flows :
            # update_features
            flows[tuple5] = c
            if tcp_close :
                temp = flows[tuple5]
                del flows[tuple5]
                tuple5 = (srcAddr, sport, dstAddr, dport, proto, False)
                flows[tuple5] = temp
        else :
            flows[tuple5] = c            # features_list
            c = c + 1
        i = i + 1
    return flows

dic = flows_from_pcap('2020-06-12-traffic-analysis-exercise.pcap')
print(len(dic))
print(dic)