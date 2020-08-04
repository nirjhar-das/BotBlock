from scapy.all import *
from scapy.layers.http import *


def create_features(srcPort, dstPort, proto=4, fps=0, byte_size=0, payl=0, time=0, dur=0, incoming=False, http=4):
    features = {}
    features['srcPort'] = srcPort
    features['dstPort'] = dstPort
    if proto == 2 :
        features['proto'] = 2
    elif proto == 6 :
        features['proto'] = 0
    elif proto == 17 :
        features['proto'] = 1
    else :
        features['proto'] = 3
    features['PX'] = 1
    if byte_size <= 62 :
        features['NNP'] = 1
    else :
        features['NNP'] = 0
    if 63 <= byte_size and byte_size <= 400 :
        features['NSP'] = 1
    else :
        features['NSP'] = 0
    features['PSP'] = (features['NSP']/features['PX'])*100
    features['PNP'] = (features['NNP']/features['PX'])*100
    if not incoming :
        features['out'] = 1
        features['in'] = 0
    else :
        features['in'] = 1
        features['out'] = 0
    features['IOPR'] = features['in']/features['out']
    features['dur'] = dur
    features['FPS'] = fps
    features['TBT'] = byte_size
    features['APL'] = payl
    features['PV'] = 0.0
    features['BS'] = features['TBT']/features['dur']
    features['PPS'] = features['PX']/features['dur']
    features['AIT'] = 0
    features['HTTPM'] = {0:0, 1:0, 2:0, 3:0, 4:0}
    features['HTTPM'][http] = 1
    features['time'] = time

    return features
    
    

def update_features(features, nnp=False, nsp=False, incoming=False, byte_size=0, payl=0, time=0, dur=0, http=4):

    features['PX'] = features['PX'] + 1
    if nnp :
        features['NNP'] = features['NNP'] + 1
        features['PNP'] = (features['NNP']/features['PX'])*100
    if nsp :
        features['NSP'] = features['NSP'] + 1
        features['PSP'] = (features['NSP']/features['PX'])*100
    if incoming :
        features['in'] = features['in'] + 1
    else :
        features['out'] = features['out'] + 1
    features['IOPR'] = features['in'] / features['out']
    features['TBT'] = features['TBT'] + byte_size
    av = features['APL']
    sd = features['PV']
    n = features['PX'] - 1
    features['APL'] = ((av * n) + payl)/(n + 1)
    features['PV'] = ((((n-1)*sd**2) + (n * av**2) - ((n + 1)*features['APL']**2) + payl**2)/n)**0.5
    features['dur'] = features['dur'] + 1
    features['BS'] = features['TBT']/features['dur']
    features['PPS'] = features['PX']/features['dur']
    del_t = time - features['time']
    features['time'] = time
    features['AIT'] = ((features['AIT'] * n) + del_t)/ (n + 1)
    features['HTTPM'][http] = features['HTTPM'][http] + 1

    return features
    



def flows_from_pcap(filePath) :
    flows = {}
    fpcap = PcapReader(filePath)
    f_dup = PcapReader(filePath)
    pkt_nxt = next(f_dup)
    c = 0
    i = 0
    for pkt in fpcap :
        dur = 0
        try :
            pkt_nxt = next(f_dup)
            dur = pkt_nxt.time - pkt.time
        except :
            dur = 0.000001

        srcAddr, dstAddr, sport, dport, proto = '', '', 0, 0, 3
        pload, http_meth = 0, 4
        tcp_close = False
        if 'Ethernet' in pkt :
            eth = pkt['Ethernet']
            if eth.type == 2048 :
                ip = pkt['IP']
                proto = ip.proto
                srcAddr = ip.src
                dstAddr = ip.dst
                if proto == 17 :
                    sport = pkt['UDP'].sport
                    dport = pkt['UDP'].dport
                    pload = len(pkt['UDP'].payload)
                elif proto == 6 :
                    sport = pkt['TCP'].sport
                    dport = pkt['TCP'].dport
                    pload = len(pkt['TCP'].payload)
                    if pkt.haslayer('HTTPRequest') :
                        meth = pkt['HTTPRequest'].Method
                        if meth == b'GET' :
                            http_meth = 0
                        elif meth == b'POST' :
                            http_meth = 1
                        elif meth == b'PUT' :
                            http_meth = 2
                        elif meth == b'DELETE' :
                            http_meth = 3
                        else :
                            http_meth = 4
                    tcp_close = ('F' in pkt['TCP'].flags) or ('R' in pkt['TCP'].flags)
        bs = pkt.len + 14
        nnp = pload == 0
        nsp = 63 <= bs and bs <= 400        
        tuple5 = (srcAddr, sport, dstAddr, dport, proto, True)
        tuple5_inv = (dstAddr, dport, srcAddr, sport, proto, True)
        if tuple5 in flows :
            features = flows[tuple5]
            flows[tuple5] = update_features(features, nnp, nsp, incoming=False, byte_size= bs, payl= pload, time = pkt.time, dur= dur, http= http_meth)
            if tcp_close :
                temp = flows[tuple5]
                del flows[tuple5]
                tuple5 = (srcAddr, sport, dstAddr, dport, proto, False)
                flows[tuple5] = temp
        elif tuple5_inv in flows :
            features = flows[tuple5_inv]
            flows[tuple5_inv] = update_features(features, nnp, nsp, incoming=True, byte_size= bs, payl= pload, time = pkt.time, dur= dur, http= http_meth)
            if tcp_close :
                temp = flows[tuple5_inv]
                del flows[tuple5_inv]
                tuple5_inv = (dstAddr, dport, srcAddr, sport, proto, False)
                flows[tuple5_inv] = temp
        else :
            flows[tuple5] = create_features(sport, dport, proto, fps= pload, byte_size= bs, payl= pload, time= pkt.time, dur= dur, incoming= False, http= http_meth)            # features_list
        if i%1000 == 0 :
            print(i, ' packets processed')
        i = i + 1
    
    return flows

dic = flows_from_pcap('2020-06-12-traffic-analysis-exercise.pcap')
print(len(dic))
i = 0
for key in dic :
    if i % 100 == 0:
        print(dic[key])
    i = i + 1