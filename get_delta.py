#!/usr/bin/env python2
from scapy.all import *
import sys
import os
import datetime
import matplotlib.pyplot as plt

if __name__ == "__main__":
#    if not len(sys.argv) == 2:
#        print 'Usage: ./plot.py data-file'
#    packets = rdpcap(sys.argv[1])

    file_list = os.listdir('../')

    delta_list = []
    file_list = ['logfile.pcap']
    for f in file_list:
        current_time = 0
        print 'Read packets: ' + f
        packets = rdpcap('../' + f)
        for p in packets:
            if current_time == 0:
                current_time = p.time
            else:
                delta_list.append(p.time - current_time)
                current_time = p.time

    delta_list_str = [str(x) for x in delta_list]
    with open('delta_times.txt', 'w') as doc:
        doc.write('\n'.join(delta_list_str))

    plt.hist(delta_list,1000)
    plt.title("Interpacket Delay Histogram")
    plt.xlabel("Time")
    plt.ylabel("Frequency")
    plt.show()
