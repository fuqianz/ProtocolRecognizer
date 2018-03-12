#!/usr/bin/env python2
from scapy.all import *
import sys
import os
import datetime
import matplotlib.pyplot as plt

if __name__ == "__main__":
    if not len(sys.argv) == 2:
        print 'Usage: ./assign_labels.py delta-time'
        sys.exit()

    files = os.listdir(sys.argv[1])
    for f in files :
        if f.find("delta_times") < 0 :
            continue

        delta_list = []

        fe = open(sys.argv[1]+"./"+f,'r')
        delta_list = fe.read().strip().split('\n')

        delta_list = [float(x.strip()) for x in delta_list]

        plt.ion()
        plt.hist(delta_list,800,(0,0.0004))
        plt.title("Interpacket Delay Histogram")
        plt.xlabel("Time")
        plt.ylabel("Frequency")
        plt.savefig(f.replace("txt","pdf"))       
        '''
        rsp = ''
        lines = []
        while True:
            rsp = raw_input('Enter value (Q to stop)\n> ')
            if rsp.upper() == 'Q':
                break

            val = float(rsp)
            lines.append(val)
            lines.sort()

            for l in lines:
                plt.axvline(x=l,color='r')

        ranges = [0] + lines + [max(delta_list)]

        with open('mapping.txt','w') as f:
            idx = 0
            while idx + 1 < len(ranges):
                f.write('%s,%s;%s\n' % (str(ranges[idx]),str(ranges[idx+1]),chr(idx+97)))
                idx += 1
        '''
