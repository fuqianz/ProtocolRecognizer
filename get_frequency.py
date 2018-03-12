#!/usr/bin/env python2
from scapy.all import *
import sys
import os
import datetime
import matplotlib.pyplot as plt

if __name__ == "__main__":
    if not len(sys.argv) == 4:
        print 'Usage: ./parse_labels.py delta-time_path mappings protocol'
        sys.exit()

    dtimeofpath = sys.argv[1]
    protocol = sys.argv[3]
    with open(sys.argv[2],'r') as f:
        lines = f.read().strip().split('\n')

    ranges = []
    for l in lines:
        ranges += l.split(';')[0].split(',')

    ranges = [float(x) for x in ranges]
    ranges.sort()
    ranges.pop(0)
    ranges = list(set(ranges))
    ranges.sort()

    file_list = os.listdir(dtimeofpath)
   
    os.system("rm -rf frequency/"+protocol)
    os.system("mkdir -p frequency/"+protocol)

    size =100000
    print len(file_list)    
    for fi in file_list :
        if fi.find('txt') < 0 :
            continue
        print fi
        delta_list = []

        with open(dtimeofpath + '/' + fi,'r') as f:
            delta_list = f.read().strip().split('\n')

        #delta_list = [float(x.strip()) for x in delta_list]
        all_delta_list =[]# [float(x.strip()) for x in delta_list]
   
        for x in delta_list :
            if x != "" :
                all_delta_list.append(float(x.strip()))
        # invalid flows packet 
        if len(all_delta_list) < size :
            continue;

        delta_list = all_delta_list[0:size]
 
        labels = []
        timings = {}
        for idx in range(len(ranges)):
            timings[chr(idx+97)] = []
        for t in delta_list:
            for idx,r in enumerate(ranges):
                if t <= r:
                    labels.append(idx)
                    timings[chr(idx+97)] += [t]
                    break
        
        fw = open('frequency/' + sys.argv[3] + '/' + fi.replace('delta_times',"").replace('.txt',""), 'w+')
        
        fw.write(str(len(labels))+'\n')
        for l in timings.keys():
            tmp = timings[l]
            tmp.sort()
            str_tmp = [str(x) for x in tmp]
            fw.write(l + ' = ' + str(len(tmp)) +' '+ str(float(len(tmp))/float(len(labels)))+'\n')

        fw.close()

