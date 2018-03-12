#!/usr/bin/env python2

import os
from scipy.stats import chisquare

path = "./frequency"

dirs = os.listdir(path)

fres = {}

for d in dirs:
    files = os.listdir(path+'/'+d)
    for f in files:
        print f
        fd = open(path+'/'+d+'/'+f, 'r')
        
        fre = []
        
        for line in fd:
            if line.find('=') > 0 :
                l = line.split('=')[1]
                ll = l.split(' ')[1]
                lll = ll.replace(' ', '').replace('\n','')
                fr = int(lll)
                fre.append(fr+5)
        fres[d+f] = fre
        print d+f, fre
ks = fres.keys()
ks.sort()
for i in range(0, len(ks)) :

    gfp = []
    scp = []

    for j in range(0, len(ks)) :
        if i == j :
            continue
        e1 = ks[i]
        if e1.find("ftp") > 0 :
            e2 = ks[j]
            v2 = chisquare(fres[e2], fres[e1], 0)

            if e2.find("ftp") > 0 :
                gfp.append(v2.statistic)
            else :
                scp.append(v2.statistic)
      
    minv = 1000000000
    cnt1 = 0
    cnt2 = 0
    vno = 0
    for value in scp :
        cnt1 += 1
        if minv > value :
            minv = value
    for value in gfp :
        cnt2 += 1
        if value < minv :
            vno += 1
#    print cnt1, cnt2, 1.0*cnt1/(cnt1+cnt2)
    if cnt1 + cnt2 != 0:
        print 1.0*(cnt2 - vno)/cnt2,1.0*vno/cnt2, 1.0*(vno+cnt1)/(cnt1+cnt2)

#            print e1,e2,v2.statistic
#    print "<==============================>"




