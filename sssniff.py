#! /usr/bin/env python

from scipy.stats import entropy
from scapy.all import *
import numpy as np
import dpkt

def conn(ip1, ip2, port1, port2):
	swap = False

	if ip1 > ip2:
		ip1, ip2 = ip2, ip1
		port1, port2 = port2, port1
		swap = True

	if ip1 == ip2 and port1 > port2:
		port1, port2 = port2, port1
		swap = True

	return (ip1, ip2, port1, port2), swap

def dist(str):
	p = np.zeros(256)
	for i in str:
		p[ord(i)] += 1
	return p

score = {}
blocked = {}
thres = 16
sample = 0
limit = 100000
mtu = 1600

def add_score(c, x):
	if blocked.has_key(c):
		return
	if not score.has_key(c):
		score[c] = x
	else:
		score[c] += x
	if score[c] >= thres:
                print "detected:", c
		blocked[c] = True
        print "conn:", c, "score", score[c]

def add(c, x):
	add_score((c[0], c[2]), x)
	add_score((c[1], c[3]), x)

track = {}
def sniffer(pkt):
        global sample
        if sample > limit:
            score.clear()
            track.clear()
            sample = 0
        sample += 1

	ip = pkt.payload
	tcp = ip.payload
	c, s = conn(ip.src, ip.dst, tcp.sport, tcp.dport)

	if tcp.flags & dpkt.tcp.TH_SYN != 0:
		track[c] = []
	if not track.has_key(c):
		return

	if tcp.flags & dpkt.tcp.TH_FIN != 0 or tcp.flags & dpkt.tcp.TH_RST != 0:
		del track[c]
		return

        # SS Original
	if tcp.flags & dpkt.tcp.TH_PUSH != 0:
		track[c].append((entropy(dist(str(tcp.payload))), s))
		if len(track[c]) >= 4:
			if track[c][0][0] > 4.8 or \
			   (track[c][0][0] > 4.4 and track[c][1][0] > 4.2) or \
			   (track[c][0][0] > 4.2 and track[c][2][0] > 4.2 and \
				track[c][0][1] == track[c][2][1]) or \
			   track[c][0][1] == track[c][1][1]:
				add(c, 1)
			else:
				add(c, -1)
			del track[c]

len_dist = {}
len_count = {}
def ssr_sniffer(pkt):
        global sample
        if sample > limit:
            score.clear()
            len_dist.clear()
            len_count.clear()
            sample = 0
        sample += 1

	ip = pkt.payload
	tcp = ip.payload
        c = (ip.src, tcp.sport)

        if not len_count.has_key(c):
                len_count[c] = 0
                len_dist[c] = np.zeros(mtu)

        # SSR
	if tcp.flags & dpkt.tcp.TH_PUSH != 0:
                if len_count[c] <= 128:
                        l = len(tcp.payload) % mtu
                        len_dist[c][l] += 1
                        len_count[c] += 1

                if len_count[c] == 128:
                        e = entropy(len_dist[c])
                        # print len_count
                        # print len_dist[c]
                        # print c, e
                        if e > 3.2:
				add_score(c, 1)
			else:
				add_score(c, -1)
                        del len_dist[c]
                        del len_count[c]

sniff(filter='tcp', store=False, prn=ssr_sniffer)
