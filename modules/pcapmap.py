#!/usr/bin/env python

# Part of the sniffMyPackets framework by @catalyst256

# Code for importing pcap files into a dynamic map

import pygeoip
import pyshark

ipaddr = []
geoip = []
home_lat = '51.5081'
home_lng = '0.0761'

def load_packets(pcap):
    try:
        c = pyshark.FileCapture(pcap)
        for pkt in c:
            if pkt[1].layer_name == 'ip':
                x = pkt[1].dst, pkt[1].src, pkt.transport_layer
                if x not in ipaddr:
                    ipaddr.append(x)
            else:
                pass
    except Exception as e:
        return str(e)


def find_geo():
    try:
        geoipdb = '/Users/amaxwell/Coding/Security/GeoIP/GeoLiteCity.dat'
    except Exception as e:
        return str(e)
    try:
        gi = pygeoip.GeoIP(geoipdb)
        for i in ipaddr:
            if i[2] is not None:
                proto = i[2]
            else:
                proto = 'N/A'
            print proto
            geosrc_lat = ''
            geosrc_lng = ''
            geodst_lat = ''
            geodst_lng = ''
            srcrec = gi.record_by_addr(i[0])
            if srcrec is None:
                geosrc_lat = home_lat
                geosrc_lng = home_lng
            else:
                geosrc_lat = srcrec['latitude']
                geosrc_lng = srcrec['longitude']
            dstrec = gi.record_by_addr(i[1])
            if dstrec is None:
                geodst_lat = home_lat
                geodst_lng = home_lng
            else:
                geodst_lat = dstrec['latitude']
                geodst_lng = dstrec['longitude']
            data = [i[0], geosrc_lat, geosrc_lng, i[1], geodst_lat, geodst_lng, proto]
            geoip.append(data)
    except Exception as e:
        return str(e)


def generatemap():
    pcap = '/Users/amaxwell/pcaps/skype1.pcap'
    load_packets(pcap)
    find_geo()
    print geoip
    return geoip