#!/usr/bin/env python

# Part of the sniffMyPackets framework by @catalyst256

# Code for importing pcap files into a dynamic map

import pygeoip
import pyshark

home_lat = '51.5081'
home_lng = '0.0761'


def load_packets(pcap):
    ipaddr = []
    try:
        c = pyshark.FileCapture(pcap)
        for pkt in c:
            if pkt[1].layer_name == 'ip':
                x = pkt[1].dst, pkt[1].src, pkt.transport_layer
                if x not in ipaddr:
                    ipaddr.append(x)
            else:
                pass
        return ipaddr
    except Exception as e:
        return str(e)


def find_geo(ipaddr):
    geoip = []
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
        return geoip
    except Exception as e:
        return str(e)


def generatemap():
    pcap = '/Users/amaxwell/pcaps/skype1.pcap'
    x = load_packets(pcap)
    s = find_geo(x)
    return s
