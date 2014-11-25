#!/usr/bin/env python

# Part of the sniffMyPackets framework by @catalyst256
# Code for uploading pcap file into database
# Code taken from https://github.com/thepacketgeek/cloud-pcap by Mat Wood @thepacketgeek

import dbconnect
import pyshark
import uuid


def load_packets(pcap):
    sessid = str(uuid.uuid4()).replace('-', '')
    cap = pyshark.FileCapture(pcap)
    cap.load_packets(timeout=10)
    details = {'Session': sessid, 'Details': {'packets': []}}

    def decode_packet(packet):
        pkt_details = packet.pretty_print()
        # pkt_details = dict(number=packet.no, length=packet.length, time=packet.time)
        # pkt_details['src_ip'] = packet.source
        # pkt_details['dst_ip'] = packet.destination
        # pkt_details['protocol'] = packet.protocol
        # pkt_details['desc'] = packet.info
        details['Details']['packets'].append(pkt_details)
    try:
        cap.apply_on_packets(decode_packet)
    except Exception as e:
        return str(e)
    return details


def mongo_load(pcap):
    x = load_packets(pcap)
    d = dbconnect.mongo_connect()
    collect = d['summary']
    collect.insert(x)


if __name__ == '__main__':
    pcap = '/Users/amaxwell/pcaps/skype1.pcap'
    mongo_load(pcap)
