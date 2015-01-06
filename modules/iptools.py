#!/usr/bin/env python

import requests
import socket
import dns.name
import dns.message
import dns.query
import dns.resolver


def ip_lookup(ipaddr):
    url = 'http://www.telize.com/geoip/%s' % ipaddr
    r = requests.get(url)
    if r.status_code == 200:
        return r.json()
    else:
        return 'No Records Found'


def reverse_dns(ipaddr):
    try:
        host = socket.gethostbyaddr(ipaddr)[0]
        return host
    except Exception as e:
        return str(e)


def dns_query(domain):

    nameservers = dns.resolver.query(domain, 'NS')
    for rdata in nameservers:
        print rdata


# target = 'theplanet.com'
# target = 'google.com'
# dns_query(target)