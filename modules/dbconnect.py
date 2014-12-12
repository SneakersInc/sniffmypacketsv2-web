#!/usr/bin/env python

import os
import pymongo
from ConfigParser import SafeConfigParser

basedir = os.path.abspath(os.path.dirname(__file__))
conf_file = os.path.join(basedir, 'sniffmypackets-web.conf')

conf = SafeConfigParser()
conf.read('../sniffmypackets-web.conf')


def mongo_connect():
    dbs = conf.get('mongodb', 'dbs').strip('\'')
    server = conf.get('mongodb', 'server').strip('\'')
    # port = conf.get('mongodb', 'port').strip('\'')
    port = 27017
    username = conf.get('mongodb', 'username').strip('\'')
    password = conf.get('mongodb', 'username').strip('\'')
    try:
        connection = pymongo.MongoClient(server, port)
        db = connection[dbs]
    except pymongo.errors.ConnectionFailure, e:
        return "Could not connect to MongoDB: %s" % e
    else:
        return db
