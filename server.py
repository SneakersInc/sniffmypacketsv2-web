#!/usr/bin/env python

# Part of the sniffMyPackets framework

# API/Web server
import os
from flask.ext.pymongo import PyMongo
from flask import Flask, jsonify, make_response, request, render_template, url_for, redirect, send_from_directory


basedir = os.path.abspath(os.path.dirname(__file__))

ALLOWED_EXTENSIONS = ['pcap', 'pcapng', 'cap']
UPLOAD_FOLDER = os.path.join(basedir, 'static/uploads/')

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MONGO_HOST'] = 'devserver'
app.config['MONGO_PORT'] = 27017
app.config['MONGO_DBNAME'] = 'sniffMyPackets'

mongo = PyMongo(app, config_prefix='MONGO')



@app.route('/pcap/<pcapid>/map', methods=['GET'])
def buildgeomap(pcapid):
    try:
        geo = mongo.db.GEOIP.find({"PCAP ID": pcapid})
        return render_template('pcapgeomap.html', geomap=geo, line=geo)
    except Exception as e:
        return make_response(jsonify({'error': e}))

@app.route('/', methods=['GET'])
def home():
    try:
        pcaps = mongo.db.INDEX.find()
        return render_template('home.html', pcaps=pcaps)
    except Exception as e:
        return make_response(jsonify({'error': e}))

@app.route('/about', methods=['GET'])
def about():
    return render_template('about.html')

@app.route('/pcap/<pcapid>', methods=['GET'])
def pcapsummary(pcapid):
    return render_template('summary.html', id=pcapid)

@app.route('/pcap/<pcapid>/dns', methods=['GET'])
def dnspcapsummary(pcapid):
    try:
        dns = mongo.db.DNS.find({"PCAP ID": pcapid})
        return render_template('dns.html', records=dns)
    except Exception as e:
        return make_response(jsonify({'error': e}))

@app.route('/pcap/dns', methods=['GET'])
def dnssummary():
    try:
        dns = mongo.db.DNS.find()
        return render_template('dns.html', records=dns)
    except Exception as e:
        return make_response(jsonify({'error': e}))

@app.route('/pcap/<pcapid>/http', methods=['GET'])
def httppcapsummary(pcapid):
    try:
        http = mongo.db.HTTP.find({"PCAP ID": pcapid})
        return render_template('http.html', records=http)
    except Exception as e:
        return make_response(jsonify({'error': e}))

@app.route('/pcap/http', methods=['GET'])
def httpsummary():
    try:
        http = mongo.db.HTTP.find()
        return render_template('http.html', records=http)
    except Exception as e:
        return make_response(jsonify({'error': e}))

@app.route('/pcap/<pcapid>/streams', methods=['GET'])
def streampcapsummary(pcapid):
    try:
        http = mongo.db.STREAMS.find({"Parent ID": pcapid})
        return render_template('streams.html', records=http)
    except Exception as e:
        return make_response(jsonify({'error': e}))

@app.route('/pcap/http', methods=['GET'])
def streamsummary():
    try:
        http = mongo.db.STREAMS.find()
        return render_template('streams.html', records=http)
    except Exception as e:
        return make_response(jsonify({'error': e}))

@app.route('/pcap/<pcapid>/geo', methods=['GET'])
def geopcapsummary(pcapid):
    try:
        geo = mongo.db.GEOIP.find({"PCAP ID": pcapid})
        return render_template('geo.html', records=geo)
    except Exception as e:
        return make_response(jsonify({'error': e}))

@app.route('/pcap/geo', methods=['GET'])
def geosummary():
    try:
        geo = mongo.db.GEOIP.find()
        return render_template('geo.html', records=geo)
    except Exception as e:
        return make_response(jsonify({'error': e}))

@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)

if __name__ == '__main__':
  app.run(host='0.0.0.0', port=5666, debug=True)