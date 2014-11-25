#!/usr/bin/env python

# Part of the sniffMyPackets framework

# API/Web server
import os
import modules.pcapmap
from flask import Flask, jsonify, make_response, request, render_template

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)

ALLOWED_EXTENSIONS = ['pcap', 'pcapng', 'cap']
UPLOAD_FOLDER = os.path.join(basedir, 'static/uploads/')

@app.route('/geomap/', methods=['GET'])
def buildgeomap():
    x = modules.pcapmap.generatemap()
    return render_template('pcapgeomap.html', geomap=x)



@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)


if __name__ == '__main__':
  app.run(host='0.0.0.0', port=5666, debug=True)