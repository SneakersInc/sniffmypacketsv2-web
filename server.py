#!/usr/bin/env python

# Part of the sniffMyPackets framework

# API/Web server

import modules.pcapmap
from flask import Flask, jsonify, make_response, request, render_template

app = Flask(__name__)

@app.route('/geomap/', methods=['GET'])
def buildgeomap():
    x = modules.pcapmap.generatemap()
    return render_template('pcapgeomap.html', geomap=x)
    # return make_response(jsonify({'Infoblox': x}))

@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)


if __name__ == '__main__':
  app.run(host='0.0.0.0', port=5666, debug=True)