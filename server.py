#!/usr/bin/env python

# Part of the sniffMyPackets framework

# API/Web server
import os
from flask.ext.pymongo import PyMongo
from flask import Flask, jsonify, make_response, render_template, send_from_directory, request, redirect, url_for
from werkzeug import secure_filename

basedir = os.path.abspath(os.path.dirname(__file__))

ALLOWED_EXTENSIONS = ['zip', 'pcap', 'cap', 'pcapng']
UPLOAD_FOLDER = os.path.join(basedir, 'static/uploads/')

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MONGO_HOST'] = 'localhost'
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
    try:
        summary = mongo.db.INDEX.find({"PCAP ID": pcapid})
        http = mongo.db.HTTP.find({"PCAP ID": pcapid}).count()
        dns = mongo.db.DNS.find({"PCAP ID": pcapid}).count()
        streams = mongo.db.STREAMS.find({"PCAP ID": pcapid}).count()
        files = mongo.db.ARTIFACTS.find({"PCAP ID": pcapid}).count()
        creds = mongo.db.CREDS.find({"PCAP ID": pcapid}).count()
        return render_template('summary.html', records=summary, http=http, dns=dns, streams=streams, files=files,
                               creds=creds)
    except Exception as e:
        return make_response(jsonify({'error': str(e)}))

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


@app.route('/pcap/streams', methods=['GET'])
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

@app.route('/pcap/<pcapid>/ssl', methods=['GET'])
def sslpcapsummary(pcapid):
    try:
        ssl = mongo.db.SSL.find({"PCAP ID": pcapid})
        return render_template('ssl.html', records=ssl)
    except Exception as e:
        return make_response(jsonify({'error': e}))

@app.route('/pcap/ssl', methods=['GET'])
def sslsummary():
    try:
        ssl = mongo.db.SSL.find()
        return render_template('ssl.html', records=ssl)
    except Exception as e:
        return make_response(jsonify({'error': e}))

@app.route('/pcap/<pcapid>/artifacts', methods=['GET'])
def filespcapsummary(pcapid):
    try:
        files = mongo.db.ARTIFACTS.find({"PCAP ID": pcapid})
        return render_template('artifacts.html', records=files)
    except Exception as e:
        return make_response(jsonify({'error': e}))

@app.route('/pcap/artifacts', methods=['GET'])
def filesummary():
    try:
        files = mongo.db.ARTIFACTS.find()
        return render_template('artifacts.html', records=files)
    except Exception as e:
        return make_response(jsonify({'error': e}))

@app.route('/pcap/dodgy', methods=['GET'])
def dodgysummary():
    try:
        files = mongo.db.MALWARE.find()
        return render_template('dodgy.html', records=files)
    except Exception as e:
        return make_response(jsonify({'error': e}))

@app.route('/pcap/creds', methods=['GET'])
def credssummary():
    try:
        files = mongo.db.CREDS.find()
        return render_template('creds.html', records=files)
    except Exception as e:
        return make_response(jsonify({'error': e}))

@app.route('/pcap/uploadfiles', methods=['GET'])
def uploadfilesummary():
    try:
        files = mongo.db.FILES.find()
        return render_template('uploadfiles.html', records=files)
    except Exception as e:
        return make_response(jsonify({'error': e}))


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

@app.route('/pcap/_uploads', methods=['GET', 'POST'])
def upload_file():
    try:
        if request.method == 'POST':
            f = request.files['files']
            if f and allowed_file(f.filename):
                filename = secure_filename(f.filename)
                f.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                return '200'
    except:
        return make_response(jsonify({'error': 'Bad Robot'}))

@app.route('/pcap/downloads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'],
                               filename)

@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)

if __name__ == '__main__':
  app.run(host='0.0.0.0', port=5666, debug=True)