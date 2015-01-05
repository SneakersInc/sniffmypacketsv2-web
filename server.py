#!/usr/bin/env python

# Part of the sniffMyPackets framework
# by @catalyst256


# API/Web server
import os
import commands
from flask.ext.pymongo import PyMongo
from flask import Flask, jsonify, make_response, render_template, send_from_directory, request
from werkzeug import secure_filename

basedir = os.path.abspath(os.path.dirname(__file__))

# ALLOWED_EXTENSIONS = ['zip', 'pcap', 'cap', 'pcapng', 'msg']
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
        uploads = mongo.db.FILES.find({"PCAP ID": pcapid}).count()
        packets = mongo.db.PACKETS.find({"Buffer.PCAP ID": pcapid}).count()
        return render_template('summary.html', records=summary, http=http, dns=dns, streams=streams, files=files,
                               creds=creds, pcapid=pcapid, uploads=uploads, packets=packets)
    except Exception as e:
        return make_response(jsonify({'error': str(e)}))

@app.route('/pcap/<pcapid>/dns', methods=['GET'])
def dnspcapsummary(pcapid):
    try:
        dns = mongo.db.DNS.find({"PCAP ID": pcapid})
        return render_template('dns.html', records=dns, pcapid=pcapid)
    except Exception as e:
        return make_response(jsonify({'error': e}))

@app.route('/pcap/dns', methods=['GET'])
def dnssummary():
    try:
        dns = mongo.db.DNS.find()
        return render_template('dnssummary.html', records=dns)
    except Exception as e:
        return make_response(jsonify({'error': e}))

@app.route('/pcap/<pcapid>/http', methods=['GET'])
def httppcapsummary(pcapid):
    try:
        http = mongo.db.HTTP.find({"PCAP ID": pcapid})
        return render_template('http.html', records=http, pcapid=pcapid)
    except Exception as e:
        return make_response(jsonify({'error': e}))

@app.route('/pcap/http', methods=['GET'])
def httpsummary():
    try:
        http = mongo.db.HTTP.find()
        return render_template('httpsummary.html', records=http)
    except Exception as e:
        return make_response(jsonify({'error': e}))

@app.route('/pcap/<pcapid>/streams', methods=['GET'])
def streampcapsummary(pcapid):
    try:
        http = mongo.db.STREAMS.find({"PCAP ID": pcapid})
        return render_template('streams.html', records=http, pcapid=pcapid)
    except Exception as e:
        return make_response(jsonify({'error': e}))


@app.route('/pcap/streams', methods=['GET'])
def streamsummary():
    try:
        http = mongo.db.STREAMS.find()
        return render_template('streamssummary.html', records=http)
    except Exception as e:
        return make_response(jsonify({'error': e}))

@app.route('/pcap/<pcapid>/geo', methods=['GET'])
def geopcapsummary(pcapid):
    try:
        geo = mongo.db.GEOIP.find({"PCAP ID": pcapid})
        return render_template('geo.html', records=geo, pcapid=pcapid)
    except Exception as e:
        return make_response(jsonify({'error': e}))

@app.route('/pcap/geo', methods=['GET'])
def geosummary():
    try:
        geo = mongo.db.GEOIP.find()
        return render_template('geosummary.html', records=geo)
    except Exception as e:
        return make_response(jsonify({'error': e}))

@app.route('/pcap/<pcapid>/ssl', methods=['GET'])
def sslpcapsummary(pcapid):
    try:
        ssl = mongo.db.SSL.find({"PCAP ID": pcapid})
        return render_template('ssl.html', records=ssl, pcapid=pcapid)
    except Exception as e:
        return make_response(jsonify({'error': e}))

@app.route('/pcap/ssl', methods=['GET'])
def sslsummary():
    try:
        ssl = mongo.db.SSL.find()
        return render_template('sslsummary.html', records=ssl)
    except Exception as e:
        return make_response(jsonify({'error': e}))

@app.route('/pcap/<pcapid>/artifacts', methods=['GET'])
def filespcapsummary(pcapid):
    try:
        files = mongo.db.ARTIFACTS.find({"PCAP ID": pcapid})
        return render_template('artifacts.html', records=files, pcapid=pcapid)
    except Exception as e:
        return make_response(jsonify({'error': e}))

@app.route('/pcap/artifacts', methods=['GET'])
def filesummary():
    try:
        files = mongo.db.ARTIFACTS.find()
        return render_template('artifactssummary.html', records=files)
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
        return render_template('credssummary.html', records=files)
    except Exception as e:
        return make_response(jsonify({'error': e}))

@app.route('/pcap/<pcapid>/<streamid>/packets/<packetnumber>')
def packetsummary(pcapid, streamid, packetnumber):
    try:
        r = mongo.db.PACKETS.find({"Buffer.StreamID": streamid, "Buffer.packetnumber": int(packetnumber)}, {"_id": 0})
        for d in r:
            return make_response(jsonify(d))
    except Exception as e:
        return make_response(jsonify({'error': e}))

@app.route('/logs', methods=['GET'])
def errorlogs():
    try:
        files = mongo.db.ERRORS.find()
        return render_template('logs.html', records=files)
    except Exception as e:
        return make_response(jsonify({'error': e}))

@app.route('/pcap/<pcapid>/creds', methods=['GET'])
def credspcapsummary(pcapid):
    try:
        files = mongo.db.CREDS.find({"PCAP ID": pcapid})
        return render_template('creds.html', records=files, pcapid=pcapid)
    except Exception as e:
        return make_response(jsonify({'error': e}))

@app.route('/pcap/<pcapid>/<streamid>/packets', methods=['GET'])
def packetpcapsummary(pcapid, streamid):
    try:
        files = mongo.db.PACKETSUMMARY.find({"Buffer.StreamID": streamid})
        return render_template('packets.html', records=files, pcapid=pcapid)
    except Exception as e:
        return make_response(jsonify({'error': e}))

@app.route('/pcap/<pcapid>/packets', methods=['GET'])
def pcappacketsummarypage(pcapid):
    try:
        files = mongo.db.PACKETSUMMARY.find({"PCAP ID": pcapid})
        return render_template('packets.html', records=files, pcapid=pcapid)
    except Exception as e:
        return make_response(jsonify({'error': e}))

@app.route('/pcap/packets', methods=['GET'])
def packetsummarypage():
    try:
        files = mongo.db.PACKETSUMMARY.find()
        return render_template('packetsummary.html', records=files)
    except Exception as e:
        return make_response(jsonify({'error': e}))

@app.route('/pcap/uploadfiles', methods=['GET'])
def uploadfilesummary():
    try:
        files = mongo.db.FILES.find()
        return render_template('uploadfiles.html', records=files)
    except Exception as e:
        return make_response(jsonify({'error': e}))

@app.route('/pcap/<pcapid>/uploadfiles', methods=['GET'])
def uploadfiles(pcapid):
    try:
        files = mongo.db.FILES.find({"PCAP ID": pcapid})
        return render_template('uploadfiles.html', records=files, pcapid=pcapid)
    except Exception as e:
        return make_response(jsonify({'error': e}))

@app.route('/pcap/_uploads', methods=['GET', 'POST'])
def upload_file():
    try:
        if request.method == 'POST':
            f = request.files['files']
            filename = secure_filename(f.filename)
            f.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return '200'
    except:
        return make_response(jsonify({'error': 'Bad Robot'}))

@app.route('/pcap/downloads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'],
                               filename)
@app.route('/pcap/<pcapid>/hex/<filename>', methods=['GET'])
def get_hex(pcapid, filename):
    f = mongo.db.FILES.find({"File Name": filename}, {"MD5 Hash": 1})
    for i in f:
        files = i['MD5 Hash']
        return render_template('hex.html', records=files, fname=filename, pcapid=pcapid)


# Hex Viewer by @kevthehermit https://github.com/kevthehermit/viper/blob/web_update/web.py
@app.route('/hex', methods=['GET', 'POST'])
def hex_viewer():
    md5_hash = request.form.get('file_hash')

    f = mongo.db.FILES.find({"MD5 Hash": md5_hash}, {"File Name": 1})
    for i in f:
        filename = i['File Name']

    # get post data
    file_hash = request.form.get('file_hash')
    try:
        hex_offset = int(request.form.get('hex_start'))
    except:
        return '<p class="text-danger">Error Generating Request</p>'
    hex_length = 256

    # get file path
    hex_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    # create the command string
    hex_cmd = 'hd -s {0} -n {1} {2}'.format(hex_offset, hex_length, hex_path)

    # get the output
    hex_string = commands.getoutput(hex_cmd)

    # Format the data
    html_string = ''
    hex_rows = hex_string.split('\n')
    for row in hex_rows:
        if len(row) > 9:
            off_str = row[0:8]
            hex_str = row[9:58]
            asc_str = row[58:78]
            asc_str = asc_str.replace('"', '&quot;')
            asc_str = asc_str.replace('<', '&lt;')
            asc_str = asc_str.replace('>', '&gt;')
            html_string += '<div class="row"><span class="text-primary mono">{0}</span> <span class="text-muted mono">{1}</span> <span class="text-success mono">{2}</span></div>'.format(off_str, hex_str, asc_str)
    # return the data
    return html_string

@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)

if __name__ == '__main__':
  app.run(host='0.0.0.0', port=5666, debug=True)