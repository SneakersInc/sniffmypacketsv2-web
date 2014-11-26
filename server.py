#!/usr/bin/env python

# Part of the sniffMyPackets framework

# API/Web server
import os
import modules.pcapmap
from flask import Flask, jsonify, make_response, request, render_template, url_for, redirect, send_from_directory
from werkzeug import secure_filename

basedir = os.path.abspath(os.path.dirname(__file__))

ALLOWED_EXTENSIONS = ['pcap', 'pcapng', 'cap']
UPLOAD_FOLDER = os.path.join(basedir, 'static/uploads/')

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

@app.route('/pcap/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return redirect(url_for('uploaded_file', filename=filename))

@app.route('/pcap/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/geomap/', methods=['GET'])
def buildgeomap():
    x = modules.pcapmap.generatemap()
    return render_template('pcapgeomap.html', geomap=x)

@app.route('/', methods=['GET'])
def home():
    return render_template('home.html')

@app.route('/about', methods=['GET'])
def about():
    return render_template('about.html')

@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)

if __name__ == '__main__':
  app.run(host='0.0.0.0', port=5666, debug=True)