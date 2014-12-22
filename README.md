sniffmypacketsv2-web
====================

Web framework for sniffmypackets v2

**Requirements:**  
pip install -r requirements.txt  
Flask  
Flask-PyMongo  

**Vagrant Machine:**  
The sniffMyPackets web interface requires a MongoDB backend to store PCAP information in. A vagrant machine has been included to save you the hassle of building this yourself.
To start the Vagrant machine (vagrant up), run the following commands:  
`cd vagrant`  
`vagrant up`  
This will start the build process (can take up to 20 minutes the first time). Once all done, the web interface will be accessible on:  

**http://localhost:5666**  

