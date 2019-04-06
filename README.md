# nmap_xml_to_json
Convert nmap xml stdin to json stdout

# requires:
Python 2.7 and above (not tested on anything below)

# libraries:
import json
import time
import codecs
import struct
import locale
import glob
import sys
import getopt
import xml.etree.ElementTree as xml
import re

# example command 
nmap -O 192.168.0.1-255 -oX - | python np_vuln_to_file.py > test.json

# used in this docker machine:
https://github.com/nateshull/nmap_to_logstash_docker
