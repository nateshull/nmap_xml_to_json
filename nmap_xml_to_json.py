#!/usr/bin/env python

from datetime import datetime
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

class NmapToJSON:
	"This class will parse an Nmap XML file and send data to Elasticsearch"
	def __init__(self, input_file):
		self.input_file = input_file
		self.tree = self.__importXML()
		self.root = self.tree.getroot()

	def displayInputFileName(self):
		print(self.input_file)

	def __importXML(self):
		#Parse XML directly from the file path
		return xml.parse(self.input_file)

	def toFile(self):
		"Returns a list of dictionaries (only for open ports) for each host in the report"
		start_line = ""
		end_line = ","
		print "["
		for h in self.root.iter('host'):
			base_host_dict = {}
			dict_item = {}
			dict_item['scanner'] = 'nmap'
			for c in h:
				if c.tag == 'address':
					if c.attrib['addrtype'] == "ipv4":
						dict_item['ipv4'] = c.attrib['addr']
					elif c.attrib['addrtype'] == "ipv6":
						dict_item['ipv6'] = c.attrib['addr']
					elif c.attrib['addrtype'] == "mac":
						dict_item['mac'] = c.attrib['addr']
					base_dict_host = dict_item.copy()
				elif c.tag == 'hostnames':
					for names in c.getchildren():
						if names.attrib['name']:
							dict_item['hostname'] = names.attrib['name']
					base_dict_host = dict_item.copy()
				elif c.tag == 'ports':
					for port in c.getchildren():
						dict_item = base_dict_host.copy()
						if port.tag == 'port':
							dict_item['port'] = port.attrib['portid']
							dict_item['protocol'] = port.attrib['protocol']
							for p in port.getchildren():
								if p.tag == 'state':
									dict_item['state'] = p.attrib['state']
								elif p.tag == 'service':
									dict_item['service'] = p.attrib['name']
								elif p.tag == 'script':
									dict_item['script_id'] = p.attrib['id']
									dict_item['script_output'] = p.attrib['output']
								print start_line + json.dumps(dict(dict_item.items()), sort_keys=True) + end_line
				elif c.tag == 'hostscript':
					for script in c.getchildren():
						dict_item = base_dict_host.copy()
						if script.tag == 'script':
							dict_item['script_id'] = script.attrib['id']
							dict_item['script_output'] = script.attrib['output']
							print start_line + json.dumps(dict(dict_item.items()), sort_keys=True) + end_line
				elif c.tag == 'os':
					for osmatch in c.getchildren():
						osname = ""
						dict_item = base_dict_host.copy()
						if osmatch.tag == 'osmatch':
							if osname == "":
								dict_item['os_description'] = osmatch.attrib['name']
								osname = osmatch.attrib['name']
							else:								
								osname = osname + ',\n' + osmatch.attrib['name']
								dict_item['os_description'] = osmatch.attrib['name']
							for osc in osmatch.getchildren():
								if osc.tag == 'osclass':
									dict_item['os_type'] = osc.attrib['type']
									dict_item['os_vendor'] = osc.attrib['vendor']
									dict_item['os_family'] = osc.attrib['osfamily']
									#try:
									if hasattr(osc, 'osgen'):
										dict_item['os_gen'] = osc.attrib['osgen']
										#except AttributeError:
									#else:									
										#dict_item['os_gen'] = ''
					print start_line + json.dumps(dict(dict_item.items()), sort_keys=True) + end_line
		print "{ \"hostname\" : \"end_of_data\" }"
		print "]"

def main():
	input_stream = sys.stdin
	np = NmapToJSON(input_stream)
	np.toFile()

if __name__ == "__main__":
	main()
