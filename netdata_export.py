#!/usr/bin/env python

from __future__ import print_function

import sys
import requests
import json
import contextlib
import logging
import traceback
import textwrap
import re
import zlib
import base64

logging.basicConfig(stream=sys.stderr, format='%(name)s (%(levelname)s): %(message)s')
logger = logging.getLogger(__name__)

_API_URL_BASE = 'http://{host}:{port}/{path}api/v{api}/'

_API_DEF_HOST = "127.0.0.1"
_API_DEF_PORT = 19999
_API_DEF_PATH = ""
_API_DEF_VERS = 1


# Taken from https://stackoverflow.com/questions/17602878/
@contextlib.contextmanager
def opensmart(filename=None):

	if filename == '-':
		fh = sys.stdout
	else:
		fh = open(filename, 'w+')

	try:
		yield fh
	finally:
		if fh is not sys.stdout:
			fh.close()


class NetdataAPI(object):
	""" Class for accessing Netdata API"""

	def __init__(self, host=_API_DEF_HOST, port=_API_DEF_PORT, path=_API_DEF_PATH, api=_API_DEF_VERS):

		self.host = host
		self.port = port
		self.path = path
		self.api = api
		self._url = self.geturl()

	def _query(self, query, outfile=None):

		# If we want to dump a file, use stream
		if outfile:
			# from https://stackoverflow.com/questions/16694907/
			r = requests.get(self._url + query, stream=True)

			with opensmart(outfile) as fh:
				for chunk in r.iter_content(chunk_size=1024):
					if chunk:
						print(chunk.decode('utf8'), file=fh, end='')
		# else, just return the content as str
		else:
			return requests.get(self._url + query).content

	def geturl(self):
		""" Get the backend url used for queries """
		return _API_URL_BASE.format(host=self.host, port=self.port, path=self.path, api=self.api)

	def filter_chart(self, filters, name):
		# Check all items
		for filter_rgx in filters:
			foundreturns = True
			# Negated pattern
			if (filter_rgx[:1] == '!'):
				filter_rgx = filter_rgx[1:]
				foundreturns = False

			# Check for match
			if (re.match(filter_rgx, name)):
				return foundreturns

		# If notthing has matched, return false
		return False

	def extract(self, fromts, tots, chartsfilter=None, datacompress=True):

		snapshot = "{"
		header = """
			"after_ms": {time_after},
			"before_ms": {time_before},
			"duration_ms": {time_duration},
			"update_every_ms": {time_samplerate},
			"highlight_after_ms": 0,
			"highlight_beofre_ms": 0,

			"url": "{url}",
			"hash": "{url_hash}",
			"server": "{url_server}",

			"hostname": "{netdata_host}",
			"netdata_version": "{netdata_version}",
			"snapshot_version": 1,
			"comments": "{comments}",
		"""

		try:

			#
			# Generic information
			#

			# Load the global info about the server
			global_info_str = self._query("info")
			global_info = json.loads(global_info_str)
			comments = json.dumps(global_info).replace('"', '\\"')

			# Load the charts listing
			charts_info_str = self._query("charts")
			charts_info = json.loads(charts_info_str)

			header_data = {
				# Time arguments
				"time_after": fromts * 1000,
				"time_before": tots * 1000,
				"time_duration": (tots - fromts) * 1000,
				"time_samplerate": charts_info["update_every"] * 1000,
				# Version and host info
				"netdata_version": global_info["version"],
				"netdata_host": charts_info["hostname"],
				"url": self.geturl(),
				"url_hash": "#",
				"url_server": self.host,
				# Snapshot detail
				"comments": comments,
			}

			snapshot += textwrap.dedent(header.format(**header_data))

			#
			# Add the charts definitions
			#

			# If there is a filter, apply it
			if (len(chartsfilter)):
				for chartname, chartdata in charts_info['charts'].items():
					if (not self.filter_chart(chartsfilter, chartname)):
						del charts_info['charts'][chartname]

				# recalculate the values
				charts_info['charts_count'] = 0
				charts_info['dimensions_count'] = 0
				charts_info['alarms_count'] = 0
				for chartname, chartdata in charts_info['charts'].items():
					charts_info['charts_count'] += 1
					charts_info['dimensions_count'] += len(chartdata['dimensions'])
					charts_info['alarms_count'] += len(chartdata['alarms'])

			# Add the selected charts
			snapshot += '"charts": ' + json.dumps(charts_info) + ",\n"
			snapshot += '"charts_failed": 0,\n'
			snapshot += '"charts_ok": ' + str(len(charts_info['charts'])) + ",\n"

			#
			# Add charts data
			#
			if (datacompress):
				snapshot += '"compression": "pako.deflate.base64",\n'
			else:
				snapshot += '"compression": "none",\n'

			snapshot += '"data": {\n'

			# And dump the data
			is_first = 1
			data_size = 0
			data_points = 0
			data_count = 0
			for chartname, chartinfo in charts_info.get('charts', []).items():

				# Skip unmatching charts
				if (len(chartsfilter) and not self.filter_chart(chartsfilter, chartname)):
					continue

				options = ["ms", "flip", "jsonwrap", "nonzero"]
				optionsstr = "%7C".join(options)

				# Now, foreach chart, get its data
				urlfmt = (
					"data?chart={chart}&format=json"
					"&group=average&gtime=0&points=0"
					"&after={time_from}&before={time_to}&points={points}"
					"&options={options}"
				)

				url = urlfmt.format(chart=chartname, time_from=fromts, time_to=tots, points='', options=optionsstr)
				chartdatastr = self._query(url)
				chartdatastr = re.sub(r'[\t\n\r ]*', '', chartdatastr)

				data_size += len(chartdatastr)
				data_count += 1
				data_points += len(chartinfo['dimensions'].keys())

				# apps.cpu,dygraph,null,ms%7Cflip%7Cjsonwrap%7Cnonzero":
				# Selection of options is from web/gui/src/dashboard.js/main.js:3090
				chartsnapkey = chartinfo["id"] + ",dygraph,null," + optionsstr

				# Will prepend the ,\n on 2+
				if (is_first):
					is_first = 0
				else:
					snapshot += ",\n"

				if (datacompress):
					snapshot += '"' + chartsnapkey + '": "' + base64.b64encode(zlib.compress(chartdatastr)) + '"'
				else:
					snapshot += '"' + chartsnapkey + '": "' + chartdatastr.replace('"', '\\"') + '"'

			# Add data ?? TODO !
			snapshot += "\n},\n"

			snapshot += '"data_points": {points},\n'.format(points=data_points)
			snapshot += '"data_size": {size}\n'.format(size=data_size)

			# Finally, More info from gui (web/gui/dashboard_info.js
			# snapshot += '"info": undefined'
			snapshot += "}"

			print(textwrap.dedent(snapshot))

		except Exception as e:
			print(e)
			print(traceback.format_exc())


if __name__ == "__main__":

	import os
	import argparse
	import datetime

	myself = os.path.realpath(__file__)
	mydir = os.path.dirname(myself)

	# Default output folder
	outfile = mydir + "/extracts/netdata_" + datetime.datetime.now().strftime("%y%m%d_%H%M%S") + ".snapshot"

	# Parse arguments
	argsparser = argparse.ArgumentParser(description="Extract netdata values")
	argsparser.add_argument('-v', '--verbose', help="Increase verbosity", action='count')
	# Endpoint access
	argsparser.add_argument('-H', '--host', help="Target server to query", default=_API_DEF_HOST)
	argsparser.add_argument('-P', '--port', help="Port of target server", default=_API_DEF_PORT, type=int)
	argsparser.add_argument('-S', '--subpath', help="Path to connect to host", default=_API_DEF_PATH)
	# Netdata data filtering
	argsparser.add_argument('-b', '--begin', help="Timestamp of collection begin", default=-600, type=int)
	argsparser.add_argument('-e', '--end', help="Timestamp of collection end", default=0, type=int)
	argsparser.add_argument('-c', '--charts', help="Filter (regex) charts to export. Prefix with '!' to negate pattern", default=[], action='append')
	# Output
	argsparser.add_argument('-o', '--outfile', help="Output snapshot file", default=outfile)

	args = argsparser.parse_args()

	# Call for extraction
	nd = NetdataAPI(host=args.host, port=args.port, path=args.subpath)

	nd.extract(fromts=args.begin, tots=args.end, chartsfilter=args.charts)
