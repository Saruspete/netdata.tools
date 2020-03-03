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
import time

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

		self.data_sep = '%7C'

	def _query(self, query, outfile=None):

		url = self._url + query
		logging.debug("Fetching '%s'", url)

		# If we want to dump a file, use stream
		if outfile:
			# from https://stackoverflow.com/questions/16694907/
			r = requests.get(url, stream=True)

			with opensmart(outfile) as fh:
				for chunk in r.iter_content(chunk_size=1024):
					if chunk:
						print(chunk.decode('utf8'), file=fh, end='')
		# else, just return the content as str
		else:
			return requests.get(url).content

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

	def extract_dashboard(self, fromts, tots, chartsfilter=None, datacompress=True, outfile=None):

		snapshot = "{"
		header = """
			"after_ms": {time_after},
			"before_ms": {time_before},
			"duration_ms": {time_duration},
			"update_every_ms": {time_samplerate},
			"highlight_after_ms": 0,
			"highlight_before_ms": 0,

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
			global_info = {}
			try:
				global_info_str = self._query("info")
				global_info = json.loads(global_info_str)
			except:
				pass

			comments = json.dumps(global_info).replace('"', '\\"')

			# Load the charts listing
			charts_info_str = self._query("charts")
			charts_info = json.loads(charts_info_str)
			fromms = fromts * 1000
			toms = tots * 1000

			# Zero or negative: relative to now
			if toms <= 0:
				toms = int(time.time() * 1000)

			# Negative value
			if fromms < 0:
				fromms = toms + fromms


			header_data = {
				# Time arguments
				"time_after": fromms,
				"time_before": toms,
				"time_duration": (toms - fromms),
				"time_samplerate": charts_info["update_every"] * 1000,
				# Version and host info
				"netdata_version": global_info.get("version", "v1.10 (or older)"),
				"netdata_host": charts_info["hostname"],
				"url": self.geturl(),
				"url_hash": "#menu_system_submenu;after={after};before={before};theme=slate"
					.format(after=fromms, before=toms),
				"url_server": self.host,
				# Snapshot detail
				"comments": comments,
			}

			# Older versions doesn't urlencode the '|' as separator
			if not global_info.get("version", None):
				self.data_sep = '|'

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
				optionsstr = self.data_sep.join(options)

				# Now, foreach chart, get its data
				urlfmt = (
					"data?chart={chart}&format=json"
					"&group=average&gtime=0&points=0"
					"&after={time_from}&before={time_to}&points={points}"
					"&options={options}"
				)

				url = urlfmt.format(chart=chartname, time_from=fromts, time_to=tots, points='', options=optionsstr)
				chartdatastr = self._query(url)
				chartdatastr = re.sub(r'[\t\n\r ]*', '', chartdatastr.decode('utf8'))

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
					snapshot += '"' + chartsnapkey + '": "' + base64.b64encode(zlib.compress(chartdatastr.encode('utf8'))).decode('utf8') + '"'
				else:
					snapshot += '"' + chartsnapkey + '": "' + chartdatastr.replace('"', '\\"') + '"'

			# Add data ?? TODO !
			snapshot += "\n},\n"

			snapshot += '"data_points": {points},\n'.format(points=data_points)
			snapshot += '"data_size": {size}\n'.format(size=data_size)

			# Finally, More info from gui (web/gui/dashboard_info.js
			# snapshot += '"info": undefined'
			snapshot += "}"

			# Output to file directly
			if outfile:
				with opensmart(outfile) as fh:
					print(snapshot, file=fh, end='')
			# Output to stdout
			else:
				print(textwrap.dedent(snapshot))

		except Exception as e:
			print(e)
			print(traceback.format_exc())


	def extract_csv(self, fromts, tots, chartsfilter=None, datacompress=True, outfile=None):
		try:
			charts_info_str = self._query("charts")
			charts_info = json.loads(charts_info_str)

			# Zero or negative: relative to now
			if tots <= 0:
				tots = int(time.time())

			# Negative value
			if fromts < 0:
				fromts = tots + fromts

			# If there is a filter, apply it
			if (len(chartsfilter)):
				for chartname, chartdata in charts_info['charts'].items():
					if (not self.filter_chart(chartsfilter, chartname)):
						del charts_info['charts'][chartname]

			for chartname, chartinfo in charts_info.get('charts', []).items():

				# Skip unmatching charts
				if (len(chartsfilter) and not self.filter_chart(chartsfilter, chartname)):
					continue

				options = ["flip", "nonzero"]
				optionsstr = self.data_sep.join(options)

				# Now, foreach chart, get its data
				urlfmt = (
					"data?chart={chart}&format=csv"
					"&group=average&gtime=0&points=0"
					"&after={time_from}&before={time_to}&points={points}"
					"&options={options}"
				)

				url = urlfmt.format(chart=chartname, time_from=fromts, time_to=tots, points='', options=optionsstr)
				chartdatastr = self._query(url)
				chartdatastr = re.sub(r'(\r\n)', "\n", chartdatastr.decode('utf8'))

				# Output current chart to file directly
				if outfile:
					if not os.path.exists(outfile):
						os.makedirs(outfile)

					with opensmart(outfile + "/" + chartname + ".csv") as fh:
						print(chartdatastr, file=fh, end='')
				else:
					print(chartdatastr)

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
	outformat = "dashboard"

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
	argsparser.add_argument('-f', '--format', help="Output format. Can be: 'dashboard' 'json' or 'csv'", default=outformat)

	args = argsparser.parse_args()

	# Call for extraction
	nd = NetdataAPI(host=args.host, port=args.port, path=args.subpath)

	outformats = {
		"dashboard": nd.extract_dashboard,
		"csv":       nd.extract_csv
	}

	# Create folder if not existing
	outdir = os.path.dirname(outfile)
	if not os.path.exists(outdir):
		os.makedirs(outdir)

	if (outformats.get(args.format)):
		outformats[args.format](fromts=args.begin, tots=args.end, chartsfilter=args.charts, outfile=args.outfile)
	else:
		print("Error: Invalid format '"+args.format+"'. Must be one of: " + " ".join(outformats.keys()));

	#nd.extract(fromts=args.begin, tots=args.end, chartsfilter=args.charts)
