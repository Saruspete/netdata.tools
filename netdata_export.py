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
#coloredlogs.install(level='DEBUG', logger=logger)


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
			if (re.match(filter_rgx, name)):
				if (filter_rgx[:1] == '!'):
					return False
				else:
					return True
		
		# If notthing has matched, return false
		return False


	def extract(self, fromts, tots, chartsfilter=None):

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

			# Load the global info about the server
			global_info_str = self._query("info")
			global_info = json.loads(global_info_str)
			comments = json.dumps(global_info).replace('"', '\\"')

			# Load the charts listing
			charts_info_str = self._query("charts")
			charts_info = json.loads(charts_info_str)


			header_data = {
				# Time arguments
				"time_after":     fromts * 1000,
				"time_before":    tots * 1000,
				"time_duration":  (tots - fromts) * 1000,
				"time_samplerate": charts_info["update_every"] * 1000,
				# 
				"netdata_version": global_info["version"],
				"netdata_host":    charts_info["hostname"],
				# URLs
				"url": self.geturl(),
				"url_hash": "#",
				"url_server": self.host,
				# Snapshot detail
				"comments": comments,
			}

			# Format the header
			snapshot += textwrap.dedent(header.format(**header_data))


			# Add the charts details
			charts_list = charts_info["charts"]
			#snapshot += '"charts": ' + json.dumps(charts_list) + ','

			snapshot += '"charts": ' + json.dumps(charts_info) + ",\n"
			snapshot += '"charts_failed": 0,\n'
			snapshot += '"charts_ok": ' + str(len(charts_list)) + ",\n"

			snapshot += '"compression": "pako.deflate.base64",\n'
			#snapshot += '"compression": "none",\n'
			snapshot += '"data": {\n'

			# And dump the data
			is_first = 1
			data_size = 0
			data_points = 0
			data_count = 0
			for chartname, chartinfo in charts_info.get('charts', []).items():

				# Skip unmatching charts
				if (not self.filter_chart(chartsfilter, chartname)):
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
				chartsnapkey = chartinfo["id"]+",dygraph,null," + optionsstr
				
				# Will prepend the ,\n on 2+
				if (is_first):
					is_first = 0
				else:
					snapshot += ",\n"
				
				snapshot += '"' + chartsnapkey + '": "' + base64.b64encode(zlib.compress(chartdatastr)) + '"'
				#snapshot += '"' + chartsnapkey + '": "' + chartdatastr.replace('"', '\\"') + '"'


			# Add data ?? TODO !
			snapshot += "\n},\n"

			snapshot += '"data_points": {points},\n'.format(points=data_points)
			snapshot += '"data_size": {size}\n'.format(size=data_size)
			
			# Finally, More info from gui (web/gui/dashboard_info.js
			#snapshot += '"info": undefined'
			snapshot += "}"

			print(textwrap.dedent(snapshot))

		except Exception as e:
			print(e)
			print(traceback.format_exc())


# ===================== Resulting Snapshot wanted
""" 
Resulting snapshot should be
{
"after_ms": 1562337754500,
"before_ms": 1562337782500,
"charts": {
	"alarms_count": 117,
	"charts": {
		"apps.cpu": {
			"alarms": {},
			"chart_type": "stacked",
			"context": "apps.cpu",
			"data_url": "/api/v1/data?chart=apps.cpu",
			"dimensions": {
				"VMs": {
					"name": "VMs"
				},
				"X": {
					"name": "X"
				},
				...
			},
			"duration": 3997,
			"enabled": true,
			"family": "cpu",
			"first_entry": 1562330948,
			"green": null,
			"id": "apps.cpu",
			"last_entry": 1562334944,
			"menu": "apps",
			"module": "",
			"name": "apps.cpu",
			"plugin": "apps.plugin",
			"priority": 20001,
			"red": null,
			"submenu": "cpu",
			"title": "Apps CPU Time (800% = 8 cores) (apps.cpu)",
			"type": "apps",
			"units": "percentage",
			"update_every": 1
		},
	},
	"charts_by_name": null,
	"charts_count": 387,
	"custom_info": "",
	"dimensions_count": 2007,
	"history": 3996,
	"hostname": "munin",
	"hosts": [
		{
			"hostname": "munin"
		}
	],
	"hosts_count": 1,
	"os": "linux",
	"release_channel": "nightly",
	"rrd_memory_bytes": 34802208,
	"timezone": "Europe/Paris",
	"update_every": 1,
	"version": "v1.15.0"
},
"charts_failed": 6,
"charts_ok": 424,
"comments": "",

"compression": "pako.deflate.base64",
"data": {
	"apps.cpu,dygraph,null,ms%7Cflip%7Cjsonwrap%7Cnonzero": "base64encodedstirng......."
},
"data_points": 3,
"data_size": 179904,
"duration_ms": 28000,
"hash": "#menu_pcm_submenu_System_CPU_Frequency",
"highlight_after_ms": 0,
"highlight_before_ms": 0,
"hostname": "munin",
"info": "{\"menu\":{\"system\":{\"title\":\"System Overview\",\"icon\":\"<i class=\\\"fas fa-bookmark\\\"></i>\",\"info\":\"Overview of the key system metrics.\"},\"services\":{\"title\":\"systemd Services\",\"icon\":\"<i class=\\\"fas fa-cogs\\\"></i>\",\"info\":\"Resources utilization of systemd services. netdata monitors all systemd services via CGROUPS (the resources accounting used by containers). \"},\"ap\":{\"title\":\"Access Points\",\"icon\":\"<i class=\\\"fas fa-wifi\\\"></i>\",\"info\":\"Performance metrics for the access points (i.e. wireless interfaces in AP mode) found on the system.\"},\"tc\":{\"title\":\"Quality of Service\",\"icon\":\"<i class=\\\"fas fa-globe\\\"></i>\",\"info\":\"Netdata collects and visualizes <code>tc</code> class utilization using its <a href=\\\"https://github.com/netdata/netdata/blob/master/collectors/tc.plugin/tc-qos-helper.sh.in\\\" target=\\\"_blank\\\">tc-helper plugin</a>. If you also use <a href=\\\"http://firehol.org/#fireqos\\\" target=\\\"_blank\\\">FireQOS</a> for setting up QoS, netdata automatically collects interface and class names. If your QoS configuration includes overheads calculation, the values shown here will include these overheads (the total bandwidth for the same interface as reported in the Network Interfaces section, will be lower than the total bandwidth reported here). QoS data collection may have a slight time difference compared to the interface (QoS data collection uses a BASH script, so a shift in data collection of a few milliseconds should be justified).\"},\"net\":{\"title\":\"Network Interfaces\",\"icon\":\"<i class=\\\"fas fa-sitemap\\\"></i>\",\"info\":\"Performance metrics for network interfaces.\"},\"ip\":{\"title\":\"Networking Stack\",\"icon\":\"<i class=\\\"fas fa-cloud\\\"></i>\",\"info\":\"function (os) {\\n			if(os === \\\"linux\\\")\\n				return 'Metrics for the networking stack of the system. These metrics are collected from <code>/proc/net/netstat</code>, apply to both IPv4 and IPv6 traffic and are related to operation of the kernel networking stack.';\\n			else\\n				return 'Metrics for the networking stack of the system.';\\n		}\"},\"ipv4\":{\"title\":\"IPv4 Networking\",\"icon\":\"<i class=\\\"fas fa-cloud\\\"></i>\",\"info\":\"Metrics for the IPv4 stack of the system. <a href=\\\"https://en.wikipedia.org/wiki/IPv4\\\" target=\\\"_blank\\\">Internet Protocol version 4 (IPv4)</a> is the fourth version of the Internet Protocol (IP). It is one of the core protocols of standards-based internetworking methods in the Internet. IPv4 is a connectionless protocol for use on packet-switched networks. It operates on a best effort delivery model, in that it does not guarantee delivery, nor does it assure proper sequencing or avoidance of duplicate delivery. These aspects, including data integrity, are addressed by an upper layer transport protocol, such as the Transmission Control Protocol (TCP).\"},\"ipv6\":{\"title\":\"IPv6 Networking\",\"icon\":\"<i class=\\\"fas fa-cloud\\\"></i>\",\"info\":\"Metrics for the IPv6 stack of the system. <a href=\\\"https://en.wikipedia.org/wiki/IPv6\\\" target=\\\"_blank\\\">Internet Protocol version 6 (IPv6)</a> is the most recent version of the Internet Protocol (IP), the communications protocol that provides an identification and location system for computers on networks and routes traffic across the Internet. IPv6 was developed by the Internet Engineering Task Force (IETF) to deal with the long-anticipated problem of IPv4 address exhaustion. IPv6 is intended to replace IPv4.\"},\"sctp\":{\"title\":\"SCTP Networking\",\"icon\":\"<i class=\\\"fas fa-cloud\\\"></i>\",\"info\":\"<a href=\\\"https://en.wikipedia.org/wiki/Stream_Control_Transmission_Protocol\\\" target=\\\"_blank\\\">Stream Control Transmission Protocol (SCTP)</a> is a computer network protocol which operates at the transport layer and serves a role similar to the popular protocols TCP and UDP. SCTP provides some of the features of both UDP and TCP: it is message-oriented like UDP and ensures reliable, in-sequence transport of messages with congestion control like TCP. It differs from those protocols by providing multi-homing and redundant paths to increase resilience and reliability.\"},.........
"netdata_version": "v1.15.0",
"server": "http://127.0.0.1:19999/",
"snapshot_version": 1,
"update_every_ms": 1000,
"url": "http://127.0.0.1:19999/"
}
"""


# ================ /info
"""


"""


# ================ /charts
#
# Additionnal options are provided in the HTML
# <div class="netdata-container-easypiechart" style="margin-right: 10px; width: 9%; will-change: auto;" data-netdata="system.swap" data-dimensions="used" data-append-options="percentage" data-chart-library="easypiechart" data-title="Used Swap" data-units="%" data-easypiechart-max-value="100" data-width="9%" data-before="0" data-after="-480" data-points="480" data-colors="#DD4400" role="application">
"""
	"hostname": "munin",
	"version": "v1.15.0",
	"release_channel": "nightly",
	"os": "linux",
	"timezone": "Europe/Paris",
	"update_every": 1,
	"history": 3996,
	"custom_info": "",
	"charts": {
		"disk_qops.dm-5": 		{
			"id": "disk_qops.dm-5",
			"name": "disk_qops.munin_swap",
			"type": "disk_qops",
			"family": "munin-swap",
			"context": "disk.qops",
			"title": "Disk Current I/O Operations (disk_qops.munin_swap)",
			"priority": 2002,
			"plugin": "proc.plugin",
			"module": "/proc/diskstats",
			"enabled": true,
			"units": "operations",
			"data_url": "/api/v1/data?chart=disk_qops.munin_swap",
			"chart_type": "line",
			"duration": 3997,
			"first_entry": 1565907012,
			"last_entry": 1565911008,
			"update_every": 1,
			"dimensions": {
				"operations": { "name": "operations" }
			},
			"green": null,
			"red": null,
			"alarms": {}
		},
	},
	"charts_count": 386,
	"dimensions_count": 1986,
	"alarms_count": 118,
	"rrd_memory_bytes": 34453184,
	"hosts_count": 1,
	"hosts": [
		{
			"hostname": "munin"
		}
	]
}
"""

# ================ /data

# Query
"""
chart=netdata.plugin_proc_cpu
format=json
group=average
gtime=0
options=ms%7Cflip%7Cjsonwrap%7Cnonzero
after=1562337755
before=1562337783
_=1562334945610
"""

# Result
"""
{
   "api": 1,
   "id": "system.cpu",
   "name": "system.cpu",
   "view_update_every": 1,
   "update_every": 1,
   "first_entry": 1565955506,
   "last_entry": 1565959502,
   "before": 1565959502,
   "after": 1565959493,
   "dimension_names": ["guest_nice", "guest", "steal", "softirq", "irq", "user", "system", "nice", "iowait"],
   "dimension_ids": ["guest_nice", "guest", "steal", "softirq", "irq", "user", "system", "nice", "iowait"],
   "latest_values": [0, 0, 0, 0.3768844, 0.879397, 5.4020101, 2.5125628, 0, 0],
   "view_latest_values": [0, 0, 0, 0.3768844, 0.879397, 5.40201, 2.512563, 0, 0],
   "dimensions": 9,
   "points": 10,
   "format": "json",
   "result": {
 "labels": ["time", "guest_nice", "guest", "steal", "softirq", "irq", "user", "system", "nice", "iowait"],
    "data":
 [
      [ 1565959502, 0, 0, 0, 0.3768844, 0.879397, 5.40201, 2.512563, 0, 0],
      [ 1565959501, 0, 0, 0, 0.375, 0.75, 8, 2.375, 0, 0],
      [ 1565959500, 0, 0, 0, 0.3773585, 1.0062893, 6.037736, 2.641509, 0.1257862, 0.2515723],
      [ 1565959499, 0, 0, 0, 0.3764115, 0.7528231, 8.406524, 2.007528, 0, 0],
      [ 1565959498, 0, 0, 0, 0.2506266, 0.877193, 7.64411, 2.631579, 0, 0],
      [ 1565959497, 0, 0, 0, 0.3778338, 0.8816121, 7.178841, 2.518892, 0, 0],
      [ 1565959496, 0, 0, 0, 0.3773585, 1.0062893, 5.408805, 2.264151, 0, 0],
      [ 1565959495, 0, 0, 0, 0.3773585, 0.8805031, 6.918239, 2.389937, 0, 0.1257862],
      [ 1565959494, 0, 0, 0, 0.3764115, 0.7528231, 9.284818, 2.50941, 0, 0.1254705],
      [ 1565959493, 0, 0, 0, 0.3759398, 0.877193, 7.518797, 2.756892, 0, 0]
  ]
},
 "min": 0,
 "max": 9.284818
}
"""


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
	argsparser.add_argument('-c', '--charts', help="Filter (regex) charts to export. Prefix with '!' to negate pattern", default=[".+"], action='append')
	# Output
	argsparser.add_argument('-o', '--outfile', help="Output snapshot file", default=outfile)

	args = argsparser.parse_args()

	# Set log level to WARN going more verbose for each new -v
	#loglvl = max(3 - args.verbose, 0) * 10
	#logger.setLevel(loglvl)
	#coloredlogs.install(level=loglvl, logger=logger)


	# Call for extraction
	nd = NetdataAPI(host=args.host, port=args.port, path=args.subpath)

	nd.extract(fromts=args.begin, tots=args.end, chartsfilter=args.charts)