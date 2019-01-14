#!/usr/bin/env python

from __future__ import print_function

import sys
import requests
import json
import contextlib

_API_URL_BASE = 'http://{host}:{port}/{path}/api/v{api}/'

_API_DEF_HOST = "127.0.0.1"
_API_DEF_PORT = 19999
_API_DEF_PATH = "/"
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
        self.api  = api

        self._url = self.geturl()



    def _query(self, query, outfile=None):

        # If we want to dump a file, use stream
        if outfile:
            # from https://stackoverflow.com/questions/16694907/
            r = requests.get(self._url+query, stream=True)

            with opensmart(outfile) as fh:
                for chunk in r.iter_content(chunk_size=1024):
                    if chunk:
                        print(chunk.decode('utf8'), file=fh, end='')

        # else, just return the content as str
        else:
            return requests.get(self._url+query).content


    def geturl(self):
        """ Get the backend url used for queries """
        return _API_URL_BASE.format(host=self.host, port=self.port, path=self.path, api=self.api)


    def extract(self, fromts=0, tots="", outdir=None, filtercharts=None):

        # Extract the charts
        try:
            chartsoutput = self._query("/charts")

            # Write output file
            chartsfile = open(outdir + "/charts.json", "wb+")
            chartsfile.write(chartsoutput)
            chartsfile.close()

            chartsdata = json.loads(chartsoutput)



            # Now, foreach chart, get its data
            for chartname,chartdata in chartsdata.get('charts', []).items():

                urlfmt = (
                    "/data?chart={0}&format=json"
                    "&group=average&gtime=0&points=0"
                    "&after={1}&before={2}&points={3}"
                )

                url = urlfmt.format(chartname, fromts, tots, '')
                outfile = outdir + "/" + chartname + ".json"

                self._query(url, outfile)


        except Exception as e:
            print(e)

"""
"snapshot_version": 1,
"server": "http://'+self.host+':'+self.port+'/'+self.path+'",
"hostname": "todo",
"url": "' + self.geturl() +'",
"netdata_version": "1234",
"update_every_ms": 1000,
"hash": "#",
"highlight_after_ms": 0,
"highlight_before_ms": 0,
"compression": "none",
"charts_ok": 999,
"charts_failed": 0,
"charts": ' + json.dumps(chartsjson) + ',
"info": {},
"data_points": 999,
"data_size": "123456789,
"data": {')
"""



if __name__ == "__main__":

    import os
    import argparse
    import datetime

    myself = os.path.realpath(__file__)
    mydir = os.path.dirname(myself)

    # Default output folder
    outdir = mydir + "/extracts/netdata_"  + datetime.datetime.now().strftime("%y%m%d_%H%M%S")


    # Parse arguments
    argsparser = argparse.ArgumentParser(description="Extract netdata values")
    argsparser.add_argument('-H', '--host',   help="Target server to query", default=_API_DEF_HOST)
    argsparser.add_argument('-P', '--port',   help="Port of target server",  default=_API_DEF_PORT, type=int)
    argsparser.add_argument('-S', '--subpath', help="Path to connect to host", default=_API_DEF_PATH)
    argsparser.add_argument('-o', '--outdir', help="Output folder to store data files", default=outdir)
    argsparser.add_argument('-b', '--begin',  help="Timestamp of collection begin", default=0)
    argsparser.add_argument('-e', '--end',    help="Timestamp of collection end", default='')

    args = argsparser.parse_args()

    # Call for extraction
    nd = NetdataAPI(host=args.host, port=args.port, path=args.subpath)

    # Create output folder
    os.makedirs(outdir)

    # Extract to requested dest
    nd.extract(outdir=args.outdir)

    print(args.outdir)

