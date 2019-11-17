#!/usr/bin/env python3

from cyapi.cyapi import CyAPI
from cortexutils.analyzer import Analyzer
import requests

class CylanceAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.tid = self.get_param('config.tid', None, 'Tenant ID is missing')
        self.app_id = self.get_param('config.app_id', None, 'App_ID is missing')
        self.app_secret = self.get_param('config.app_secret', None, 'Secret is missing')
        self.polling_interval = self.get_param('config.polling_interval', 60)
        self.API = CyAPI(self.tid, self.app_id, self.app_secret)
        self.API.create_conn()

    def run(self):
        if self.data_type == 'hash':
            data = self.get_param('data', None, 'Data is missing')
            myurl = self.API.get_threat_download_url(sha256=data)
            print(myurl.data)

            r = requests.get(myurl.data['url'], allow_redirects=True)
            open('/tmp/sample', 'wb').write(r.content)

if __name__ == '__main__':
    CylanceAnalyzer().run()
