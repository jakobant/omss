import json
import sys
import os
import time
import re
import argparse
import requests
import urllib.request
from datetime import datetime

from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class NessusScans:

    def __init__(self):
        self.session = requests.Session()

        self.api_url = os.getenv('NESSUS_API_URL', None)
        self.api_access_key = os.getenv('ACCESS_KEY', None)
        self.api_secret_key = os.getenv('SECRET_KEY', None)
        self.report_folder = os.getenv('REPORT_FOLDER', '/tmp')
        self._set_apikeysheaders()
        self.user_token = None
        self.user_session = requests.Session()
        self._set_userheaders()
        self.username = os.getenv('NESSUS_USERNAME', None)
        self.password = os.getenv('NESSUS_PASSWORD', None)
        self.slack_hook =  os.getenv('SLACK_HOOK', None)
        self.scans = None

    def notify(self, msg, who=None):
        prefix = ''
        if who:
            prefix = f'<@{who}>: '

        values = {'text': f'{prefix}{msg}'}
        data = json.dumps(values).encode('ascii')
        headers = {'Content-type': 'application/json'}
        req = urllib.request.Request(self.slack_hook, data, headers)
        with urllib.request.urlopen(req) as response:
            the_page = response.read()
            return the_page == b'ok'

    def _set_apikeysheaders(self):
        if None in [self.api_secret_key, self.api_access_key, self.api_url]:
            raise RuntimeError('API_URL, ACCESS_KEY or SECRET_KEY missing!!!')
        self.session.headers = {
            'Origin': self.api_url,
            'Accept-Language': 'en-US,en;q=0.8',
            'Content-Type': 'application/json',
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Referer': self.api_url,
            'Connection': 'keep-alive',
            'X-Cookie': None,
            'X-ApiKeys': 'accessKey={}; secretKey={}'.format(self.api_access_key, self.api_secret_key)
        }

    def _set_userheaders(self, token=''):
        self.user_session.headers = {
            'Origin': self.api_url,
            'Accept-Language': 'en-US,en;q=0.8',
            'Content-Type': 'application/json',
            'Accept': 'application/json, text/javascript, */*; q=0.01',
            'Referer': self.api_url + '/api',
            'Connection': 'keep-alive',
            'X-Requested-With': 'XMLHttpRequest',
            'X-Cookie': 'token='+token,
            'X-API-Token': '9A7C788B-7107-4D5F-9B98-0E2C913479A0'
        }

    #'X-API-Token':
    def create_session(self):

        if None in [self.username, self.password]:
            raise RuntimeError('NESSUS_USERNAME or NESSUS_PASSWORD missing!!!')
        data = { 'username': self.username, 'password': self.password }
        response = self.user_session.post('{}/session'.format(self.api_url), data=json.dumps(data), verify=False)
        self._set_userheaders(token=response.json()['token'])
        try:
            token = response.json()['token']
            self.user_token = token
        except Exception as e:
            print('Err', e)
            sys.exit(1)

    def start_scan(self, scan_id):
        if not self.user_token:
            self.create_session()
        response = self.user_session.post('{}/scans/{}/launch'.format(self.api_url, scan_id), verify=False)
        return response.json()

    def stop_scan(self, scan_id):
        if not self.user_token:
            self.create_session()
        response = self.user_session.post('{}/scans/{}/kill'.format(self.api_url, scan_id), verify=False)

    def get_filename_from_cd(self, cd):
        if not cd:
            return None
        fname = re.findall('filename=\"(.+)\"', cd)
        if len(fname) == 0:
            return None
        return fname[0]

    def get_folders(self):
        response = self.session.get('{}/folders'.format(self.api_url), verify=False)
        return response.json()['folders']

    def get_scans(self, folder=None):
        if folder:
            folder= {
                'folder_id': folder
            }
        response = self.session.get('{}/scans'.format(self.api_url), verify=False, params=folder)
        self.scans = response.json()

    def get_scan_details(self, scan_id, history_id):
        response = self.session.get('{}/scans/{}?historiy_id={}'.format(
            self.api_url, scan_id, history_id), verify=False)
        return response.json()

    def get_scan_id_info(self, folder):
        for folder_id in self.scans['folders']:
            if folder_id['id'] == folder:
                return folder_id
        return "Unknown"

    def get_scan_history(self, scan_id):
        res = self.get_scan_detail(scan_id)
        return res['history']

    def get_scanids(self):
        if not self.scans['scans']:
            return []
        scan_ids = [scan_id['id'] for scan_id in self.scans['scans']]
        return scan_ids

    def wait_on_export(self, file, scan_id):
        waiting = True
        counter = 0
        while waiting:
            export_status = self.session.get('{}/scans/{}/export/{}/status'.format(self.api_url, scan_id, file), verify=False)
            if export_status.json()['status'] == 'ready':
                waiting = False
            time.sleep(3)
            counter += 3
            sys.stdout.write(".")
            sys.stdout.flush()

    def download_scan_csv(self, scan_id, history, file, folder):
        scan_folder_name = self.get_scan_id_info(folder)['name'].replace(' ', '_')
        if not os.path.exists(os.path.join(self.report_folder, scan_folder_name)):
            os.mkdir(os.path.join(self.report_folder, scan_folder_name))
        scan = self.get_scan_details(scan_id, history['history_id'])
        info = scan['info']
        # Enrich the filename with scan details
        filename = '{}#{}#{}#{}#{}#{}.csv'.format(
            scan_folder_name,
            scan_id,
            history['uuid'],
            history['creation_date'],
            history['last_modification_date'],
            info['name'].replace(' ', '_').replace('/', '_'))
        response = self.session.get('{}/scans/{}/export/{}/download'.format(self.api_url, scan_id, file), verify=False)
        print("Downloaded report {} as {}".format(self.get_filename_from_cd(response.headers['Content-Disposition']), filename))

        full_filename = os.path.join(self.report_folder, scan_folder_name, filename)
        open(full_filename, 'wb').write(response.content)

    def get_scanner_status(self):
        response = self.session.get('{}/scanners/1/scans'.format(self.api_url), verify=False)
        return response.json()

    def get_host_detail(self, scan_id, host_id):
        response = self.session.get('{}/scans/{}/hosts/{}'.format(self.api_url, scan_id, host_id), verify=False)
        return response.json()

    def get_host_plugin_detail(self, scan_id, host_id, plugin_id):
        response = self.session.get('{}/scans/{}/hosts/{}/plugins/{}'.format(self.api_url, scan_id,
                                                                             host_id, plugin_id), verify=False)
        return response.json()

    def get_scan_detail(self, scan_id):
        response = self.session.get('{}/scans/{}'.format(self.api_url, scan_id), verify=False)
        return response.json()

    def print_scan_details(self, scan_id):
        scan = self.get_scan_detail(scan_id)
        print(scan['info']['hostcount'])
        for host in scan['hosts']:
            #import pdb; pdb.set_trace()
            print(host)
            detail = self.get_host_detail(scan_id, host['host_id'])
            print(detail['info'])
            for vuln in detail['vulnerabilities']:
                #print(vuln)
                if vuln['plugin_id'] in (22964, 56984):
                    print(vuln['plugin_name'])
                    pid = self.get_host_plugin_detail(scan_id, host['host_id'], vuln['plugin_id'])
                    for o in pid['outputs']:
                        print(o['ports'])

    def get_folder_info(self, folders, scan_id):
        scan_info = self.get_scan_detail(scan_id)
        folder_id = scan_info['info']['folder_id']
        for folder in folders:
            if folder['id'] == folder_id:
                return folder

    def monitor_scans(self):
        folders = self.get_folders()
        scan_ids = []
        while True:
            scanner = self.get_scanner_status()
            if scanner['scans']:
                for scan in scanner['scans']:
                    folder = self.get_folder_info(folders, scan['scan_id'])
                    if scan['scan_id'] not in scan_ids:
                        self.notify('{} for {} on {} started at {}'.format(
                            scan['name'],
                            folder['name'],
                            self.api_url,
                            datetime.fromtimestamp(int(scan['start_time']))))
                    if (scan['scan_id']) not in scan_ids:
                        scan_ids.append(scan['scan_id'])
            temp_scanids = scan_ids
            for scan in temp_scanids:
                scan_detail = self.get_scan_detail(scan)
                if scan_detail['info']['status'] != 'running':
                    folder = self.get_folder_info(folders, scan)
                    self.notify('{} for {} on {} ended at {}'.format(
                        scan_detail['info']['name'],
                        folder,
                        self.api_url,
                        datetime.fromtimestamp(int(scan_detail['info']['scan_end']))))
                    scan_ids.remove(scan)
            time.sleep(60 * 2)

    def export_scan_csv(self, scan_id=None, current_folder=None, history=None):
        data = {
            'format': 'csv',
            'reportContents': {
                'hostSections': {
                    'scan_information': True,
                    'host_information': True
                },
                'csvColumns': {
                    'synopsis': True,
                    'description': True,
                    'see_also': True,
                    'solution': True,
                    'risk_factor': True,
                    'cvss3_base_score': True,
                    'cvss3_temporal_score': True,
                    'cvss_base_score': True,
                    'cvss_temporal_score': True,
                    'stig_severity': True,
                    'references': True,
                    'exploitable_with': True,
                    'plugin_information': True,
                    'plugin_output': True
                }
            },
        }
        print("Exporting report for scan id: {} with history {}.".format(scan_id, history['history_id']))
        response = self.session.post('{}/scans/{}/export?history_id={}'.format(
            self.api_url, scan_id, history['history_id']), data=json.dumps(data), verify=False)
        print(response.json())
        try:
            file = response.json()['file']
        except Exception as e:
            print('Err', e)
            sys.exit(1)
        self.wait_on_export(file, scan_id)
        self.download_scan_csv(scan_id, history, file, current_folder)


def setup_parser(parser):
    parser.add_argument('--folder_id', type=str, default=None, help='Download folder id')
    parser.add_argument('--history', default=False, action='store_true', help='Download all history')
    parser.add_argument('--scanid', type=str, default=None, help='Scanid to download')
    parser.add_argument('--monitor', action='store_true', help='Monitor Running scan')
    parser.add_argument('--scan_targets', type=str, default=None, help='Scan id targets')
    parser.add_argument('--start_scan', type=str, default=None, help='Start Scan id')
    parser.add_argument('--kill_scan', type=str, default=None, help='Kill Scan id')
    parser.set_defaults(func=main, monitor=False)
    return parser


def export_scans(nessus, args, fid):
    nessus.get_scans(folder=fid)
    scans = nessus.get_scanids()
    if args.scanid and int(args.scanid) in scans:
        scans = [args.scanid]
    # else:
    #    print("Scanid {} not found!!!".format(args.scanid))
    #    #sys.exit(1)
    for scanid in scans:
        historys = nessus.get_scan_history(scan_id=scanid)
        if historys and args.history:
            for history in historys:
                nessus.export_scan_csv(scan_id=scanid, history=history, current_folder=fid)
        elif historys:
            history = historys[len(historys) - 1]
            nessus.export_scan_csv(scan_id=scanid, history=history, current_folder=fid)


def main(args):
    nessus = NessusScans()
    if args.start_scan:
        nessus.start_scan(args.start_scan)
    if args.kill_scan:
        nessus.stop_scan(args.kill_scan)
    if args.scan_targets:
        res = nessus.get_scan_detail(args.scan_targets)
        print(res['info']['targets'])
    if args.monitor:
        nessus.monitor_scans()
    if args.folder_id:
        fid = int(args.folder_id)
        if fid == 0: #All scans
            folders = nessus.get_folders()
            for folder in folders:
                export_scans(nessus, args, int(folder['id']))
        else:
            export_scans(nessus, args, fid)


if __name__ == '__main__':
    parser = setup_parser(argparse.ArgumentParser())
    args = parser.parse_args()
    args.func(args)
