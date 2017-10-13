from lib.core.module import BaseModule
from lib.mixins.nessus import NessusMixin, SSLException, HttpException
import time
import os
import sys


class Module(BaseModule, NessusMixin):

    meta = {
        'name': 'Nessus Vulnerability Scanner',
        'author': 'Sion Dafydd',
        'description': 'Detect vulnerabilities with the Tenable Nessus vulnerability scanner. This module will use the '
                       '\'ports\' table to gather hosts and corresponding ports to scan. Only the ports stored within '
                       'this table will be scanned.',
        'options': (
            ('url', 'https://localhost:8834', True, 'nessus server'),
            ('username', 'nmap_username', True, 'nessus username'),
            ('password', 'nmap_password', True, 'nessus password'),
            ('concurrent', 10, True, 'maximum concurrent scans'),
        ),
    }

    def module_run(self):

        try:
            scanner = self.get_scanner(url=self.options['url'], username=self.options['username'],
                                       password=self.options['password'])
            self.output("Connecting to the Nessus server on %s" % self.options['url'])
            scanner.login()
        except HttpException as http_e:
            self.error("%s" % http_e)
            return

        scans = list()
        path = self.generate_uniq_filepath()
        # create the directory structure required to store the nessus output
        if not os.path.exists(os.path.dirname(path)):
            os.makedirs(os.path.dirname(path))

        query_ips = self.query('SELECT DISTINCT ip_address FROM ports WHERE ip_address IS NOT NULL')
        for ip_address in query_ips:
            host = ip_address[0]
            query_ports = self.query('SELECT port FROM ports WHERE ip_address = ? AND port NOT NULL', (host,))
            ports = set()
            for port in query_ports:
                ports.add(port[0])
            if len(ports) == 0:
                continue
            # scan host
            while len(scans) >= self.options['concurrent']:
                self.check_scans(scanner, scans, os.path.dirname(path))
                if len(scans) < self.options['concurrent']:
                    break
                time.sleep(15)
            self.output('Scanning ports %s on host %s' % (','.join(sorted(ports)), host))
            scan_id = scanner.create_scan(host, host, ','.join(sorted(ports)))
            scanner.start_scan(scan_id)
            scans.append(scan_id)

        self.output("[*] All scans submitted, waiting for scans to finish...")
        last = 0
        while len(scans) > 0:
            self.check_scans(scanner, scans, os.path.dirname(path))
            if len(scans) == 0:
                break
            if len(scans) != last:
                self.output("%s left..." % (len(scans)))
                sys.stdout.flush()
                last = len(scans)
            time.sleep(15)
        self.output("Finished.")

    def check_scans(self, scanner, scans, path):
        data = scanner.list_scans()
        for scan in data:
            if (scan['status'] == 'completed' or scan['status'] == 'aborted' or scan['status'] == 'canceled') \
                    and scan['id'] in scans:
                scanner.download_report(scan['id'], '%s/%s.nessus' % (path, scan['name']))
                scanner.delete_scan(scan['id'])
                scans.remove(scan['id'])
