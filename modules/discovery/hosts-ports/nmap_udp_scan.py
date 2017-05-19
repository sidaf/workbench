from lib.core.module import BaseModule
from lib.mixins.nmap import NmapMixin
from netaddr import *
import os


class Module(BaseModule, NmapMixin):

    meta = {
        'name': 'Nmap UDP Scan',
        'author': 'Sion Dafydd',
        'description': ('Identify open UDP ports by performing a UDP scan using the Nmap security scanner. '
                        'Updates the \'ports\' table with the results.'),
        'query': 'SELECT DISTINCT ip_address FROM hosts WHERE ip_address IS NOT NULL',
        'options': (
            ('ports', '7,9,17,19,49,53,67-69,80,88,111,120,123,135-139,158,161,162,177,427,443,445,497,500,514,515,518,'
                      '520,593,623,626,631,996-999,1022,1023,1025-1030,1433,1434,1645,1646,1701,1718,1719,1812,1813,'
                      '1900,2000,2048,2049,2222,2223,3283,3456,3703,4444,4500,5000,5060,5353,5632,9200,10000,17185,'
                      '20031,30718,31337,32768,32769,32771,32815,33281,49152-49154,49156,49181,49182,49186,49188,'
                      '49190-49194,49200,49201,49211,65024,523,1604,2302,2362,3478,3671,6481,44818,47808',
                      True, 'the UDP ports to be scanned'),
            ('version_detection', False, True, 'if set to true will also perform service and version detection'),
            ('speed', 4, True, 'speed as per Nmap timing templates (-T#)'),
            ('internal', False, True, 'if set to true a scan profile suited for scanning an internal network is used, '
                                      'otherwise an external network profile is used'),
        ),
    }

    def module_run(self, ip_addresses):
        # Check if Nmap is installed
        nmap_path = self.whereis('nmap')
        if nmap_path is None:
            self.error("Nmap is not installed or could not be found in system path")
            return

        # Merge ip addresses to create the smallest possible list of subnets
        subnets = list()
        for ip_address in ip_addresses:
            subnets.append(IPNetwork(ip_address))
        subnets = cidr_merge(subnets)
        merged = list()
        for subnet in subnets:
            merged.append(str(subnet))
        target = " ".join(merged)

        # Build Nmap arguments
        ports = "%s" % self.options['ports']
        version = '-sV --version-all' if self.options['version_detection'] else ''
        speed = '%s' % self.options['speed']
        variable = '-g 88 --max-rtt-timeout=500ms' if self.options['internal'] else '-g 53 --max-rtt-timeout=1000ms'

        file_path = self.generate_uniq_filepath()
        xml_out = "%s" % os.path.splitext(file_path)[0] + '.xml'

        # Compile command string and execute
        command = "%s -v -Pn -n -sU %s -T%s -p %s --open %s --initial-rtt-timeout=200ms --min-rtt-timeout=100ms " \
                  "--stats-every 15s -oX %s %s" % (nmap_path, version, speed, ports, variable, xml_out, target)
        output = self.execute(command, sudo=True)
        self.save_output(file_path, output)

        # parse xml_out to import open port information, but only for the ip addresses in the list provided
        ports = self.extract_ports(xml_out, ip_addresses)
        count = 0
        for port in ports:
            count += self.add_ports(ip_address=port['ip_address'], host=port['host'], port=port['port'],
                                    state=port['state'], protocol=port['protocol'], service=port['service'],
                                    product=port['product'], version=port['version'], extrainfo=port['extrainfo'])

