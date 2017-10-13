from lib.core.module import BaseModule
from lib.mixins.nmap import NmapMixin
from netaddr import *
import os


class Module(BaseModule, NmapMixin):

    meta = {
        'name': 'Nmap SYN Scan',
        'author': 'Sion Dafydd',
        'description': ('Identify open TCP ports by performing a SYN scan using the Nmap security scanner. '
                        'Updates the \'ports\' table with the results.'),
        'query': 'SELECT DISTINCT ip_address FROM hosts WHERE ip_address IS NOT NULL',
        'options': (
            ('ports', '1-65535', True, 'the TCP ports to be scanned'),
            ('version_intensity', 7, True, 'intensity level of version detection, must be between 0 and 9'),
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
        version = '-sV --version-intensity %s' % self.options['version_intensity']
        speed = '%s' % self.options['speed']
        variable = '-g 88 --max-rtt-timeout=500ms' if self.options['internal'] else '-g 53 --max-rtt-timeout=1000ms'

        file_path = self.generate_uniq_filepath()
        # create the directory structure required to store the log output
        if not os.path.exists(os.path.dirname(file_path)):
            os.makedirs(os.path.dirname(file_path))
        xml_out = "%s" % os.path.splitext(file_path)[0] + '.xml'

        # Compile command string and execute
        command = "%s -v -Pn -n -sS %s -T%s -p %s --open %s --initial-rtt-timeout=200ms --min-rtt-timeout=100ms " \
                  "--stats-every 15s -oX %s %s" % (nmap_path, version, speed, ports, variable, xml_out, target)
        output = self.shell(command, sudo=True)
        self.save_output(file_path, output)

        # parse xml_out to import open port information, but only for the ip addresses in the list provided
        ports = self.extract_ports(xml_out, ip_addresses)
        count = 0
        for port in ports:
            count += self.add_ports(ip_address=port['ip_address'], host=port['host'], port=port['port'],
                                    state=port['state'], protocol=port['protocol'], service=port['service'],
                                    product=port['product'], version=port['version'])

