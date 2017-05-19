from lib.core.module import BaseModule
from lib.mixins.nmap import NmapMixin
from netaddr import *
import os


class Module(BaseModule, NmapMixin):

    meta = {
        'name': 'Nmap SYN Ping',
        'author': 'Sion Dafydd',
        'description': ('Identify active hosts by performing SYN ping scan against the 100 most common TCP ports '
                        'using the Nmap security scanner. Updates the \'hosts\' table with the results.'),
        'query': 'SELECT DISTINCT netblock FROM netblocks WHERE netblock IS NOT NULL',
    }

    def module_run(self, netblocks):
        # Check if Nmap is installed
        nmap_path = self.whereis('nmap')
        if nmap_path is None:
            self.error("Nmap is not installed or could not be found in system path")
            return

        # Merge ip addresses to create the smallest possible list of subnets
        subnets = list()
        for netblock in netblocks:
            subnets.append(IPNetwork(netblock))
        subnets = cidr_merge(subnets)
        merged = list()
        for subnet in subnets:
            merged.append(str(subnet))
        target = " ".join(merged)

        # Build Nmap arguments
        file_path = self.generate_uniq_filepath()
        xml_out = "%s" % os.path.splitext(file_path)[0] + '.xml'

        # Compile command string and execute
        command = "%s -v -sn -n -PS7,9,13,21-23,25-26,37,53,79,80-81,88,106,110-111,113,119,135,139,143-144,179,199," \
                  "389,427,443-445,465,513-515,543,544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720," \
                  "1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101," \
                  "5190,5357,5432,5631,5666,5800,5900,6000-6001,6646,7070,8000,8008-8009,8080,8081,8443,8888,9100," \
                  "9999,10000,32768,49152-49157 --reason --stats-every 15s -oX %s %s" % (nmap_path, xml_out, target)
        output = self.execute(command, sudo=True)
        self.save_output(file_path, output)

        # parse xml_out to import active hosts
        hosts = self.extract_hosts(xml_out)
        count = 0
        for host in hosts:
            count += self.add_hosts(ip_address=host['ip_address'], host=host['host'])
        self.output("%d new records added." % count)

