from lib.core.module import BaseModule
from lib.mixins.nmap import NmapMixin
from netaddr import *
import os


class Module(BaseModule, NmapMixin):

    meta = {
        'name': 'Nmap SYN Ping',
        'author': 'Sion Dafydd',
        'description': ('Identify active hosts by performing UDP ping scan against the 25 most common UDP ports '
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
        command = "%s -v -sn -n -PU53,67,68-69,111,123,135,137-139,161-162,445,500,514,520,631,998,1434,1701,1900," \
                  "4500,5353,49152,49154 --reason --stats-every 15s -oX %s %s" % (nmap_path, xml_out, target)
        output = self.execute(command, sudo=True)
        self.save_output(file_path, output)

        # parse xml_out to import active hosts
        hosts = self.extract_hosts(xml_out)
        count = 0
        for host in hosts:
            count += self.add_hosts(ip_address=host['ip_address'], host=host['host'])
        self.output("%d new records added." % count)

