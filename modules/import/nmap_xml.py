from lib.core.module import BaseModule
from lib.mixins.nmap import NmapMixin


class Module(BaseModule, NmapMixin):
    meta = {
        'name': 'Nmap XML Importer',
        'author': 'Sion Dafydd',
        'description': 'Imports hosts and ports from an Nmap XML file.',
        'options': (
            ('filename', None, True, 'path and filename for list input'),
            ('import_hosts', True, True, 'if true hosts table is populated'),
            ('import_ports', True, True, 'if true ports table is populated'),
        ),
    }

    def module_run(self):
        file_path = self.options['filename']

        if self.options['import_hosts']:
            hosts = self.extract_hosts(file_path)
            count = 0
            for host in hosts:
                count += self.add_hosts(ip_address=host['ip_address'], host=host['host'])

        if self.options['import_ports']:
            ports = self.extract_ports(file_path)
            count = 0
            for port in ports:
                count += self.add_ports(ip_address=port['ip_address'], host=port['host'], port=port['port'],
                                        state=port['state'], protocol=port['protocol'], service=port['service'],
                                        product=port['product'], version=port['version'])
