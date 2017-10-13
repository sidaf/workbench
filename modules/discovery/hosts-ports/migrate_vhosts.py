from lib.core.module import BaseModule
import re


class Module(BaseModule):

    meta = {
        'name': 'Migrate Virtual Hosts',
        'author': 'Sion Dafydd',
        'description': 'Add duplicate entries to the \'port\' table for all ports bound to http/https based services '
                       'that have a corresponding IP address with a host entry in the \'hosts\' table',
    }

    def module_run(self):
        # get a list of ports that are bound by either http or https based services
        ports = self.query('SELECT * FROM ports WHERE service LIKE "http%"')
        for port in ports:
            # get a list of all hosts entries with a matching ip address and a host value
            hosts = self.query("SELECT host FROM hosts WHERE ip_address=? AND host NOT NULL", (port[0],))
            for host in hosts:
                self.add_ports(ip_address=port[0], host=host[0], port=port[2], state=port[3], protocol=port[4],
                               service=port[5], product=port[6], version=port[7])
