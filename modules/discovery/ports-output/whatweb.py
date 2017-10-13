from lib.core.module import BaseModule
from urlparse import urlparse
import os


class Module(BaseModule):

    meta = {
        'name': 'WhatWeb',
        'author': 'Sion Dafydd',
        'description': ('Identify websites hosted on web servers using the WhatWeb tool. '
                        'Updates the \'notes\' table with the results.'),
        'query': "SELECT ports.service || '://' || ports.ip_address || ':' || ports.port || '|' || COALESCE(hosts.host, '') FROM ports JOIN hosts ON ports.ip_address=hosts.ip_address WHERE ports.service LIKE 'http%' AND ports.ip_address NOT NULL ORDER BY ports.ip_address",
        'options': (
            ('aggression', 3, True, 'the aggression level of a scan (-a #), valid values include 1, 3, and 4'),
            ('path', os.path.join(BaseModule.workspace, 'whatweb'), True, 'path for output'),
        ),
    }

    def module_run(self, targets):
        # Check if WhatWeb is installed
        bin_path = self.whereis('whatweb')
        if bin_path is None:
            self.error("WhatWeb is not installed or could not be found in system path")
            return

        # Build WhatWeb arguments
        aggression = "%s" % self.options['aggression']

        for target in targets:
            line = target.rsplit('|')

            url = line[0]
            u_parse = urlparse(url, allow_fragments=False)
            # Append a slash to the the url if there is no defined path
            if u_parse.path == '':
                url += '/'
                u_parse = urlparse(url, allow_fragments=False)

            if line[1] and line[1] != '':
                vhost = line[1]
            else:
                vhost = u_parse.hostname

            path = self.options['path']
            filename = self.generate_uniq_filename(
                prefix="%s-[%s]-" % (url.replace("//", "_").replace(":", "_").replace("/", "_"), vhost))
            file_path = os.path.join(path, filename)

            # Create the directory structure required to store the log output
            if not os.path.exists(os.path.dirname(file_path)):
                os.makedirs(os.path.dirname(file_path))

            # Compile command string and execute
            command = "%s -a %s --quiet --colour=never --follow-redirect=never " \
                      "--header \"Host:%s\" --log-brief=\"%s\" %s" % (bin_path, aggression, vhost, file_path, url)

            output = self.shell(command, suppress_stdout=True)

            if os.stat(file_path).st_size == 0:
                os.remove(file_path)
            else:
                # parse log to import information
                with open(file_path, 'r') as fh:
                    for line in fh:
                        if line.rstrip() == '':
                            continue
                        if not line.startswith('http'):
                            continue
                        if "ERROR:" in line:
                            continue
                        host = vhost if u_parse.hostname != vhost else ''
                        if u_parse.port is None:
                            if u_parse.scheme == 'https':
                                port = 443
                            else:
                                port = 80
                        else:
                            port = u_parse.port
                        #self.add_notes(ip_address=u_parse.hostname, host=host, port=port,
                        #               protocol='tcp', service=u_parse.scheme, note=line.rstrip())
                        self.output(line.rstrip())

            if output != '':
                lines = output.splitlines()
                for line in lines:
                    if not line.startswith('http'):
                        continue
                    else:
                        self.error("Analysis of %s [Host:%s] failed, %s" % (url, vhost, line.rstrip().split('ERROR:', 1)[1]))
