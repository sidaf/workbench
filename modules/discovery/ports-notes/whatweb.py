from lib.core.module import BaseModule
import os


class Module(BaseModule):

    meta = {
        'name': 'WhatWeb',
        'author': 'Sion Dafydd',
        'description': ('Identify websites hosted on web servers using the WhatWeb tool. '
                        'Updates the \'notes\' table with the results.'),
        'query': "SELECT service || ',' || COALESCE(ip_address, '') || ',' || port || ',' || COALESCE(host, '') "
                 "FROM ports WHERE service LIKE 'http%'",
        'options': (
            ('aggression', 3, True, 'the aggression level of a scan (-a #), valid values include 1, 3, and 4'),
        ),
    }

    def module_run(self, targets):
        # Check if WhatWeb is installed
        bin_path = self.whereis('whatweb')
        if bin_path is None:
            self.error("WhatWeb is not installed or could not be found in system path")
            return

        for target in targets:
            # Build WhatWeb arguments
            aggression = "%s" % self.options['aggression']

            # Build URL value
            args = target.split(',')
            service = args[0]
            ip_address = args[1]
            host = args[3]

            if ip_address != '' and host != '':
                server = ip_address
                header = host
            elif host != '' and ip_address == '':
                server = host
                header = host
            elif host == '' and ip_address != '':
                server = ip_address
                header = ip_address
            elif host != '' and ip_address != '':
                self.error("host and ip_address values cannot be empty! skipping...")
                continue

            # Don't append standard ports
            port = ":%s" % args[2] if args[2] != '443' and args[2] != '80' else ''

            url = "%s://%s%s" % (service, server, port)

            file_path = self.generate_uniq_filepath(
                prefix="%s-[%s]-" % (url.replace("//", "_").replace(":", "_").replace("/", "_"), header))

            # Create the directory structure required to store the log output
            if not os.path.exists(os.path.dirname(file_path)):
                os.makedirs(os.path.dirname(file_path))

            # Compile command string and execute
            command = "%s -a %s --quiet --colour=never --follow-redirect=never " \
                      "--header \"Host:%s\" --log-brief=%s %s" % (bin_path, aggression, header, file_path, url)

            output = self.execute(command, suppress_stdout=True)

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
                        self.add_notes(ip_address=ip_address, host=host, port=args[2],
                                       protocol='tcp', service=service, note=line.rstrip())

            if output != '':
                lines = output.splitlines()
                for line in lines:
                    if not line.startswith('http'):
                        continue
                    else:
                        self.error("Analysis of %s [Host:%s] failed, %s" % (url, header, line.rstrip().split('ERROR:', 1)[1]))
