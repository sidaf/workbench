from lib.core.module import BaseModule
import os


class Module(BaseModule):

    meta = {
        'name': 'Website Screenshots',
        'author': 'Sion Dafydd',
        'description': 'Take screenshots of hosted websites using the PhantomJS tool.',
        'query': "SELECT service || ',' || COALESCE(ip_address, '') || ',' || port || ',' || COALESCE(host, '') "
                 "FROM ports WHERE service LIKE 'http%'",
    }

    def module_run(self, targets):
        # Check if WhatWeb is installed
        bin_path = self.whereis('phantomjs')
        if bin_path is None:
            self.error("PhantomJS is not installed or could not be found in system path")
            return

        for target in targets:
            # Build PhantomJS arguments
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
                prefix="%s-[%s]-" % (url.replace("//", "_").replace(":", "_").replace("/", "_"), header), suffix='png')

            # Create the directory structure required to store the log output
            if not os.path.exists(os.path.dirname(file_path)):
                os.makedirs(os.path.dirname(file_path))

            # Compile command string and execute
            command = "%s --ignore-ssl-errors=yes --ssl-protocol=ANY %s %s %s %s 1024px*768px" % (bin_path,
                                                                            os.path.join(self.data_path, 'webshot.js'),
                                                                            url, header, file_path)
            output = self.execute(command, suppress_stdout=True)
            if output == '':
                self.output("Screenshot of %s [Host:%s] saved to %s" % (url, header, file_path))
            else:
                self.error("Screenshot of %s [Host:%s] failed, %s" % (url, header, output.rstrip()))
