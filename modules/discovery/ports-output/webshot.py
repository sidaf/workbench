from lib.core.module import BaseModule
from urlparse import urlparse
import os


class Module(BaseModule):

    meta = {
        'name': 'Website Screenshots',
        'author': 'Sion Dafydd',
        'description': 'Take screenshots of hosted websites using the PhantomJS tool.',
        'query': "SELECT ports.service || '://' || ports.ip_address || ':' || ports.port || '|' || COALESCE(hosts.host, '') FROM ports JOIN hosts ON ports.ip_address=hosts.ip_address WHERE ports.service LIKE 'http%' AND ports.ip_address NOT NULL ORDER BY ports.ip_address",
        'options': (
            ('path', os.path.join(BaseModule.workspace, 'webshot'), True, 'path for output'),
        ),
    }

    def module_run(self, targets):
        # Check if WhatWeb is installed
        bin_path = self.whereis('phantomjs')
        if bin_path is None:
            self.error("PhantomJS is not installed or could not be found in system path")
            return

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
                prefix="%s-[%s]-" % (url.replace("//", "_").replace(":", "_").replace("/", "_"), vhost), suffix='png')
            file_path = os.path.join(path, filename)

            # Create the directory structure required to store the log output
            if not os.path.exists(path):
                os.makedirs(path)

            proxy = ''
            if self._global_options['proxy']:
                proxy = "--proxy=%s" % self._global_options['proxy']

            # Compile command string and execute
            command = "%s --ignore-ssl-errors=yes --ssl-protocol=ANY %s \"%s\" %s %s \"%s\" 1024px*768px" % (
                bin_path, proxy, os.path.join(self.data_path, 'webshot.js'), url, vhost, file_path)
            output = self.shell(command, suppress_stdout=True)
            if output == '':
                self.output("Screenshot of %s [Host:%s] saved." % (url, vhost))
            else:
                self.error("Screenshot of %s [Host:%s] failed, %s" % (url, vhost, output.rstrip()))
