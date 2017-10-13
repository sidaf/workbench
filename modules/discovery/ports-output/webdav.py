from lib.core.module import BaseModule
from urlparse import urlparse


class Module(BaseModule):

    meta = {
        'name': 'WebDav Scanner',
        'author': 'Sion Dafydd',
        'description': 'Detect webservers with WebDAV enabled',
        'query': "SELECT service || '://' || ip_address || ':' || port FROM ports "
                 "WHERE service LIKE 'http%' AND ip_address NOT NULL",
    }

    def module_run(self, targets):
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

            # perform request
            try:
                resp = self.request(url, method='OPTIONS', headers={'Host': vhost}, redirect=False)
            except IOError as e:
                self.error("Error connecting to %s, %s" % (url, e))
                continue

            if 'dav' in resp.headers:
                header = resp.headers['dav']
                webdav_type = 'WEBDAV'
                if header == '1, 2' or header[0:3] == '1,2':
                    webdav_type = 'SHAREPOINT DAV'
                self.alert("%s (%s) has %s enabled." % (url, vhost, webdav_type))

