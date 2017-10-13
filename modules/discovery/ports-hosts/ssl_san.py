from lib.core.module import BaseModule
from socket import socket
import OpenSSL
import re


class Module(BaseModule):

    meta = {
        'name': 'SSL SAN Lookup',
        'author': 'Sion Dafydd',
        'description': 'This module will parse the SSL certificate provided by the remote service and enumerate any '
                       'subject alternative names. Updates the \'hosts\' table with the results.',
        'query': "SELECT DISTINCT(ip_address || ':' || port) FROM ports WHERE service = 'https' AND ip_address NOT NULL",
    }

    def module_run(self, targets):
        for target in targets:
            ip_address = str(target.split(':')[0])
            port = int(target.split(':')[1])

            context = OpenSSL.SSL.Context(OpenSSL.SSL.SSLv23_METHOD)
            context.set_verify(OpenSSL.SSL.VERIFY_NONE, self.verify_cb)
            sock = socket()
            try:
                sock.connect((ip_address, port))
                sock.setblocking(1)
                connection = OpenSSL.SSL.Connection(context, sock)
                connection.set_connect_state()
                connection.do_handshake()

                x509 = connection.get_peer_certificate()
                sock.close()
            except OpenSSL.SSL.Error as e:
                self.error("Error extracting certificate from host %s:%s, (%s) %s" % (ip_address, port, type(e).__name__, e))
                continue
            except Exception as e:
                self.error("Error extracting certificate from host %s:%s, %s" % (ip_address, port, e))
                continue

            #self.output("%s %s" % (ip_address, x509.get_subject().commonName))
            name = x509.get_subject().commonName.lower().strip()
            self.add_potential_host(ip_address, name)

            text = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_TEXT, x509).decode("utf-8")

            # WARNING: this function does not support multiple SANs extensions - multiple X509v3 extensions of
            # the same type is disallowed by RFC 5280.
            match = re.search(r"X509v3 Subject Alternative Name:\s*(.*)", text)
            # WARNING: this function assumes that no SAN can include ", "!
            sans_parts = [] if match is None else match.group(1).split(', ')

            for part in sans_parts:
                if part.startswith('DNS:'):
                    name = part.split(':')[1].strip()
                    name = name.lower()
                    self.add_potential_host(ip_address, name)

    def verify_cb(self, conn, cert, errnum, depth, ok):
        # Yeah, we accept everything!
        return ok

    def add_potential_host(self, ip_address, name):
        regex_ip = '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
        regex_fqdn = '^\S*\.\S*$'
        regex_wildcard = '^\*\.'
        if re.match(regex_wildcard, name):
            self.output('Wildcard entry found for \'%s\'=> \'%s\'.' % (ip_address, name))
            return
        if not re.match(regex_ip, name) and re.match(regex_fqdn, name):
            self.add_hosts(ip_address=ip_address, host=name)
