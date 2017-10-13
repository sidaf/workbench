import os
try:
    import xml.etree.cElementTree as ElementTree
except ImportError:
    import xml.etree.ElementTree as ElementTree


class NmapMixin(object):

    def extract_hosts(self, xml_file):
        if not os.path.exists(xml_file):
            raise RuntimeError("File does not exist: %s" % xml_file)

        xml = ElementTree.parse(xml_file)
        hosts = list()
        for host in xml.findall('host'):
            # TODO: add option to check if host has at least one open port (if importing port scans with -Pn flag set)
            state = host.find('status').get('state')
            if state == 'down':
                continue
            address = host.find('address').get('addr')
            hostnames_xml = host.find('hostnames')
            hostname = hostnames_xml.get('hostname') if hostnames_xml is not None else None
            hosts.append(dict(ip_address=address, host=hostname))
        return hosts

    def extract_ports(self, xml_file, ip_addresses=None):
        if not os.path.exists(xml_file):
            raise RuntimeError("File does not exist: %s" % xml_file)

        xml = ElementTree.parse(xml_file)
        ports = list()
        for host in xml.findall('host'):
            address = host.find('address').get('addr')
            hostnames_xml = host.find('hostnames')
            hostname = hostnames_xml.get('hostname') if hostnames_xml is not None else None
            if ip_addresses is not None:
                if address not in ip_addresses:
                    continue
            try:
                for port in host.find('ports').findall('port'):
                    state = port.find('state').get('state')
                    if state == 'open':
                        service_xml = port.find('service')
                        service = service_xml.get('name') if service_xml is not None else None
                        tunnel = service_xml.get('tunnel') if service_xml is not None else None
                        # rename some of the standard nmap service names so that they are a bit easier to deal with
                        if service == 'http-alt' or service == 'http-proxy' or service == 'http-wmap':
                            service = 'http'
                        if service == 'https-alt' or service == 'http-proxy' or service == 'https-wmap':
                            service = 'https'
                        if tunnel == 'ssl':
                            if service == 'http' or service == 'https' or service == 'upnp' or service == 'socks5':
                                service = 'https'
                            elif service == 'ftps':
                                service == 'ftps'
                            else:
                                service = "%s/%s" % (tunnel, service)
                        ports.append(dict(ip_address=address,
                                          host=hostname,
                                          port=port.get('portid'),
                                          state=state,
                                          protocol=port.get('protocol'),
                                          service=service,
                                          product=service_xml.get('product') if service_xml is not None else None,
                                          version=service_xml.get('version') if service_xml is not None else None))
            except AttributeError:
                pass
        return ports


