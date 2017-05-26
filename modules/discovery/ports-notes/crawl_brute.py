from lib.core.module import BaseModule
from cookielib import CookieJar
from urlparse import urlparse
from urlparse import urljoin
from lxml.html import fromstring
import random
import string
import os
import re


class Module(BaseModule):

    meta = {
        'name': 'Crawl and Brute Website Resources',
        'author': 'Sion Dafydd',
        'description': 'Crawl then perform dictionary brute force attacks against a website.',
        'query': "SELECT service || ',' || COALESCE(ip_address, '') || ',' || port || ',' || COALESCE(host, '') "
                 "FROM ports WHERE service LIKE 'http%'",
    }

    def module_run(self, targets):
        for target in targets:
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

            crawler = Crawler(parent=self)
            crawler.crawl(url, headers={'Host': header})


class Crawler(object):
    def __init__(self, parent, max_pages=100):
        self.parent = parent
        self.max_pages = max_pages
        self.content = dict()
        self.domain = ''
        self.cookiejar = CookieJar()
        self.headers = None
        self.ecode = 404
        self.emesg = None

    def crawl(self, url, headers=None):
        u_parse = urlparse(url, allow_fragments=False)
        self.domain = u_parse.netloc
        self.headers = headers
        self.detect_error_code(u_parse.geturl())
        self._crawl([u_parse.geturl()], self.headers, self.max_pages)

    def get(self, url, headers):
        resp = self.parent.request(url, method='GET', headers=headers, cookiejar=self.cookiejar, redirect=False)

        page = None
        if resp.status_code == 200:
            if self.emesg is not None and self.emesg in resp.text:
                page = None
            else:
                page = resp.text
            if 'content-length' in resp.headers:
                self.parent.output("%s [Code: %s | Length: %s]" % (url, resp.status_code, resp.headers['content-length']))
            else:
                self.parent.output("%s [Code: %s | Length: unknown]" % (url, resp.status_code))
        elif resp.status_code == self.ecode:
            page = None
        elif resp.status_code == 401 or resp.status_code == 403:
            self.parent.alert("%s [Code: %s]" % (url, resp.status_code))
        elif resp.status_code == 301 or resp.status_code == 302 or resp.status_code == 303:
            page = "<html><body><a href=\"%s\">Redirect Header</a></body></html>" % resp.headers['location']
            self.parent.output("%s -> %s [Code: %s]" % (url, resp.headers['location'], resp.status_code))
        elif 500 <= resp.status_code <= 599:
            self.parent.alert("%s [Code: %s]" % (url, resp.status_code))
        else:
            self.parent.error("%s [Code: %s] - Unhandled Status Code Returned" % (url, resp.status_code))
        return page

    def extract_links(self, url, html):
        unsanitised = set()

        if html is None:
            return unsanitised
        doc = fromstring(html)

        # Extracts paths from "a" HTML elements.
        for a in doc.xpath("//a"):
            unsanitised.add(a.get("href"))

        # Extracts paths from "area" HTML elements.
        for area in doc.xpath("//area"):
            unsanitised.add(area.get("href"))

        # Extracts paths from "form" HTML elements.
        for form in doc.xpath("//form"):
            unsanitised.add(form.get("action"))

        # Extracts paths from "frame" HTML elements.
        for frame in doc.xpath("//frame"):
            unsanitised.add(frame.get("src"))

        # Extracts paths from "iframe" HTML elements.
        for iframe in doc.xpath("//iframe"):
            unsanitised.add(iframe.get("src"))

        # Extracts paths from "link" HTML elements.
        for links in doc.xpath("//link"):
            unsanitised.add(links.get("href"))

        # Extracts meta refresh URLs.
        for r in doc.xpath('//html/head/meta[re:test(@http-equiv, "^refresh", "i")]',
                           namespaces={"re": "http://exslt.org/regular-expressions"}):
            content = r.get("content")
            if len(content.lower().split('url=', 1)) == 2:
                url = content.lower().split('url=', 1)[1]
                unsanitised.add(url.strip().replace('\'', '').replace('"', ''))

        # Extracts paths from "data-url" attributes.
        for match in re.finditer(r'''data-url\s*=\s*['"]?(.*?)?['"]?[\s>]''', html):
            unsanitised.add(match.group(1))

        # Extracts paths within "script" HTML elements.
        for script in doc.xpath("//script"):
            for match in re.finditer(r'''([\/a-zA-Z0-9%._-]+)''', script.text):
                potential = match.group(0)
                if '.' in potential and '/' in potential and '*' not in potential \
                        and not potential.startswith('//') and potential.startswith('/'):
                    unsanitised.add(potential)

        # Extracts paths within "comments".
        for comment in doc.xpath("//comment()"):
            for match in re.finditer(r'''(^|\s)(\/[\/a-zA-Z0-9%._-]+)''', comment.text):
                potential = match.group(0).strip()
                if potential.startswith('/'):
                    unsanitised.add(potential)

        sanitised = set()
        for href in unsanitised:
            if href is None or href == '' or href.lower().startswith('mailto:') \
                    or href.lower().startswith('javascript:'):
                continue

            if href.startswith('http://') or href.startswith('https://'):
                u_parse = urlparse(href, allow_fragments=False)
                sanitised.add(u_parse.geturl())
            else:
                sanitised.add(urljoin(url, href, allow_fragments=False))
        return sanitised

    def detect_error_code(self, url):
        rand_dir = ''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(10)])
        test_url = urljoin(url, rand_dir)
        resp = self.parent.request(test_url, redirect=False)

        if 200 <= resp.status_code <= 299:
            with open(os.path.join(self.data_path, '404_sigs.txt', 'r')) as fh:
                for sig in fh:
                    if sig in resp.text:
                        self.emesg = sig
                        break
            if self.emesg is None:
                self.parent.output("Using first 256 bytes of the response as a page not found identifier.")
                self.emesg = resp.text[0:256]
            else:
                self.parent.output("Using custom string of '%s' as a page not found identifier" % self.emesg)
        else:
            self.ecode = resp.status_code
            self.parent.output("Using status code '%s' as a page not found identifier." % str(self.ecode))

    def _crawl(self, urls, headers, max_pages):
        if max_pages:
            for url in urls:
                # do not crawl the same page twice
                if url not in self.content:
                    if urlparse(url).netloc == self.domain:
                        html = self.get(url, headers)
                        self.content[url] = html
                        n_urls = self.extract_links(url, html)
                        self._crawl(n_urls, headers, max_pages - 1)
