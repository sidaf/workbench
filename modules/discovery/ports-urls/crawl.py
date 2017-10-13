from lib.core.brute import BruteModule, BRUTE_STATUS_SUCCESS, BRUTE_STATUS_FAIL
from lib.mixins.curl import CurlMixin
import os
import re
from urlparse import urljoin, urlparse
import cPickle as Pickle
import threading
from lxml.html import fromstring


class Module(BruteModule, CurlMixin):

    meta = {
        'name': 'Websites Crawler',
        'author': 'Sion Dafydd',
        'description': 'Crawls a website for linked resources.',
        'query': "SELECT ports.service || '://' || ports.ip_address || ':' || ports.port || '|' || COALESCE(hosts.host, '') FROM ports JOIN hosts ON ports.ip_address=hosts.ip_address WHERE ports.service LIKE 'http%' AND ports.ip_address NOT NULL ORDER BY ports.ip_address",
        'options': (
            ('max_attempts', 2, True, 'skip request attempt after N failed connections'),
            ('target_max_attempts', 2, True, 'skip target after N failed max_attempts'),
            ('rate_limit', 0, True, 'wait N seconds between each test'),
            ('ignore_extensions', '.exe,.zip,.tar,.bz2,.run,.asc,.gz,.bin,.iso,.dmg,.xz,.pdf,.docx,.doc,.pptx,.ppt', False, 'file types that should not be requested'),
            ('url_cache', os.path.join(BruteModule.workspace, 'crawl', 'visited_urls.cache'), True,
                'cache file that stores visited URLs between invocations'),
            ('disable_cache', True, True, 'disable cache file'),
            #('crawl_depth', '5', True, 'skip resources that are N directories deep, -1 for unlimited'),
            #('crawl_limit', '-1', True, 'skip target after N resources are retrieved, -1 for unlimited'),
            #('ignore_regex', '', False, 'skip resources that match regex'),
            #('allow_regex', '', False, 'crawl resources that match regex'),
            ('method', 'GET', True, 'Request method to use for requests'),
            ('ignore_status_code', '404', True, 'do not crawl responses with a matching status code'),
            ('add_status_code', '200, 401', True, 'updates the \'urls\' table with responses with a matching status code'),
        ),
    }

    def module_run(self, targets):
        # Override base class options
        BruteModule.module_run(self)
        self.max_attempts = self.options['max_attempts']
        self.target_max_attempts = self.options['target_max_attempts'] * self.max_attempts
        self.rate_limit = self.options['rate_limit']

        # Module options
        self.visited_urls_lock = threading.Lock()
        self.visited_urls = self.load_cache()
        self.method = self.options['method']

        for target in targets:
            # List to store attack candidates
            self.candidates = set()
            self.candidates.add(target)
            self.candidates_lock = threading.Lock()

            # Output a pretty header
            self.heading(target, level=0)

            while True:
                candidate_count = len(self.candidates)
                # Start attack
                self.thread(self.candidates.copy(), target)
                # Break out of loop if no new candidates exist
                if candidate_count >= len(self.candidates):
                    break

            # Save visited urls to disk cache
            self.save_cache(self.visited_urls)

    def execute(self, connection, candidate, target):
        # Explode target into usable components
        url, scheme, host, ip_address, port, resource, resolve = self.explode_target(candidate)

        # Check that a request is not being repeated
        vid = candidate + "|" + url + "|" + self.method
        with self.visited_urls_lock:
            if vid in self.visited_urls:
                return

        # Perform request
        response = self.curl(method=self.method, url=url, resolve=resolve)

        # Process successful hit
        if any(response.status_code != int(code.strip()) for code in self.options['ignore_status_code'].split(',')):
            # Extract links
            links = self.extract_links(url, response)

            # Remove links deemed out of scope
            links = self.remove_out_of_scope(links, scheme, host, port)

            # Convert validated links into consumable format
            targets = self.implode_to_target(links, ip_address, host)

            # Add new targets as candidates
            with self.candidates_lock:
                for t in targets:
                    self.candidates.add(t)

        # Print and add to db
        if any(response.status_code == int(code.strip()) for code in self.options['add_status_code'].split(',')):
            self.alert(self.build_output(response, self.method, resource))
            # Extract the resource that was accessed
            self.add_urls(scheme, ip_address, host, port, resource, self.method,
                          response.status_code, response.content_length, True)
        else:
            self.debug(self.build_output(response, self.method, resource))

        # Add to visited urls cache
        with self.visited_urls_lock:
            self.visited_urls.add(vid)

    def implode_to_target(self, links, ip_address, host):
        tmp = list()
        for link in links:
            l_url, l_scheme, l_host, _, l_port, l_resource, _ = self.explode_target(link)
            # Check source target structure
            if host is not None and ip_address is not None:
                # Format will be http[s]://ip_address/resource|host
                target = "%s://%s:%s%s|%s" % (l_scheme, ip_address, l_port, l_resource, host)
            else:
                # Format will be http[s]://host/resource
                target = "%s://%s:%s%s" % (l_scheme, l_host, l_port, l_resource)
            tmp.append(target)
        return tmp

    def remove_out_of_scope(self, links, scheme, host, port):
        tmp = list()
        for link in links:
            l_url, l_scheme, l_host, _, l_port, _, _ = self.explode_target(link)
            # scheme, host, and port need to match the source target
            if scheme != l_scheme or host != l_host or port != l_port:
                continue
            # do not crawl a page with a blacklisted extension
            if any((l_url.endswith(ext.strip()) for ext in self.options['ignore_extensions'].split(','))):
                continue
            tmp.append(link)
        return tmp

    def extract_links(self, url, response):
        unsanitised = set()

        # Extract from location header
        if 'location' in response.headers:
            unsanitised.add(response.headers['location'])

        # No point in carrying on if there is nothing to parse
        if response.text and response.text.strip() != '':
            # Only proceed if we the response contains a html document
            if 'content-type' in response.headers and 'text/html' in response.headers['content-type'].lower():
                doc = fromstring(response.text)

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
                for match in re.finditer(r'''data-url\s*=\s*['"]?(.*?)?['"]?[\s>]''', response.text):
                    unsanitised.add(match.group(1))

                # Extracts paths within "script" HTML elements.
                for script in doc.xpath("//script"):
                    if script.text is None:
                        continue
                    for match in re.finditer(r'''([\/a-zA-Z0-9%._+-]+)''', script.text):
                        potential = match.group(0)
                        if '.' in potential and '/' in potential and '*' not in potential \
                                and not potential.startswith('//') and potential.startswith('/'):
                            unsanitised.add(potential)

                # Extracts paths within "comments".
                for comment in doc.xpath("//comment()"):
                    if comment.text is None:
                        continue
                    for match in re.finditer(r'''(^|\s)(\/[\/a-zA-Z0-9%._+-]+)''', comment.text):
                        potential = match.group(0).strip()
                        if potential.startswith('/'):
                            unsanitised.add(potential)

                # Extracts images.
                for img in doc.xpath("//img"):
                    unsanitised.add(img.get("src"))

                # Extracts objects.
                for obj in doc.xpath("//object/embed"):
                    unsanitised.add(obj.get("src"))

                # Extracts scripts.
                for script in doc.xpath("//script"):
                    unsanitised.add(script.get("src"))

        sanitised = set()
        for href in unsanitised:
            if href is None or href.strip() == '' or href.lower().startswith('mailto:') \
                    or href.lower().startswith('javascript:') or href.lower().startswith('#') \
                    or href.startswith('..') or href.startswith('/..'):
                continue

            if href.startswith('http://') or href.startswith('https://'):
                u_parse = urlparse(href, allow_fragments=False)
                sanitised.add(u_parse.geturl())
            else:
                sanitised.add(urljoin(url, href, allow_fragments=False))
        return sanitised

    def load_cache(self):
        cache_path = self.options['url_cache']
        if not os.path.exists(cache_path):
            # The cache doesn't exist, return an empty set
            return set()
        return Pickle.load(open(cache_path, 'rb'))

    def save_cache(self, urls):
        if self.options['disable_cache']:
            return
        cache_path = self.options['url_cache']
        if not os.path.exists(os.path.dirname(cache_path)):
            os.makedirs(os.path.dirname(cache_path))
        with open(cache_path, 'wb') as cache_file:
            # Write it to the result to the file as a pickled object
            # Use the binary protocol for better performance
            Pickle.dump(urls, cache_file, protocol=1)
