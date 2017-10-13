from lib.core.brute import BruteModule, BRUTE_STATUS_SUCCESS, BRUTE_STATUS_FAIL
from lib.mixins.curl import CurlMixin
import os
from urlparse import urljoin
import threading
import cPickle as Pickle


class Module(BruteModule, CurlMixin):

    meta = {
        'name': 'Interesting Resource Finder',
        'author': 'Sion Dafydd',
        'description': 'Checks hosts for interesting resources in predictable locations.',
        'query': "SELECT ports.service || '://' || ports.ip_address || ':' || ports.port || '|' || COALESCE(hosts.host, '') FROM ports JOIN hosts ON ports.ip_address=hosts.ip_address WHERE ports.service LIKE 'http%' AND ports.ip_address NOT NULL ORDER BY ports.ip_address",
        'options': (
            ('wordlist', os.path.join(BruteModule.data_path, 'interesting_resources.txt'), True, 'path to wordlist file'),
            ('max_attempts', 3, True, 'skip brute attempt after N failed connections'),
            ('target_max_attempts', 4, True, 'skip target after N failed max_attempts'),
            ('rate_limit', 0, True, 'wait N seconds between each test'),
            ('method', 'HEAD', True, 'Request method to use for requests'),
            ('ecode', None, False, 'Status code to match as page not found identifier'),
            ('emesg', None, False, 'Text to match as a page not found identifier'),
            ('url_cache', os.path.join(BruteModule.workspace, 'interesting_resources', 'visited_urls.cache'), True,
             'cache file that stores visited URLs between invocations'),
            ('disable_cache', True, True, 'disable cache file'),
        ),
    }

    def module_run(self, targets):
        # Override base class options
        BruteModule.module_run(self)
        self.max_attempts = self.options['max_attempts']
        self.target_max_attempts = self.options['target_max_attempts'] * self.max_attempts
        self.rate_limit = self.options['rate_limit']

        # Module options
        wordlist = self.load_wordlist(self.options['wordlist'])
        method = self.options['method']
        ecode = self.options['ecode']
        emesg = self.options['emesg']
        self.visited_urls_lock = threading.Lock()
        self.visited_urls = self.load_cache()

        # List to store attack candidates
        candidates = list()

        for word in wordlist:
            if word.startswith('/'):
                word = word[1:]
            if word.startswith('#'):
                continue
            candidates.append(word)

        for target in targets:
            # Explode target into usable components
            url, scheme, host, ip_address, port, resource, resolve = self.explode_target(target)

            # Output a pretty header
            self.heading(target, level=0)

            if emesg is None and emesg is None:
                # Detect an error code or text that can be used to identify non-existent resources
                ecode, emesg = self.detect_error_code(method, url, resolve)
                print("")

            # Start attack
            self.thread(candidates, target, method, ecode, emesg)

            # Save visited urls to disk cache
            self.save_cache(self.visited_urls)

    def execute(self, connection, candidate, target, method, ecode, emesg):
        # Explode target into usable components
        url, scheme, host, ip_address, port, resource, resolve = self.explode_target(target)
        test_url = urljoin(url, candidate)

        # Check that a request is not being repeated
        vid = candidate + "|" + test_url + "|" + method
        with self.visited_urls_lock:
            if vid in self.visited_urls:
                return

        # Perform request
        response = self.curl(method=method, url=test_url, resolve=resolve)

        # Check response
        if (response.status_code == 200 and emesg is not None and emesg in response.text) \
                or response.status_code == ecode or response.status_code == 404:
            status = BRUTE_STATUS_FAIL
        else:
            status = BRUTE_STATUS_SUCCESS

        # Extract the resource that was accessed
        _, _, _, _, _, resource, _ = self.explode_target(test_url)

        # Print message and add to db
        if status == BRUTE_STATUS_SUCCESS:
            self.alert(self.build_output(response, method, resource))
            self.add_urls(scheme, ip_address, host, port, resource, method,
                          response.status_code, response.content_length, True)
        else:
            self.debug(self.build_output(response, method, resource))

        # Add to visited urls cache
        with self.visited_urls_lock:
            self.visited_urls.add(vid)

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
