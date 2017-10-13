from lib.core.module import BaseModule
from lib.mixins.threadpool import ThreadPoolMixin
from cookielib import CookieJar
from urlparse import urlparse
from urlparse import urljoin
from Queue import Queue, Empty
from lxml.html import fromstring
import random
import string
import os
import re
import time
import threading


class TooManyServerErrors(Exception):
    pass


class Module(BaseModule, ThreadPoolMixin):

    meta = {
        'name': 'Enumerate Website Resources',
        'author': 'Sion Dafydd',
        'description': 'Enumerate content within a website by crawling linked content and scanning for unlinked '
                       'directories and files using wordlists.',
        'query': "SELECT ports.service || '://' || ports.ip_address || ':' || ports.port || '|' || COALESCE(hosts.host, '') FROM ports JOIN hosts ON ports.ip_address=hosts.ip_address WHERE ports.service LIKE 'http%' AND ports.ip_address NOT NULL ORDER BY ports.ip_address",
        'options': (
            ('crawl', True, True, 'if true the website will be crawled for linked content'),
            ('crawl_max_pages', 50, True, 'the maximum number of pages that will be crawled'),
            ('crawl_ignore_extensions', '.exe,.zip,.tar,.bz2,.run,.asc,.gz,.bin,.iso,.dmg', True,
                'file types that should not be crawled'),
            ('dir_scan', False, True,
                'if true the website will be scanned for the existence of interesting directories'),
            ('dir_scan_wordlist', os.path.join(BaseModule.data_path, 'dirs.txt'), True,
                'path of directory word dictionary to use'),
            ('file_scan', False, True,
                'if true the website will be scanned for the existence of interesting files'),
            ('file_scan_wordlist', os.path.join(BaseModule.data_path, 'files.txt'), True,
                'path of file word dictionary to use'),
            ('file_scan_ext', '.html,.htm,.php,.aspx', True, 'file extension to append to words in the wordlist'),
            ('recursive', False, True, 'if true any new content will also be crawled/scanned to identify additional '
                                       'content'),
        ),
    }

    """
    TODO: Put locks around 'self.crawled_urls' and  'self.interesting_urls' and 'self.add_to_db', supposed to be atomic 
    operations due to the GIL, but better be safe than sorry.
    TODO: Cater for too many redirects e.g. dir_scanning a directory might just redirect to another for every attempt
    """

    def __init__(self, *args, **kwargs):
        result = BaseModule.__init__(self, *args, **kwargs)

        self.todo = Queue()
        self.crawled_urls = set()
        self.interesting_urls = dict()
        self.server_error_count = 0
        self.crawl_domain = urlparse('')
        self.max_pages = 0
        self.cookiejar = CookieJar()
        self.ecode = 404
        self.emesg = None
        self.db_lock = threading.Lock()

        return result

    def module_run(self, targets):
        for target in targets:
            # reset variables on every run
            self.todo = Queue()
            self.crawled_urls = set()
            self.interesting_urls = dict()
            self.server_error_count = 0
            self.crawl_domain = urlparse('')
            self.max_pages = self.options['crawl_max_pages']
            self.cookiejar = CookieJar()
            self.ecode = 404
            self.emesg = None

            line = target.rsplit('|')

            url = line[0]
            self.crawl_domain = urlparse(url, allow_fragments=False)
            # Append a slash to the the url if there is no defined path
            if self.crawl_domain.path == '':
                url += '/'
                self.crawl_domain = urlparse(url, allow_fragments=False)

            if len(line) > 1 and line[1] != '':
                vhost = line[1]
            else:
                vhost = self.crawl_domain.hostname

            while True:
                last_count = len(self.interesting_urls)

                if self.options['crawl']:
                    print("")
                    self.output("Crawling %s [host:%s]" % (self.crawl_domain.geturl(), vhost))
                    # Detect an error code or error message that can be used to identify non-existent resources
                    #self.detect_error_code(self.crawl_domain.geturl(), vhost)
                    # Set domain variable so we only crawl the targeted domain:port
                    self.todo.put(self.crawl_domain.geturl())
                    # Start crawling
                    self.crawl(vhost)

                if self.options['dir_scan']:
                    print("")
                    if not self.options['crawl']:
                        # We need at least one entry to build scan list
                        self.interesting_urls[self.crawl_domain.geturl()] = 'prime'
                    self.output("Scanning for directories on %s [host:%s]" % (self.crawl_domain.geturl(), vhost))
                    with open(self.options['dir_scan_wordlist'], "r") as fh:
                        wordlist = [line.strip() for line in fh]
                    # detect error code for each base directory as error codes can be different
                    self.detect_error_code(self.crawl_domain.geturl(), vhost, include_redirects=True)
                    self.dir_scan(vhost, wordlist)

                if self.options['file_scan']:
                    print("")
                    if not self.options['crawl']:
                        # We need at least one entry to build scan list
                        self.interesting_urls[self.crawl_domain.geturl()] = 'prime'
                    self.output("Scanning for files on %s [host:%s]" % (self.crawl_domain.geturl(), vhost))
                    with open(self.options['file_scan_wordlist'], "r") as fh:
                        wordlist = [line.strip() for line in fh]
                    self.detect_error_code(self.crawl_domain.geturl(), vhost, include_redirects=True)
                    self.file_scan(vhost, wordlist)

                if not self.options['recursive'] or last_count == len(self.interesting_urls):
                    break

            # TODO Add status code column to table so can differentiate between these responses
            #self.output("Saving results to the database...")
            for url in sorted(self.interesting_urls.keys()):
                self.add_to_db(url, vhost)

    def crawl(self, vhost):
        # Use a threadpool to speed up crawling
        threadpool = self.get_threadpool()
        while not self.todo.empty() or threadpool.tasks.unfinished_tasks > 0:
            try:
                if self.server_error_count >= 3:
                    raise TooManyServerErrors
                if len(self.interesting_urls) >= self.max_pages:
                    self.alert("Maximum number of pages crawled, finishing existing work...")
                    break
                url = self.todo.get_nowait()
                threadpool.add_task(self.get, url=url, host=vhost)
            except Empty:
                time.sleep(.7)
            except KeyboardInterrupt:
                self.error('Ok. Waiting for threads to exit...')
                threadpool.shutdown()
                raise
            except TooManyServerErrors:
                threadpool.shutdown()
                self.error('Too many errors connecting to the remote server, skipping...')
                return
            except Exception as e:
                self.error("Error while crawling, %s" % e)
                self.error('Waiting for threads to exit...')
                threadpool.shutdown()
                return
            except:
                self.error("Unknown error while crawling, stopping.")
                self.error('Waiting for threads to exit...')
                threadpool.shutdown()
                return
        threadpool.wait_completion()
        threadpool.shutdown()

    def dir_scan(self, vhost, wordlist):
        # Use a threadpool to speed up scanning
        threadpool = self.get_threadpool()
        try:
            for base in self.interesting_urls.keys():
                if not base.endswith('/'):
                    # if this is a file, find the parent directory and use that as a base instead
                    i = base.rfind('/') + 1
                    base = base[:i]
                for word in wordlist:
                    if self.server_error_count >= 3:
                        raise TooManyServerErrors
                    try:
                        # fix up word
                        if word.startswith('/'):
                            word = word[1:]
                        if not word.endswith('/'):
                            word += '/'
                        url_word = urljoin(base, word, allow_fragments=False)
                        threadpool.add_task(self.get, url=url_word, host=vhost)
                    except KeyboardInterrupt:
                        raise
                    except Exception as e:
                        self.error("Error while scanning a wordlist item '%s', %s" % (word, e))
                        continue
                    except:
                        self.error("Unknown error while scanning a wordlist item '%s'" % word)
                        continue
        except KeyboardInterrupt:
            self.parent.error('Ok. Waiting for threads to exit...')
            threadpool.shutdown()
            raise
        except TooManyServerErrors:
            threadpool.shutdown()
            self.error('Too many errors connecting to the remote server, skipping...')
            return
        threadpool.wait_completion()
        threadpool.shutdown()

    def file_scan(self, vhost, wordlist):
        # Use a threadpool to speed up scanning
        threadpool = self.get_threadpool()
        try:
            for base in self.interesting_urls.keys():
                if not base.endswith('/'):
                    # if this is a file, find the parent directory and use that as a base instead
                    i = base.rfind('/') + 1
                    base = base[:i]
                for word in wordlist:
                    try:
                        for ext in self.options['file_scan_ext'].split(','):
                            if self.server_error_count >= 3:
                                raise TooManyServerErrors
                            # fix up word
                            if word.startswith('/'):
                                word = word[1:]
                            url_word = urljoin(base, word + ext.strip(), allow_fragments=False)
                            threadpool.add_task(self.get, url=url_word, host=vhost)
                    except KeyboardInterrupt:
                        raise
                    except TooManyServerErrors:
                        raise
                    except Exception as e:
                        self.error("Error while scanning a wordlist item '%s', %s" % (word, e))
                        continue
                    except:
                        self.error("Unknown error while scanning a wordlist item '%s'" % word)
                        continue
        except KeyboardInterrupt:
            self.error('Ok. Waiting for threads to exit...')
            threadpool.shutdown()
            raise
        except TooManyServerErrors:
            threadpool.shutdown()
            self.error('Too many errors connecting to the remote server, skipping...')
            return
        threadpool.wait_completion()
        threadpool.shutdown()

    def get(self, url, host):
        if self.server_error_count >= 3:
            return
        # Where the vhost is used as the hostname value in an url, replace with self.crawl_domain in case the request is sent to another server
        host_u = urlparse(self.crawl_domain.geturl().replace(self.crawl_domain.hostname, host))
        if url.startswith(host_u.scheme + "://" + host_u.hostname):
            url = url.replace(host_u.scheme + "://" + host_u.hostname,
                              host_u.scheme + "://" + self.crawl_domain.hostname, 1)
        # do not visit the same page twice
        if url in self.crawled_urls:
            return
        potential_u = urlparse(url)
        # do not crawl a page located on another domain / host
        if potential_u.hostname != self.crawl_domain.hostname or potential_u.scheme != self.crawl_domain.scheme:
            return
        # do not crawl a page with a blacklisted extension
        if any((url.endswith(ext.strip()) for ext in self.options['crawl_ignore_extensions'].split(','))):
            return
        # Perform the request
        try:
            resp = self.request(url, method='GET', headers={'Host': host}, cookiejar=self.cookiejar, redirect=False)
        except IOError as e:
            self.error("Error connecting to %s, %s" % (url, e))
            self.server_error_count += 1
            return
        # record that we have visited the url
        self.crawled_urls.add(url)
        # shall we proceed to try and extract urls from the response?
        if self.check_response(url, resp):
            n_urls = self.extract_links(url, resp)
            for n in n_urls:
                self.todo.put(n)

    def check_response(self, url, resp):
        u_parse = urlparse(url)
        resource = url.replace("%s://%s" % (u_parse.scheme, u_parse.netloc), '', 1)
        if resp.status_code == 200:
            if self.emesg is None or self.emesg not in resp.text:
                if 'content-length' in resp.headers:
                    self.alert("[Code: %s][%s bytes]\t%s" % (resp.status_code, resp.headers['content-length'], resource))
                else:
                    self.alert("[Code: %s][? bytes]\t%s" % (resp.status_code, resource))
                self.interesting_urls[url] = resp
                return True
        elif resp.status_code == self.ecode:
            self.debug("[Code: %s][NOT FOUND INDICATOR]\t%s" % (resp.status_code, resource))
        elif resp.status_code == 401:
            self.error("[Code: %s][UNAUTHORIZED]\t%s" % (resp.status_code, resource))
            self.interesting_urls[url] = resp
        elif resp.status_code == 403:
            self.output("[Code: %s][FORBIDDEN]\t%s" % (resp.status_code, resource))
            self.interesting_urls[url] = resp
        elif resp.status_code == 404:
            self.debug("[Code: %s][NOT FOUND]\t%s" % (resp.status_code, resource))
        elif resp.status_code == 400:
            self.output("[Code: %s][BAD REQUEST]\t%s" % (resp.status_code, resource))
            self.interesting_urls[url] = resp
        elif resp.status_code == 301 or resp.status_code == 302 or resp.status_code == 303 or resp.status_code == 307:
            self.output("[Code: %s][REDIRECT]\t%s\t=>\t%s" % (resp.status_code, resource, resp.headers['location']))
            self.interesting_urls[url] = resp
            return True
        elif 500 <= resp.status_code <= 599:
            self.output("[Code: %s][SERVER ERR]\t%s" % (resp.status_code, resource))
            self.interesting_urls[url] = resp
        else:
            self.error("[Code: %s][TODO!]\t%s" % (resp.status_code, resource))
            self.interesting_urls[url] = resp
        return False

    def extract_links(self, url, resp):
        unsanitised = set()

        # Extract from location header
        if 'location' in resp.headers:
            unsanitised.add(resp.headers['location'])

        # No point in carrying on if there is nothing to parse
        if resp.text and resp.text.strip() != '':
            # Only proceed if we the response contains a html document
            if resp.content_type and 'text/html' in resp.content_type:
                doc = fromstring(resp.text)

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
                for match in re.finditer(r'''data-url\s*=\s*['"]?(.*?)?['"]?[\s>]''', resp.text):
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
                    or href.lower().startswith('javascript:') or href.lower().startswith('#'):
                continue

            if href.startswith('http://') or href.startswith('https://'):
                u_parse = urlparse(href, allow_fragments=False)
                sanitised.add(u_parse.geturl())
            else:
                sanitised.add(urljoin(url, href, allow_fragments=False))
        return sanitised

    def detect_error_code(self, url, host, include_redirects=False):
        rand_dir = ''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(10)])
        test_url = urljoin(url, rand_dir)
        try:
            resp = self.request(test_url, headers={'Host': host}, redirect=False)
        except IOError as e:
            self.error("Error connecting to %s, %s" % (url, e))
            return

        if 200 <= resp.status_code <= 299:
            with open(os.path.join(self.data_path, '404_sigs.txt'), 'r') as fh:
                for sig in fh:
                    sig = sig.rstrip()
                    if sig in resp.text:
                        self.emesg = sig
                        break
            if self.emesg is None:
                self.output("Using first 256 bytes of the response as a page not found identifier")
                self.emesg = resp.text[0:256]
            else:
                self.output("Using custom string of '%s' as a page not found identifier" % self.emesg)
        elif resp.status_code == 301 or resp.status_code == 302 or resp.status_code == 303 or resp.status_code == 307:
            if include_redirects:
                self.ecode = resp.status_code
            self.output("Using status code '%s' as a page not found identifier" % str(self.ecode))
        else:
            self.ecode = resp.status_code
            self.output("Using status code '%s' as a page not found identifier" % str(self.ecode))

    def add_to_db(self, url, host):
        u = urlparse(url)
        if u.port is None:
            if u.scheme == 'https':
                port = 443
            else:
                port = 80
        else:
            port = u.port
        resource = url.replace("%s://%s" % (u.scheme, u.netloc), '', 1)
        with self.db_lock:
            self.add_urls(scheme=u.scheme, ip_address=u.hostname, host=host, port=port, resource=resource, mute=True)
