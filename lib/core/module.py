from __future__ import print_function
import cookielib
import HTMLParser
import os
import re
import socket
import sqlite3
import struct
import sys
import textwrap
import json
import subprocess
import pwd
import datetime
# framework libs
from lib.core import framework

#=================================================
# MODULE CLASS
#=================================================

class BaseModule(framework.Framework):

    def __init__(self, params, query=None):
        framework.Framework.__init__(self, params)
        self.options = framework.Options()
        # register a data source option if a default query is specified in the module
        if self.meta.get('query'):
            self._default_source = self.meta.get('query')
            self.register_option('source', 'default', True, 'source of input (see \'show info\' for details)')
        # register all other specified options
        if self.meta.get('options'):
            for option in self.meta.get('options'):
                self.register_option(*option)
        # register any required keys
        if self.meta.get('required_keys'):
            self.keys = {}
            for key in self.meta.get('required_keys'):
                # add key to the database
                self._query_keys('INSERT OR IGNORE INTO keys (name) VALUES (?)', (key,))
                # migrate the old key if needed
                self._migrate_key(key)
                # add key to local keys dictionary
                # could fail to load on exception here to prevent loading modules
                # without required keys, but would need to do it in a separate loop
                # so that all keys get added to the database first. for now, the
                # framework will warn users of the missing key, but allow the module
                # to load.
                self.keys[key] = self.get_key(key)
                if not self.keys.get(key):
                    self.error('\'%s\' key not set. %s module will likely fail at runtime. See \'keys add\'.' % (key, self._modulename.split('/')[-1]))
        self._reload = 0

    #==================================================
    # SUPPORT METHODS
    #==================================================

    def _migrate_key(self, key):
        '''migrate key from old .dat file'''
        key_path = os.path.join(self._home, 'keys.dat')
        if os.path.exists(key_path):
            try:
                key_data = json.loads(open(key_path, 'rb').read())
                if key_data.get(key):
                    self.add_key(key, key_data.get(key))
            except:
                self.error('Corrupt key file. Manual migration of \'%s\' required.' % (key))

    def ascii_sanitize(self, s):
        return ''.join([char for char in s if ord(char) in [10,13] + range(32, 126)])

    def html_unescape(self, s):
        '''Unescapes HTML markup and returns an unescaped string.'''
        h = HTMLParser.HTMLParser()
        return h.unescape(s)
        #p = htmllib.HTMLParser(None)
        #p.save_bgn()
        #p.feed(s)
        #return p.save_end()

    def html_escape(self, s):
        escapes = {
            '&': '&amp;',
            '"': '&quot;',
            "'": '&apos;',
            '>': '&gt;',
            '<': '&lt;',
            }
        return ''.join(escapes.get(c,c) for c in s)

    def cidr_to_list(self, string):
        # references:
        # http://boubakr92.wordpress.com/2012/12/20/convert-cidr-into-ip-range-with-python/
        # http://stackoverflow.com/questions/8338655/how-to-get-list-of-ip-addresses
        # parse address and cidr
        (addrString, cidrString) = string.split('/')
        # split address into octets and convert cidr to int
        addr = addrString.split('.')
        cidr = int(cidrString)
        # initialize the netmask and calculate based on cidr mask
        mask = [0, 0, 0, 0]
        for i in range(cidr):
            mask[i/8] = mask[i/8] + (1 << (7 - i % 8))
        # initialize net and binary and netmask with addr to get network
        net = []
        for i in range(4):
            net.append(int(addr[i]) & mask[i])
        # duplicate net into broad array, gather host bits, and generate broadcast
        broad = list(net)
        brange = 32 - cidr
        for i in range(brange):
            broad[3 - i/8] = broad[3 - i/8] + (1 << (i % 8))
        # print information, mapping integer lists to strings for easy printing
        #mask = '.'.join(map(str, mask))
        net = '.'.join(map(str, net))
        broad = '.'.join(map(str, broad))
        ips = []
        f = struct.unpack('!I',socket.inet_pton(socket.AF_INET,net))[0]
        l = struct.unpack('!I',socket.inet_pton(socket.AF_INET,broad))[0]
        while f <= l:
            ips.append(socket.inet_ntop(socket.AF_INET,struct.pack('!I',f)))
            f = f + 1
        return ips

    def parse_name(self, name):
        elements = [self.html_unescape(x) for x in name.strip().split()]
        # remove prefixes and suffixes
        names = []
        for i in range(0,len(elements)):
            # preserve initials
            if re.search(r'^\w\.$', elements[i]):
                elements[i] = elements[i][:-1]
            # remove unecessary prefixes and suffixes
            elif re.search(r'(?:\.|^the$|^jr$|^sr$|^I{2,3}$)', elements[i], re.IGNORECASE):
                continue
            names.append(elements[i])
        # make sense of the remaining elements
        if len(names) > 3:
            names[2:] = [' '.join(names[2:])]
        # clean up any remaining garbage characters
        names = [re.sub(r"[,']", '', x) for x in names]
        # set values and return names
        fname = names[0] if len(names) >= 1 else None
        mname = names[1] if len(names) >= 3 else None
        lname = names[-1] if len(names) >= 2 else None
        return fname, mname, lname

    def hosts_to_domains(self, hosts, exclusions=[]):
        domains = []
        for host in hosts:
            elements = host.split('.')
            # recursively walk through the elements
            # extracting all possible (sub)domains
            while len(elements) >= 2:
                # account for domains stored as hosts
                if len(elements) == 2:
                    domain = '.'.join(elements)
                else:
                    # drop the host element
                    domain = '.'.join(elements[1:])
                if domain not in domains + exclusions:
                    domains.append(domain)
                del elements[0]
        return domains

    def execute(self, command, suppress_stdout=False, sudo=False, run_as='root'):
        if sudo:
            sudo_user = run_as.split().pop()
            try:
                pwd.getpwnam(sudo_user).pw_uid
            except KeyError:
                self.error("Username '%s' does not exists. Please supply a valid username" % run_as)
                return ""
            sudo_path = self.whereis("sudo")
            if sudo_path is None:
                self.error("sudo is not installed or could not be found in system path")
                return ""
            command = "%s -u %s %s" % (sudo_path, sudo_user, command)

        try:
            output = ""
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            while process.poll() is None:
                for streamline in iter(process.stdout.readline, ''):
                    output += streamline
                    if not suppress_stdout:
                        sys.stdout.write(streamline)
            return output
        except Exception as exception:
            self.error("Error running command '%s'" % command)
            self.error("Exception: %s" % exception)
            return ""

    def whereis(self, program):
        for path in os.environ.get('PATH', '').split(':'):
            if os.path.exists(os.path.join(path, program)) and not os.path.isdir(os.path.join(path, program)):
                return os.path.join(path, program)
        return None

    def generate_uniq_filepath(self, prefix='', suffix='txt'):
        timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S%f')
        filename = "%s%s.%s" % (prefix, timestamp, suffix)
        filepath = os.path.join(self.workspace, self._modulename.split('/')[-1], filename)
        return filepath

    def save_output(self, filepath, output, append=False):
        if not os.path.exists(os.path.dirname(filepath)):
            os.makedirs(os.path.dirname(filepath))
        if append:
            outfile = open(filepath, 'a')
        else:
            outfile = open(filepath, 'w')
        outfile.write(output)
        outfile.close()

    #==================================================
    # OPTIONS METHODS
    #==================================================

    def _get_source(self, params, query=None):
        prefix = params.split()[0].lower()
        if prefix in ['query', 'default']:
            query = ' '.join(params.split()[1:]) if prefix == 'query' else query
            try: results = self.query(query)
            except sqlite3.OperationalError as e:
                raise framework.FrameworkException('Invalid source query. %s %s' % (type(e).__name__, e.message))
            if not results:
                sources = []
            elif len(results[0]) > 1:
                sources = [x[:len(x)] for x in results]
                #raise framework.FrameworkException('Too many columns of data as source input.')
            else:
                sources = [x[0] for x in results]
        elif os.path.exists(params):
            sources = open(params).read().split()
        else:
            sources = [params]
        source = [self.to_unicode(x) for x in sources]
        if not source:
            raise framework.FrameworkException('Source contains no input.')
        return source

    #==================================================
    # REQUEST METHODS
    #==================================================

    def make_cookie(self, name, value, domain, path='/'):
        return cookielib.Cookie(
            version=0, 
            name=name, 
            value=value,
            port=None, 
            port_specified=False,
            domain=domain, 
            domain_specified=True, 
            domain_initial_dot=False,
            path=path, 
            path_specified=True,
            secure=False,
            expires=None,
            discard=False,
            comment=None,
            comment_url=None,
            rest=None
        )

    #==================================================
    # SHOW METHODS
    #==================================================

    def show_inputs(self):
        if hasattr(self, '_default_source'):
            try:
                self._validate_options()
                inputs = self._get_source(self.options['source'], self._default_source)
                self.table([[x] for x in inputs], header=['Module Inputs'])
            except Exception as e:
                self.output(e.__str__())
        else:
            self.output('Source option not available for this module.')

    def show_source(self):
        for path in [os.path.join(x, 'modules', self._modulename) +'.py' for x in (self.app_path, self._home)]:
            if os.path.exists(path):
                filename = path
        with open(filename) as f:
            content = f.readlines()
            nums = [str(x) for x in range(1, len(content)+1)]
            num_len = len(max(nums, key=len))
            for num in nums:
                print('%s|%s' % (num.rjust(num_len), content[int(num)-1]), end='')

    def show_info(self):
        self.meta['path'] = os.path.join('modules', self._modulename) + '.py'
        print('')
        # meta info
        for item in ['name', 'path', 'author', 'version']:
            if self.meta.get(item):
                print('%s: %s' % (item.title().rjust(10), self.meta[item]))
        # required keys
        if self.meta.get('required_keys'):
            print('%s: %s' % ('keys'.title().rjust(10), ', '.join(self.meta.get('required_keys'))))
        print('')
        # description
        if 'description' in self.meta:
            print('Description:')
            print('%s%s' % (self.spacer, textwrap.fill(self.meta['description'], 100, subsequent_indent=self.spacer)))
            print('')
        # options
        print('Options:', end='')
        self.show_options()
        # sources
        if hasattr(self, '_default_source'):
            print('Source Options:')
            print('%s%s%s' % (self.spacer, 'default'.ljust(15), self._default_source))
            print('%s%sstring representing a single input' % (self.spacer, '<string>'.ljust(15)))
            print('%s%spath to a file containing a list of inputs' % (self.spacer, '<path>'.ljust(15)))
            print('%s%sdatabase query returning one column of inputs' % (self.spacer, 'query <sql>'.ljust(15)))
            print('')
        # comments
        if 'comments' in self.meta:
            print('Comments:')
            for comment in self.meta['comments']:
                prefix = '* '
                if comment.startswith('\t'):
                    prefix = self.spacer+'- '
                    comment = comment[1:]
                print('%s%s' % (self.spacer, textwrap.fill(prefix+comment, 100, subsequent_indent=self.spacer)))
            print('')

    def show_globals(self):
        self.show_options(self._global_options)

    #==================================================
    # COMMAND METHODS
    #==================================================

    def do_reload(self, params):
        '''Reloads the current module'''
        self._reload = 1
        return True

    def do_run(self, params):
        '''Runs the module'''
        try:
            self._summary_counts = {}
            self._validate_options()
            pre = self.module_pre()
            params = [pre] if pre is not None else []
            # provide input if a default query is specified in the module
            if hasattr(self, '_default_source'):
                objs = self._get_source(self.options['source'], self._default_source)
                params.insert(0, objs)
            self.module_run(*params)
            self.module_post()
        except KeyboardInterrupt:
            print('')
        except Exception:
            self.print_exception()
        finally:
            # print module summary
            if self._summary_counts:
                self.heading('Summary', level=0)
                for table in self._summary_counts:
                    new = self._summary_counts[table][0]
                    cnt = self._summary_counts[table][1]
                    if new > 0:
                        method = getattr(self, 'alert')
                    else:
                        method = getattr(self, 'output')
                    method('%d total (%d new) %s found.' % (cnt, new, table))
                self._summary_counts = {}
            # update the dashboard
            self.query('INSERT OR REPLACE INTO dashboard (module, runs) VALUES (\'%(x)s\', COALESCE((SELECT runs FROM dashboard WHERE module=\'%(x)s\')+1, 1))' % {'x': self._modulename})

    def module_pre(self):
        pass

    def module_run(self):
        pass

    def module_post(self):
        pass
