from lib.core.module import BaseModule
from lib.mixins.threads import ThreadingMixin
import sys
from time import time, sleep, strftime, localtime
from collections import defaultdict
import threading

# Pseudo constants
BRUTE_STATUS_ERROR = -1
BRUTE_STATUS_SUCCESS = 1
BRUTE_STATUS_FAIL = 2


class BruteModule(BaseModule, ThreadingMixin):

    def __init__(self, *args, **kwargs):
        result = BaseModule.__init__(self, *args, **kwargs)

        self.max_attempts = 4
        self.target_try_count = defaultdict(int)
        self.target_max_attempts = 4 * self.max_attempts
        self.rate_limit = 0
        self.iteration = 0
        self.iteration_lock = threading.Lock()

        return result

    def module_run(self):
        # Reset base class options on every 'run'
        self.target_try_count = defaultdict(int)
        self.iteration = 0

    def connect(self, target):
        # Function to be overridden by child class
        return None

    def execute(self, connection, candidate, target, *args):
        # Function to be overridden by child class
        pass

    def module_thread(self, candidate, target, *args):
        with self.iteration_lock:
            self.iteration += 1
            count = self.iteration

        try_count = 1
        connection = None

        while True:
            if self.rate_limit > 0:
                sleep(self.rate_limit)

            if try_count <= self.max_attempts and self.target_try_count[target] < self.target_max_attempts:
                try:
                    connection = self.connect(target)
                    self.execute(connection, candidate, target, *args)
                except:
                    message = '%s %s' % sys.exc_info()[:2]
                    #self.error("Error processing candidate '%s', %s" % (candidate, message))
                    sleep(try_count * .1)

                    self.target_try_count[target] += 1
                    if self.target_try_count[target] >= self.target_max_attempts:
                        self.error("Maximum error count reached for target, skipping.")

                    try_count += 1
                    if try_count > self.max_attempts:
                        self.error("Maximum error count reached for candidate '%s', skipping." % candidate)

                    continue
                finally:
                    if connection:
                        connection.close()
            break

    def load_wordlist(self, path):
        if path is None:
            return list()
        with open(path) as fp:
            wordlist = [line.strip() for line in fp]
        return wordlist


class Timing:
    def __enter__(self):
        self.t1 = time()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.time = time() - self.t1
