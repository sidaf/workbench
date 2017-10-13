from Queue import Queue, Empty
from threading import Thread
import threading
import time


class ThreadPoolMixin(object):

    def get_threadpool(self):
        thread_count = self._global_options['threads']
        return ThreadPool(thread_count, self)


class Worker(Thread):
    """ Thread executing tasks from a given tasks queue """
    def __init__(self, tasks, parent):
        Thread.__init__(self)
        self.tasks = tasks
        self.parent = parent
        self.daemon = True
        self.stopped = threading.Event()
        self.start()

    def run(self):
        while not self.stopped.is_set():
            try:
                # use the get_nowait() method for retrieving a queued item to
                # prevent the thread from blocking when the queue is empty
                func, args, kargs = self.tasks.get_nowait()
            except Empty:
                continue
            try:
                func(*args, **kargs)
            except:
                # handle exceptions local to the thread
                self.parent.print_exception('(thread=%s, function=%s, args=%s, kargs=%s)' %
                                            (self.name, repr(func), repr(args), repr(kargs)))
            finally:
                # Mark this task as done, whether an exception happened or not
                self.tasks.task_done()


class ThreadPool:
    """ Pool of threads consuming tasks from a queue """
    def __init__(self, num_threads, parent):
        self.tasks = Queue(num_threads)
        self.parent = parent
        self.workers = []
        for _ in range(num_threads):
            worker = Worker(self.tasks, self.parent)
            self.workers.append(worker)

    def add_task(self, func, *args, **kargs):
        """ Add a task to the queue """
        self.tasks.put((func, args, kargs))

    def map(self, func, args_list):
        """ Add a list of tasks to the queue """
        for args in args_list:
            self.add_task(func, args)

    def wait_completion(self):
        """ Wait for completion of all the tasks in the queue """
        # hack to catch keyboard interrupts
        try:
            while not self.tasks.empty():
                time.sleep(.7)
        except KeyboardInterrupt:
            self.parent.error('Ok. Waiting for threads to exit...')
            # set the event flag to trigger an exit for all threads (interrupt condition)
            for worker in self.workers:
                worker.stopped.set()
            # prevent the module from returning to the interpreter until all threads have exited
            for worker in self.workers:
                worker.join()
            raise
        self.tasks.join()

    def shutdown(self):
        # set the event flag to trigger an exit for all threads (interrupt condition)
        for worker in self.workers:
            worker.stopped.set()
        # prevent the module from returning to the interpreter until all threads have exited
        for worker in self.workers:
            worker.join()
