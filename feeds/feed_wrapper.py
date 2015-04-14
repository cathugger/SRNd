#!/usr/bin/python

import Queue
import time
import threading

import feeds.outfeed
import feeds.infeed

def OutFeed(master, logger, config, server, sync_on_startup, proxy, debug):
  if 'multiconn' not in config or 10 < config['multiconn'] < 2:
    handler = feeds.outfeed.OutFeed
  else:
    handler = MultiOutFeed
  return handler(master, logger, config, server, sync_on_startup, proxy, debug)

class MultiFeed(object):
  """base wrapper"""
  def __init__(self):
    self._feeds = list()
    self._feeds_count = 0
    self.terminated = False
    self._feeds_lock = threading.Lock()

  def get_status(self, target=None):
    if target == 'state':
      state_ = dict()
      for feed_state in [xx.state for xx in self._feeds]:
        state_[feed_state] = state_.get(feed_state, 0) + 1
      return '|'.join(['{}({})'.format(xx, state_[xx]) for xx in state_])
    elif target == 'qsize':
      return sum([xx.qsize for xx in self._feeds])
    elif target == 'byte_transfer':
      return sum([xx.byte_transfer for xx in self._feeds])
    elif target == 'time_transfer':
      return sum([xx.time_transfer for xx in self._feeds]) / self._feeds_count
    else:
      return None

class MultiInFeed(MultiFeed):

  def log(self, loglevel, message):
    if loglevel >= self.loglevel:
      self.logger.log(self.name, message, loglevel)

  def __init__(self, logger, debug, master, wrapper_name):
    MultiFeed.__init__(self)
    self.logger = logger
    self.loglevel = debug
    self._srnd = master
    self.name = wrapper_name
    self.sync_on_startup = False

  def append_infeed(self, infeed_instance, name=None):
    """Add infeed and return new infeed name"""
    if self.terminated:
      return None
    self._feeds_lock.acquire()
    try:
      # change master link
      infeed_instance.SRNd = self
      # rename infeed force
      if name is not None:
        infeed_instance.name = '{}-{}'.format(self.name, self._feeds_count)
      self._feeds.append(infeed_instance)
      self._feeds_count += 1
      return '{}-{}'.format(self.name, self._feeds_count - 1)
    finally:
      self._feeds_lock.release()

  def terminate_feed(self, name):
    if self.terminated:
      return
    self._feeds_lock.acquire()
    try:
      targets = [xx for xx in self._feeds if xx.name == name]
      if len(targets) != 1:
        self.log(self.logger.ERROR, 'Find {} infeed instance for {}.WTF?'.format(len(targets), name))
        return False
      self._feeds.pop(self._feeds.index(targets[0]))
      self._feeds_count -= 1
    finally:
      self._feeds_lock.release()
    if self._feeds_count == 0:
      self.shutdown()
    return True

  def shutdown(self):
    if self.terminated:
      return
    self.terminated = True
    check_wait = 0.2
    max_check = 50
    check_count = 0
    for xx in self._feeds:
      xx.shutdown()
    while [True for xx in self._feeds if xx.isAlive()] and check_count < max_check:
      check_count += 1
      time.sleep(check_wait)
    status = [True for xx in self._feeds if xx.isAlive()]
    if status:
      self.log(self.logger.ERROR, 'Not shutdown {} infeeds instance: {} work. Fix it'.format(self._feeds_count, len(status)))
    self._srnd.terminate_feed(self.name)

class OutFeedInstance(feeds.outfeed.OutFeed):
  def __init__(self, postfix, **kwargs):
    feeds.outfeed.OutFeed.__init__(self, **kwargs)
    self.name += '-{}'.format(postfix)

  def update_trackdb(self, line):
    # rewrite
    self.log(self.logger.DEBUG, 'updating trackdb: %s' % line)
    message_id = line.split(' ')[1]
    # remove existing\sending\etc article
    self._recheck_sending(message_id, 'remove')
    self.SRNd.add_trackdb(message_id)

class MultiOutFeed(MultiFeed):

  def log(self, loglevel, message):
    if loglevel >= self.loglevel:
      self.logger.log(self.name, message, loglevel)

  def __init__(self, master, logger, config, server, sync_on_startup, proxy, debug):
    MultiFeed.__init__(self)
    self.sync_on_startup = sync_on_startup
    # tuple(host, port)
    self.name = 'outfeed-{}-{}'.format(*server)
    self.loglevel = debug
    self.logger = logger
    self._srnd = master
    self._trackdb_busy = False
    self.trackdb_queue = Queue.Queue()
    self._feeds_count = config['multiconn']
    for target in range(self._feeds_count):
      self._feeds.append(
          OutFeedInstance(
              master=self,
              logger=logger,
              config=config,
              server=server,
              sync_on_startup=sync_on_startup,
              proxy=proxy,
              debug=debug,
              postfix=target
          )
      )
    self._current_outfeed = 0

  def add_article(self, message_id):
    self._feeds[self._current_outfeed].add_article(message_id)
    self._current_outfeed += 1
    if self._current_outfeed >= self._feeds_count:
      self._current_outfeed = 0

  def add_trackdb(self, message_id):
    self.trackdb_queue.put(message_id)
    if self.trackdb_queue.qsize() > self._feeds_count * 5:
      self._update_trackdb()

  def start(self):
    return len([target.start() for target in self._feeds])

  def shutdown(self):
    if self.terminated:
      return
    self.terminated = True
    check_wait = 0.2
    max_check = 30
    check_count = 0
    for xx in self._feeds:
      xx.shutdown()
    while [True for xx in self._feeds if xx.isAlive()] and check_count < max_check:
      check_count += 1
      time.sleep(check_wait)
    status = [True for xx in self._feeds if xx.isAlive()]
    if status:
      self.log(self.logger.ERROR, 'Not shutdown {} outfeeds instance: {} work. Fix it'.format(self._feeds_count, len(status)))
    self._feeds = None
    self._update_trackdb()
    self._srnd.terminate_feed(self.name)

  @staticmethod
  def terminate_feed(name):
    # dummy
    return True

  def _update_trackdb(self):
    if self._trackdb_busy:
      return
    self._trackdb_busy = True
    messages = set()
    while self.trackdb_queue.qsize() > 0:
      messages.add(self.trackdb_queue.get())
    if len(messages) > 0:
      try:
        f = open('{0}.trackdb'.format(self.name), 'a')
      except IOError as e:
        self.log(self.logger.ERROR, 'cannot open: %s: %s' % ('{0}.trackdb'.format(self.name), e.strerror))
      else:
        f.write('\n'.join(messages))
        f.write('\n')
        f.close()
    self._trackdb_busy = False
