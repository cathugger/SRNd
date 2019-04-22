#!/usr/bin/env python2

import Queue
import time
import threading

import feeds.outfeed
import feeds.infeed

def OutFeed(kill_me, logger, config):
  if 'multiconn' not in config or config['multiconn'] < 2 or config['multiconn'] > 10:
    handler = feeds.outfeed.OutFeed
  else:
    handler = MultiOutFeed
  return handler(kill_me, logger, config)

class MultiFeed(object):
  """base wrapper"""
  def __init__(self):
    self._feeds = list()
    self._feeds_count = 0
    self.terminated = False
    self._feeds_lock = threading.Lock()

  def get_status(self, target=None):
    if target == 'qsize':
      return sum([xx.qsize for xx in self._feeds])
    elif target == 'byte_transfer':
      return sum([xx.byte_transfer for xx in self._feeds])
    elif target == 'time_transfer':
      return sum([xx.time_transfer for xx in self._feeds]) / self._feeds_count
    elif target in ('state', 'mode'):
      return self._get_status_all(target)
    else:
      return None

  def _get_status_all(self, target):
    status_ = dict()
    for state in [feed.get_status(target) for feed in self._feeds]:
      status_[state] = status_.get(state, 0) + 1
    return '|'.join('{}({})'.format(k, v) for k, v in status_.items())

class MultiInFeed(MultiFeed):

  def log(self, loglevel, message):
    if loglevel >= self.loglevel:
      self.logger.log(self.name, message, loglevel)

  def __init__(self, logger, debug, kill_me, already_wait, wrapper_name):
    MultiFeed.__init__(self)
    self.logger = logger
    self.loglevel = debug
    self._already_wait = already_wait
    self._kill_me = kill_me
    self.name = wrapper_name
    self.sync_on_startup = False

  def append_infeed(self, infeed_instance, name=None):
    """Add infeed and return new infeed name"""
    if self.terminated:
      return None
    self._feeds_lock.acquire()
    try:
      # change kill_me link
      infeed_instance.kill_me = self.kill_me
      # change already_wait link
      infeed_instance.already_wait = self.already_wait
      # rename infeed force
      if name is not None:
        infeed_instance.name = '{}-{}'.format(self.name, self._feeds_count)
      self._feeds.append(infeed_instance)
      self._feeds_count += 1
      return '{}-{}'.format(self.name, self._feeds_count - 1)
    finally:
      self._feeds_lock.release()

  def i_wait(self, message_id):
    for target in self._feeds:
      if target.i_wait(message_id):
        return True
    return False

  def already_wait(self, _, message_id):
    return self._already_wait(self.name, message_id)

  def kill_me(self, name):
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
    self._kill_me(self.name)

class OutFeedInstance(feeds.outfeed.OutFeed):
  def __init__(self, postfix, add_trackdb, **kwargs):
    feeds.outfeed.OutFeed.__init__(self, **kwargs)
    self._add_trackdb = add_trackdb
    self.name += '-{}'.format(postfix)

  def update_trackdb(self, line):
    # rewrite
    self.log(self.logger.DEBUG, 'updating trackdb: %s' % line)
    message_id = line.split(' ')[1]
    # remove existing\sending\etc article
    self._recheck_sending(message_id, 'remove')
    self._add_trackdb(message_id)

class MultiOutFeed(MultiFeed):

  def log(self, loglevel, message):
    if loglevel >= self.loglevel:
      self.logger.log(self.name, message, loglevel)

  def __init__(self, kill_me, logger, config):
    MultiFeed.__init__(self)
    self.sync_on_startup = config['sync_on_startup']
    # tuple(host, port)
    self.name = 'outfeed-{}-{}'.format(*config['server'])
    self.loglevel = config['debug']
    self.logger = logger
    self._kill_me = kill_me
    self._trackdb_busy = False
    self.trackdb_queue = Queue.Queue()
    self._feeds_count = config['multiconn']
    for target in range(self._feeds_count):
      self._feeds.append(
          OutFeedInstance(
              kill_me=self.kill_me,
              logger=logger,
              config=config,
              postfix=target,
              add_trackdb=self.add_trackdb
          )
      )
    self._current_outfeed = 0

  def add_article(self, message_id, ctl):
    self._feeds[self._current_outfeed].add_article(message_id, ctl)
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
    self._kill_me(self.name)

  @staticmethod
  def kill_me(_):
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
