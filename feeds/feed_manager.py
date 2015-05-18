#!/usr/bin/python

import time
import threading

from feeds.infeed import InFeed
from feeds.feed_wrapper import OutFeed, MultiInFeed

class LockDict(dict):

  def __init__(self):
    self.lock = threading.Lock()
    dict.__init__(self)

class FeedsManager(object):

  def __init__(self, **kwargs):
    self.log = kwargs['log']
    self.logger = kwargs['logger']
    self._infeed_config = kwargs['infeed_config']
    self.infeed_debuglevel = kwargs.get('infeed_debuglevel', 2)

    self._in = LockDict()
    self._out = LockDict()

  def is_infeed(self, name):
    return name in self._in

  def is_outfeed(self, name):
    return name in self._out

  def add_infeed(self, name, connection, db_connector):
    self._in[name] = InFeed(
        rename_infeed=self._rename_infeed,
        kill_me=self._terminate_infeed,
        logger=self.logger,
        config=self._infeed_config,
        connection=connection,
        debug=self.infeed_debuglevel,
        db_connector=db_connector
    )

  def add_outfeed(self, name, config):
    self._out[name] = OutFeed(kill_me=self._terminate_outfeed, logger=self.logger, config=config)

  def start_infeed(self, name):
    self._in[name].start()

  def start_outfeed(self, name):
    self._out[name].start()

  def list_infeed(self):
    return self._in.keys()

  def list_outfeed(self):
    return self._out.keys()

  def shutdown_infeed(self, name):
    return self._shutdown(self._in, name)

  def shutdown_outfeed(self, name):
    return self._shutdown(self._out, name)

  @staticmethod
  def _shutdown(obj, name):
    wait_count = 50
    c_count = 0
    wait_time = 0.4
    obj[name].shutdown()
    while name in obj and c_count < wait_count:
      c_count += 1
      time.sleep(wait_time)
    return name not in obj

  def shutdown_all(self):
    wait_count = 50
    c_count = 0
    wait_time = 0.4
    for target in self._in.values():
      target.shutdown()
    for target in self._out.values():
      target.shutdown()
    while (self._in or self._out) and c_count < wait_count:
      c_count += 1
      time.sleep(wait_time)
    error = self.list_infeed() + self.list_outfeed()
    if error:
      self.log(self.logger. ERROR, '{} does not respond to shutdown in {} second'.format(', '.join(error), int(c_count * wait_time)))

  def status(self):
    stats = {'infeeds': {}, 'outfeeds': {}}
    for infeed in self.list_infeed():
      stats['infeeds'][infeed[7:]] = self.stat_infeed(infeed)
    for outfeed in self.list_outfeed():
      stats['outfeeds'][outfeed[8:]] = self.stat_outfeed(outfeed)
    return stats

  def stat_infeed(self, name):
    return self._get_feed_stat(self._in, name)

  def stat_outfeed(self, name):
    return self._get_feed_stat(self._out, name)

  @staticmethod
  def _get_feed_stat(obj, name):
    return {
        "state": obj[name].get_status('state'),
        "queue": obj[name].get_status('qsize'),
        "transfer": obj[name].get_status('byte_transfer'),
        "transfer_time": obj[name].get_status('time_transfer'),
        "mode": obj[name].get_status('mode')
    }

  def add_article(self, name, message_id, ctl):
    self._out[name].add_article(message_id, ctl)

  def sync_outfeed(self, name):
    return self._out[name].sync_on_startup

  def _terminate_infeed(self, name):
    self._terminate_feed(self._in, name)

  def _terminate_outfeed(self, name):
    self._terminate_feed(self._out, name)

  def _terminate_feed(self, obj, name):
    obj.lock.acquire()
    try:
      if name in obj:
        del obj[name]
      else:
        self.log(self.logger.WARNING, 'should remove %s but not in dict. wtf?' % name)
    finally:
      obj.lock.release()

  def _rename_infeed(self, old_name, new_name, allow_multiconn=True):
    self._in.lock.acquire()
    try:
      if not (new_name.startswith('infeed-') and self.is_infeed(old_name)):
        return None
      if self.is_infeed(new_name):
        if not allow_multiconn:
          # multiconnection not allowed for this key\name\whatever
          return None
        if not isinstance(self._in[new_name], MultiInFeed):
          # convert normal infeed to MultiInFeed.
          # pop old infeed, create instance MultiInFeed, append old infeed to multiinfeed
          darling = self._in.pop(new_name)
          self._in[new_name] = MultiInFeed(logger=self.logger, debug=self.infeed_debuglevel, kill_me=self._terminate_infeed, wrapper_name=new_name)
          self._in[new_name].append_infeed(darling, new_name)
        return self._in[new_name].append_infeed(self._in.pop(old_name))
      else:
        self._in[new_name] = self._in.pop(old_name)
        return new_name
    finally:
      self._in.lock.release()

