#!/usr/bin/python

from feeds.feed import feed

def OutFeed(master, logger, config, db_connector, host, port, sync_on_startup, proxy=None, debug=2):
  if 'multiconn' not in config['config'] or 10 < config['config']['multiconn'] < 2:
    handler = feed
  else:
    handler = MultiOutFeed
  return handler(master=master, logger=logger, config=config, host=host, port=port, db_connector=db_connector, outstream=True, sync_on_startup=sync_on_startup, proxy=proxy, debug=debug)

class MultiOutFeed(object):
  def __init__(self, master, logger, config, host, port, db_connector, sync_on_startup, proxy, debug):
    pass
