#!/usr/bin/python

import os
import platform
import signal
import threading
import time

import logger
import SRNd

log_targets = (
  { 'target':   'stderr',
    'loglevel': ('all',),
    'format':   '${date} ${loglevel} [${source}] ${message}\n',
    'date_fmt': '%H:%M:%S'
  },
  { 'target':   'SRNd.log',
    'loglevel': ('warn', 'err', 'crit'),
    'date_fmt': '%Y/%m/%d %H:%M:%S'
  }
)
logger = logger.logger(log_targets)
loglevel_own = logger.INFO
logger.start()

def log(loglevel, message):
  if loglevel >= loglevel_own:
    logger.log('SRNd', message, loglevel)

if platform.system().lower() == 'linux':
  log(logger.INFO, 'linux detected, using F_NOTIFY')
  import fcntl
  bsd = False
elif platform.system().lower().endswith('bsd'):
  log(logger.INFO, '*BSD detected: %s, using select.kqueue()' % platform.system())
  import select
  try:
    queue = select.kqueue()
    bsd = True
  except Exception as e:
    log(logger.CRITICAL, 'could not load BSD kqueue: %s' % e)
    logger.running = False
    exit(1)
else:
  log(logger.CRITICAL, 'unsupported platform: \'%s\'' % platform.system())
  logger.running = False
  exit(1)

srnd = SRNd.SRNd(logger)
fd = os.open(srnd.watching(), os.O_RDONLY | os.O_NONBLOCK)

srnd.start()
terminate = False
try:
  while not srnd.dropper.running:
    time.sleep(0.5)
  log(logger.INFO, 'starting initial check for new articles')
  srnd.dropper.handler_progress_incoming(None, None)
except KeyboardInterrupt:
  terminate = True

if bsd:
  watching = (select.kevent(fd, filter=select.KQ_FILTER_VNODE, flags=select.KQ_EV_ADD | select.KQ_EV_ENABLE | select.KQ_EV_CLEAR, fflags=select.KQ_NOTE_WRITE),)
else:
  signal.signal(signal.SIGIO, srnd.dropper.handler_progress_incoming)
  fcntl.fcntl(fd, fcntl.F_SETSIG, 0)
  fcntl.fcntl(fd, fcntl.F_NOTIFY, fcntl.DN_MODIFY | fcntl.DN_CREATE | fcntl.DN_MULTISHOT)
signal.signal(signal.SIGHUP, srnd.update_hooks_outfeeds_plugins)

try:
  while not terminate:
    if bsd:
      log(logger.DEBUG, 'reading events..')
      log(logger.DEBUG, 'got events: \'%s\'' % str(queue.control(watching, 1, None)))
      srnd.dropper.handler_progress_incoming(None, None)
    else:
      time.sleep(3600)
except KeyboardInterrupt:
  print()
  pass
log(logger.INFO, 'shutting down..')
srnd.shutdown()
for thread in threading.enumerate():
  if thread.name == 'logger': continue
  try: thread.join()
  except RuntimeError as e:
    pass
logger.running = False
logger.join()
log(logger.INFO, 'bye')
exit(0)
