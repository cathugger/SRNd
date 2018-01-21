#!/usr/bin/python
import json
import queue
import string
import sys
import threading
import time
from datetime import datetime

loglevel_all = (0, 1, 2, 3, 4, 5)
loglevel_names = (
  'VERBOSE',
  'DEBUG',
  'INFO',
  'WARNING',
  'ERROR',
  'CRITICAL'
)
loglevel_names_nice = (
  '%8s' % 'VERBOSE',
  '%8s' % 'DEBUG',
  '\x1b[32m%8s\x1b[m' % 'INFO',
  '\x1b[33m%8s\x1b[m' % 'WARNING',
  '\x1b[31m%8s\x1b[m' % 'ERROR',
  '\x1b[31m\x1b[01m%8s\x1b[m' % 'CRITICAL'
)
target_mapper = {
  'stdout': sys.stdout,
  'stderr': sys.stderr
}

class logger(threading.Thread):

  def log(self, source, message, loglevel):
    if not self.shut_down:
      self.queue.put((source, message, loglevel))
      return
    self.write(source, message, loglevel)

  def __init__(self, log_targets=None):
    threading.Thread.__init__(self)
    self.queue = queue.Queue()
    self.running = False
    self.VERBOSE =  0
    self.DEBUG =    1
    self.INFO =     2
    self.WARNING =  3
    self.ERROR =    4
    self.CRITICAL = 5
    self.level = {
      'VERBOSE':  self.VERBOSE,
      'DEBUG':    self.DEBUG,
      'INFO':     self.INFO,
      'WARNING':  self.WARNING,
      'ERROR':    self.ERROR,
      'CRITICAL': self.CRITICAL,
      'WARN':     self.WARNING,
      'ERR':      self.ERROR,
      'CRIT':     self.CRITICAL
    }
    self.generate_targets(log_targets)
    self.shut_down = False
    self.name = 'logger'

  @staticmethod
  def encode_big_endian(number, length):
    if number >= 256**length:
      raise OverflowError("%i can't be represented in %i bytes." % (number, length))
    data = b""
    for i in range(0, length):
      data += chr(number >> (8*(length-1-i)))
      number -= (ord(data[-1]) << (8*(length -1 -i)))
    return data

  def generate_targets(self, targets):
    self.targets = list()
    for target in targets:
      # configure target
      if not 'target' in target:
        target_target = sys.stdout
      elif target['target'] in target_mapper:
        target_target = target_mapper[target['target']]
      else:
        target_target = open(target['target'], 'a')
      #configure loglevels
      if not 'loglevel' in target:
        target_loglevels = loglevel_all
      else:
        target_loglevels = list()
        for loglevel in target['loglevel']:
          if loglevel == 'all':
            target_loglevels = loglevel_all
            break
          if loglevel.upper() in self.level:
            target_loglevels.append(self.level[loglevel.upper()])
          else:
            sys.stderr.write('unknown loglevel: \'%s\'\n' % loglevel)
      # TODO: implement source filters
      # configure format
      if not 'format' in target:
        target_format = string.Template('${date} ${loglevel} ${source} ${message}\n')
      else:
        target_format = string.Template(target['format'])
      # configure date format
      if not 'date_fmt' in target:
        target_date_fmt = '%m/%d %H:%M:%S'
      else:
        target_date_fmt = target['date_fmt']
      self.targets.append((target_target, target_loglevels, target_format, target_date_fmt, False))

  def add_target(self, file_object, loglevel=('all',), fmt='${date} ${loglevel} [${source}] ${message}\n', date_fmt='%H:%M:%S', json_framing_4=False):
    if type(file_object) != file:
      raise ValueError("argument 1 must be of type 'file'")
    for item in self.targets:
      if item[0] == file_object:
        return self.update_target(file_object, loglevel=loglevel)
    self.targets.append([file_object, None, string.Template(fmt), date_fmt, json_framing_4])
    return self.update_target(file_object, loglevel=loglevel)

  def update_target(self, file_object, loglevel=None, fmt=None, date_fmt=None, json_framing_4=None):
    # TODO: implement missing updates for fmt, date_fmt and json_framing_4
    for item in self.targets:
      if item[0] != file_object:
        continue
      if loglevel != None:
        item[1] = list()
        for level in loglevel:
          if level == 'all':
            item[1] = loglevel_all
            break
          if level.upper() not in self.level:
            raise ValueError('unknown loglevel: \'%s\'. available loglevels are VERBOSE, DEBUG, INFO, WARNING, ERROR and CRITICAL' % level)
          foo = self.level[level.upper()]
          if len(loglevel) != 1:
            item[1].append(foo)
            continue
          for level in range(foo, max(loglevel_all)+1):
            item[1].append(level)
        return 'logging enabled for loglevels %s' % ', '.join((loglevel_names[x] for x in item[1]))
    raise Exception("modifying logging target for file_object %s failed: not found" % file_object)

  def remove_target(self, file_object):
    for item in self.targets:
      if item[0] == file_object:
        self.targets.remove(item)
        self.log("logger", "removed target for file_object %s" % file_object, self.INFO)
        return "removed logging target for file_object %s" % file_object
    self.log("logger", "removing target for file_object %s failed: not found" % file_object, self.WARNING)
    raise Exception("removing logging target for file_object %s failed: not found" % file_object)

  def write(self, source, message, loglevel):
    for target_file, loglevels, fmt, date_fmt, json_framing_4 in self.targets:
      if loglevel not in loglevels: continue
      for line in ('%s' % message).split('\n'):
        if json_framing_4:
          data = json.dumps({"type": "log", "status": loglevel_names[loglevel], "source": source, "date": time.time(), "data": line})
          data = self.encode_big_endian(len(data), 4) + data
        else:
          date = datetime.utcfromtimestamp(time.time()).strftime(date_fmt)
          data = fmt.substitute(date=date, loglevel=loglevel_names_nice[loglevel], source=source, message=line)
        try: target_file.write(data)
        except:
          #FIXME: write exception to STDERR, eventually remove target
          pass
      try:    target_file.flush()
      except: pass

  def run(self):
    self.write(self.name, 'starting up', self.INFO)
    self.running = True
    while True:
      try:
        source, message, loglevel = self.queue.get(block=True, timeout=3)
        self.write(source, message, loglevel)
      except queue.Empty:
        if not self.running:
          self.shut_down = True
          break
    self.write(self.name, 'shutting down', self.INFO)

if __name__ == '__main__':
  print("can't run as standalone")
  exit(1)
