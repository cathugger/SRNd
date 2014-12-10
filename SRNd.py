#!/usr/bin/python
import json
import os
import pwd
import random
import select
import socket
import sys
import threading
import time
import traceback
from distutils.dir_util import copy_tree

import dropper
import feed

class SRNd(threading.Thread):

  def log(self, loglevel, message):
    if loglevel >= self.loglevel:
      self.logger.log('SRNd', message, loglevel)

  def __init__(self, logger):
    self.logger = logger
    # FIXME: read SRNd loglevel from SRNd.conf
    self.loglevel = self.logger.INFO
    self.read_and_parse_config()
    self.log(self.logger.VERBOSE,  'srnd test logging with VERBOSE')
    self.log(self.logger.DEBUG,    'srnd test logging with DEBUG')
    self.log(self.logger.INFO,     'srnd test logging with INFO')
    self.log(self.logger.WARNING,  'srnd test logging with WARNING')
    self.log(self.logger.ERROR,    'srnd test logging with ERROR')
    self.log(self.logger.CRITICAL, 'srnd test logging with CRITICAL')

    try:
      self.stats_ramfile = open('/proc/self/statm', 'r')
    except Exception as e:
      self.log(self.logger.WARNING, 'can\'t open ram stat file at /proc/self/statm: %s' % e)
      self.stats_ramfile = None

    # create some directories
    for directory in ('filesystem', 'outfeeds', 'plugins'):
      dir = os.path.join(self.data_dir, 'config', 'hooks', directory)
      if not os.path.exists(dir):
        os.makedirs(dir)
      os.chmod(dir, 0o777) # FIXME think about this, o+r should be enough?

    # install / update plugins
    self.log(self.logger.INFO, "installing / updating plugins")
    for directory in os.listdir('install_files'):
      copy_tree(os.path.join('install_files', directory), os.path.join(self.data_dir, directory), preserve_times=True, update=True)
    if self.setuid != '':
      self.log(self.logger.INFO, "fixing plugin permissions")
      for directory in os.listdir(os.path.join(self.data_dir, 'plugins')):
        try:
          os.chown(os.path.join(self.data_dir, 'plugins', directory), self.uid, self.gid)
        except OSError as e:
          if e.errno == 1:
            # FIXME what does this errno actually mean? write actual descriptions for error codes -.-
            self.log(self.logger.WARNING, "couldn't change owner of %s. %s will likely fail to create own directories." % (os.path.join(self.data_dir, 'plugins', directory), directory))
          else:
            # FIXME: exit might not allow logger to actually output the message.
            self.log(self.logger.CRITICAL, "trying to chown plugin directory %s failed: %s" % (os.path.join(self.data_dir, 'plugins', directory), e))
            exit(1)

    # start listening
    if self.ipv6:
      self.socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    else:
      self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
      self.log(self.logger.INFO, 'start listening at %s:%i' % (self.ip, self.port))
      self.socket.bind((self.ip, self.port))
    except socket.error as e:
      if e.errno == 13:
        # FIXME: exit might not allow logger to actually output the message.
        self.log(self.logger.CRITICAL,  '''[error] current user account does not have CAP_NET_BIND_SERVICE: %s
        You have three options:
         - run SRNd as root
         - assign CAP_NET_BIND_SERVICE to the user you intend to use
         - use a port > 1024 by setting bind_port at %s''' % (e, os.path.join(self.data_dir, 'config', 'SRNd.conf')))
        exit(2)
      elif e.errno == 98:
        # FIXME: exit might not allow logger to actually output the message.
        self.log(self.logger.CRITICAL, '[error] %s:%i already in use, change to a different port by setting bind_port at %s' % (self.ip, self.port, os.path.join(self.data_dir, 'config', 'SRNd.conf')))
        exit(2)
      else:
        raise e
    self.socket.listen(5)

    # create jail
    os.chdir(self.data_dir)

    # reading and starting plugins
    # we need to do this before chrooting because plugins may need to import other libraries
    self.plugins = dict()
    self.update_plugins()

    if self.chroot:
      self.log(self.logger.INFO, 'chrooting..')
      try:
        os.chroot('.')
      except OSError as e:
        if e.errno == 1:
          print "[error] current user account does not have CAP_SYS_CHROOT."
          print "        You have three options:"
          print "         - run SRNd as root"
          print "         - assign CAP_SYS_CHROOT to the user you intend to use"
          print "         - disable chroot in {0} by setting chroot=False".format(os.path.join(self.data_dir, 'config', 'SRNd.conf'))
          exit(3)
        else:
          raise e

    if self.setuid != '':
      self.log(self.logger.INFO, 'dropping privileges..')
      try:
        os.setgid(self.gid)
        os.setuid(self.uid)
      except OSError as e:
        if e.errno == 1:
          print "[error] current user account does not have CAP_SETUID/CAP_SETGID: ", e
          print "        You have three options:"
          print "         - run SRNd as root"
          print "         - assign CAP_SETUID and CAP_SETGID to the user you intend to use"
          print "         - disable setuid in {0} by setting setuid=".format(os.path.join(self.data_dir, 'config', 'SRNd.conf'))
          exit(4)
        else:
          raise e

    # check for directory structure
    directories = (
        'incoming',
        os.path.join('incoming', 'tmp'),
        os.path.join('incoming', 'spam'),
        'articles',
        os.path.join('articles', 'censored'),
        os.path.join('articles', 'restored'),
        os.path.join('articles', 'invalid'),
        os.path.join('articles', 'duplicate'),
        'groups',
        'hooks',
        'stats',
        'plugins')
    for directory in directories:
      if not os.path.exists(directory):
        os.mkdir(directory)
    threading.Thread.__init__(self)
    self.name = "SRNd-listener"
    # FIXME add config var for dropper_debug
    self.dropper = dropper.dropper(self.socket, self, self.dropper_debug)

  def read_and_parse_config(self):
    # read configuration
    # FIXME think about path.. always use data/config/SRNd.conf unless argument states otherwise?
    config_file = os.path.join('data', 'config', 'SRNd.conf')
    writeConfig = False
    if os.path.exists(config_file):
      self.ip = ''
      self.port = 0
      self.hostname = ''
      self.data_dir = ''
      self.chroot = ''
      self.setuid = ''
      self.ipv6 = ''
      self.infeed_debug = -1
      self.dropper_debug = -1
      self.instance_name = ''
      f = open(config_file, 'r')
      config = f.read()
      f.close()
      lines = config.split('\n')
      for line in lines:
        if len(line) == 0:
          continue
        if line[0] == '#':
          continue
        if not '=' in line:
          self.log(self.logger.WARNING, 'no = in setting \'%s\'' % line)
          continue
        key = line.split('=', 1)[0]
        value = line.split('=', 1)[1]
        #self.config[key] = value
        if key == 'bind_ip':
          self.ip = value
        elif key == 'bind_port':
          try:
            self.port = int(value)
          except ValueError as e:
            self.port = 0
        elif key == 'bind_use_ipv6':
          if value.lower() == 'true':
            self.ipv6 = True
          elif value.lower() == 'false':
            self.ipv6 = False
          else:
            self.log(self.logger.WARNING, 'bind_user_ipv6: unknown value. only accepting true or false. using default of false')
            self.ipv6 = False
        elif key == 'data_dir':
          self.data_dir = value
        elif key == 'use_chroot':
          if value.lower() == 'true':
            self.chroot = True
          elif value.lower() == 'false':
            self.chroot = False
          else:
            self.log(self.logger.WARNING, 'use_chroot: unknown value. only accepting true or false. using default of true')
            self.chroot = True
        elif key == 'setuid':
          self.setuid = value
        elif key == 'srnd_debuglevel':
          error = False
          try:
            self.loglevel = int(value)
            if self.loglevel > 5 or self.loglevel < 0:
              error = True
          except ValueError as e:
            error = True
          if error:
            self.loglevel = 2
            self.log(self.logger.WARNING, 'srnd_debuglevel: only accepting integer between 0 and 5. using default of 2')
        elif key == 'infeed_debuglevel':
          error = False
          try:
            self.infeed_debug = int(value)
            if self.infeed_debug > 5 or self.infeed_debug < 0:
              error = True
          except ValueError as e:
            error = True
          if error:
            self.infeed_debug = 2
            self.log(self.logger.WARNING, 'infeed_debuglevel: only accepting integer between 0 and 5. using default of 2')
        elif key == 'dropper_debuglevel':
          error = False
          try:
            self.dropper_debug = int(value)
            if self.dropper_debug > 5 or self.dropper_debug < 0:
              error = True
          except ValueError as e:
            error = True
          if error:
            self.dropper_debug = 2
            self.log(self.logger.WARNING, 'dropper_debuglevel: only accepting integer between 0 and 5. using default of 2')
        elif key == 'instance_name':
          error = False
          if ' ' in value:
            error = True
          else:
            self.instance_name = value
          if error:
            self.instance_name = 'SRNd'
            self.log(self.logger.WARNING, 'instance_name contains a space. using default of \'SRNd\'')

      # initialize required variables if currently unset
      if self.ip == '':
        self.ip = ''
        writeConfig = True
      if self.port == 0:
        self.port = 119
        writeConfig = True
      #if self.hostname == '':
      #  self.config = 'some random NNTPd v 0.1'
      #  writeConfig = True
      if self.data_dir == '':
        self.data_dir = 'data'
        writeConfig = True
      if self.ipv6 == '':
        self.ipv6 = False
        writeConfig = True
      if self.infeed_debug == -1:
        self.infeed_debug = 2
        writeConfig = True
      if self.dropper_debug == -1:
        self.dropper_debug = 2
        writeConfig = True
      if self.instance_name == '':
        self.instance_name = 'SRNd'
        writeConfig = True
    else:
      # initialize variables with sane defaults
      self.ip = ''
      self.port = 119
      #self.config = 'some random NNTPd v 0.1'
      self.data_dir = 'data'
      self.chroot = True
      self.setuid = 'news'
      self.ipv6 = False
      self.infeed_debug = 2
      self.dropper_debug = 2
      self.instance_name = 'SRNd'
      writeConfig = True
    if self.setuid != '':
      try:
        self.uid, self.gid = pwd.getpwnam(self.setuid)[2:4]
      except KeyError as e:
        # FIXME: user can't change config file as it might not exist at this point.
        print "[error] '{0}' is not a valid user on this system.".format(self.setuid)
        print "[error] either create {0} or change setuid at '{1}' into a valid username or an empty value to disable setuid".format(self.setuid, config_file)
        exit(1)
    else:
      if self.chroot:
        print "[error] You defined use_chroot=True and set setuid to an empty value."
        print "[error] This would result in chrooting without dropping privileges which defeats the purpose of chrooting completely."
        exit(3)
    if writeConfig:
      configPath = os.path.join(self.data_dir, 'config')
      if not os.path.exists(configPath):
        os.makedirs(configPath)
        if self.setuid != '':
          try:
            os.chown(self.data_dir, self.uid, self.gid)
            os.chown(configPath, self.uid, self.gid)
          except OSError as e:
            if e.errno == 1:
              print "[warning] can't change ownership of newly generated data directory."
              print "[warning] If you don't intend to run SRNd as root and let it chroot and setuid/gid itself (which is the recommend way to run SRNd), you"
              print "[warning] need to modify the configuration file at {0} and set setuid to an empty value.".format(os.path.join(self.data_dir, 'config', 'SRNd.conf'))
              print "[warning] If you want to run as root delete the data directory before you restart SRNd."
            else:
              print "[error] trying to chown configuration files failed: ", e
              exit(1)
      f = open(os.path.join(configPath, 'SRNd.conf'), 'w')
      f.write('# changing this file requires a restart of SRNd\n')
      f.write('# empty lines or lines starting with # are ignored\n')
      f.write('# do not add whitespaces before or after =\n')
      f.write('# additional data in this file will be overwritten every time a value has been changed\n')
      f.write('\n')
      f.write('bind_ip={0}\n'.format(self.ip))
      f.write('bind_port={0}\n'.format(self.port))
      f.write('bind_use_ipv6={0}\n'.format(self.ipv6))
      f.write('data_dir={0}\n'.format(self.data_dir))
      f.write('use_chroot={0}\n'.format(self.chroot))
      f.write('setuid={0}\n'.format(self.setuid))
      f.write('srnd_debuglevel={0}\n'.format(self.loglevel))
      f.write('infeed_debuglevel={0}\n'.format(self.infeed_debug))
      f.write('dropper_debuglevel={0}\n'.format(self.dropper_debug))
      f.write('instance_name={0}\n'.format(self.instance_name))
      f.close()

  def update_hooks(self):
    self.log(self.logger.INFO, 'reading hook configuration..')
    self.hooks = dict()
    self.hook_blacklist = dict()
    total = 0
    for hook_type in ('filesystem', 'outfeeds', 'plugins'):
      directory = os.path.join('config', 'hooks', hook_type)
      found = 0
      for hook in os.listdir(directory):
        link = os.path.join(directory, hook)
        if not os.path.isfile(link):
          continue
        # FIXME ignore new plugin hooks after startup, needs a boolean somewhere
        # FIXME if hook_type == "plugins" and "plugin-{0}".format(hook) not in self.
        # read hooks into self.hooks[group_name] = hook_name
        f = open(link, 'r')
        line = f.readline()
        while line != "":
          if len(line) == 1:
            line = f.readline()
            continue
          if line[0] == '#':
            line = f.readline()
            continue
          line = line[:-1]
          if line[0] == '!':
            # blacklist
            line = line[1:]
            if line[0] == '*':
              self.log(self.logger.WARNING, 'invalid blacklist rule: !* is not allowed. everything not whitelisted will be rejected automatically.')
              line = f.readline()
              continue
            if not line in self.hook_blacklist:
              self.hook_blacklist[line] = list()
            name = '{0}-{1}'.format(hook_type, hook)
            if not name in self.hook_blacklist[line]:
              self.hook_blacklist[line].append(name)
              found += 1
          else:
            # whitelist
            if not line in self.hooks:
              self.hooks[line] = list()
            name = '{0}-{1}'.format(hook_type, hook)
            if not name in self.hooks[line]:
              self.hooks[line].append(name)
              found += 1
          line = f.readline()
        f.close()
        if hook_type == 'filesystem':
          # create hook directory
          hook_dir = os.path.join('hooks', hook)
          if not os.path.exists(hook_dir):
            os.mkdir(hook_dir)
            os.chmod(hook_dir, 0o777)
      total += found
    #if not '*' in self.hooks:
    #  self.hooks['*'] = list()
    output_log = list()
    if total > 0:
      output_log.append('found %i hooks:' % total)
      output_log.append('whitelist')
      for pattern in self.hooks:
        output_log.append(' %s' % pattern)
        for hook in self.hooks[pattern]:
          output_log.append('   %s' % hook)
      output_log.append('blacklist')
      for pattern in self.hook_blacklist:
        output_log.append(' %s' % pattern)
        for hook in self.hook_blacklist[pattern]:
          output_log.append('   %s' % hook)
      self.log(self.logger.INFO, '\n'.join(output_log))
    else:
      self.log(self.logger.WARNING, 'did not find any hook')

  def update_plugins(self):
    self.log(self.logger.INFO, 'importing plugins..')
    new_plugins = list()
    current_plugin = None
    errors = False
    for plugin in os.listdir(os.path.join('config', 'hooks', 'plugins')):
      link = os.path.join('config', 'hooks', 'plugins', plugin)
      if os.path.isfile(link):
        plugin_path = os.path.join('plugins', plugin)
        if not plugin_path in sys.path:
          sys.path.append(plugin_path)
        name = 'plugin-' + plugin
        if name in self.plugins:
          continue
        args = dict()
        f = open(link, 'r')
        line = f.readline()
        while line != "":
          if len(line) == 1:
            line = f.readline()
            continue
          if line.startswith('#start_param '):
            line = line[13:-1]
            key = line.split('=', 1)[0]
            args[key] = line.split('=', 1)[1]
          line = f.readline()
        f.close()
        #print "[SRNd] trying to import {0}..".format(name)
        try:
          if 'SRNd' in args:
            args['SRNd'] = self
          current_plugin = __import__(plugin)
          self.plugins[name] = current_plugin.main(name, self.logger, args)
          new_plugins.append(name)
        except Exception as e:
          errors = True
          self.log(self.logger.ERROR, 'error while importing %s: %s' % (name, e))
          if name in self.plugins:
            del self.plugins[name]
          continue
    del current_plugin
    if errors:
      self.log(self.logger.CRITICAL, 'could not import at least one plugin. Terminating.')
      self.log(self.logger.CRITICAL, traceback.format_exc())
      exit(1)
    self.log(self.logger.INFO, 'added %i new plugins' % len(new_plugins))
    # TODO: stop and remove plugins not listed at config/plugins anymore

  def update_outfeeds(self):
    self.log(self.logger.INFO, 'reading outfeeds..')
    counter_new = 0
    current_feedlist = list()
    self.feed_db = dict()
    for outfeed in os.listdir(os.path.join('config', 'hooks', 'outfeeds')):
      outfeed_file = os.path.join('config', 'hooks', 'outfeeds', outfeed)
      if os.path.isfile(outfeed_file):
        f = open(outfeed_file)
        sync_on_startup = False
        debuglevel = self.loglevel
        proxy_type = None
        proxy_ip = None
        proxy_port = None
        for line in f:
          lowerline = line.lower()
          if lowerline.startswith('#start_param '):
            if lowerline.startswith('#start_param sync_on_startup=true'):
              sync_on_startup = True
            elif lowerline.startswith('#start_param debug='):
              try:
                debuglevel = int(lowerline.split('=')[1][0])
              except:
                pass
            elif lowerline.startswith('#start_param proxy_type='):
              proxy_type = lowerline.split('=', 1)[1].rstrip()
            elif lowerline.startswith('#start_param proxy_ip='):
              proxy_ip = lowerline.split('=', 1)[1].rstrip()
            elif lowerline.startswith('#start_param proxy_port='):
              proxy_port = lowerline.split('=', 1)[1].rstrip()
        f.close()
        if ':' in outfeed:
          host = ':'.join(outfeed.split(':')[:-1])
          port = int(outfeed.split(':')[-1])
        else:
          # FIXME: how to deal with ipv6 and no default port?
          host = outfeed
          port = 119
        name = "outfeed-{0}-{1}".format(host, port)
        # open track db here, read, close
        if sync_on_startup == True:
          self.feed_db[name] = list()
          try:
            f = open('{0}.trackdb'.format(name), 'r')
          except IOError as e:
            if e.errno == 2:
              pass
            else:
              self.log(self.logger.ERROR, 'cannot open: %s: %s' % ('{0}.trackdb'.format(name), e.strerror))
          else:
            for line in f.readlines():
              self.feed_db[name].append(line.rstrip('\n'))
        current_feedlist.append(name)
        proxy = None
        if proxy_type != None:
          if proxy_ip != None:
            try:
              proxy_port = int(proxy_port)
              proxy = (proxy_type, proxy_ip, proxy_port)
              self.log(self.logger.INFO, "starting outfeed %s using proxy: %s" % (name, str(proxy)), 2)
            except:
              pass
        if name not in self.feeds:
          try:
            self.log(self.logger.DEBUG, 'starting outfeed: %s' % name)
            self.feeds[name] = feed.feed(self, self.logger, outstream=True, host=host, port=port, sync_on_startup=sync_on_startup, proxy=proxy, debug=debuglevel)
            self.feeds[name].start()
            counter_new += 1
          except Exception as e:
            self.log(self.logger.WARNING, 'could not start outfeed %s: %s' % (name, e))
    counter_removed = 0
    feeds = list()
    for name in self.feeds:
      if name.startswith('outfeed'):
        feeds.append(name)
    for name in feeds:
      if not name in current_feedlist and name in self.feeds:
        self.feeds[name].shutdown()
        counter_removed += 1
    self.log(self.logger.INFO, 'outfeeds added: %i' % counter_new)
    self.log(self.logger.INFO, 'outfeeds removed: %i' % counter_removed)

  def update_hooks_outfeeds_plugins(self, signum, frame):
    self.update_outfeeds()
    self.update_plugins()
    self.update_hooks()

  def encode_big_endian(self, number, length):
    if number >= 256**length:
      raise OverflowError("%i can't be represented in %i bytes." % (number, length))
    data = b""
    for i in range(0, length):
      data += chr(number >> (8*(length-1-i)))
      number = number - (ord(data[-1]) << (8*(length -1 -i)))
    return data

  def decode_big_endian(self, data, length):
    if len(data) < length:
      raise IndexError("data length %i lower than given length of %i." % (len(data), length))
    cur_len = 0
    for i in range(0, length):
      cur_len |= ord(data[i]) << (8*(length-1-i))
    return cur_len

  def ctl_socket_send_data(self, fd, data):
    data = json.dumps(data)
    data = self.encode_big_endian(len(data), 4) + data
    length = os.write(fd, data)
    while length != len(data):
      length += os.write(fd, data[length:])

  def ctl_socket_handler_logger(self, data, fd):
    if data["data"] == "off" or data["data"] == "none":
      return self.logger.remove_target(self.ctl_socket_clients[fd][1])
    elif data["data"] == "on":
      data["data"] = 'all'
    return self.logger.add_target(self.ctl_socket_clients[fd][1], loglevel=data["data"].split(' '), json_framing_4=True)

  def ctl_socket_handler_stats(self, data, fd):
    if not 'stats' in self.__dict__:
      self.stats = { "start_up_timestamp": self.start_up_timestamp }
      self.stats_last_update = 0
      self.ram_usage = 0
      if 'SC_PAGESIZE' in os.sysconf_names:
        self.stats_pagesize = os.sysconf('SC_PAGESIZE')
      elif 'SC_PAGE_SIZE' in os.sysconf_names:
        self.stats_pagesize = os.sysconf('SC_PAGE_SIZE')
      elif '_SC_PAGESIZE' in os.sysconf_names:
        self.stats_pagesize = os.sysconf('_SC_PAGESIZE')
      else:
        self.stats_pagesize = 4096
    self.stats["infeeds"]  = sum(1 for x in self.feeds if x.startswith('infeed-'))
    self.stats["outfeeds"] = sum(1 for x in self.feeds if x.startswith('outfeed-'))
    self.stats["plugins"]  = len(self.plugins)
    if time.time() - self.stats_last_update > 5:
      if self.stats_ramfile != None:
        self.stats_ramfile.seek(0)
        self.ram_usage = int(self.stats_ramfile.read().split(' ')[1]) * self.stats_pagesize
      st = os.statvfs(os.getcwd())
      self.stats["groups"]    = os.stat('groups').st_nlink - 2
      self.stats["articles"]  = sum(1 for x in os.listdir('articles')) - os.stat('articles').st_nlink + 2
      self.stats["cpu"]       = 15
      self.stats["ram"]       = self.ram_usage
      self.stats["disk_free"] = st.f_bavail * st.f_frsize
      self.stats["disk_used"] = (st.f_blocks - st.f_bfree) * st.f_frsize
      self.stats_last_update = time.time()
    return self.stats

  def ctl_socket_handler_status(self, data, fd):
    if not data["data"]:
      return "all fine"
    ret = dict()
    if data["data"] == "feeds":
      infeeds = dict()
      for name in self.feeds:
        if name.startswith("outfeed-"):
          ret[name[8:]] = {
            "state": self.feeds[name].state,
            "queue": self.feeds[name].qsize
          }
        else:
          infeeds[name[7:]] = {
            "state": self.feeds[name].state,
            "queue": self.feeds[name].qsize
          }
      return { "infeeds": infeeds, "outfeeds": ret }
    if data["data"] == "plugins":
      for name in self.plugins:
        ret[name] = {
          #"queue": self.plugins[name].qsize
        }
      return { "active": ret }
    if data["data"] == "hooks":
      return { "blacklist": self.hook_blacklist, "whitelist": self.hooks }
    return "obviously all fine in %s" % str(data["data"])

  def run(self):
    self.running = True
    self.feeds = dict()
    self.update_outfeeds()
    if len(self.plugins) > 0:
      self.log(self.logger.INFO, 'starting plugins..')
      for plugin in self.plugins:
        self.plugins[plugin].start()
      time.sleep(0.1)
    self.update_hooks()

    current_sync_targets = list()
    synclist = dict()
    groups = os.listdir('groups')
    # sync groups in random order
    random.shuffle(groups)
    for group in groups:
      group_dir = os.path.join('groups', group)
      if os.path.isdir(group_dir):
        self.log(self.logger.DEBUG, 'startup sync, checking %s..' % group)
        current_sync_targets = list()
        for group_item in self.hooks:
          if (group_item[-1] == '*' and group.startswith(group_item[:-1])) or group == group_item:
            # group matches whitelist
            for current_hook in self.hooks[group_item]:
              if current_hook.startswith('filesystem-'):
                continue
              # loop through matching hooks in whitelist
              current_hook_blacklisted = False
              for blacklist_group_item in self.hook_blacklist:
                # loop through blacklist
                if (blacklist_group_item[-1] == '*' and group.startswith(blacklist_group_item[:-1])) or group == blacklist_group_item:
                  # group matches blacklist
                  if current_hook in self.hook_blacklist[blacklist_group_item]:
                    # current hook is blacklisted, don't add and try next whitelist_hook 
                    current_hook_blacklisted = True
                    break
              if not current_hook_blacklisted:
                if current_hook.startswith('outfeeds-'):
                  # FIXME this doesn't look like its working with ipv6?
                  if current_hook[9:].find(':') == -1:
                    self.log(self.logger.ERROR, 'outfeed filename should be in host:port format')
                    break
                  parts = current_hook[9:].split(':')
                  name = 'outfeed-' + ':'.join(parts[:-1]) + '-' + parts[-1]
                  if name in self.feeds:
                    if self.feeds[name].sync_on_startup and name not in current_sync_targets:
                      self.log(self.logger.DEBUG, 'startup sync, adding %s' % name)
                      current_sync_targets.append(name)
                  else:
                    self.log(self.logger.WARNING, 'unknown outfeed detected. wtf? %s' % name)
                elif current_hook.startswith('plugins-'):
                  name = 'plugin-' + current_hook[8:]
                  if name in self.plugins:
                    if self.plugins[name].sync_on_startup and name not in current_sync_targets:
                      self.log(self.logger.DEBUG, 'startup sync, adding %s' % name)
                      current_sync_targets.append(name)
                  else:
                    self.log(self.logger.WARNING, 'unknown plugin detected. wtf? %s' % name)
                else:
                  self.log(self.logger.WARNING, 'unknown hook detected. wtf? %s' % current_hook)
        # got all whitelist matching hooks for current group which are not matched by blacklist as well in current_sync_targets. hopefully.
        if len(current_sync_targets) > 0:
          # send fresh articles first
          file_list = os.listdir(group_dir)
          file_list = [int(k) for k in file_list]
          file_list.sort()
          synclist[group] = {'targets': current_sync_targets, 'file_list': file_list }
    while len(synclist) > 0:
      for group in synclist:
        empty_sync_group = list()
        if len(synclist[group]['file_list']) == 0:
          empty_sync_group.append(group)
        else:
          group_dir = os.path.join('groups', group)
          sync_chunk = synclist[group]['file_list'][:500]
          for link in sync_chunk:
            link = str(link)
            try:
              message_id = os.path.basename(os.readlink(os.path.join(group_dir, link)))
              if os.stat(os.path.join(group_dir, link)).st_size == 0:
                self.log(self.logger.WARNING, 'empty article found in group %s with id %s pointing to %s' % (group_dir, link, message_id))
                continue
            except:
              self.log(self.logger.ERROR, 'invalid link found in group %s with id %s' % (group_dir, link))
              continue
            for current_hook in synclist[group]['targets']:
              if current_hook.startswith('outfeed-'):
                try:
                  self.feed_db[current_hook].index(message_id)
                except ValueError:
                  self.feeds[current_hook].add_article(message_id)
              elif current_hook.startswith('plugin-'):
                self.plugins[current_hook].add_article(message_id)
              else:
                self.log(self.logger.WARNING, 'unknown sync_hook detected. wtf? %s' % current_hook)
          del synclist[group]['file_list'][:500]
      for group in empty_sync_group:
        del synclist[group]

    self.log(self.logger.DEBUG, 'startup_sync done. hopefully.')
    del current_sync_targets
    del self.feed_db
    
    #files = filter(lambda f: os.stat(os.path.join(group_dir, f)).st_size > 0, os.listdir(group_dir)
    #files = filter(lambda f: os.path.isfile(os.path.join('articles', f)), os.listdir('articles'))
    #files.sort(key=lambda f: os.path.getmtime(os.path.join('articles', f)))
    #for name in self.feeds:
    #  if name.startswith('outfeed-127.0.0.1'):
    #    for item in files:
    #      self.feeds[name].add_article(item)

    self.dropper.start()

    # setup admin control socket
    # FIXME: add path of linux socket to SRNd.conf
    s_addr = 'control.socket'
    try:
      os.unlink(s_addr)
    except OSError:
      if os.path.exists(s_addr):
        raise
    ctl_socket_server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    ctl_socket_server.bind(s_addr)
    ctl_socket_server.listen(10)
    ctl_socket_server.setblocking(0)
    os.chmod(s_addr, 0o660)

    poller = select.poll()
    poller.register(self.socket.fileno(), select.POLLIN)
    poller.register(ctl_socket_server.fileno(), select.POLLIN)
    self.poller = poller

    self.ctl_socket_clients = dict()
    self.ctl_socket_handlers = dict()
    self.ctl_socket_handlers["status"] = self.ctl_socket_handler_status
    self.ctl_socket_handlers["log"] = self.ctl_socket_handler_logger
    self.ctl_socket_handlers["stats"] = self.ctl_socket_handler_stats


    self.start_up_timestamp = int(time.time())
    while self.running:
      result = poller.poll(-1)
      for fd, mask in result:
        if fd == self.socket.fileno():
          try:
            con = self.socket.accept()
            name = 'infeed-{0}-{1}'.format(con[1][0], con[1][1])
            if name not in self.feeds:
              self.feeds[name] = feed.feed(self, self.logger, connection=con, debug=self.infeed_debug)
              self.feeds[name].start()
            else:
              self.log(self.logger.WARNING, 'got connection from %s but its still in feeds. wtf?' % name)
          except socket.error as e:
            if   e.errno == 22: break      # wtf is this? add comments or use STATIC_VARS instead of strange numbers
            elif e.errno ==  4: continue   # system call interrupted
            else:               raise e
          continue
        elif fd == ctl_socket_server.fileno():
          con, addr = ctl_socket_server.accept()
          con.setblocking(0)
          poller.register(con.fileno(), select.POLLIN)
          self.ctl_socket_clients[con.fileno()] = (con, os.fdopen(con.fileno(), 'w', 1))
          continue
        else:
          try:
            try: data = os.read(fd, 4)
            except: data = ''
            if len(data) < 4:
              self.terminate_ctl_socket_connection(fd)
              continue
            length = self.decode_big_endian(data, 4)
            data = os.read(fd, length)
            if len(data) != length:
              self.terminate_ctl_socket_connection(fd)
              continue
            try: data = json.loads(data)
            except Exception as e:
              self.log(self.logger.WARNING, "failed to decode json data: %s" % e)
              continue
            self.log(self.logger.DEBUG, "got something to read from control socket at fd %i: %s" % (fd, data))
            if not "command" in data:
              self.ctl_socket_send_data(fd, { "type": "response", "status": "failed", "data": "no command given"})
              continue
            if not "data" in data:
              data["data"] = ''
            if data["command"] in self.ctl_socket_handlers:
              try: self.ctl_socket_send_data(fd, { "type": "response", "status": "success", "command": data["command"], "args": data["data"], "data": self.ctl_socket_handlers[data["command"]](data, fd)})
              except Exception as e:
                try:
                  self.ctl_socket_send_data(fd, { "type": "response", "status": "failed", "command": data["command"], "args": data["data"], "data": "internal SRNd handler returned exception: %s" % e })
                except Exception as e1:
                  self.log(self.logger.INFO, "can't send exception message to control socket connection using fd %i: %s, original exception was %s" % (fd, e1, e))
                  self.terminate_ctl_socket_connection(fd)
              continue
            self.ctl_socket_send_data(fd, { "type": "response", "status": "failed", "command": data["command"], "args": data["data"], "data": "no handler for given command '%s'" % data["command"] })
          except Exception as e:
            self.log(self.logger.INFO, "unhandled exception while processing control socket request using fd %i: %s" % (fd, e))
            self.terminate_ctl_socket_connection(fd)

    ctl_socket_server.shutdown(socket.SHUT_RDWR)
    ctl_socket_server.close()
    self.socket.close()

  def terminate_ctl_socket_connection(self, fd):
    self.log(self.logger.INFO, "connection at control socket fd %i closed" % fd)
    try: self.ctl_socket_clients[fd][0].shutdown(socket.SHUT_RDWR)
    except: pass
    try: self.ctl_socket_clients[fd][1].close()
    except Exception as e: print "close of fdopened file failed: %s" % e
    try: self.ctl_socket_clients[fd][0].close()
    except Exception as e: print "close of socket failed: %s" % e
    self.poller.unregister(fd)
    try: self.logger.remove_target(self.ctl_socket_clients[fd][1])
    except: pass
    del self.ctl_socket_clients[fd]

  def terminate_feed(self, name):
    if name in self.feeds:
      del self.feeds[name]
    else:
      self.log(self.logger.WARNING,  'should remove %s but not in dict. wtf?' % name)

  def relay_dropper_handler(self, signum, frame):
    #TODO: remove, this is not needed anymore at all?
    self.dropper.handler_progress_incoming(signum, frame)

  def watching(self):
    return self.dropper.watching

  def shutdown(self):
    self.dropper.running = False
    self.running = False
    self.log(self.logger.INFO, 'closing listener..')
    self.socket.shutdown(socket.SHUT_RDWR)
    self.log(self.logger.INFO, 'closing plugins..')
    for plugin in self.plugins:
      self.plugins[plugin].shutdown()
    self.log(self.logger.INFO, 'closing feeds..')
    feeds = list()
    for name in self.feeds:
      feeds.append(name)
    for name in feeds:
      if name in self.feeds:
        self.feeds[name].shutdown()
    self.log(self.logger.INFO, 'waiting for feeds to shut down..')
