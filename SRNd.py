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

try:
  import psutil
  psutil_import_result = True
except ImportError:
  psutil_import_result = False

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

    self._init_sysinfo()

    # create some directories
    for directory in ('filesystem', 'outfeeds', 'plugins'):
      dir_ = os.path.join(self.data_dir, 'config', 'hooks', directory)
      if not os.path.exists(dir_):
        os.makedirs(dir_)
      os.chmod(dir_, 0o777) # FIXME think about this, o+r should be enough?

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
    #add data_dir in syspath
    sys.path.append(os.path.abspath(self.data_dir))

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
        self.log(self.logger.CRITICAL, '''[error] current user account does not have CAP_NET_BIND_SERVICE: %s
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

    # init db manager
    if not os.path.exists(self._db_dir):
      os.makedirs(self._db_dir)
    # fix permissin for chroot
    if self.setuid != '':
      os.chown(self._db_dir, self.uid, self.gid)
    else:
      os.chown(self._db_dir, os.geteuid(), os.getegid())

    self._db_manager = __import__('srnd.db_utils').db_utils.DatabaseManager(self._db_dir)
    self._auto_db_migration()

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
    self.dropper = dropper.dropper(thread_name='SRNd-dropper', logger=self.logger, listener=self.socket, master=self, debug=self.dropper_debug, db_connector=self._db_manager.connect)

    self.start_up_timestamp = -1
    self.ctl_socket_handlers = dict()
    self.ctl_socket_handlers["status"] = self.ctl_socket_handler_status
    self.ctl_socket_handlers["log"] = self.ctl_socket_handler_logger
    self.ctl_socket_handlers["stats"] = self.ctl_socket_handler_stats
    self.hooks = dict()
    self.hook_blacklist = dict()

  def _auto_db_migration(self):
    # Work only for default plugins and db locations
    targets = (
        ('censor.db3', 'censor.db3'), ('dropper.db3', 'dropper.db3'), ('hashes.db3', 'hashes.db3'), ('postman.db3', 'postman.db3'),
        ('overchan.db3', os.path.join('plugins', 'overchan', 'overchan.db3')), ('pastes.db3', os.path.join('plugins', 'paste', 'pastes.db3'))
    )
    for target in targets:
      new_location = os.path.join(self._db_dir, target[0])
      if os.path.isfile(target[1]) and os.path.isfile(new_location):
        self.log(self.logger.ERROR, 'DB migrator: {0} duplicate found {1}. If you copy {2} manually, delete {1}. If not - WTF!'.format(new_location, target[1], target[0]))
      elif os.path.isfile(target[1]):
        try:
          os.rename(target[1], new_location)
        except OSError as e:
          self.log(self.logger.ERROR, 'DB migrator: Error move {} to {}: {}'.format(target[1], new_location, e))

  def get_info(self, data=None):
    if data is not None and data.get('command', None) in self.ctl_socket_handlers:
      return self.ctl_socket_handlers[data['command']](data)
    else:
      return None

  def _get_sysinfo(self, target):
    result = None
    if target == 'cpu':
      if psutil_import_result:
        result = self._sysinfo['psutil'].cpu_percent(interval=None)
      else:
        result = 0
    elif target == 'ram':
      if psutil_import_result:
        result = self._sysinfo['psutil'].memory_info()[0]
      else:
        if self._sysinfo['ramfile'] is not None:
          self._sysinfo['ramfile'].seek(0)
          result = int(self._sysinfo['ramfile'].read().split(' ')[1]) * self._sysinfo['pagesize']
        else:
          result = 0
    elif target == 'disk_free':
      result = self._sysinfo['statvfs'].f_bavail * self._sysinfo['statvfs'].f_frsize
    elif target == 'disk_used':
      result = (self._sysinfo['statvfs'].f_blocks - self._sysinfo['statvfs'].f_bfree) * self._sysinfo['statvfs'].f_frsize
    return result

  def _init_sysinfo(self):
    self._sysinfo = dict()
    if psutil_import_result:
      self._sysinfo['psutil'] = psutil.Process()
    else:
      try:
        self._sysinfo['ramfile'] = open('/proc/self/statm', 'r')
      except Exception as e:
        self.log(self.logger.WARNING, 'can\'t open ram stat file at /proc/self/statm: %s' % e)
        self._sysinfo['ramfile'] = None
      if 'SC_PAGESIZE' in os.sysconf_names:
        self._sysinfo['pagesize'] = os.sysconf('SC_PAGESIZE')
      elif 'SC_PAGE_SIZE' in os.sysconf_names:
        self._sysinfo['pagesize'] = os.sysconf('SC_PAGE_SIZE')
      elif '_SC_PAGESIZE' in os.sysconf_names:
        self._sysinfo['pagesize'] = os.sysconf('_SC_PAGESIZE')
      else:
        self._sysinfo['pagesize'] = 4096
    self._sysinfo['statvfs'] = os.statvfs(os.getcwd())

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
      self._db_dir = ''
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
        elif key == 'db_dir':
          self._db_dir = value
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
      if self._db_dir == '':
        self._db_dir = 'database'
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
      self._db_dir = 'database'
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
      f.write('db_dir={0}\n'.format(self._db_dir))
      f.write('use_chroot={0}\n'.format(self.chroot))
      f.write('setuid={0}\n'.format(self.setuid))
      f.write('srnd_debuglevel={0}\n'.format(self.loglevel))
      f.write('infeed_debuglevel={0}\n'.format(self.infeed_debug))
      f.write('dropper_debuglevel={0}\n'.format(self.dropper_debug))
      f.write('instance_name={0}\n'.format(self.instance_name))
      f.close()

  @staticmethod
  def _list_config_files(path):
    for target in os.listdir(path):
      if os.path.isfile(os.path.join(path, target)) and not target.startswith('.'):
        yield target

  def _read_hook_rules(self, config_file):
    rules = {'whitelist': set(), 'blacklist': set()}
    with open(config_file, 'r') as f:
      for line in f:
        line = line.rstrip('\r\n')
        if len(line) > 0 and not line.startswith('#'):
          # whitelist
          if not line.startswith('!'):
            rules['whitelist'].add(line)
          # blacklist
          elif len(line) > 1:
            line = line[1:]
            if line.startswith('*'):
              self.log(self.logger.WARNING, 'invalid blacklist rule in "{}": !* is not allowed. everything not whitelisted will be rejected automatically.'.format(config_file))
            else:
              rules['blacklist'].add(line)
    return rules

  def _load_infeeds_config(self, cfg_file=os.path.join('config', 'infeeds.conf')):
    if not os.path.isfile(cfg_file):
      with open(cfg_file, 'w') as f:
        f.write('# see docs/hooks.txt for a detailed description about the hook configuration syntax.\n\n')
        f.write('# All infeeds use this config\n\n\n\n')
        f.write('# allow all groups\n')
        f.write('*\n')
    rules = self._read_hook_rules(cfg_file)
    w_count = len(rules['whitelist'])
    b_count = len(rules['blacklist'])
    if w_count + b_count > 0:
      output_log = list()
      output_log.append('Found {} infeeds hooks:'.format(w_count + b_count))
      if w_count > 0:
        output_log.append('whitelist')
        output_log.extend([' {}'.format(x) for x in rules['whitelist']])
      if b_count > 0:
        output_log.append('blacklist')
        output_log.extend([' {}'.format(x) for x in rules['blacklist']])
      self.log(self.logger.INFO, '\n'.join(output_log))
    return {'rules': rules, 'config': self._config_reader(cfg_file)}

  def update_hooks(self):
    self.log(self.logger.INFO, 'reading hook configuration..')
    hook_whitelist = dict()
    hook_blacklist = dict()
    for hook_type, hook_name in (('filesystem', 'filesystem'), ('outfeeds', 'outfeed'), ('plugins', 'plugin')):
      directory = os.path.join('config', 'hooks', hook_type)
      for hook in self._list_config_files(directory):
        link = os.path.join(directory, hook)
        if hook_name != 'outfeed':
          name = '{0}-{1}'.format(hook_name, hook)
        else:
          name = 'outfeed-%s-%s' % self._extract_outfeed_data(hook)
        # ignore hooks for inactive plugins and outfeeds
        if (hook_name == 'outfeed' and name not in self.feeds) or (hook_name == 'plugin' and name not in self.plugins):
          continue
        # read hooks into self.hooks[group_name] = hook_name
        rules = self._read_hook_rules(link)
        # whitelist update
        for rule in rules['whitelist']:
          if rule not in hook_whitelist:
            hook_whitelist[rule] = set()
          if name not in hook_whitelist[rule]:
            hook_whitelist[rule].add(name)
        # blacklist update
        for rule in rules['blacklist']:
          if rule not in hook_blacklist:
            hook_blacklist[rule] = set()
          if name not in hook_blacklist[rule]:
            hook_blacklist[rule].add(name)
        if hook_type == 'filesystem':
          # create hook directory
          hook_dir = os.path.join('hooks', hook)
          if not os.path.exists(hook_dir):
            os.mkdir(hook_dir)
            os.chmod(hook_dir, 0o777)
    output_log = list()
    # adding hooks
    diff, diff_count = self._get_two_hooks_diff(self.hooks, hook_whitelist, self.hook_blacklist, hook_blacklist)
    if diff_count > 0:
      output_log.append('Adding {} hooks'.format(diff_count))
      output_log.extend(diff)
      output_log.append('')
    # removed hooks
    diff, diff_count = self._get_two_hooks_diff(hook_whitelist, self.hooks, hook_blacklist, self.hook_blacklist)
    if diff_count > 0:
      output_log.append('Remove {} hooks'.format(diff_count))
      output_log.extend(diff)
      output_log.append('')
    if len(output_log) > 0:
      self.log(self.logger.INFO, '\n'.join(output_log))
    elif len(self.hook_blacklist) + len(self.hooks) == 0:
      self.log(self.logger.WARNING, 'did not find any hook')
    else:
      self.log(self.logger.INFO, 'Hooks not changes')
    # rewrite old hooks
    self.hooks = hook_whitelist
    self.hook_blacklist = hook_blacklist

  def _get_two_hooks_diff(self, old_whitelist, whitelist, old_blacklist, blacklist):
    diff = list()
    diff_whitelist, count_whitelist = self._get_hook_diff(old_whitelist, whitelist)
    diff_blacklist, count_blacklist = self._get_hook_diff(old_blacklist, blacklist)
    if count_whitelist > 0:
      diff.append('whitelist')
      diff.extend(diff_whitelist)
    if count_blacklist > 0:
      diff.append('blacklist')
      diff.extend(diff_blacklist)
    return diff, count_whitelist + count_blacklist

  @staticmethod
  def _get_hook_diff(old_hooks, new_hooks):
    diff = list()
    total = 0
    for hook in new_hooks:
      new = new_hooks[hook] - old_hooks.get(hook, set())
      total += len(new)
      if len(new) > 0:
        diff.append(' {}'.format(hook))
        diff.extend(['   {} '.format(x) for x in new])
    return diff, total

  def update_plugins(self):
    self.log(self.logger.INFO, 'importing plugins..')
    new_plugins = list()
    current_plugin = None
    errors = False
    for plugin in self._list_config_files(os.path.join('config', 'hooks', 'plugins')):
      link = os.path.join('config', 'hooks', 'plugins', plugin)
      plugin_path = os.path.join('plugins', plugin)
      if not plugin_path in sys.path:
        sys.path.append(plugin_path)
      name = 'plugin-' + plugin
      if name in self.plugins:
        continue
      args = self._config_reader(link)
      #print "[SRNd] trying to import {0}..".format(name)
      args['db_connector'] = self._db_manager.connect
      if 'srnd' in args:
        args['srnd'] = self
      if 'srnd_info' in args:
        args['srnd_info'] = self.get_info
      try:
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

  @staticmethod
  def _extract_outfeed_data(outfeed):
    if ':' in outfeed:
      host = ':'.join(outfeed.split(':')[:-1])
      port = int(outfeed.split(':')[-1])
    else:
      # FIXME: how to deal with ipv6 and no default port?
      host = outfeed
      port = 119
    return host, port

  def _config_reader(self, config_file):
    start_params = dict()
    with open(config_file, 'r') as f:
      for line in f:
        if line.lower().startswith('#start_param '):
          try:
            key, value = line[13:].rstrip('\r\n').split('=', 1)
          except ValueError as e:
            self.log(self.logger.WARNING, 'Strange config line "{}" in "{}": {}. Ignore'.format(line.rstrip('\r\n'), config_file, e))
            continue
          key = key.lower()
          if key in start_params:
            self.log(self.logger.WARNING, 'Found duplicate key {} in {}: Last value rewrite previous'.format(key, config_file))
          start_params[key] = value
    return start_params

  def _trackdb_reder(self, trackdb_file):
    duplicates = 0
    trackdb = set()
    # open track db here, read, close
    try:
      f = open(trackdb_file, 'r')
    except IOError as e:
      if e.errno != 2:
        self.log(self.logger.ERROR, 'cannot open: {}: {}'.format(trackdb_file, e.strerror))
    else:
      for line in f:
        if line.rstrip('\n') in trackdb:
          duplicates += 1
        else:
          trackdb.add(line.rstrip('\n'))
      f.close()
      # remove duplicates
      if duplicates > 0:
        self.log(self.logger.INFO, 'found {} duplicates in {}. Rewriting'.format(duplicates, trackdb_file))
        with open(trackdb_file, 'w') as f:
          f.write('\n'.join(trackdb))
          f.write('\n')
    return trackdb

  def update_outfeeds(self):
    self.log(self.logger.INFO, 'reading outfeeds..')
    counter_new = 0
    current_feedlist = list()
    for outfeed in self._list_config_files(os.path.join('config', 'hooks', 'outfeeds')):
      start_params = self._config_reader(os.path.join('config', 'hooks', 'outfeeds', outfeed))
      proxy_conn = {'proxy_type': None, 'proxy_ip': None, 'proxy_port': None}
      for proxy_key in proxy_conn:
        if proxy_key in start_params:
          proxy_conn[proxy_key] = start_params[proxy_key].lower()
      sync_on_startup = True if start_params.get('sync_on_startup', 'nope').lower() == 'true' else False
      try:
        debuglevel = int(start_params.get('debug', self.loglevel))
      except ValueError:
        debuglevel = self.loglevel
      else:
        if 9 < debuglevel < 0:
          debuglevel = self.loglevel

      host, port = self._extract_outfeed_data(outfeed)
      name = 'outfeed-{}-{}'.format(host, port)
      current_feedlist.append(name)
      proxy = None
      if name not in self.feeds:
        if proxy_conn['proxy_type'] is not None and proxy_conn['proxy_ip'] is not None:
          try:
            proxy_conn['proxy_port'] = int(proxy_conn['proxy_port'])
          except ValueError:
            pass
          else:
            proxy = (proxy_conn['proxy_type'], proxy_conn['proxy_ip'], proxy_conn['proxy_port'])
            self.log(self.logger.INFO, 'starting outfeed {} using proxy: {}'.format(name, str(proxy)))
        try:
          self.log(self.logger.DEBUG, 'starting outfeed: %s' % name)
          self.feeds[name] = feed.feed(self, self.logger, config={'config': start_params}, outstream=True, host=host, port=port, sync_on_startup=sync_on_startup, proxy=proxy, debug=debuglevel, db_connector=self._db_manager.connect)
          self.feeds[name].start()
        except Exception as e:
          self.log(self.logger.WARNING, 'could not start outfeed %s: %s' % (name, e))
        else:
          counter_new += 1
    counter_removed = 0
    for name in [xx for xx in self.feeds if xx.startswith('outfeed') and xx not in current_feedlist]:
      self.feeds[name].shutdown()
      counter_removed += 1
    self.log(self.logger.INFO, 'outfeeds added: %i' % counter_new)
    self.log(self.logger.INFO, 'outfeeds removed: %i' % counter_removed)

  def update_hooks_outfeeds_plugins(self, signum, frame):
    self.update_outfeeds()
    self.update_plugins()
    self.update_hooks()

  @staticmethod
  def encode_big_endian(number, length):
    if number >= 256**length:
      raise OverflowError("%i can't be represented in %i bytes." % (number, length))
    data = b""
    for i in range(0, length):
      data += chr(number >> (8*(length-1-i)))
      number -= (ord(data[-1]) << (8*(length -1 -i)))
    return data

  @staticmethod
  def decode_big_endian(data, length):
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

  def ctl_socket_handler_logger(self, data, fd=None):
    if data["data"] == "off" or data["data"] == "none":
      return self.logger.remove_target(self.ctl_socket_clients[fd][1])
    elif data["data"] == "on":
      data["data"] = 'all'
    return self.logger.add_target(self.ctl_socket_clients[fd][1], loglevel=data["data"].split(' '), json_framing_4=True)

  def ctl_socket_handler_stats(self, data, fd=None):
    if not 'stats' in self.__dict__:
      self.stats = {"start_up_timestamp": self.start_up_timestamp}
      self.stats_last_update = 0
    self.stats["infeeds"]  = sum(1 for x in self.feeds if x.startswith('infeed-'))
    self.stats["outfeeds"] = sum(1 for x in self.feeds if x.startswith('outfeed-'))
    self.stats["plugins"]  = len(self.plugins)
    if time.time() - self.stats_last_update > 5:
      self.stats["groups"]    = os.stat('groups').st_nlink - 2
      self.stats["articles"]  = sum(1 for x in os.listdir('articles')) - os.stat('articles').st_nlink + 2
      self.stats["cpu"]       = self._get_sysinfo('cpu')
      self.stats["ram"]       = self._get_sysinfo('ram')
      self.stats["disk_free"] = self._get_sysinfo('disk_free')
      self.stats["disk_used"] = self._get_sysinfo('disk_used')
      self.stats_last_update = time.time()
    return self.stats

  def _get_feed_stat(self, name):
    return {
        "state": self.feeds[name].state,
        "queue": self.feeds[name].qsize,
        "transfer": self.feeds[name].byte_transfer,
        "transfer_time": self.feeds[name].time_transfer
    }

  def ctl_socket_handler_status(self, data, fd=None):
    if not data["data"]:
      return "all fine"
    ret = dict()
    if data["data"] == "feeds":
      infeeds = dict()
      for name in self.feeds:
        if name.startswith("outfeed-"):
          ret[name[8:]] = self._get_feed_stat(name)
        else:
          infeeds[name[7:]] = self._get_feed_stat(name)
      return {"infeeds": infeeds, "outfeeds": ret}
    if data["data"] == "plugins":
      for name in self.plugins:
        ret[name] = {
          #"queue": self.plugins[name].qsize
        }
      return {"active": ret}
    if data["data"] == "hooks":
      return {"blacklist": self.hook_blacklist, "whitelist": self.hooks}
    return "obviously all fine in %s" % str(data["data"])

  def get_message_list_by_group(self, group):
    group_dir = os.path.join('groups', group)
    # send fresh articles first
    file_list = [int(k) for k in os.listdir(group_dir)]
    file_list.sort()

    message_list = list()
    for link in file_list:
      try:
        target = os.path.join(group_dir, str(link))
        message_id = os.path.basename(os.readlink(target))
        if os.stat(target).st_size == 0:
          self.log(self.logger.WARNING, 'empty article found in group %s with id %s pointing to %s' % (group_dir, link, message_id))
          continue
      except:
        self.log(self.logger.ERROR, 'invalid link found in group %s with id %s' % (group_dir, link))
        continue
      message_list.append(message_id)
    return message_list

  @staticmethod
  def _ishook_match(group_name, regexp):
    return regexp == group_name or regexp == '*' or regexp[-1] == '*' and group_name.startswith(regexp[:-1])

  def get_allow_hooks(self, group_name):
    targets = set()
    for white_group in self.hooks:
      if self._ishook_match(group_name, white_group):
        # hook found, extend
        targets |= self.hooks[white_group]
    if len(targets) > 0:
      # remove blacklisted elements
      for black_group in self.hook_blacklist:
        if self._ishook_match(group_name, black_group):
          targets -= self.hook_blacklist[black_group]
    return targets

  def _is_valid_outfeed(self, target, hook, targets):
    return self._is_allow_sync(target, hook, targets) and self._is_valid_any(self.feeds, target, 'outfeed')

  def _is_valid_plugin(self, target, hook, targets):
    return self._is_allow_sync(target, hook, targets) and self._is_valid_any(self.plugins, target, 'plugin')

  def _is_valid_any(self, dict_data, target, type_):
    if target in dict_data:
      if dict_data[target].sync_on_startup:
        self.log(self.logger.DEBUG, 'startup sync, adding {}'.format(target))
        return True
    else:
      self.log(self.logger.WARNING, 'unknown {} detected. wtf? {}'.format(type_, target))
    return False

  @staticmethod
  def _is_allow_sync(target, hook, targets):
    if hook is not None and not target.startswith(hook):
      return False
    if targets is not None and target not in targets:
      return False
    return True

  def _sync_on_startup(self, hook=None, targets=None):
    # hook - plugin, outfeed. None - all
    # targets - object name. None - any
    groups = [x for x in os.listdir('groups') if os.path.isdir(os.path.join('groups', x))]
    synclist = dict()
    # sync groups in random order
    random.shuffle(groups)
    for group in groups:
      self.log(self.logger.DEBUG, 'startup sync, checking {}..'.format(group))
      current_sync_targets = set()
      for sync_target in self.get_allow_hooks(group):
        if sync_target.startswith('outfeed-'):
          if self._is_valid_outfeed(sync_target, hook, targets):
            current_sync_targets.add(sync_target)
        elif sync_target.startswith('plugin-'):
          if self._is_valid_plugin(sync_target, hook, targets):
            current_sync_targets.add(sync_target)
        elif sync_target.startswith('filesystem-'):
          pass
        else:
          self.log(self.logger.WARNING, 'unknown hook detected. wtf? {}'.format(sync_target))
      if len(current_sync_targets) > 0:
        synclist[group] = {'targets': current_sync_targets, 'file_list': self.get_message_list_by_group(group)}

    while len(synclist) > 0:
      empty_sync_group = list()
      for group in synclist:
        if len(synclist[group]['file_list']) == 0:
          empty_sync_group.append(group)
        else:
          for message_id in synclist[group]['file_list'][:500]:
            for current_hook in synclist[group]['targets']:
              if current_hook.startswith('outfeed-'):
                if message_id not in self.feed_db.get(current_hook, ''):
                  self.feeds[current_hook].add_article(message_id)
              elif current_hook.startswith('plugin-'):
                self.plugins[current_hook].add_article(message_id)
          del synclist[group]['file_list'][:500]
      for group in empty_sync_group:
        del synclist[group]

    self.log(self.logger.DEBUG, 'startup_sync done. hopefully.')
    self.feed_db.clear()

  def _load_outfeed_db(self, targets=None):
    for target in (xx for xx in self.feeds if xx.startswith('outfeed-')):
      if self.feeds[target].sync_on_startup and targets is None or target in targets:
        self.feed_db[target] = self._trackdb_reder('{0}.trackdb'.format(target))

  def internal_ctl(self, args):
    self.log(self.logger.DEBUG, 'Got control request {}'.format(args))
    # reload hooks
    if args['action'] == 'update':
      if args.get('hook') == 'hooks':
        self.update_hooks()
        return True
      elif args.get('hook') == 'outfeed':
        self.update_outfeeds()
        return True
      elif args.get('hook') == 'plugin':
        #self.update_plugin
        pass
    # resync
    elif args['action'] == 'sync' and args.get('hook') in ('plugin', 'outfeed', None):
      # reload trackdb
      if args.get('hook') != 'plugin':
        self._load_outfeed_db(targets=args.get('targets'))
      self._sync_on_startup(hook=args.get('hook'), targets=args.get('targets'))
      return True
    # shutdown
    elif args['action'] == 'die' and args.get('hook') in ('infeed', 'outfeed', 'plugin'):
      wait_count = 8
      wait_time = 0.5
      status = False
      if args.get('hook') in ('infeed', 'outfeed'):
        for feed_ in [xx for xx in self.feeds if xx.startswith(args.get('hook'))]:
          if args.get('targets') is None or feed_ in args.get('targets'):
            self.feeds[feed_].shutdown()
            c_count = 0
            while feed_ in self.feeds and c_count < wait_count:
              c_count += 1
              time.sleep(wait_time)
            status = feed_ not in self.feeds
      if args.get('hook') == 'plugin':
        for plugin in [xx for xx in self.plugins]:
          if plugin in args.get('targets', plugin):
            self.plugins[plugin].shutdown()
            c_count = 0
            while self.plugins[plugin].isAlive() and c_count < wait_count:
              c_count += 1
              time.sleep(wait_time)
            if not self.plugins[plugin].isAlive():
              del self.plugins[plugin]
              status = True
      return status
    self.log(self.logger.WARNING, 'Invalid control request: {}'.format(args))
    return False

  def run(self):
    self.running = True
    self.feeds = dict()
    self.feed_db = dict()
    self.update_outfeeds()
    self._load_outfeed_db()
    if len(self.plugins) > 0:
      self.log(self.logger.INFO, 'starting plugins..')
      for plugin in self.plugins:
        self.plugins[plugin].start()
      time.sleep(0.1)
    self.update_hooks()

    self.infeeds_config = self._load_infeeds_config()

    self._sync_on_startup()

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

    self.start_up_timestamp = int(time.time())
    while self.running:
      result = poller.poll(-1)
      for fd, mask in result:
        if fd == self.socket.fileno():
          try:
            con = self.socket.accept()
            name = 'infeed-{0}-{1}'.format(con[1][0], con[1][1])
            if name not in self.feeds:
              self.feeds[name] = feed.feed(self, self.logger, config=self.infeeds_config, connection=con, debug=self.infeed_debug, db_connector=self._db_manager.connect)
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
              self.ctl_socket_send_data(fd, {"type": "response", "status": "failed", "data": "no command given"})
              continue
            if not "data" in data:
              data["data"] = ''
            if data["command"] in self.ctl_socket_handlers:
              try: self.ctl_socket_send_data(fd, {"type": "response", "status": "success", "command": data["command"], "args": data["data"], "data": self.ctl_socket_handlers[data["command"]](data, fd)})
              except Exception as e:
                try:
                  self.ctl_socket_send_data(fd, {"type": "response", "status": "failed", "command": data["command"], "args": data["data"], "data": "internal SRNd handler returned exception: %s" % e})
                except Exception as e1:
                  self.log(self.logger.INFO, "can't send exception message to control socket connection using fd %i: %s, original exception was %s" % (fd, e1, e))
                  self.terminate_ctl_socket_connection(fd)
              continue
            self.ctl_socket_send_data(fd, {"type": "response", "status": "failed", "command": data["command"], "args": data["data"], "data": "no handler for given command '%s'" % data["command"]})
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
      self.log(self.logger.WARNING, 'should remove %s but not in dict. wtf?' % name)

  def relay_dropper_handler(self, signum, frame):
    #TODO: remove, this is not needed anymore at all?
    self.dropper.handler_progress_incoming(signum, frame)

  def rename_infeed(self, old_name, new_name):
    if not (old_name.startswith('infeed-') and new_name.startswith('infeed-')):
      return False
    if old_name in self.feeds and new_name not in self.feeds:
      self.feeds[new_name] = self.feeds.pop(old_name)
      return True
    return False

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
