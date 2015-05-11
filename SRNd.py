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
from feeds.infeed import InFeed
from feeds.feed_wrapper import OutFeed, MultiInFeed

class SRNd(threading.Thread):

  def log(self, loglevel, message):
    if loglevel >= self.config['srnd_debuglevel']:
      self.logger.log('SRNd', message, loglevel)

  def __init__(self, logger):
    self.logger = logger
    self.config = {'srnd_debuglevel': self.logger.INFO}
    self.log(self.logger.VERBOSE,  'srnd test logging with VERBOSE')
    self.log(self.logger.DEBUG,    'srnd test logging with DEBUG')
    self.log(self.logger.INFO,     'srnd test logging with INFO')
    self.log(self.logger.WARNING,  'srnd test logging with WARNING')
    self.log(self.logger.ERROR,    'srnd test logging with ERROR')
    self.log(self.logger.CRITICAL, 'srnd test logging with CRITICAL')
    old_owner = (os.stat('data').st_uid, os.stat('data').st_gid) if os.path.exists('data') else (None, None)
    # default config. key = (value, position). position need for write human readable config
    def_config = {
        'bind_ip': ('', 1),
        'bind_port': (119, 2),
        'bind_use_ipv6': (False, 3),
        'data_dir': ('data', 4),
        'db_dir': ('database', 5),
        'db_url': ('postgres://root:root@localhost', 6),
        'use_chroot': (True, 7),
        'setuid': ('news', 8),
        'srnd_debuglevel': (self.logger.INFO, 9),
        'infeed_debuglevel': (self.logger.INFO, 10),
        'dropper_debuglevel': (self.logger.INFO, 11),
        'instance_name': ('SRNd', 12)
    }
    self.config = self.init_srnd_config(def_config)

    self._use_psutil = psutil_import_result and not self.config['use_chroot']
    self._init_sysinfo()

    # install / update plugins
    self.log(self.logger.INFO, "installing / updating plugins")
    for directory in os.listdir('install_files'):
      copy_tree(os.path.join('install_files', directory), os.path.join(self.config['data_dir'], directory), preserve_times=True, update=True)

    #add data_dir in syspath and fix permission
    sys.path.append(os.path.abspath(self.config['data_dir']))

    # create jail
    os.chdir(self.config['data_dir'])

    # get initial owner
    init_owner = (os.geteuid(), os.getegid())

    # get owner
    if self.config['setuid'] != '':
      owner = (self.config['uid'], self.config['gid'])
    else:
      owner = init_owner

    # load\create infeeds.cfg
    self.infeeds_config = self._load_infeeds_config()

    # test and fixing plugin dir permissions
    for directory in os.listdir('plugins'):
      dir_ = os.path.join('plugins', directory)
      try:
        self._permission_fix(0o755, owner, dir_)
      except OSError as e:
        if e.errno == 1:
          # FIXME what does this errno actually mean? write actual descriptions for error codes -.-
          self.log(self.logger.WARNING, "couldn't change owner of %s. %s will likely fail to create own directories." % (dir_, directory))
        else:
          # FIXME: exit might not allow logger to actually output the message.
          self.log(self.logger.CRITICAL, "trying to chown plugin directory %s failed: %s" % (dir_, e))
          exit(1)

    # create some directories
    for directory in ('filesystem', 'outfeeds', 'plugins'):
      dir_ = os.path.join('config', 'hooks', directory)
      if not os.path.exists(dir_):
        os.makedirs(dir_)

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
        self.config['db_dir'])
    for directory in directories:
      if not os.path.exists(directory):
        os.mkdir(directory)
        self._permission_fix(0o755, owner, directory)

    # migrate db
    self._auto_db_migration()

    # fix all permission if owner change. it is a long time
    if old_owner != owner:
      self.log(self.logger.INFO, "onwer change, fixing all permissions...")
      self._deep_permission_fix(owner, '.', False)

    # protect some files from changes, if srnd dropping privileges
    if owner != init_owner:
      self._protect_files(init_owner)

    # base fixing permissions
    self._deep_permission_fix(owner, os.path.join('config', 'hooks', 'filesystem'), False)
    self._deep_permission_fix(owner, self.config['db_dir'], False)

    # init db manager
    self._db_manager = __import__('srnd.db_utils').db_utils.DatabaseManager(self.config['db_url'])

    # importing plugins
    # we need to do this before chrooting because plugins may need to import other libraries
    self.plugins = dict()
    self.update_plugins()

    # start listening
    if self.config['bind_use_ipv6']:
      self.socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    else:
      self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
      self.log(self.logger.INFO, 'start listening at %s:%i' % (self.config['bind_ip'], self.config['bind_port']))
      self.socket.bind((self.config['bind_ip'], self.config['bind_port']))
    except socket.error as e:
      if e.errno == 13:
        # FIXME: exit might not allow logger to actually output the message.
        self.log(self.logger.CRITICAL, '''[error] current user account does not have CAP_NET_BIND_SERVICE: %s
        You have three options:
         - run SRNd as root
         - assign CAP_NET_BIND_SERVICE to the user you intend to use
         - use a port > 1024 by setting bind_port at %s''' % (e, os.path.join(self.config['data_dir'], 'config', 'SRNd.conf')))
        exit(2)
      elif e.errno == 98:
        # FIXME: exit might not allow logger to actually output the message.
        self.log(self.logger.CRITICAL, '%s:%i already in use, change to a different port by setting bind_port at %s' % (self.config['bind_ip'], self.config['bind_port'], os.path.join(self.config['data_dir'], 'config', 'SRNd.conf')))
        exit(2)
      else:
        raise e
    self.socket.listen(5)

    if self.config['use_chroot']:
      self.log(self.logger.INFO, 'chrooting..')
      try:
        os.chroot('.')
      except OSError as e:
        if e.errno == 1:
          print "[error] current user account does not have CAP_SYS_CHROOT."
          print "        You have three options:"
          print "         - run SRNd as root"
          print "         - assign CAP_SYS_CHROOT to the user you intend to use"
          print "         - disable chroot in {0} by setting chroot=False".format(os.path.join(self.config['data_dir'], 'config', 'SRNd.conf'))
          exit(3)
        else:
          raise e

    if self.config['setuid'] != '':
      self.log(self.logger.INFO, 'dropping privileges..')
      try:
        os.setgid(self.config['gid'])
        os.setuid(self.config['uid'])
      except OSError as e:
        if e.errno == 1:
          print "[error] current user account does not have CAP_SETUID/CAP_SETGID: ", e
          print "        You have three options:"
          print "         - run SRNd as root"
          print "         - assign CAP_SETUID and CAP_SETGID to the user you intend to use"
          print "         - disable setuid in {0} by setting setuid=".format(os.path.join(self.config['data_dir'], 'config', 'SRNd.conf'))
          exit(4)
        else:
          raise e

    threading.Thread.__init__(self)
    self.name = "SRNd-listener"
    self.dropper = dropper.dropper(
        thread_name='SRNd-dropper',
        logger=self.logger,
        master=self,
        debug=self.config['dropper_debuglevel'],
        db_connector=self._db_manager.connect,
        instance_name=self.config['instance_name']
    )

    self.start_up_timestamp = -1
    self.ctl_socket_handlers = dict()
    self.ctl_socket_handlers["status"] = self.ctl_socket_handler_status
    self.ctl_socket_handlers["log"] = self.ctl_socket_handler_logger
    self.ctl_socket_handlers["stats"] = self.ctl_socket_handler_stats
    self.hooks = dict()
    self.hook_blacklist = dict()
    self._feeds_lock = threading.Lock()

  def _auto_db_migration(self):
    # Work only for default plugins and db locations
    targets = (
        ('censor.db3', 'censor.db3'), ('dropper.db3', 'dropper.db3'), ('hashes.db3', 'hashes.db3'), ('postman.db3', 'postman.db3'),
        ('overchan.db3', os.path.join('plugins', 'overchan', 'overchan.db3')), ('pastes.db3', os.path.join('plugins', 'paste', 'pastes.db3'))
    )
    for target in targets:
      new_location = os.path.join(self.config['db_dir'], target[0])
      if os.path.isfile(target[1]) and os.path.isfile(new_location):
        self.log(self.logger.ERROR, 'DB migrator: {0} duplicate found {1}. If you copy {2} manually, delete {1}. If not - WTF!'.format(new_location, target[1], target[0]))
      elif os.path.isfile(target[1]):
        try:
          os.rename(target[1], new_location)
        except OSError as e:
          self.log(self.logger.ERROR, 'DB migrator: Error move {} to {}: {}'.format(target[1], new_location, e))

  def _deep_permission_fix(self, owner, path, only_dir=True):
    """Set permission and owner to all files and directories"""
    #TODO: 755 or 777? Or maybe 700
    mode_dir = 0o755 # rwxrwx-r-x
    mode_file = 0o664 # rw-rw-r--
    for dirpath, _, filenames in os.walk(path):
      self._permission_fix(mode_dir, owner, dirpath)
      if not only_dir:
        for file_ in filenames:
          file_link = os.path.join(dirpath, file_)
          if not os.path.islink(file_link):
            # ignore symlinks
            self._permission_fix(mode_file, owner, file_link)

  def _permission_fix(self, mode, owner, path):
    try:
      os.chmod(path, mode)
      os.chown(path, owner[0], owner[1])
    except OSError as e:
      username = pwd.getpwuid(self.config['uid']).pw_name if self.config['setuid'] else pwd.getpwuid(os.geteuid()).pw_name
      if e.errno == 1:
        warnings = (
            "can't change ownership of {}.".format(path),
            "If you want to run as '{}' user modify {} :".format(username, os.path.join(self.config['data_dir'], 'config', 'SRNd.conf')),
            "set use_chroot=False, setuid={0}, start SRNd root privileges(su, sudo etc.), stop, wait, and starting SRNd as {0} without root privileges,".format(username),
            "or change ownership manually eg. 'sudo chown -R {0}:{0} data/', or delete the data directory".format(username),
            "die."
        )
        self.log(self.logger.CRITICAL, '\n'.join(warnings))
      else:
        self.log(self.logger.CRITICAL, "couldn't change owner or permission of {}: {}".format(path, e))
      exit(1)

  def _protect_files(self, owner):
    mode_file = 0o664
    # Prevent add and load plugin after dropping privileges
    for dir_ in ('config', 'srnd'):
      self._deep_permission_fix(owner, dir_, False)
    # Prevent modify files and templates files - plugin can be reload
    # TODO: Protect all plugin files and directories, without tmp and out. Also, templates directory may be renamed in plugin config
    for plugin_dir in os.listdir('plugins'):
      for target in os.listdir(os.path.join('plugins', plugin_dir)):
        path = os.path.join('plugins', plugin_dir, target)
        if os.path.isfile(path):
          self._permission_fix(mode_file, owner, path)
        elif target == 'templates':
          self._deep_permission_fix(owner, path, False)


  def get_info(self, data=None):
    if data is not None and data.get('command', None) in self.ctl_socket_handlers:
      return self.ctl_socket_handlers[data['command']](data)
    else:
      return None

  def _get_sysinfo(self, target):
    result = None
    if target == 'cpu':
      if self._use_psutil:
        result = self._sysinfo['psutil'].cpu_percent(interval=None)
      else:
        result = 0
    elif target == 'ram':
      if self._use_psutil:
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
    if self._use_psutil:
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

  def _sanitize_srnd_config(self, def_config, config):
    """
    Fix bad or missing value, delete unknown keys
    It's modify config dict as mutable type.
    return False if need rewrite config file
    """
    no_change = True
    for key, value in [xx for xx in config.iteritems()]:
      if key not in def_config:
        # Unknown key, del? del!
        del config[key]
        no_change = False
      elif isinstance(def_config[key][0], bool):
        # cast bool
        if value.lower() == 'true':
          config[key] = True
        elif value.lower() == 'false':
          config[key] = False
        else:
          self.log(self.logger.WARNING, '{}: unknown value. only accepting true or false. using default of {}'.format(key, def_config[key][0]))
          config[key] = def_config[key][0]
          no_change = False
      else:
        # cast to type form type(default value)
        try:
          config[key] = type(def_config[key][0])(value)
        except ValueError:
          self.log(self.logger.WARNING, '{}: bad value type. only accepting {}, get {}. using default of {}'.format(key, type(def_config[key][0]), type(value), def_config[key][0]))
          config[key] = def_config[key][0]
          no_change = False
    # add missing key
    for key, value in def_config.iteritems():
      if key not in config:
        config[key] = value[0]
        no_change = False
    # deep check
    for key in ('srnd_debuglevel', 'infeed_debuglevel', 'dropper_debuglevel'):
      if config[key] < 0 or config[key] > 5:
        self.log(self.logger.WARNING, '{}: only accepting integer between 0 and 5. using default of {}'.format(key, def_config[key][0]))
        config[key] = def_config[key][0]
        no_change = False
    if ' ' in config['instance_name']:
      self.log(self.logger.WARNING, "instance_name contains a space. using default of '{}'".format(def_config['instance_name'][0]))
      config['instance_name'] = def_config['instance_name'][0]
      no_change = False
    return no_change

  def _read_srnd_config(self, config_file):
    config = dict()
    with open(config_file, 'r') as f:
      for line in f:
        if line[0] not in ('#', '\n'):
          data = line.strip('\n').split('=', 1)
          if len(data) == 1:
            self.log(self.logger.WARNING, "no = in setting '{}'".format(line))
          else:
            config[data[0]] = data[1]
    return config

  def _write_srnd_config(self, config_list, data_dir, uid, gid):
    config_head = (
        '# changing this file requires a restart of SRNd',
        '# empty lines or lines starting with # are ignored',
        '# do not add whitespaces before or after =',
        '# additional data in this file will be overwritten every time a value has been changed'
    )
    config_path = os.path.join(data_dir, 'config')
    if not os.path.exists(config_path):
      os.makedirs(config_path)
      if uid is not None and gid is not None:
        try:
          os.chown(data_dir, uid, gid)
          os.chown(config_path, uid, gid)
        except OSError as e:
          if e.errno == 1:
            warnings = (
                "can't change ownership of newly generated data directory.",
                "If you don't intend to run SRNd as root and let it chroot and setuid/gid itself (which is the recommend way to run SRNd), you",
                "need to modify the configuration file at {} and set setuid to an empty value.".format(os.path.join(config_path, 'SRNd.conf')),
                "If you want to run as root delete the data directory before you restart SRNd."
            )
            self.log(self.logger.WARNING, '\n'.join(warnings))
          else:
            self.log(self.logger.CRITICAL, "trying to chown configuration files failed: {}".format(e))
            exit(1)
    with open(os.path.join(config_path, 'SRNd.conf'), 'w') as f:
      f.write('\n'.join(config_head))
      f.write('\n\n')
      f.write('\n'.join(config_list))
      f.write('\n')

  def init_srnd_config(self, def_config, config_file=os.path.join('data', 'config', 'SRNd.conf')):
    config = self._read_srnd_config(config_file) if os.path.isfile(config_file) else dict()
    no_change = self._sanitize_srnd_config(def_config, config)
    # check setuid
    uid = None
    gid = None
    if config['setuid']:
      try:
        uid, gid = pwd.getpwnam(config['setuid'])[2:4]
      except KeyError:
        # FIXME: user can't change config file as it might not exist at this point.
        crits = (
            "'{}' is not a valid user on this system.".format(config['setuid']),
            "either create {} or change setuid at '{}' into a valid username or an empty value to disable setuid".format(config['setuid'], config_file)
        )
        self.log(self.logger.CRITICAL, '\n'.join(crits))
        exit(1)
    elif config['use_chroot']:
      crits = (
          "You defined use_chroot=True and set setuid to an empty value.",
          "This would result in chrooting without dropping privileges which defeats the purpose of chrooting completely."
      )
      self.log(self.logger.CRITICAL, '\n'.join(crits))
      exit(3)
    if not no_change:
      # create human readable config - sort from position in def_config
      config_list = sorted([('='.join((key, str(value))), def_config[key][1]) for key, value in config.iteritems()], key=lambda line_: line_[1])
      # remove positions
      config_list = [line[0] for line in config_list]
      self._write_srnd_config(config_list, config['data_dir'], uid, gid)
    # add uid and gid in config if present. No write this in config file
    if uid is not None and gid is not None:
      config['uid'] = uid
      config['gid'] = gid
    return config

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
        f.write('# All infeeds use this config\n\n')
        f.write('# 0 - authentication disallowed, 1 - authentication support, 2 - authentication required (WARNING! Not work with original srnd)\n')
        f.write('#start_param auth_required=0\n\n')
        f.write('# authentication mode support. nntp - support standart nntp client, private key send as plaintext. srnd - best and support srnd-client (recommend)\n')
        f.write('# example: #start_param auth_support=srnd,nntp\n')
        f.write('#start_param auth_support=srnd\n\n\n')
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
    return {'rules': rules, 'config': self._infeed_config_sanitize(self._config_reader(cfg_file))}

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
          config_ = self._outfeed_config_sanitize(self._config_reader(link))
          server_ = self._extract_server_link(config_.get('server', hook), config_['ipv6'])
          if server_ is None:
            continue
          name = 'outfeed-{}-{}'.format(*server_)
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
    plugins_added = 0
    plugins_removed = 0
    all_plugins = set()
    current_plugin = None
    for plugin in self._list_config_files(os.path.join('config', 'hooks', 'plugins')):
      link = os.path.join('config', 'hooks', 'plugins', plugin)
      plugin_path = os.path.join('plugins', plugin)
      if not plugin_path in sys.path:
        sys.path.append(plugin_path)
      name = 'plugin-' + plugin
      all_plugins.add(name)
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
        plugins_added += 1
      except Exception as e:
        self.log(self.logger.ERROR, 'error while importing %s: %s' % (name, e))
        self.log(self.logger.ERROR, traceback.format_exc())
        if name in self.plugins:
          del self.plugins[name]
        all_plugins.discard(name)
        continue
    del current_plugin
    for name in [xx for xx in self.plugins if xx not in all_plugins]:
      if self._close_plugin(name):
        del self.plugins[name]
        plugins_removed += 1
    if plugins_added > 0:
      self.log(self.logger.INFO, 'added {} plugins'.format(plugins_added))
    if plugins_removed > 0:
      self.log(self.logger.INFO, 'removed {} plugins'.format(plugins_removed))

  def start_plugins(self):
    to_start = [xx for xx in self.plugins if not self.plugins[xx].isAlive()]
    if len(to_start) > 0:
      self.log(self.logger.INFO, 'starting {} plugins..'.format(len(to_start)))
      for plugin in to_start:
        self.plugins[plugin].start()
        time.sleep(0.1)

  def _extract_server_link(self, outfeed, ipv6=False):
    """Return host, port from host:port. return None, if wrong format"""
    outfeed = outfeed.split(':')
    # check server ip:port
    if (ipv6 and len(outfeed) < 2) or (not ipv6 and len(outfeed) > 2):
      self.log(self.logger.ERROR, 'incorrect server ip:port: {}'.format(':'.join(outfeed)))
      return None
    if len(outfeed) > 1:
      host = ':'.join(outfeed[:-1])
      try:
        port = int(outfeed[-1])
      except ValueError:
        if ipv6:
          host = ':'.join(outfeed)
          port = 119
        else:
          self.log(self.logger.ERROR, 'incorrect server ip:port: {}. If you use ipv6 address add #start_param ipv6=true to config'.format(':'.join(outfeed)))
          return None
    else:
      host = ':'.join(outfeed)
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
      config = self._outfeed_config_sanitize(self._config_reader(os.path.join('config', 'hooks', 'outfeeds', outfeed)))

      # get host:port from config if present or use config name
      config['server'] = self._extract_server_link(config.get('server', outfeed), config['ipv6'])
      if config['server'] is None:
        continue
      name = 'outfeed-{}-{}'.format(*config['server'])
      current_feedlist.append(name)
      if name not in self.feeds:
        if config['proxy']:
          self.log(self.logger.INFO, 'starting outfeed {} using proxy: {proxy_type} {proxy_ip}:{proxy_port}'.format(name, **config['proxy']))
        try:
          self.log(self.logger.DEBUG, 'starting outfeed: %s' % name)
          self.feeds[name] = OutFeed(
              self,
              self.logger,
              config=config
          )
          self.feeds[name].start()
        except Exception as e:
          self.log(self.logger.WARNING, 'could not start outfeed %s: %s' % (name, e))
          self.log(self.logger.WARNING, traceback.format_exc())
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
    self.start_plugins()
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
        "state": self.feeds[name].get_status('state'),
        "queue": self.feeds[name].get_status('qsize'),
        "transfer": self.feeds[name].get_status('byte_transfer'),
        "transfer_time": self.feeds[name].get_status('time_transfer'),
        "mode": self.feeds[name].get_status('mode')
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
    updates = {'hooks': self.update_hooks, 'outfeed': self.update_outfeeds, 'plugin': self.update_plugins}
    if args['action'] == 'update' and args.get('hook') in updates:
      # reload any hooks
      updates[args['hook']]()
      return True
    elif args['action'] == 'start' and args.get('hook') == 'plugin':
      # start not running plugins
      self.start_plugins()
      return True
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
            if self._close_plugin(plugin):
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
    self.start_plugins()
    self.update_hooks()

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
      try:
        result = poller.poll(-1)
      except socket.error as e:
        if e.errno == 22:
          # [Errno 22] Invalid argument
          break
        elif e.errno == 4:
          # system call interrupted
          continue
        else:
          raise e
      for fd, mask in result:
        if fd == self.socket.fileno():
          try:
            con = self.socket.accept()
            name = 'infeed-{0}-{1}'.format(con[1][0], con[1][1])
            if name not in self.feeds:
              self.feeds[name] = InFeed(self, self.logger, config=self.infeeds_config, connection=con, debug=self.config['infeed_debuglevel'], db_connector=self._db_manager.connect)
              self.feeds[name].start()
            else:
              self.log(self.logger.WARNING, 'got connection from %s but its still in feeds. wtf?' % name)
          except socket.error as e:
            if e.errno == 22:
              # [Errno 22] Invalid argument
              break
            elif e.errno == 4:
              # system call interrupted
              continue
            else:
              raise e
        elif fd == ctl_socket_server.fileno():
          con, addr = ctl_socket_server.accept()
          con.setblocking(0)
          poller.register(con.fileno(), select.POLLIN)
          self.ctl_socket_clients[con.fileno()] = (con, os.fdopen(con.fileno(), 'w', 1))
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
    self._feeds_lock.acquire()
    try:
      if name in self.feeds:
        del self.feeds[name]
      else:
        self.log(self.logger.WARNING, 'should remove %s but not in dict. wtf?' % name)
    finally:
      self._feeds_lock.release()


  def relay_dropper_handler(self, signum, frame):
    #TODO: remove, this is not needed anymore at all?
    self.dropper.handler_progress_incoming(signum, frame)

  def rename_infeed(self, old_name, new_name, allow_multiconn=True):
    self._feeds_lock.acquire()
    try:
      if not (old_name.startswith('infeed-') and new_name.startswith('infeed-') and old_name in self.feeds):
        return None
      if new_name in self.feeds:
        if not allow_multiconn:
          # multiconnection not allowed for this key\name\whatever
          return None
        if not isinstance(self.feeds[new_name], MultiInFeed):
          # convert normal infeed to MultiInFeed.
          # pop old infeed from self.feeds, create instance MultiInFeed, append old infeed to multiinfeed
          darling = self.feeds.pop(new_name)
          self.feeds[new_name] = MultiInFeed(logger=self.logger, debug=self.config['infeed_debuglevel'], master=self, wrapper_name=new_name)
          self.feeds[new_name].append_infeed(darling, new_name)
        return self.feeds[new_name].append_infeed(self.feeds.pop(old_name))
      else:
        self.feeds[new_name] = self.feeds.pop(old_name)
        return new_name
    finally:
      self._feeds_lock.release()

  def _infeed_config_sanitize(self, config):
    # 0 - disallow 1 - allow 2 - required
    config['srndgzip'] = config.get('srndgzip', 'false').lower() in ('true', 'enable', 'on')
    try:
      auth_required = int(config.get('auth_required', 0))
    except ValueError:
      auth_required = None
    if auth_required is None or 2 < auth_required < 0:
      self.log(self.logger.WARNING, 'abnormal value auth_required={}. Set 0 - diwallow'.format(auth_required))
      auth_required = 0
    config['auth_required'] = auth_required
    config['auth_support'] = config.get('auth_support', 'srnd').lower().split(',')
    config['pretty_name'] = 'pretty_name' in config and config['pretty_name'].lower() in ('true', 'yes', '1')
    # add SRNd instance_name from SRNd config
    config['instance_name'] = self.config['instance_name']
    # Parse support_ items
    support = set()
    for key in [xx for xx in config if xx.startswith('support_')]:
      support.add('{} {}'.format(key.upper()[8:], config.pop(key)))
    config['support'] = tuple(support)
    return config

  def _outfeed_config_sanitize(self, config):
    config['infinity_stream'] = config.get('infinity_stream', 'false').lower() in ('true', 'on', 'yes', '1')
    config['srndauth_key'] = config.get('srndauth_key')
    if config['srndauth_key'] is not None and len(config['srndauth_key']) != 64:
      self.log(self.logger.WARNING, 'len srndauth_key != 64. Set None')
      config['srndauth_key'] = None
    if 'multiconn' in config:
      multiconn = config['multiconn']
      try:
        config['multiconn'] = int(config['multiconn'])
      except ValueError:
        config['multiconn'] = None
      else:
        if 10 < config['multiconn'] < 2:
          config['multiconn'] = None
      if config['multiconn'] is None:
        self.log(self.logger.WARNING, 'abnormal value multiconn="{}". Set 1 - only one outfeed'.format(multiconn))
        config['multiconn'] = 1
    config['ipv6'] = config.get('ipv6', 'false').lower() in ('true', 'yes', '1')
    # check proxy
    proxy = {'proxy_type': None, 'proxy_ip': None, 'proxy_port': None}
    for proxy_key in proxy:
      if proxy_key in config:
        proxy[proxy_key] = config.pop(proxy_key).lower()
    if proxy['proxy_type'] is not None and proxy['proxy_ip'] is not None:
      try:
        proxy['proxy_port'] = int(proxy['proxy_port'])
      except ValueError:
        proxy = None
    config['proxy'] = proxy

    config['sync_on_startup'] = 'sync_on_startup' in config and config['sync_on_startup'].lower() in ('true', 'yes', '1')
    try:
      config['debug'] = int(config.get('debug', self.config['srnd_debuglevel']))
    except ValueError:
      config['debug'] = self.config['srnd_debuglevel']
    else:
      if 9 < config['debug'] < 0:
        config['debug'] = self.config['srnd_debuglevel']
    return config

  def watching(self):
    return self.dropper.watching

  def _close_plugin(self, name):
    wait_count = 50
    wait_time = 0.2
    c_count = 0
    self.plugins[name].shutdown()
    while self.plugins[name].isAlive() and c_count < wait_count:
      c_count += 1
      time.sleep(wait_time)
    if self.plugins[name].isAlive():
      self.log(self.logger. ERROR, '{} does not respond to shutdown in {} second'.format(name, int(c_count * wait_time)))
      return False
    else:
      return True

  def shutdown(self):
    self.dropper.running = False
    self.running = False
    self.log(self.logger.INFO, 'closing listener..')
    self.socket.shutdown(socket.SHUT_RDWR)
    self.log(self.logger.INFO, 'closing plugins..')
    for plugin in self.plugins:
      self._close_plugin(plugin)
    self.log(self.logger.INFO, 'closing feeds..')
    feeds = list()
    for name in self.feeds:
      feeds.append(name)
    for name in feeds:
      if name in self.feeds:
        self.feeds[name].shutdown()
    self.log(self.logger.INFO, 'waiting for feeds to shut down..')
