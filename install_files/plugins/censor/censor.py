#!/usr/bin/python

import os
import Queue
import sqlite3
import threading
import time
import traceback
import base64
from binascii import unhexlify
from calendar import timegm
from datetime import datetime, timedelta
from email.utils import parsedate_tz
from hashlib import sha512

import nacl.signing

from srnd.utils import basicHTMLencode

import censor_httpd

class main(threading.Thread):

  def log(self, loglevel, message):
    if loglevel >= self.loglevel:
      self.logger.log(self.name, message, loglevel)

  def __init__(self, thread_name, logger, args):
    threading.Thread.__init__(self)
    self.name = thread_name
    self.logger = logger
    # TODO: move sleep stuff to config table
    self.sleep_threshold = 10
    self.sleep_time = 0.03
    if 'debug' not in args:
      self.loglevel = self.logger.INFO
      self.log(self.logger.INFO, 'debuglevel not defined, using default of debug = %i' % self.logger.INFO)
    else:
      try:
        self.loglevel = int(args['debug'])
        if self.loglevel < 0 or self.loglevel > 5:
          self.loglevel = self.logger.INFO
          self.log(self.logger.INFO, 'debuglevel not between 0 and 5, using default of debug = %i' % self.logger.INFO)
        else:
          self.log(self.logger.DEBUG, 'using debuglevel %i' % self.loglevel)
      except ValueError:
        self.loglevel = self.logger.INFO
        self.log(self.logger.INFO, 'debuglevel not between 0 and 5, using default of debug = %i' % self.logger.INFO)
    self.log(self.logger.INFO, 'initializing as plugin..')
    if not 'srnd' in args:
      # FIXME add self.die()
      self.log(self.logger.CRITICAL, 'SRNd not in args')
      return
    self._db_connector = args['db_connector']
    if 'add_admin' in args:
      self.add_admin = args['add_admin']
    else:
      self.add_admin = ""
    self.sync_on_startup = False
    if 'sync_on_startup' in args:
      if args['sync_on_startup'].lower() == 'true':
        self.sync_on_startup = True
    self.ignore_old = 14
    if 'ignore_old' in args:
      try:    self.ignore_old = int(args['ignore_old'])
      except: pass
    if self.ignore_old < 0: self.ignore_old = 0
    self.ignore_old *= 3600 * 24
    self.SRNd = args['srnd']
    if 'control_newsgroup' in args:
      self.ctl_newsgroup = args['control_newsgroup']
    else:
      self.ctl_newsgroup = 'ctl'
    if 'threads_per_board' in args:
      self.threads_per_board = int(args['threads_per_board'])
    else:
      self.threads_per_board = 200
    self.log(self.logger.DEBUG, 'initializing censor_httpd..')
    args['censor'] = self
    self.httpd = censor_httpd.censor_httpd("censor_httpd", self.logger, args)
    self.DATABASE_VERSION = 12
    self.ALL_FLAGS = '8191'
    self.queue = Queue.Queue()
    self.command_mapper = dict()
    self.command_mapper['overchan-expire'] = \
    self.command_mapper['delete'] = \
    self.command_mapper['overchan-delete-attachment'] = self.handle_delete
    self.command_mapper['overchan-sticky'] = \
    self.command_mapper['overchan-close'] = self.handle_sticky_close
    self.command_mapper['srnd-acl-mod'] = self.handle_srnd_acl_mod
    self.command_mapper['overchan-board-add'] = \
    self.command_mapper['overchan-board-del'] = \
    self.command_mapper['overchan-board-mod'] = self.handle_overchan_dummy_mod
    self.command_mapper['handle-postman-mod'] = self.handle_postman_mod
    self.command_mapper['handle-srnd-cmd'] = self.handle_srnd_cmd

  def shutdown(self):
    self.httpd.shutdown()
    self.running = False

  def add_article(self, message_id, source="article", timestamp=None):
    #print "should add article:", message_id
    self.queue.put((source, message_id))
    #self.log('this plugin does not handle any article. remove hook parts from {0}'.format(os.path.join('config', 'plugins', self.name.split('-', 1)[1])), 0)

  def update_censordb(self):
    try:
      db_version = int(self.censordb.execute('SELECT value FROM config WHERE key = "db_version"').fetchone()[0])
    except sqlite3.OperationalError as e:
      db_version = 0
      self.log(self.logger.DEBUG, 'error while fetching db_version: {}. assuming new database'.format(e))
    if db_version < self.DATABASE_VERSION:
      self.log(self.logger.INFO, 'should update db from version {}'.format(db_version))
      while db_version < self.DATABASE_VERSION:
        self.log(self.logger.INFO, 'updating db from version {} to version {}'.format(db_version, db_version + 1))
        self._update_db_from(db_version)
        db_version += 1
        self.censordb.execute('UPDATE config SET value = ? WHERE key = "db_version"', (db_version,))
      self.censordb.commit()

    if self.add_admin:
      self.censordb.execute("INSERT OR IGNORE INTO keys VALUES (NULL,?,?,?)", (self.add_admin, "admin", self.ALL_FLAGS))
      self.censordb.commit()

  def _update_db_from(self, version):
    if version == 0:
      # create configuration
      self.censordb.execute("CREATE TABLE config (key text PRIMARY KEY, value text)")
      self.censordb.execute('INSERT INTO config VALUES ("db_version","0")')

      # create flags
      self.censordb.execute("CREATE TABLE commands (id INTEGER PRIMARY KEY, command TEXT, flag text)")
      self.censordb.execute('INSERT INTO commands (command, flag) VALUES (?,?)', ("delete",                     str(0b1)))
      self.censordb.execute('INSERT INTO commands (command, flag) VALUES (?,?)', ("overchan-sticky",            str(0b10)))
      self.censordb.execute('INSERT INTO commands (command, flag) VALUES (?,?)', ("overchan-delete-attachment", str(0b100)))
      self.censordb.execute('INSERT INTO commands (command, flag) VALUES (?,?)', ("overchan-news-add",          str(0b1000)))
      self.censordb.execute('INSERT INTO commands (command, flag) VALUES (?,?)', ("overchan-news-del",          str(0b10000)))
      self.censordb.execute('INSERT INTO commands (command, flag) VALUES (?,?)', ("overchan-board-add",         str(0b100000)))
      self.censordb.execute('INSERT INTO commands (command, flag) VALUES (?,?)', ("overchan-board-del",         str(0b1000000)))
      self.censordb.execute('INSERT INTO commands (command, flag) VALUES (?,?)', ("srnd-acl-view",              str(0b10000000)))
      self.censordb.execute('INSERT INTO commands (command, flag) VALUES (?,?)', ("srnd-acl-mod",               str(0b100000000)))
      #self.censordb.execute('INSERT INTO commands (command, flag) VALUES (?,?)', ("srnd-acl-del",      str(0b1000000000)))
      #self.censordb.execute('INSERT INTO commands (command, flag) VALUES (?,?)', ("testing",           str(0b1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000)))

      # create users
      self.censordb.execute("CREATE TABLE keys (id INTEGER PRIMARY KEY, key text UNIQUE, local_name text, flags text)")

      # create reasons
      self.censordb.execute("CREATE TABLE reasons (id INTEGER PRIMARY KEY, reason text UNIQUE)")
      self.censordb.execute("INSERT INTO reasons VALUES (NULL,?)", ("unknown",))
      self.censordb.execute("INSERT INTO reasons VALUES (NULL,?)", ("whitelist",))
      self.censordb.execute("INSERT INTO reasons VALUES (NULL,?)", ("own message",))
      self.censordb.execute("INSERT INTO reasons VALUES (NULL,?)", ("manually",))

      # create log
      self.censordb.execute("CREATE TABLE log (id INTEGER PRIMARY KEY, command_id INTEGER, accepted INTEGER, data TEXT, key_id INTEGER, reason_id INTEGER, comment TEXT, timestamp INTEGER, UNIQUE(key_id, command_id, data))")
    elif version == 1:
      self.censordb.execute("CREATE TABLE signature_cache (message_uid text PRIMARY KEY, valid INTEGER)")
    elif version == 2:
      self.censordb.execute("CREATE UNIQUE INDEX IF NOT EXISTS sig_cache_message_uid_idx ON signature_cache(message_uid);")
    elif version == 3:
      self.censordb.execute('INSERT INTO commands (command, flag) VALUES (?,?)', ("overchan-board-mod", str(0b1000000000)))
    elif version == 4:
      self.censordb.execute("DROP TABLE log")
      self.censordb.execute("CREATE TABLE log (id INTEGER PRIMARY KEY, command_id INTEGER, accepted INTEGER, data TEXT, key_id INTEGER, reason_id INTEGER, comment TEXT, timestamp INTEGER, UNIQUE(key_id, command_id, data, comment))")
    elif version == 5:
      self.censordb.execute('DELETE FROM commands WHERE command = "overchan-news-del"')
      self.censordb.execute('INSERT INTO commands (command, flag) VALUES (?,?)', ("overchan-close", str(0b10000)))
    elif version == 6:
      self.censordb.execute('ALTER TABLE signature_cache ADD COLUMN received INTEGER DEFAULT 0')
    elif version == 7:
      self.censordb.execute('INSERT INTO commands (command, flag) VALUES (?,?)', ("handle-postman-mod", str(1024)))
    elif version == 8:
      self.censordb.execute("INSERT INTO reasons VALUES (NULL,?)", ("local",))
      self.censordb.execute("INSERT INTO reasons VALUES (NULL,?)", ("remote",))
      self.censordb.execute("INSERT INTO reasons VALUES (NULL,?)", ("replay",))
      self.censordb.execute('INSERT INTO commands (command, flag) VALUES (?,?)', ("handle-srnd-cmd", str(2048)))
      # evil cmd replace srnd cmd.
      self.censordb.execute('CREATE TABLE evil_to_srnd (evil text PRIMARY KEY, srnd text, comment DEFAULT "")')
      for evil, srnd, comm in (('purge',      'delete', ''), ('purge_desthash', 'delete',                     ''), ('sticky', 'overchan-sticky', r'sticky\unsticky thread request'), \
                               ('purge_root', 'delete', ''), ('delete_a',       'overchan-delete-attachment', ''), ('close',  'overchan-close',  r'closing\opening thread request')):
        self.censordb.execute("INSERT INTO evil_to_srnd VALUES (?, ?, ?)", (evil, srnd, comm))
      # received 0 - local, 1 - local and remote. send - 0 local, 1 - remote if secret key present else local. replayable (work from articles)- 0 not replay cmd , 1 - replay cmd
      self.censordb.execute("CREATE TABLE cmd_map (id INTEGER PRIMARY KEY, command text, received INTEGER DEFAULT -1, send INTEGER DEFAULT -1, replayable INTEGER DEFAULT -1)")
      for command, unikey in (('delete',       1), ('overchan-delete-attach', 1), ('handle-postman-mod', 0), ('overchan-sticky', 0), ('overchan-board-add', 0), \
                              ('srnd-acl-mod', 0), ('overchan-board-del',     0), ('overchan-board-mod', 0), ('handle-srnd-cmd', 0), ('overchan-close',     0)):
        self.censordb.execute("INSERT INTO cmd_map VALUES (NULL, ?, ?, ?, ?)", (command, unikey, unikey, unikey))
    elif version == 9:
      self.censordb.execute("INSERT INTO reasons VALUES (NULL,?)", ("disable",))
      self.censordb.execute('UPDATE cmd_map SET command = "overchan-delete-attachment" WHERE command = "overchan-delete-attach"')
    elif version == 10:
      self.censordb.execute('ALTER TABLE log ADD COLUMN source TEXT DEFAULT "local"')
    elif version == 11:
      self.censordb.execute('INSERT INTO commands (command, flag) VALUES (?,?)', ("srnd-infeed-access", str(4096)))
    else:
      raise Exception('Handler for update from {} version not present in code. Fix it!'.format(version))

  def run(self):
    #if self.should_terminate:
    #  return
    self.log(self.logger.INFO, 'starting up as plugin..')

    self.dropperdb = self._db_connector('dropper', timeout=60)
    self.censordb = self._db_connector('censor')
    self.overchandb = self._db_connector('overchan', timeout=60)
    self.postmandb = self._db_connector('postman', timeout=60)

    self.allowed_cache = dict()
    self.key_cache = dict()
    self.command_cache = dict()

    self.update_censordb()

    self.httpd.start()

    self.running = True
    db_commit = False
    while self.running:
      try:
        source, data = self.queue.get(block=True, timeout=1)
        if source == "article":
          if self.process_article(data) and self.queue.qsize() > self.sleep_threshold:
            time.sleep(self.sleep_time)
          db_commit = True
        elif source == "httpd":
          public_key, data = data
          key_id = self.get_key_id(public_key)
          timestamp = int(time.time())
          for line in data.split("\n"):
            self.handle_line(line, key_id, timestamp)
          db_commit = True
        elif source == "control":
          # don't do shit
          pass
        else:
          self.log(self.logger.WARNING, 'unknown source: %s' % source)
      except Queue.Empty:
        if db_commit:
          self.censordb.commit()
          db_commit = False
    self.censordb.commit()
    self.censordb.close()
    self.dropperdb.close()
    self.overchandb.close()
    self.postmandb.close()
    self.log(self.logger.INFO, 'bye')

  def allowed(self, key_id, command, is_replay, is_local):
    if key_id is None and command == 'overchan-expire' and is_local:
      return 1, 5
    accepted, reason_id = self.command_reason(command, is_replay, is_local)
    if not self.allowed_key(key_id, command):
      return 0, 1
    return accepted, reason_id

  def allowed_key(self, key_id, command):
    # allow expiration from ourself
    if key_id is None and command == 'overchan-expire':
      return True
    if key_id in self.allowed_cache:
      if command in self.allowed_cache[key_id]:
        return self.allowed_cache[key_id][command]
    else:
      if len(self.allowed_cache) > 256:
        self.allowed_cache = dict()
      self.allowed_cache[key_id] = dict()
    try:
      flags_available = int(self.censordb.execute("SELECT flags FROM keys WHERE id=?", (key_id,)).fetchone()[0])
      flag_required = int(self.censordb.execute("SELECT flag FROM commands WHERE command=?", (command,)).fetchone()[0])
      self.allowed_cache[key_id][command] = (flags_available & flag_required) == flag_required
      return self.allowed_cache[key_id][command]
    except Exception as e:
      self.log(self.logger.ERROR, 'unknown exception in allowed(): %s' % e)
      self.log(self.logger.ERROR, traceback.format_exc())
      return False

  def command_reason(self, command, is_replay, is_local):
    if command not in self.command_cache:
      try:
        row = self.censordb.execute("SELECT commands.id, received, replayable FROM commands, cmd_map \
          WHERE commands.command = ? AND commands.command = cmd_map.command", (command,)).fetchone()
        if not row:
          cmd_id = int(self.censordb.execute("SELECT id FROM commands WHERE command = ?", (command,)).fetchone()[0])
          cmd_list = (cmd_id, -1, -1)
        else:
          cmd_list = (int(row[0]), int(row[1]), int(row[2]))
      except Exception as e:
        cmd_list = (-1, -1, -1)
        self.log(self.logger.ERROR, 'Command %s not load from db. Disallow: %s' % (command, e))
      self.command_cache[command] = cmd_list
    if self.command_cache[command][1] not in (0, 1):
      return 0, 8
    if not is_local and self.command_cache[command][1] != 1:
      return 0, 6
    if is_replay and self.command_cache[command][2] != 1:
      return 0, 7
    if is_local:
      return 1, 5
    else:
      return 1, 6

  def is_allow_message_id(self, message_id):
    # True - valid and allow, False - disallow, None - new article
    current_time = int(time.time())
    signature_row = self.censordb.execute("SELECT valid, received FROM signature_cache WHERE message_uid = ?", (message_id,)).fetchone()
    if signature_row is None:
      return None
    valid, received = int(signature_row[0]), int(signature_row[1])
    if not valid:
      return False
    if received:
      if self.ignore_old > 0 and current_time - received > self.ignore_old:
        return False
    else:
      # add missing time
      self.censordb.execute('UPDATE signature_cache SET received = ? WHERE message_uid = ?', (current_time, message_id))
    return True

  def process_article(self, message_id):
    self.log(self.logger.DEBUG, "processing %s.." % message_id)
    current_time = int(time.time())
    valid = self.is_allow_message_id(message_id)
    if valid is False:
      return False
    if not os.path.exists(os.path.join("articles", message_id)):
      self.log(self.logger.WARNING, "%s is missing" % message_id)
      # it's no longer there
      return False
    f = open(os.path.join("articles", message_id), 'r')
    if valid is True:
      try:
        self.parse_article(f, message_id)
      except Exception as e:
        self.log(self.logger.WARNING, 'something went wrong while parsing %s: %s' % (message_id, e))
      finally:
        f.close()
      return True
    public_key = None
    newsgroups = None
    references = None
    outer_sent = None
    line = f.readline()
    while len(line) != 0:
      if len(line) == 1:
        break
      if line.lower().startswith('x-pubkey-ed25519:'):
        public_key = line.lower()[:-1].split(' ', 1)[1]
      elif line.lower().startswith('x-signature-ed25519-sha512:'):
        signature = line.lower()[:-1].split(' ', 1)[1]
      elif line.lower().startswith('newsgroups:'):
        newsgroups = line.lower()[:-1].split(' ', 1)[1].split(',')
      elif line.lower().startswith('references:'):
        references = line.lower()[:-1].split(' ', 1)[1].split(',')
      elif line.lower().startswith('date:'):
        outer_sent = line.split(' ', 1)[1][:-1]
        outer_sent_tz = parsedate_tz(outer_sent)
        if outer_sent_tz:
          offset = 0
          if outer_sent_tz[-1]: offset = outer_sent_tz[-1]
          outer_sent = timegm((datetime(*outer_sent_tz[:6]) - timedelta(seconds=offset)).timetuple())
        else:
          outer_sent = int(time.time())

      line = f.readline()
    # is this article for expiration
    if newsgroups and self.ctl_newsgroup not in newsgroups:
      # yas it is
      # we don't need anything more from this article, close the file
      f.close()
      # do the expiration
      return self.handle_expiration(message_id, newsgroups, references)
    hasher = sha512()
    bodyoffset = f.tell()
    oldline = None
    for line in f:
      if oldline:
        hasher.update(oldline)
      oldline = line.replace("\n", "\r\n")
    hasher.update(oldline.replace("\r\n", ""))
    try:
      nacl.signing.VerifyKey(unhexlify(public_key)).verify(hasher.digest(), unhexlify(signature))
      self.log(self.logger.DEBUG, "found valid signature: %s" % message_id)
      self.log(self.logger.VERBOSE, "seeking from %i back to %i" % (f.tell(), bodyoffset))
      f.seek(bodyoffset)
      self.censordb.execute('INSERT INTO signature_cache (message_uid, valid, received) VALUES (?, ?, ?)', (message_id, 1, current_time))
    except Exception as e:
      if self.loglevel < self.logger.INFO:
        self.log(self.logger.DEBUG, "could not verify signature: %s: %s" % (message_id, e))
      else:
        self.log(self.logger.INFO, "could not verify signature: %s" % message_id)
      f.close()
      self.censordb.execute('INSERT INTO signature_cache (message_uid, valid, received) VALUES (?, ?, ?)', (message_id, 0, current_time))
      return True
    self.parse_article(f, message_id, self.get_key_id(public_key))
    f.close()
    return True

  def get_key_id(self, public_key):
    if public_key in self.key_cache:
      return self.key_cache[public_key]
    if len(self.key_cache) > 256:
      self.key_cache = dict()
    try:
      #self.log("should get key_id for public_key %s" % public_key, 1)
      key_id = int(self.censordb.execute("SELECT id FROM keys WHERE key = ?", (public_key,)).fetchone()[0])
    except Exception:
      self.censordb.execute("INSERT INTO keys (key, local_name, flags) VALUES (?, ?, ?)", (public_key, '', '0'))
      self.censordb.commit()
      key_id = int(self.censordb.execute("SELECT id FROM keys WHERE key = ?", (public_key,)).fetchone()[0])
    self.key_cache[public_key] = key_id
    return key_id

  def handle_expiration(self, message_id, newsgroups, references):
    """
    handle content expiration
    :param message_id: the new messasge's nntp id
    :param newsgroups: the newsgroups this message is in
    :param references: the messages this message references or None if it doesn't
    """
    if True: # references is None:
      self.log(self.logger.INFO, "handle expiration policy for %s" % message_id)
      now = int(time.time())
      # this is a new thread
      # for each newsgroup
      for newsgroup in newsgroups:
        # does this group exist?
        group = self.overchandb.execute("SELECT group_id FROM groups WHERE group_name = ?", (newsgroup,)).fetchone()
        if group:
          # yas it does exist
          # get the group id
          group_id = group[0]
          # get the root posts that we want to expire in the newsgroup
          for row in self.overchandb.execute("SELECT article_uid FROM articles WHERE article_uid NOT IN ( SELECT article_uid FROM articles WHERE parent = '' AND group_id = ? ORDER BY last_update DESC LIMIT ? ) AND group_id = ? AND parent = ''", (group_id, self.threads_per_board, group_id)).fetchall():
            # get all children for this thread
            for child_row in self.overchandb.execute("SELECT article_uid FROM articles WHERE parent = ?", (row[0],)).fetchall():
              # issue local overchan-expire to all children that are too old
              self.handle_line('overchan-expire %s' % child_row[0], None, now)
            # issue local overchan-expire to root post
            self.handle_line('overchan-expire %s' % row[0], None, now)
            
    return True
  def parse_article(self, article_fd, message_id, key_id=None):
    self.log(self.logger.DEBUG, "parsing %s.." % message_id)
    is_replay = False
    if key_id == None:
      is_replay = True
      public_key = ''
      for line in article_fd:
        if len(line) == 1:
          break
        elif line.lower().startswith('x-pubkey-ed25519:'):
          public_key = line.lower()[:-1].split(' ', 1)[1]
      if public_key != '':
        key_id = self.get_key_id(public_key)
    sent = None
    for line in article_fd:
      if len(line) == 1:
        break
      elif line.lower().startswith('date:'):
        sent = line.split(' ', 1)[1][:-1]
        sent_tz = parsedate_tz(sent)
        if sent_tz:
          offset = 0
          if sent_tz[-1]: offset = sent_tz[-1]
          sent = timegm((datetime(*sent_tz[:6]) - timedelta(seconds=offset)).timetuple())
        else:
          sent = int(time.time())
    if not sent:
      self.log(self.logger.INFO, "received article does not contain a date: header. using current timestamp instead")
      sent = int(time.time())

    for line in article_fd:
      if len(line) == 1:
        continue
      line = line.split('\n')[0]
      self.handle_line(line, key_id, sent, is_replay, message_id)

  def redistribute_command(self, group, line, comment, timestamp):
    # TODO add universal redistributor? Add SRNd queue? Currents methods thread-safe?
    for hook in self.SRNd.get_allow_hooks(group):
      if hook.startswith('plugin-'):
        if hook in self.SRNd.plugins:
          self.log(self.logger.DEBUG, "redistribute %s to %s" % (group, hook))
          self.SRNd.plugins[hook].add_article(line, source="control", timestamp=timestamp)
        else:
          self.log(self.logger.ERROR, 'unknown plugin hook detected. wtf? {}'.format(hook))

  def handle_line(self, line, key_id, timestamp, is_replay=False, message_id=None):
    if message_id is None:
      is_local = True
      source = 'local'
    else:
      is_local = False
      source = message_id
    command = line.lower().split(" ", 1)[0]
    if '#' in line:
      line, comment = line.split("#", 1)
      line = line.rstrip(" ")
    else:
      comment = ''
    if not command in self.command_mapper:
      self.log(self.logger.WARNING, 'got unknown command: "{}", source: "{}"'.format(line, source))
      return
    accepted, reason_id = self.allowed(key_id, command, is_replay, is_local)
    if key_id is not None:
      if self.command_cache[command][0] != -1:
        command_id = self.command_cache[command][0]
      else:
        self.log(self.logger.ERROR, "command %s not found in command_cache. FIXME!" % command)
        return
    if accepted == 1:
      data, groups = self.command_mapper[command](line)
      if groups:
        for group in groups:
          self.redistribute_command(group, line, comment, timestamp)
    else:
      data = line.lower().split(" ", 1)[-1].split(" ", 1)[0]
      self.log(self.logger.DEBUG, 'not authorized for "{}": {}. source: {}'.format(command, key_id, source))
    try:
      if key_id is None:
        # ths means censor executed the command on itself
        self.log(self.logger.INFO, "censor executed %s own its own" % line)
      else:
        self.censordb.execute('INSERT INTO log (accepted, command_id, data, key_id, reason_id, comment, timestamp, source) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', \
                              (accepted, command_id, data.decode('UTF-8'), key_id, reason_id, basicHTMLencode(comment).decode('UTF-8'), int(time.time()), source))
    except sqlite3.Error:
      pass

  def handle_srnd_acl_mod(self, line):
    self.log(self.logger.DEBUG, "handle acl_mod: %s" % line)
    flags = '0'
    local_nick = ''
    row = line.split(" ", 3)[1:]
    key = row[0]
    if len(row) > 1:
      flags = row[1]
    if len(row) > 2:
      local_nick = row[2].decode('UTF-8')
    try:
      if int(self.censordb.execute('SELECT count(key) FROM keys WHERE key = ?', (key,)).fetchone()[0]) == 0:
        self.log(self.logger.DEBUG, "handle acl_mod: new key")
        self.censordb.execute("INSERT INTO keys (key, local_name, flags) VALUES (?, ?, ?)", (key, local_nick, flags))
      else:
        self.censordb.execute("UPDATE keys SET local_name = ?, flags = ? WHERE key = ?", (local_nick, flags, key))
      self.censordb.commit()
      self.allowed_cache = dict()
    except Exception as e:
      self.log(self.logger.WARNING, "could not handle srnd-acl-mod: %s, line = '%s'" % (e, line))
    return key, None

  def handle_postman_mod(self, line):
    self.log(self.logger.DEBUG, "handle postman-mod: %s" % line)
    userkey, base64_blob = line.split(" ", 2)[1:]
    try:
      local_name, allow, expires, logout = [base64.urlsafe_b64decode(x).decode('UTF-8') for x in base64_blob.split(':')]
    except:
      self.log(self.logger.WARNING, 'get corrupted data for %s' % userkey)
      return userkey, None
    local_name = basicHTMLencode(local_name[:20])
    try:
      allow = int(allow)
    except ValueError:
      allow = 0
    if allow not in (0, 1): allow = 0
    current_time = int(time.time())
    try:
      expires = int(expires) * 24 * 3600 + current_time
    except ValueError:
      expires = current_time
    if expires < current_time or expires - current_time > 3650 * 24 * 3600:
      expires = current_time

    try:
      if int(self.postmandb.execute('SELECT count(userkey) FROM userkey WHERE userkey = ?', (userkey,)).fetchone()[0]) == 0:
        self.log(self.logger.DEBUG, "handle postman-mod: new userkey")
        self.postmandb.execute("INSERT INTO userkey (userkey, local_name, allow, expires) VALUES (?, ?, ?, ?)", (userkey, local_name, allow, expires))
      else:
        self.postmandb.execute("UPDATE userkey SET local_name = ?, allow = ?, expires = ? WHERE userkey = ?", (local_name, allow, expires, userkey))
        if logout != '':
          self.postmandb.execute("UPDATE userkey SET cookie = ? WHERE userkey = ?", ('', userkey))
      self.postmandb.commit()
    except Exception as e:
      self.log(self.logger.WARNING, "could not handle postman-mod: %s, line = '%s'" % (e, line))
    return userkey, None

  def handle_srnd_cmd(self, line):
    self.log(self.logger.DEBUG, "handle srnd-cmd: %s" % line)
    command, base64_blob = line.split(" ", 2)[1:]
    try:
      send, received, replayable = [int(base64.urlsafe_b64decode(x)) for x in base64_blob.split(':')]
    except Exception as e:
      self.log(self.logger.WARNING, 'handle srnd-cmd: get corrupted data for {}: {}'.format(command, e))
      return command, None
    if send not in (-1, 0, 1) or received not in (-1, 0, 1) or replayable not in (0, 1):
      self.log(self.logger.WARNING, 'handle srnd-cmd: get invalid value for %s, send=%s, received=%s, replayable=%s' % (command, send, received, replayable))
      return command, None
    if command == 'handle-srnd-cmd':
      self.log(self.logger.WARNING, 'handle srnd-cmd: modifying self is not allowed. This maybe suicide!')
      return command, None

    if int(self.censordb.execute('SELECT count(command) FROM cmd_map WHERE command = ?', (command,)).fetchone()[0]) == 1:
      self.censordb.execute('UPDATE cmd_map SET send = ?, received = ?, replayable = ? WHERE command = ?', (send, received, replayable, command))
      self.censordb.commit()
      self.command_cache = dict()
    else:
      self.log(self.logger.WARNING, "handle srnd-cmd: command %s not found or duplicated" % (command,))
    return command, None

  def handle_delete(self, line):
    command, message_id = line.split(" ", 1)
    self.log(self.logger.DEBUG, "should delete %s" % message_id)

    if os.path.exists(os.path.join("articles", "restored", message_id)):
      self.log(self.logger.DEBUG, "%s has been restored, ignoring delete" % message_id)
      return message_id, None
    if command == 'delete':
      row = self.overchandb.execute('SELECT parent from articles WHERE article_uid = ?', (message_id,)).fetchone()
      if row is not None and row[0] in ('', message_id):
        self.log(self.logger.DEBUG, "article is a overchan root post, deleting whole thread")
        for row in self.overchandb.execute('SELECT article_uid from articles where parent = ?', (message_id,)).fetchall():
          self.delete_article(row[0])
    return self.delete_article(message_id, command)

  def delete_article(self, message_id, command=''):
    groups = list()
    group_rows = list()
    article_path = os.path.join('articles', message_id)
    censore_path = os.path.join('articles', 'censored', message_id)
    for row in self.dropperdb.execute('SELECT group_name, article_id from articles, groups WHERE message_id=? and groups.group_id = articles.group_id', (message_id,)).fetchall():
      group_rows.append((row[0], row[1]))
      groups.append(row[0])
    if os.path.exists(censore_path) and command == 'overchan-delete-attachment':
      self.log(self.logger.DEBUG, "already deleted, still handing over to redistribute further")
    elif os.path.exists(article_path):
      if command == 'overchan-delete-attachment':
        i = open(article_path, 'r')
        o = open(censore_path, 'w')
        o.write(i.read())
        i.close()
        o.close()
      else:
        self.log(self.logger.DEBUG, "moving %s to articles/censored/" % message_id)
        os.rename(article_path, censore_path)
        for group in group_rows:
          self.log(self.logger.DEBUG, "deleting groups/%s/%i" % (group[0], group[1]))
          try:
            # FIXME race condition with dropper if currently processing this very article
            os.unlink(os.path.join("groups", str(group[0]), str(group[1])))
          except Exception as e:
            self.log(self.logger.WARNING, "could not delete %s: %s" % (os.path.join("groups", str(group[0]), str(group[1])), e))
        if command == 'overchan-expire':
          # expire this article by blanking the article
          try:
            if os.stat(censore_path).st_size > 0:
              f = open(censore_path, 'w')
            f.close()
          except:
            pass

    elif not os.path.exists(censore_path):
      f = open(censore_path, 'w')
      f.close()
    return message_id, groups

  @staticmethod
  def handle_overchan_dummy_mod(line):
    # overchan specific, gets handled at overchan plugin via redistribute_command()
    group_name = line.lower().split(' ')[1]
    return group_name, (group_name,)

  def handle_sticky_close(self, line):
    message_id = line.split(' ')[1]
    groups = list()
    for row in self.overchandb.execute('SELECT groups.group_name from articles, groups WHERE articles.article_uid = ? and groups.group_id = articles.group_id', (message_id,)).fetchall():
      groups.append(row[0])
    return message_id, groups

if __name__ == '__main__':
  print "[%s] %s. %s" % ("censor", "this plugin can't run as standalone version.", "bye")
