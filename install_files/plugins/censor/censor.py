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
    self.sleep_time = 0.05
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
      except ValueError as e:
        self.loglevel = self.logger.INFO
        self.log(self.logger.INFO, 'debuglevel not between 0 and 5, using default of debug = %i' % self.logger.INFO)
    self.log(self.logger.INFO, 'initializing as plugin..')
    if not 'SRNd' in args:
      # FIXME add self.die()
      self.log(self.logger.CRITICAL, 'SRNd not in args')
      return
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
    self.SRNd = args['SRNd']
    self.log(self.logger.DEBUG, 'initializing censor_httpd..')
    args['censor'] = self
    self.httpd = censor_httpd.censor_httpd("censor_httpd", self.logger, args)
    self.db_version = 10
    self.all_flags = "4095"
    self.queue = Queue.Queue()
    self.command_mapper = dict()
    self.command_mapper['delete'] = self.handle_delete
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

  def add_article(self, message_id, source="article"):
    #print "should add article:", message_id
    self.queue.put((source, message_id))
    #self.log('this plugin does not handle any article. remove hook parts from {0}'.format(os.path.join('config', 'plugins', self.name.split('-', 1)[1])), 0)

  def update_db(self, current_version):
    self.log(self.logger.INFO, "should update db from version %i" % current_version)
    if current_version == 0:
      self.log(self.logger.INFO, "updating db from version %i to version %i" % (current_version, 1))
      # create configuration
      self.censordb.execute("CREATE TABLE config (key text PRIMARY KEY, value text)")
      self.censordb.execute('INSERT INTO config VALUES ("db_version","1")')

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

      self.sqlite_censor_conn.commit()
      current_version = 1
    if current_version == 1:
      self.log(self.logger.INFO, "updating db from version %i to version %i" % (current_version, 2))
      self.censordb.execute("CREATE TABLE signature_cache (message_uid text PRIMARY KEY, valid INTEGER)")
      self.censordb.execute('UPDATE config SET value = "2" WHERE key = "db_version"')
      self.sqlite_censor_conn.commit()
      current_version = 2
    if current_version == 2:
      self.log(self.logger.INFO, "updating db from version %i to version %i" % (current_version, 3))
      self.censordb.execute("CREATE UNIQUE INDEX IF NOT EXISTS sig_cache_message_uid_idx ON signature_cache(message_uid);")
      self.censordb.execute('UPDATE config SET value = "3" WHERE key = "db_version"')
      self.sqlite_censor_conn.commit()
      current_version = 3
    if current_version == 3:
      self.log(self.logger.INFO, "updating db from version %i to version %i" % (current_version, 4))
      self.censordb.execute('INSERT INTO commands (command, flag) VALUES (?,?)', ("overchan-board-mod", str(0b1000000000)))
      self.censordb.execute('UPDATE config SET value = "4" WHERE key = "db_version"')
      self.sqlite_censor_conn.commit()
      current_version = 4
    if current_version == 4:
      self.log(self.logger.INFO, "updating db from version %i to version %i" % (current_version, 5))
      self.censordb.execute("DROP TABLE log")
      self.censordb.execute("CREATE TABLE log (id INTEGER PRIMARY KEY, command_id INTEGER, accepted INTEGER, data TEXT, key_id INTEGER, reason_id INTEGER, comment TEXT, timestamp INTEGER, UNIQUE(key_id, command_id, data, comment))")
      self.censordb.execute('UPDATE config SET value = "5" WHERE key = "db_version"')
      self.sqlite_censor_conn.commit()
      current_version = 5
    if current_version == 5:
      self.log(self.logger.INFO, "updating db from version %i to version %i" % (current_version, 6))
      self.censordb.execute('DELETE FROM commands WHERE command = "overchan-news-del"')
      self.censordb.execute('INSERT INTO commands (command, flag) VALUES (?,?)', ("overchan-close", str(0b10000)))
      self.censordb.execute('UPDATE config SET value = "6" WHERE key = "db_version"')
      self.sqlite_censor_conn.commit()
      current_version = 6
    if current_version == 6:
      self.log(self.logger.INFO, "updating db from version %i to version %i" % (current_version, 7))
      self.censordb.execute('ALTER TABLE signature_cache ADD COLUMN received INTEGER DEFAULT 0')
      self.censordb.execute('UPDATE config SET value = "7" WHERE key = "db_version"')
      self.sqlite_censor_conn.commit()
      current_version = 7
    if current_version == 7:
      self.log(self.logger.INFO, "updating db from version %i to version %i" % (current_version, 8))
      self.censordb.execute('INSERT INTO commands (command, flag) VALUES (?,?)', ("handle-postman-mod", str(1024)))
      self.censordb.execute('UPDATE config SET value = "8" WHERE key = "db_version"')
      self.sqlite_censor_conn.commit()
      current_version = 8
    if current_version == 8:
      self.log(self.logger.INFO, "updating db from version %i to version %i" % (current_version, 9))
      self.censordb.execute("INSERT INTO reasons VALUES (NULL,?)", ("local",))
      self.censordb.execute("INSERT INTO reasons VALUES (NULL,?)", ("remote",))
      self.censordb.execute("INSERT INTO reasons VALUES (NULL,?)", ("replay",))
      self.censordb.execute('INSERT INTO commands (command, flag) VALUES (?,?)', ("handle-srnd-cmd", str(2048)))
      # evil cmd replace srnd cmd.
      self.censordb.execute('CREATE TABLE evil_to_srnd (evil text PRIMARY KEY, srnd text, comment DEFAULT "")')
      for evil, srnd, comm in (('purge',      'delete', ''), ('purge_desthash', 'delete',                     ''), ('sticky', 'overchan-sticky', 'sticky\unsticky thread request'), \
                               ('purge_root', 'delete', ''), ('delete_a',       'overchan-delete-attachment', ''), ('close',  'overchan-close',  'closing\opening thread request')):
        self.censordb.execute("INSERT INTO evil_to_srnd VALUES (?, ?, ?)", (evil, srnd, comm))
      # received 0 - local, 1 - local and remote. send - 0 local, 1 - remote if secret key present else local. replayable (work from articles)- 0 not replay cmd , 1 - replay cmd
      self.censordb.execute("CREATE TABLE cmd_map (id INTEGER PRIMARY KEY, command text, received INTEGER DEFAULT -1, send INTEGER DEFAULT -1, replayable INTEGER DEFAULT -1)")
      for command, unikey in (('delete',       1), ('overchan-delete-attach', 1), ('handle-postman-mod', 0), ('overchan-sticky', 0), ('overchan-board-add', 0), \
                              ('srnd-acl-mod', 0), ('overchan-board-del',     0), ('overchan-board-mod', 0), ('handle-srnd-cmd', 0), ('overchan-close',     0)):
        self.censordb.execute("INSERT INTO cmd_map VALUES (NULL, ?, ?, ?, ?)", (command, unikey, unikey, unikey))
      self.censordb.execute('UPDATE config SET value = "9" WHERE key = "db_version"')
      self.sqlite_censor_conn.commit()
      current_version = 9
    if current_version == 9:
      self.log(self.logger.INFO, "updating db from version %i to version %i" % (current_version, 10))
      self.censordb.execute("INSERT INTO reasons VALUES (NULL,?)", ("disable",))
      self.censordb.execute('UPDATE cmd_map SET command = "overchan-delete-attachment" WHERE command = "overchan-delete-attach"')
      self.censordb.execute('UPDATE config SET value = "10" WHERE key = "db_version"')
      self.sqlite_censor_conn.commit()

  def run(self):
    #if self.should_terminate:
    #  return
    self.log(self.logger.INFO, 'starting up as plugin..')
    self.sqlite_dropper_conn = sqlite3.connect('dropper.db3', timeout=60)
    self.dropperdb = self.sqlite_dropper_conn.cursor()
    self.sqlite_censor_conn = sqlite3.connect('censor.db3')
    self.censordb = self.sqlite_censor_conn.cursor()
    self.sqlite_overchan_conn = sqlite3.connect('plugins/overchan/overchan.db3', timeout=60)
    self.overchandb = self.sqlite_overchan_conn.cursor()
    self.postmandb_conn = sqlite3.connect('postman.db3', timeout=60)
    self.postmandb = self.postmandb_conn.cursor()
    self.allowed_cache = dict()
    self.key_cache = dict()
    self.command_cache = dict()
    self.httpd.start()
    try:
      db_version = int(self.censordb.execute("SELECT value FROM config WHERE key = ?", ("db_version",)).fetchone()[0])
    except Exception as e:
      db_version = 0
      self.log(self.logger.DEBUG, "error while fetching db_version: %s. assuming new database" % e)
    if db_version < self.db_version:
      self.update_db(db_version)
    if self.add_admin != "":
      try:
        self.censordb.execute("INSERT INTO keys VALUES (NULL,?,?,?)", (self.add_admin, "admin", self.all_flags))
        self.sqlite_censor_conn.commit()
      except Exception as e:
        pass
    self.running = True
    while self.running:
      try:
        source, data = self.queue.get(block=True, timeout=1)
        if source == "article":
          if self.process_article(data) and self.queue.qsize() > self.sleep_threshold:
            time.sleep(self.sleep_time)
        elif source == "httpd":
          public_key, data = data
          key_id = self.get_key_id(public_key)
          timestamp = int(time.time())
          for line in data.split("\n"):
            self.handle_line(line, key_id, timestamp, False, True)
        else:
          self.log(self.logger.WARNING, 'unknown source: %s' % source)
      except Queue.Empty as e:
        pass
    self.sqlite_censor_conn.close()
    self.sqlite_dropper_conn.close()
    self.log(self.logger.INFO, 'bye')

  def allowed(self, key_id, command, is_replay, is_local):
    accepted, reason_id = self.command_reason(command, is_replay, is_local)
    if not self.allowed_key(key_id, command):
      return 0, 1
    return accepted, reason_id

  def allowed_key(self, key_id, command):
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

  def process_article(self, message_id):
    self.log(self.logger.DEBUG, "processing %s.." % message_id)
    current_time = int(time.time())
    try:
      signature_row = self.censordb.execute("SELECT valid, received FROM signature_cache WHERE message_uid = ?", (message_id,)).fetchone()
      valid, received = int(signature_row[0]), int(signature_row[1])
    except:
      pass
    else:
      if not valid:
        return False
      if received:
        if self.ignore_old > 0 and current_time - received > self.ignore_old:
          return False
      else:
        self.censordb.execute('UPDATE signature_cache SET received = ? WHERE message_uid = ?', (current_time, message_id))
        self.sqlite_censor_conn.commit()
      f = open(os.path.join("articles", message_id), 'r')
      try:
        self.parse_article(f, message_id)
      except Exception as e:
        self.log(self.logger.WARNING, 'something went wrong while parsing %s: %s' % (message_id, e))
      finally:
        f.close()
      return True
    public_key = None
    f = open(os.path.join("articles", message_id), 'r')
    line = f.readline()
    while len(line) != 0:
      if len(line) == 1:
        break
      if line.lower().startswith('x-pubkey-ed25519:'):
        public_key = line.lower()[:-1].split(' ', 1)[1]
      elif line.lower().startswith('x-signature-ed25519-sha512:'):
        signature = line.lower()[:-1].split(' ', 1)[1]
      line = f.readline()
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
      self.sqlite_censor_conn.commit()
    except Exception as e:
      if self.loglevel < self.logger.INFO:
        self.log(self.logger.DEBUG, "could not verify signature: %s: %s" % (message_id, e))
      else:
        self.log(self.logger.INFO, "could not verify signature: %s" % message_id)
      f.close()
      self.censordb.execute('INSERT INTO signature_cache (message_uid, valid, received) VALUES (?, ?, ?)', (message_id, 0, current_time))
      self.sqlite_censor_conn.commit()
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
    except Exception as e:
      self.censordb.execute("INSERT INTO keys (key, local_name, flags) VALUES (?, ?, ?)", (public_key, '', '0'))
      self.sqlite_censor_conn.commit()
      key_id = int(self.censordb.execute("SELECT id FROM keys WHERE key = ?", (public_key,)).fetchone()[0])
    self.key_cache[public_key] = key_id
    return key_id

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
      self.handle_line(line, key_id, sent, is_replay, False)

  def redistribute_command(self, group, line, comment, timestamp):
    # TODO add universal redistributor? Add SRNd queue? Currents methods thread-safe?
    for hook in self.SRNd.get_allow_hooks(group):
      if hook.startswith('plugin-'):
        if hook in self.SRNd.plugins:
          self.SRNd.plugins[hook].add_article(line, source="control", timestamp=timestamp)
        else:
          self.log(self.logger.ERROR, 'unknown plugin hook detected. wtf? {}'.format(hook))

  def handle_line(self, line, key_id, timestamp, is_replay, is_local):
    command = line.lower().split(" ", 1)[0]
    if '#' in line:
      line, comment = line.split("#", 1)
      line = line.rstrip(" ")
    else:
      comment = ''
    if not command in self.command_mapper:
      self.log(self.logger.INFO, "got unknown command: %s" % line)
      return
    accepted, reason_id = self.allowed(key_id, command, is_replay, is_local)
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
      self.log(self.logger.DEBUG, "not authorized for '%s': %i" % (command, key_id))
    try:
      self.censordb.execute('INSERT INTO log (accepted, command_id, data, key_id, reason_id, comment, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)', \
        (accepted, command_id, data, key_id, reason_id, basicHTMLencode(comment), int(time.time())))
      self.sqlite_censor_conn.commit()
    except Exception as e:
      pass

  def handle_srnd_acl_mod(self, line):
    self.log(self.logger.DEBUG, "handle acl_mod: %s" % line)
    flags = '0'
    local_nick = ''
    row = line.split(" ", 3)[1:]
    key = row[0]
    if len(row) > 1: flags = row[1]
    if len(row) > 2: local_nick = row[2]
    try:
      if int(self.censordb.execute('SELECT count(key) FROM keys WHERE key = ?', (key,)).fetchone()[0]) == 0:
        self.log(self.logger.DEBUG, "handle acl_mod: new key")
        self.censordb.execute("INSERT INTO keys (key, local_name, flags) VALUES (?, ?, ?)", (key, local_nick, flags))
      else:
        self.censordb.execute("UPDATE keys SET local_name = ?, flags = ? WHERE key = ?", (local_nick, flags, key))
      self.sqlite_censor_conn.commit()
      self.allowed_cache = dict()
    except Exception as e:
      self.log(self.logger.WARNING, "could not handle srnd-acl-mod: %s, line = '%s'" % (e, line))
    return key, None

  def handle_postman_mod(self, line):
    self.log(self.logger.DEBUG, "handle postman-mod: %s" % line)
    userkey, base64_blob = line.split(" ", 2)[1:]
    try:
      local_name, allow, expires, logout = [base64.urlsafe_b64decode(x) for x in base64_blob.split(':')]
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
    if expires < current_time or expires - current_time > 3650 * 24 * 3600: expires = current_time
    if logout != '':
      logout = True

    try:
      if int(self.postmandb.execute('SELECT count(userkey) FROM userkey WHERE userkey = ?', (userkey,)).fetchone()[0]) == 0:
        self.log(self.logger.DEBUG, "handle postman-mod: new userkey")
        self.postmandb.execute("INSERT INTO userkey (userkey, local_name, allow, expires) VALUES (?, ?, ?, ?)", (userkey, local_name, allow, expires))
      else:
        self.postmandb.execute("UPDATE userkey SET local_name = ?, allow = ?, expires = ? WHERE userkey = ?", (local_name, allow, expires, userkey))
        if logout:
          self.postmandb.execute("UPDATE userkey SET cookie = ? WHERE userkey = ?", ('', userkey))
      self.postmandb_conn.commit()
    except Exception as e:
      self.log(self.logger.WARNING, "could not handle postman-mod: %s, line = '%s'" % (e, line))
    return userkey, None

  def handle_srnd_cmd(self, line):
    self.log(self.logger.DEBUG, "handle srnd-cmd: %s" % line)
    command, base64_blob = line.split(" ", 2)[1:]
    try:
      send, received, replayable = [base64.urlsafe_b64decode(x) for x in base64_blob.split(':')]
      send, received, replayable = int(send), int(received), int(replayable)
    except:
      self.log(self.logger.WARNING, 'handle srnd-cmd: get corrupted data for %s' % command)
      return command, None
    if send not in (-1, 0, 1) or received not in (-1, 0, 1) or replayable not in (0, 1):
      self.log(self.logger.WARNING, 'handle srnd-cmd: get invalid value for %s, send=%s, received=%s, replayable=%s' % (command, send, received, replayable))
      return command, None
    if command == 'handle-srnd-cmd':
      self.log(self.logger.WARNING, 'handle srnd-cmd: modifying self is not allowed. This maybe suicide!')
      return command, None

    try:
      if int(self.censordb.execute('SELECT count(command) FROM cmd_map WHERE command = ?', (command,)).fetchone()[0]) == 1:
        self.censordb.execute('UPDATE cmd_map SET send = ?, received = ?, replayable = ? WHERE command = ?', (send, received, replayable, command))
        self.sqlite_censor_conn.commit()
        self.command_cache = dict()
      else:
        self.log(self.logger.WARNING, "handle srnd-cmd: command %s not found or duplicated" % (command,))
    except Exception as e:
      self.log(self.logger.WARNING, "handle srnd-cmd: db not upgraded: %s, line = '%s'" % (e, line))
    return command, None

  def handle_delete(self, line, debug=False):
    command, message_id = line.split(" ", 1)
    self.log(self.logger.DEBUG, "should delete %s" % message_id)

    if os.path.exists(os.path.join("articles", "restored", message_id)):
      self.log(self.logger.DEBUG, "%s has been restored, ignoring delete" % message_id)
      return message_id, None
    if command == 'delete':
      row = self.overchandb.execute('SELECT parent from articles WHERE article_uid = ?', (message_id,)).fetchone()
      if row != None:
        if row[0] == '' or row[0] == message_id:
          self.log(self.logger.DEBUG, "article is a root post, deleting whole thread")
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
  print "[%s] %s" % ("censor", "this plugin can't run as standalone version.")
  args = dict()
  args['debug'] = 5
  args['SRNd'] = None
  tester = main("testthread", args)
  tester.start()
  for article in ("1", "<wxrfozvunv1384881163@web.overchan.deliciouscake.ano>"):
    tester.add_article(article)
  tester.add_article(("somefuckeduppublickey", "delete <foobar> #baz #bar # boo\nsomenonexistendcommand foo bar\noverchan-sticky <foobaaaar> 12345"), "httpd")
  tester.join()
  exit(0)
