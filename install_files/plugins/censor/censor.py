#!/usr/bin/python

import os
import Queue
import sqlite3
import threading
import time
import traceback
from binascii import unhexlify
from calendar import timegm
from datetime import datetime, timedelta
from email.utils import parsedate_tz
from hashlib import sha512

import nacl.signing

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
    self.SRNd = args['SRNd']
    self.log(self.logger.DEBUG, 'initializing censor_httpd..')
    args['censor'] = self
    self.httpd = censor_httpd.censor_httpd("censor_httpd", self.logger, args)
    self.db_version = 6
    self.all_flags = "1023"
    self.queue = Queue.Queue()
    self.command_mapper = dict()
    self.command_mapper['delete'] = self.handle_delete
    self.command_mapper['overchan-delete-attachment'] = self.handle_delete
    self.command_mapper['overchan-sticky'] = self.handle_sticky
    self.command_mapper['overchan-close'] = self.handle_close
    self.command_mapper['srnd-acl-mod'] = self.handle_srnd_acl_mod
    self.command_mapper['overchan-board-add'] = self.handle_board_add
    self.command_mapper['overchan-board-del'] = self.handle_board_del
    self.command_mapper['overchan-board-mod'] = self.handle_overchan_board_mod

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
      #self.censordb.execute('INSERT INTO commands (command, flag) VALUES (?,?)', ("srnd-acl-add",      str(0b10000000)))
      #self.censordb.execute('INSERT INTO commands (command, flag) VALUES (?,?)', ("srnd-acl-del",      str(0b1000000000)))
      #self.censordb.execute('INSERT INTO commands (command, flag) VALUES (?,?)', ("testing",           str(0b1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000)))
      
      # create users
      self.censordb.execute("CREATE TABLE keys (id INTEGER PRIMARY KEY, key text UNIQUE, local_name text, flags text)")
      #self.censordb.execute("INSERT INTO keys VALUES (NULL,?,?,?)", ("a5bf837638d054ee15192a9886d107d326c8f84db8a1946db0635a98e446caf0", "talamon1", "1"))
      #self.censordb.execute("INSERT INTO keys VALUES (NULL,?,?,?)", ("909eee4034aa461819b72f97b0d84f95bab8a68547770119eef77b6b0c0cab9e", "talamon2", "1"))
      #self.censordb.execute("INSERT INTO keys VALUES (NULL,?,?,?)", ("dd10b55cff986c61d915a148011395dd7a52092d7e25f3c14f8856986c07cce5", "talamon3", "1"))
      
      
      
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
      #self.sqlite.execute('INSERT INTO groups(group_name, article_count, last_update) VALUES (?,?,?)', (group, 1, int(time.time())))
      #self.censordb.execute("CREATE TABLE IF NOT EXISTS config (key text PRIMARY KEY, value text)")
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

  def run(self):
    #if self.should_terminate:
    #  return
    self.log(self.logger.INFO, 'starting up as plugin..')
    self.sqlite_dropper_conn = sqlite3.connect('dropper.db3')
    self.dropperdb = self.sqlite_dropper_conn.cursor()
    self.sqlite_censor_conn = sqlite3.connect('censor.db3')
    self.censordb = self.sqlite_censor_conn.cursor()
    self.sqlite_overchan_conn = sqlite3.connect('plugins/overchan/overchan.db3')
    self.overchandb = self.sqlite_overchan_conn.cursor()
    self.allowed_cache = dict()
    self.key_cache = dict()
    self.command_cache = dict()
    self.httpd.start()
    try:
      db_version = int(self.censordb.execute("SELECT value FROM config WHERE key = ?", ("db_version",)).fetchone()[0])
      if db_version < self.db_version:
        self.update_db(db_version)
    except Exception as e:
      self.log(self.logger.DEBUG, "error while fetching db_version: %s. assuming new database" % e)
      self.update_db(0)
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
          self.process_article(data)
        elif source == "httpd":
          public_key, data = data
          key_id = self.get_key_id(public_key)
          timestamp = int(time.time())
          for line in data.split("\n"):
            self.handle_line(line, key_id, timestamp)
        else:
          self.log(self.logger.WARNING, 'unknown source: %s' % source)
        if self.queue.qsize() > self.sleep_threshold:
          time.sleep(self.sleep_time)
      except Queue.Empty as e:
        pass
    self.sqlite_censor_conn.close()
    self.sqlite_dropper_conn.close()
    self.log(self.logger.INFO, 'bye')
    
  def allowed(self, key_id, command="all", board=None):
    if key_id in self.allowed_cache:
      if command in self.allowed_cache[key_id]:
        return self.allowed_cache[key_id][command]
    else:
      if len(self.allowed_cache) > 256:
        self.allowed_cache = dict()
      self.allowed_cache[key_id] = dict()
    try:
      #self.log("should check flags for key_id %i" % key_id, 1)
      flags_available = int(self.censordb.execute("SELECT flags FROM keys WHERE id=?", (key_id,)).fetchone()[0])
      if command == "all":
        flag_required = self.all_flags
      else:
        flag_required = int(self.censordb.execute("SELECT flag FROM commands WHERE command=?", (command,)).fetchone()[0])
        self.allowed_cache[key_id][command] = (flags_available & flag_required) == flag_required
      return (flags_available & flag_required) == flag_required
    except Exception as e:
      self.log(self.logger.ERROR, 'unknown exception in allowed(): %s' % e)
      self.log(self.logger.ERROR, traceback.format_exc())
      return False
    
  def process_article(self, message_id):
    self.log(self.logger.DEBUG, "processing %s.." % message_id)
    try:
      valid = int(self.censordb.execute("SELECT valid FROM signature_cache WHERE message_uid = ?", (message_id,)).fetchone()[0])
      if not valid:
        return False
      f = open(os.path.join("articles", message_id), 'r')
      try:
        self.parse_article(f, message_id)
      except Exception as e:
        self.log(self.logger.WARNING, 'something went wrong while parsing %s: %s' % (message_id, e))
        f.close()
      return True
    except Exception as e:
      pass
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
      self.censordb.execute('INSERT INTO signature_cache (message_uid, valid) VALUES (?, ?)', (message_id, 1))
      self.sqlite_censor_conn.commit()
    except Exception as e:
      if self.loglevel < self.logger.INFO:
        self.log(self.logger.DEBUG, "could not verify signature: %s: %s" % (message_id, e))
      else:
        self.log(self.logger.INFO, "could not verify signature: %s" % message_id)
      f.close()
      self.censordb.execute('INSERT INTO signature_cache (message_uid, valid) VALUES (?, ?)', (message_id, 0))
      self.sqlite_censor_conn.commit()
      return False
    self.parse_article(f, message_id, self.get_key_id(public_key))
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
    #counter = 0
    #time_key_cache = float(0)
    #time_allowed_cache = float(0)
    #time_command_cache = float(0)
    #time_fs = float(0)
    #time_sql = float(0)
    #time_mapper = float(0)
    #time_mapper_sql = float(0)
    #time_total = time.time()
    self.log(self.logger.DEBUG, "parsing %s.." % message_id)
    if key_id == None:
      public_key = ''
      for line in article_fd:
        if len(line) == 1:
          break
        elif line.lower().startswith('x-pubkey-ed25519:'):
          public_key = line.lower()[:-1].split(' ', 1)[1]
      #timestamp_start = time.time()
      if public_key != '':
        key_id = self.get_key_id(public_key)
      #time_key_cache += time.time() - timestamp_start
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
    
    #self.handle_line(line[:-1], key_id, sent)
    #self.log("parsing %s, starting to parse commands" % message_id, 4)
    redistributors = dict()

    for line in article_fd:
      if len(line) == 1:
        continue
      line = line.split('\n')[0]
      command = line.lower().split(" ", 1)[0]
      if not command in self.command_mapper:
        self.log(self.logger.DEBUG, 'got unknown command: %s' % line)
        continue
      #counter += 1
      if '#' in line:
        line, comment = line.split("#", 1)
        line = line.rstrip(" ")
      else:
        comment = ''
      #timestamp_start = time.time()
      if self.allowed(key_id, command):
        #time_allowed_cache += time.time() - timestamp_start
        #timestamp_start = time.time()
        #data, groups, time_fs_tmp, time_mapper_sql_tmp = self.command_mapper[command](line, debug=True)
        data, groups = self.command_mapper[command](line)
        #time_fs += time_fs_tmp
        #time_mapper_sql += time_mapper_sql_tmp
        #time_mapper += time.time() - timestamp_start
        accepted = 1
        reason_id = 2
        if groups:
          for group in groups:
            if group in redistributors:
              redistributors[group].append(line)
              continue
            redistributors[group] = list()
            redistributors[group].append(line)
      else:
        #time_allowed_cache += time.time() - timestamp_start
        data = line.lower().split(" ", 1)[1]
        accepted = 0
        reason_id = 1
        self.log(self.logger.DEBUG, "not authorized for '%s': %i" % (command, key_id))
      #timestamp_start = time.time()  
      if command in self.command_cache:
        #time_command_cache += time.time() - timestamp_start
        command_id = self.command_cache[command]
      else: 
        #time_command_cache += time.time() - timestamp_start
        command_id = int(self.censordb.execute("SELECT id FROM commands WHERE command = ?", (command,)).fetchone()[0])
        self.command_cache[command] = command_id
      try:
        #timestamp_start = time.time()
        self.censordb.execute('INSERT INTO log (accepted, command_id, data, key_id, reason_id, comment, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)', (accepted, command_id, data, key_id, reason_id, comment, int(time.time())))
        self.sqlite_censor_conn.commit()
        #time_sql += time.time() - timestamp_start
      except Exception as e:
        #time_sql += time.time() - timestamp_start
        #self.log('inserting failed as expected: %s' % e, 4)
        pass
    article_fd.close()
    for group in redistributors:
      self.redistribute_command(group, '\n'.join(redistributors[group]), None, sent)
    #time_total = time.time() - time_total
    #if counter > 50:
    #  self.log("done parsing, commands: %i. mapper: %f, mapper_fs: %f, mapper_sql: %f, key_cache: %f, allowed_cache: %f, command_cache: %f, sql: %f, other: %f" % (counter, time_mapper, time_fs, time_mapper_sql, time_key_cache, time_allowed_cache, time_command_cache, time_sql, time_total - time_fs - time_mapper_sql - time_key_cache - time_allowed_cache - time_command_cache - time_sql), 1)

  def redistribute_command(self, group, line, comment, timestamp):
    # FIXME needs a hooks cache dict with key group => list hooks
    
    hooks = dict()
    # whitelist
    for group_item in self.SRNd.hooks:
      if (group_item[-1] == '*' and group.startswith(group_item[:-1])) or group == group_item:
        for hook in self.SRNd.hooks[group_item]:
          hooks[hook] = (line, timestamp)
    # blacklist
    for group_item in self.SRNd.hook_blacklist:
      if (group_item[-1] == '*' and group.startswith(group_item[:-1])) or group == group_item:
        for hook in self.SRNd.hook_blacklist[group_item]:
          if hook in hooks:
            del hooks[hook]

    # FIXME 1) crossposting may match multiple times and thus deliver same hook multiple times
    # FIXME 2) if doing this block after group loop blacklist may filter valid hook from another group
    # FIXME currently doing the second variant
    
    for hook in hooks:
      if hook.startswith('plugins-'):
        name = 'plugin-' + hook[8:]
        if name in self.SRNd.plugins:
          self.SRNd.plugins[name].add_article(hooks[hook][0], source="control", timestamp=hooks[hook][1])
        else:
          self.log(self.logger.ERROR, "unknown plugin hook detected. wtf? %s" % name)
      elif hook.startswith('outfeeds-'):
        continue
      else:
        self.log(self.logger.ERROR, "unknown hook detected. wtf? %s" % hook)
        
  def handle_line(self, line, key_id, timestamp):
    #print "should handle line for key_id %i: %s" % (key_id, line)
    command = line.lower().split(" ", 1)[0]
    if '#' in line:
      line, comment = line.split("#", 1)
      line = line.rstrip(" ")
    else:
      comment = '' 
    if not command in self.command_mapper:
      self.log(self.logger.INFO, "got unknown command: %s" % line)
      return
    if self.allowed(key_id, command):
      data, groups = self.command_mapper[command](line)
      accepted = 1
      reason_id = 2
      if groups:
        for group in groups:
          self.redistribute_command(group, line, comment, timestamp)
    else:
      data = line.lower().split(" ", 1)[1]
      accepted = 0
      reason_id = 1
      self.log(self.logger.DEBUG, "not authorized for '%s': %i" % (command, key_id))
    if command in self.command_cache:
      command_id = self.command_cache[command]
    else: 
      command_id = int(self.censordb.execute("SELECT id FROM commands WHERE command = ?", (command,)).fetchone()[0])
      self.command_cache[command] = command_id
    try:
      self.censordb.execute('INSERT INTO log (accepted, command_id, data, key_id, reason_id, comment, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)', (accepted, command_id, data, key_id, reason_id, comment, int(time.time())))
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
    return (key, None)

  def handle_delete(self, line, debug=False):
    command, message_id = line.split(" ", 1)
    self.log(self.logger.DEBUG, "should delete %s" % message_id)
    
    if os.path.exists(os.path.join("articles", "restored", message_id)):
      self.log(self.logger.DEBUG, "%s has been restored, ignoring delete" % message_id)
      return (message_id, None)
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
    if os.path.exists(censore_path):
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
    return (message_id, groups)

  def handle_board_add(self, line):
    # overchan specific, gets handled at overchan plugin via redistribute_command()
    group_name = line.lower().split(' ')[1]
    return (group_name, (group_name,))

  def handle_board_del(self, line):
    # overchan specific, gets handled at overchan plugin via redistribute_command()
    group_name = line.lower().split(' ')[1]
    return (group_name, (group_name,))

  def handle_overchan_board_mod(self, line):
    # overchan specific, gets handled at overchan plugin via redistribute_command()
    group_name = line.lower().split(' ')[1]
    return (group_name, (group_name,))

  def handle_sticky(self, line):
    message_id = line.split(' ')[1]
    groups = list()
    for row in self.overchandb.execute('SELECT groups.group_name from articles, groups WHERE articles.article_uid = ? and groups.group_id = articles.group_id', (message_id,)).fetchall():
      groups.append(row[0])
    return (message_id, groups)

  def handle_close(self, line):
    message_id = line.split(' ')[1]
    groups = list()
    for row in self.overchandb.execute('SELECT groups.group_name from articles, groups WHERE articles.article_uid = ? and groups.group_id = articles.group_id', (message_id,)).fetchall():
      groups.append(row[0])
    return (message_id, groups)

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
