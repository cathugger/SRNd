#!/usr/bin/python
import threading
import sqlite3
import os
import time
import random
import string
import sys
from hashlib import sha1

class dropper(threading.Thread):

  def log(self, loglevel, message):
    if loglevel >= self.loglevel:
      self.logger.log(self.name, message, loglevel)

  def __init__(self, **kwargs):
    threading.Thread.__init__(self)
    self.name = kwargs.get('thread_name', 'SRNd-dropper')
    self.loglevel = kwargs.get('debug', 2)
    self.socket = kwargs.get('listener', None)
    self.SRNd = kwargs.get('master', None)
    self.logger = kwargs.get('logger', None)
    if self.SRNd is None:
      raise Exception('[dropper] init error: value master is None')
    if self.logger is None:
      raise Exception('[dropper] init error: value logger is None')

    self.db_version = 2
    self.watching = os.path.join(os.getcwd(), "incoming")
    self.sqlite_conn = sqlite3.connect('dropper.db3')
    self.sqlite = self.sqlite_conn.cursor()

    self.sqlite_hasher_conn = sqlite3.connect('hashes.db3')
    self.sqlite_hasher = self.sqlite_hasher_conn.cursor()
    self.sqlite_hasher.execute('''CREATE TABLE IF NOT EXISTS article_hashes
               (message_id text PRIMARY KEY, message_id_hash text, sender_desthash text)''')
    try:
      self.sqlite_hasher.execute('ALTER TABLE article_hashes ADD COLUMN sender_desthash text DEFAULT ""')
    except:
      pass
    self.sqlite_hasher.execute('CREATE INDEX IF NOT EXISTS article_desthash_idx ON article_hashes(sender_desthash);')
    self.sqlite_hasher.execute('CREATE INDEX IF NOT EXISTS article_hash_idx ON article_hashes(message_id_hash);')
    self.sqlite_hasher_conn.commit()
    self.reqs = ['message-id', 'newsgroups', 'date', 'subject', 'from', 'path']
    try:
      db_version = int(self.sqlite.execute("SELECT value FROM config WHERE key = ?", ("db_version",)).fetchone()[0])
    except Exception as e:
      db_version = 0
      self.log(self.logger.ERROR, 'error while fetching db_version: {}'.format(e))
    if db_version < self.db_version:
      self.update_db(db_version)
    self.running = False

  def update_db(self, current_version):
    self.log(self.logger.INFO, 'should update db from version {}'.format(current_version))
    if current_version == 0:
      self.sqlite.execute("CREATE TABLE config (key text PRIMARY KEY, value text)")
      self.sqlite.execute('INSERT INTO config VALUES ("db_version","1")')

      self.sqlite.execute('''CREATE TABLE IF NOT EXISTS groups
                 (group_id INTEGER PRIMARY KEY AUTOINCREMENT, group_name text UNIQUE, lowest_id INTEGER, highest_id INTEGER, article_count INTEGER, flag text, group_added_at INTEGER, last_update INTEGER)''')
      self.sqlite.execute('''CREATE TABLE IF NOT EXISTS articles
                 (message_id text, group_id INTEGER, article_id INTEGER, received INTEGER, PRIMARY KEY (article_id, group_id))''')

      self.sqlite.execute('CREATE INDEX IF NOT EXISTS article_idx ON articles(message_id);')
      self.sqlite_conn.commit()
      current_version = 1
    if current_version == 1:
      self.sqlite.execute('CREATE TABLE article_path (id INTEGER PRIMARY KEY, src TEXT, dst TEXT, count INTEGER DEFAULT 0, UNIQUE(src, dst))')
      self.sqlite.execute('CREATE INDEX article_path_ab_idx ON article_path(src, dst)')
      self.sqlite.execute('UPDATE config SET value = "2" WHERE key = "db_version"')
      self.sqlite_conn.commit()
      current_version = 2

  def handler_progress_incoming(self, signum, frame):
    if not self.running: return
    if self.busy:
      self.retry = True
      return
    self.busy = True
    for item in os.listdir('incoming'):
      link = os.path.join('incoming', item)
      if os.path.isfile(link):
        self.log(self.logger.DEBUG, 'processing new article: {}'.format(link))
        fd = open(link, 'r')
        try:
          header, body_offset = self._read_header(fd)
          fd.close()
          self.validate(header)
          desthash, message_id, groups, compile_header, article_path = self.sanitize(header)
          self.__article_path_up(article_path)
        except Exception as e:
          fd.close()
          self.log(self.logger.WARNING, 'article is invalid. {}: {}'.format(item, e))
          os.rename(link, os.path.join('articles', 'invalid', item))
          continue
        if os.path.isfile(os.path.join('articles', message_id)):
          self.log(self.logger.WARNING, 'article is duplicate: {}, deleting.'.format(item))
          os.remove(link)
          continue
        elif os.path.isfile(os.path.join('articles', 'censored', message_id)):
          self.log(self.logger.ERROR, 'article is blacklisted: {}, deleting. this should not happen. at all.'.format(message_id))
          os.remove(link)
          continue
        elif self.loglevel < self.logger.WARNING:
          if int(self.sqlite.execute('SELECT count(message_id) FROM articles WHERE message_id = ?', (message_id,)).fetchone()[0]) != 0:
            self.log(self.logger.INFO, 'article \'{}\' was blacklisted and is moved back into incoming/. processing again'.format(message_id))
        self.write(desthash, message_id, groups, link, compile_header, body_offset)
        os.remove(link)
    self.busy = False
    if self.retry:
      self.retry = False
      self.handler_progress_incoming(None, None)

  @staticmethod
  def _read_header(fd):
    header = list()
    header_ok = False
    offset = 0
    for line in fd:
      if line == '\n':
        header_ok = True
        break
      else:
        offset += len(line)
        header.append(line)
    if offset < 12 or not header_ok:
      raise Exception('no header in article')
    elif offset == os.fstat(fd.fileno()).st_size:
      raise Exception('no body in article')
    return header, offset + 1

  def validate(self, article):
    # check for header / body part exists in message
    # check if newsgroup exists in message
    # read required headers into self.dict
    self.log(self.logger.DEBUG, 'validating article..')
    for index in xrange(0, len(article)):
      if article[index].lower().startswith('message-id:'):
        if '/' in article[index]:
          raise Exception('illegal message-id \'%s\': contains /' % article[index].rstrip())
      elif article[index].lower().startswith('from:'):
        # FIXME parse and validate from
        pass
      elif article[index].lower().startswith('newsgroups:'):
        if '/' in article[index]:
          raise Exception('illegal newsgroups \'%s\': contains /' % article[index].rstrip())
    return True

  def sanitize(self, article):
    # change required if necessary
    # don't read vars at all
    self.log(self.logger.DEBUG, 'sanitizing article..')
    found = dict()
    vals = dict()
    desthash = ''
    article_path = ''
    for req in self.reqs:
      found[req] = False
    # FIXME*3 read Path from config
    for index in xrange(0, len(article)):
      if article[index].lower().startswith('x-i2p-desthash: '):
        desthash = article[index].split(' ', 1)[1].strip()
      for key in self.reqs:
        if article[index].lower().startswith(key + ':'):
          if key == 'path':
            article_path = self.SRNd.instance_name + '!' + article[index].split(' ', 1)[1].strip()
            article[index] = 'Path: ' + self.SRNd.instance_name + '!' + article[index].split(' ', 1)[1]
          elif key == 'from':
            # FIXME parse and validate from
            pass
          found[key] = True
          vals[key] = article[index].split(' ', 1)[1][:-1]
          #print "key: " + key + " value: " + vals[key]

    additional_headers = list()
    for req in found:
      if not found[req]:
        self.log(self.logger.DEBUG, '{} missing'.format(req))
        if req == 'message-id':
          self.log(self.logger.VERBOSE, 'should generate message-id..')
          rnd = ''.join(random.choice(string.ascii_lowercase) for x in range(10))
          vals[req] = '<{}{}@POSTED_dropper.{}>'.format(rnd, int(time.time()), self.SRNd.instance_name)
          additional_headers.append('Message-ID: {0}'.format(vals[req]))
        elif req == 'newsgroups':
          vals[req] = list()
        elif req == 'date':
          self.log(self.logger.VERBOSE, 'should generate date..')
          #additional_headers.append('Date: {0}'.format(date format blah blah)
          # FIXME add current date in list, index 0 ?
        elif req == 'subject':
          self.log(self.logger.VERBOSE, 'should generate subject..')
          additional_headers.append('Subject: None')
        elif req == 'from':
          self.log(self.logger.VERBOSE, 'should generate sender..')
          additional_headers.append('From: Anonymous Coward <nobody@no.where>')
        elif req == 'path':
          self.log(self.logger.VERBOSE, 'should generate path..')
          additional_headers.append('Path: ' + self.SRNd.instance_name)
      else:
        if req == 'newsgroups':
          vals[req] = vals[req].split(',')
    if len(vals['newsgroups']) == 0:
      raise Exception('Newsgroup is missing or empty')
    if len(additional_headers) > 0:
      additional_headers.append('')
    compile_header = ''.join(('\n'.join(additional_headers), ''.join(article), '\n'))
    return desthash, vals['message-id'], vals['newsgroups'], compile_header, article_path

  def write(self, desthash, message_id, groups, inc_link, compile_header, body_offset):
    link = os.path.join('articles', message_id)
    self.log(self.logger.DEBUG, 'writing article {}'.format(link))
    if os.path.exists(link):
      self.log(self.logger.ERROR, 'got duplicate: {} which is not in database, this should not happen.'.format(message_id))
      self.log(self.logger.ERROR, 'trying to fix by moving old file to articles/invalid so new article can be processed correctly.')
      os.rename(link, os.path.join('articles', 'invalid', message_id))
    with open(link, 'w') as o, open(inc_link, 'r') as i:
      o.write(compile_header)
      i.seek(body_offset)
      o.write(i.read())
    try:
      self.sqlite_hasher.execute('INSERT INTO article_hashes VALUES (?, ?, ?)', (message_id, sha1(message_id).hexdigest(), desthash))
      self.sqlite_hasher_conn.commit()
    except:
      pass
    for group in groups:
      self.log(self.logger.DEBUG, 'creating link for {}'.format(group))
      article_link = '../../' + link
      group_dir = os.path.join('groups', group)
      if not os.path.exists(group_dir):
        # FIXME don't rely on exists(group_dir) if directory is out of sync with database
        # TODO try to read article_id as well
        article_id = 1
        try: self.sqlite.execute('INSERT INTO groups VALUES (?, ?, ?, ?, ?, ?, ?, ?)', (None, group, 1, 1, 0, 'y', int(time.time()), int(time.time())))
        except: pass
        group_id = int(self.sqlite.execute('SELECT group_id FROM groups WHERE group_name = ?', (group,)).fetchone()[0])
        try: self.sqlite.execute('INSERT INTO articles VALUES (?, ?, ?, ?)', (message_id, group_id, article_id, int(time.time())))
        except: pass
        self.sqlite_conn.commit()
        self.log(self.logger.DEBUG, 'creating directory {}'.format(group_dir))
        os.mkdir(group_dir)
      else:
        # FIXME don't rely on exists(group_dir) if directory is out of sync with database
        try:
          group_id = int(self.sqlite.execute('SELECT group_id FROM groups WHERE group_name = ?', (group,)).fetchone()[0])
        except TypeError, e:
          if self.loglevel < self.logger.CRITICAL:
            self.log(self.logger.ERROR, 'unable to get group_id for group {}'.format(group))
            sys.exit(1)
        try:
          article_id = int(self.sqlite.execute('SELECT article_id FROM articles WHERE message_id = ? AND group_id = ?', (message_id, group_id)).fetchone()[0])
        except:
          article_id = int(self.sqlite.execute('SELECT highest_id FROM groups WHERE group_name = ?', (group,)).fetchone()[0]) + 1
          self.sqlite.execute('INSERT INTO articles VALUES (?, ?, ?, ?)', (message_id, group_id, article_id, int(time.time())))
          self.sqlite.execute('UPDATE groups SET highest_id = ?, article_count = article_count + 1, last_update = ? WHERE group_id = ?', (article_id, int(time.time()), group_id))
          self.sqlite_conn.commit()
      group_link = os.path.join(group_dir, str(article_id))
      try:
        os.symlink(article_link, group_link)
      except:
        # FIXME: except os.error as e; e.errno == 17 (file already exists). errno portable?
        target = os.path.basename(os.readlink(group_link))
        if target != message_id:
          self.log(self.logger.ERROR, 'found a strange group link which should point to "{}" but instead points to "{}". Won\'t overwrite this link.'.format(message_id, target))
      self.redistribute_command(group, message_id, article_link)

  def redistribute_command(self, group, message_id, article_link):
    # TODO add universal redistributor? Add SRNd queue? Currents methods thread-safe?
    for hook in self.SRNd.get_allow_hooks(group):
      if hook.startswith('plugin-'):
        if hook in self.SRNd.plugins:
          self.SRNd.plugins[hook].add_article(message_id)
        else:
          self.log(self.logger.ERROR, 'unknown plugin hook detected. wtf? {}'.format(hook))
      elif hook.startswith('outfeed-'):
        if hook in self.SRNd.feeds:
          self.SRNd.feeds[hook].add_article(message_id)
        else:
          self.log(self.logger.ERROR, 'unknown outfeed detected. wtf? {}'.format(hook))
      elif hook.startswith('filesystem-'):
        link = os.path.join('hooks', hook[11:], message_id)
        if not os.path.exists(link):
          os.symlink(article_link, link)
      else:
        self.log(self.logger.ERROR, 'unknown hook detected. wtf? {}'.format(hook))

  def __article_path_up(self, article_path):
    article_path = article_path.split('!')
    if len(article_path) < 2: return
    for src in range(len(article_path) - 1, 0, -1):
      dst = src - 1
      if len(article_path[src]) > 2 and len(article_path[dst]) > 2:
        self.sqlite.execute('INSERT OR IGNORE INTO article_path (src, dst) VALUES (?, ?)', (article_path[src], article_path[dst]))
        self.sqlite.execute('UPDATE article_path SET count = count + 1 WHERE src = ? AND dst = ?', (article_path[src], article_path[dst]))
    self.sqlite_conn.commit()

  def run(self):
    # only called from the outside via handler_progress_incoming()
    self.busy = False
    self.retry = False
    self.running = True
    while self.running:
      time.sleep(5)
    self.log(self.logger.INFO, 'bye')
