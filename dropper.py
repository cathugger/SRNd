#!/usr/bin/python
import threading
import os
import sqlite3
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
    self.SRNd = kwargs.get('master', None)
    self.logger = kwargs.get('logger', None)
    self.instance_name = kwargs.get('instance_name', 'SRNd')
    if self.SRNd is None:
      raise Exception('[dropper] init error: value master is None')
    if self.logger is None:
      raise Exception('[dropper] init error: value logger is None')
    self.reqs = ['message-id', 'newsgroups', 'date', 'subject', 'from', 'path', 'x-i2p-desthash']
    self.running = False
    self.watching = os.path.join(os.getcwd(), "incoming")
    self.DATABASE_VERSION = 2

    self.dropperdb = kwargs['db_connector']('dropper', timeout=20)
    self.hashesdb = kwargs['db_connector']('hashes')

    self.hashesdb.execute('''CREATE TABLE IF NOT EXISTS article_hashes
               (message_id text PRIMARY KEY, message_id_hash text, sender_desthash text)''')
    try:
      self.hashesdb.execute('ALTER TABLE article_hashes ADD COLUMN sender_desthash text DEFAULT ""')
    except sqlite3.OperationalError:
      pass
    self.hashesdb.execute('CREATE INDEX IF NOT EXISTS article_desthash_idx ON article_hashes(sender_desthash);')
    self.hashesdb.execute('CREATE INDEX IF NOT EXISTS article_hash_idx ON article_hashes(message_id_hash);')
    self.hashesdb.commit()
    self.update_dropperdb()

  def update_dropperdb(self):
    try:
      db_version = int(self.dropperdb.execute('SELECT value FROM config WHERE key = "db_version"').fetchone()[0])
    except sqlite3.OperationalError as e:
      db_version = 0
      self.log(self.logger.DEBUG, 'error while fetching db_version: {}. assuming new database'.format(e))
    if db_version < self.DATABASE_VERSION:
      self.log(self.logger.INFO, 'should update db from version {}'.format(db_version))
      while db_version < self.DATABASE_VERSION:
        self.log(self.logger.INFO, 'updating db from version {} to version {}'.format(db_version, db_version + 1))
        self._update_db_from(db_version)
        db_version += 1
        self.dropperdb.execute('UPDATE config SET value = ? WHERE key = "db_version"', (db_version,))
        self.dropperdb.commit()

  def _update_db_from(self, version):
    if version == 0:
      self.dropperdb.execute("CREATE TABLE config (key text PRIMARY KEY, value text)")
      self.dropperdb.execute('INSERT INTO config VALUES ("db_version","0")')
      self.dropperdb.execute('''CREATE TABLE IF NOT EXISTS groups
                 (group_id INTEGER PRIMARY KEY AUTOINCREMENT, group_name text UNIQUE, lowest_id INTEGER, highest_id INTEGER, article_count INTEGER, flag text, group_added_at INTEGER, last_update INTEGER)''')
      self.dropperdb.execute('''CREATE TABLE IF NOT EXISTS articles
                 (message_id text, group_id INTEGER, article_id INTEGER, received INTEGER, PRIMARY KEY (article_id, group_id))''')
      self.dropperdb.execute('CREATE INDEX IF NOT EXISTS article_idx ON articles(message_id);')
    elif version == 1:
      self.dropperdb.execute('CREATE TABLE article_path (id INTEGER PRIMARY KEY, src TEXT, dst TEXT, count INTEGER DEFAULT 0, UNIQUE(src, dst))')
      self.dropperdb.execute('CREATE INDEX article_path_ab_idx ON article_path(src, dst)')
    else:
      raise Exception('Handler for update from {} version not present in code. Fix it!'.format(version))

  def handler_progress_incoming(self, signum, frame):
    self.retry = self.busy
    if self.retry or not self.running:
      return
    self.busy = True
    for item in os.listdir('incoming'):
      if not self.running:
        break
      link = os.path.join('incoming', item)
      if os.path.isfile(link):
        self.log(self.logger.DEBUG, 'processing new article: {}'.format(link))
        fd = open(link, 'r')
        try:
          desthash, message_id, groups, compile_header, article_path = self.sanitize(fd)
        except Exception as e:
          fd.close()
          self.log(self.logger.WARNING, 'article is invalid. {}: {}'.format(item, e))
          os.rename(link, os.path.join('articles', 'invalid', item))
          continue
        else:
          if os.path.isfile(os.path.join('articles', message_id)):
            fd.close()
            self.log(self.logger.WARNING, 'article is duplicate: {}, deleting.'.format(item))
            os.remove(link)
            continue
          elif os.path.isfile(os.path.join('articles', 'censored', message_id)):
            fd.close()
            self.log(self.logger.ERROR, 'article is blacklisted: {}, deleting. this should not happen. at all.'.format(message_id))
            os.remove(link)
            continue
          elif self.loglevel < self.logger.WARNING:
            if int(self.dropperdb.execute('SELECT count(message_id) FROM articles WHERE message_id = ?', (message_id,)).fetchone()[0]) != 0:
              self.log(self.logger.INFO, 'article \'{}\' was blacklisted and is moved back into incoming/. processing again'.format(message_id))
        self._article_path_up(article_path)
        self.write_article(message_id, compile_header, fd)
        fd.close()
        os.remove(link)
        self.data_update(message_id, groups, desthash)
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
    return header

  def sanitize(self, fd):
    # change required if necessary
    # don't read vars at all
    header = self._read_header(fd)
    self.log(self.logger.DEBUG, 'sanitizing article..')
    found = {req: False for req in self.reqs}
    vals = dict()
    desthash = ''
    article_path = ''
    # FIXME*3 read Path from config
    for index in xrange(0, len(header)):
      for key in self.reqs:
        if header[index].lower().startswith(key + ':'):
          if key == 'path':
            article_path = ''.join((self.instance_name, '!', header[index].split(' ', 1)[1].strip()))
            header[index] = ''.join(('Path: ', article_path, '\n'))
          elif key == 'x-i2p-desthash':
            desthash = header[index].split(' ', 1)[1].strip()
          elif key == 'from':
            # FIXME parse and validate from
            pass
          found[key] = True
          vals[key] = header[index].split(' ', 1)[1][:-1]

    additional_headers = list()
    for req in found:
      if not found[req]:
        self.log(self.logger.DEBUG, '{} missing'.format(req))
        if req == 'message-id':
          self.log(self.logger.VERBOSE, 'should generate message-id..')
          rnd = ''.join(random.choice(string.ascii_lowercase) for x in range(10))
          vals[req] = '<{}{}@POSTED_dropper.{}>'.format(rnd, int(time.time()), self.instance_name)
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
          additional_headers.append('Path: ' + self.instance_name)
      else:
        if req == 'newsgroups':
          if '/' in vals[req]:
            raise Exception('illegal newsgroups \'%s\': contains /' % vals[req])
          vals[req] = vals[req].split(',')
        elif req == 'message-id' and '/' in vals[req]:
          raise Exception('illegal message-id \'%s\': contains /' % vals[req])
    if len(vals['newsgroups']) == 0:
      raise Exception('Newsgroup is missing or empty')
    if len(additional_headers) > 0:
      additional_headers.append('')
    compile_header = ''.join(('\n'.join(additional_headers), ''.join(header), '\n'))
    return desthash, vals['message-id'], vals['newsgroups'], compile_header, article_path

  def write_article(self, message_id, compile_header, fd_article):
    link = os.path.join('articles', message_id)
    self.log(self.logger.DEBUG, 'writing article {}'.format(link))
    if os.path.exists(link):
      self.log(self.logger.ERROR, 'got duplicate: {} which is not in database, this should not happen.'.format(message_id))
      self.log(self.logger.ERROR, 'trying to fix by moving old file to articles/invalid so new article can be processed correctly.')
      os.rename(link, os.path.join('articles', 'invalid', message_id))
    with open(link, 'w') as o:
      o.write(compile_header)
      for body_line in fd_article:
        o.write(body_line)

  def data_update(self, message_id, groups, desthash):
    self.hashesdb.execute('INSERT OR IGNORE INTO article_hashes VALUES (?, ?, ?)', (message_id, sha1(message_id).hexdigest(), desthash))
    self.hashesdb.commit()

    current_time = int(time.time())
    for group in groups:
      self.log(self.logger.DEBUG, 'creating link for {}'.format(group))
      group_dir = os.path.join('groups', group)
      if not os.path.exists(group_dir):
        # FIXME don't rely on exists(group_dir) if directory is out of sync with database
        # TODO try to read article_id as well
        article_id = 1
        self.dropperdb.execute('INSERT OR IGNORE INTO groups VALUES (?, ?, ?, ?, ?, ?, ?, ?)', (None, group, 1, 1, 0, 'y', current_time, current_time))
        group_id = int(self.dropperdb.execute('SELECT group_id FROM groups WHERE group_name = ?', (group,)).fetchone()[0])
        self.dropperdb.execute('INSERT OR IGNORE INTO articles VALUES (?, ?, ?, ?)', (message_id, group_id, article_id, current_time))
        self.log(self.logger.DEBUG, 'creating directory {}'.format(group_dir))
        os.mkdir(group_dir)
      else:
        # FIXME don't rely on exists(group_dir) if directory is out of sync with database
        try:
          group_id = int(self.dropperdb.execute('SELECT group_id FROM groups WHERE group_name = ?', (group,)).fetchone()[0])
        except TypeError:
          if self.loglevel < self.logger.CRITICAL:
            self.log(self.logger.ERROR, 'unable to get group_id for group {}'.format(group))
            sys.exit(1)
        article_id = self.dropperdb.execute('SELECT article_id FROM articles WHERE message_id = ? AND group_id = ?', (message_id, group_id)).fetchone()
        if article_id is None:
          article_id = int(self.dropperdb.execute('SELECT highest_id FROM groups WHERE group_name = ?', (group,)).fetchone()[0]) + 1
          self.dropperdb.execute('INSERT INTO articles VALUES (?, ?, ?, ?)', (message_id, group_id, article_id, current_time))
          self.dropperdb.execute('UPDATE groups SET highest_id = ?, article_count = article_count + 1, last_update = ? WHERE group_id = ?', (article_id, current_time, group_id))
        else:
          article_id = article_id[0]
      self.dropperdb.commit()

      article_link = '../../' + os.path.join('articles', message_id)
      group_link = os.path.join(group_dir, str(article_id))
      try:
        os.symlink(article_link, group_link)
      except OSError as e:
        if e.errno == 17: # OSError: [Errno 17] File exists
          target = os.path.basename(os.readlink(group_link))
          if target != message_id:
            self.log(self.logger.ERROR, 'found a strange group link which should point to "{}" but instead points to "{}". Won\'t overwrite this link.'.format(message_id, target))
        else:
          self.log(self.logger.ERROR, 'unhandled error when create symlink ({} -> {}): {}'.format(article_link, group_link, e))
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

  def _article_path_up(self, article_path):
    article_path = article_path.split('!')
    if len(article_path) < 2:
      return
    for src in range(len(article_path) - 1, 0, -1):
      dst = src - 1
      if len(article_path[src]) > 2 and len(article_path[dst]) > 2:
        self.dropperdb.execute('INSERT OR IGNORE INTO article_path (src, dst) VALUES (?, ?)', (article_path[src], article_path[dst]))
        self.dropperdb.execute('UPDATE article_path SET count = count + 1 WHERE src = ? AND dst = ?', (article_path[src], article_path[dst]))

  def run(self):
    # only called from the outside via handler_progress_incoming()
    self.busy = False
    self.retry = False
    self.running = True
    while self.running:
      time.sleep(5)
    self.log(self.logger.INFO, 'bye')
