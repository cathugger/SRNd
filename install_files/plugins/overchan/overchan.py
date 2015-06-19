#!/usr/bin/python
import base64
import codecs
import os
import sqlite3
import threading
import time
import traceback
import math
import mimetypes
mimetypes.init()
import Queue
from hashlib import sha1

import Image

from srnd.utils import basicHTMLencode, css_minifer, trydecode, valid_group_name, overchan_thread_unlink
from overchan_generator import OverchanGeneratorStatic
from overchan_markup import OverchanMarkup
from overchan_parser import MessageParser

try:
  import cv2
  cv2_load_result = 'true'
except ImportError as e:
  cv2_load_result = e

class main(threading.Thread):

  def log(self, loglevel, message):
    if loglevel >= self.config.get('debug', 2):
      self.logger.log(self.name, message, loglevel)

  def die(self, message):
    self.log(self.logger.CRITICAL, message)
    self.log(self.logger.CRITICAL, 'terminating..')
    self.should_terminate = True
    raise Exception(message)

  def __init__(self, thread_name, logger, args):
    threading.Thread.__init__(self)
    self.name = thread_name
    self.should_terminate = False
    self.logger = logger
    self.DATABASE_VERSION = 2

    self.config = dict()
    self._init_config(args)
    self.config['top_counter'] = self.config['top_step']

    error = ['{} not in arguments'.format(arg) for arg in ('template_directory', 'output_directory', 'temp_directory') if not arg in self.config]
    if len(error) > 0:
      self.die('\n'.join(error))

    if not os.path.exists(self.config['template_directory']):
      self.die('error: template directory \'{}\' does not exist'.format(self.config['template_directory']))

    error = ['{} file not found in {}'.format(x, os.path.join(self.config['template_directory'], x)) for x in self.config['csss'] + self.config['thumbs'].values() \
             if not os.path.exists(os.path.join(self.config['template_directory'], x))]
    if len(error) > 0:
      self.die('\n'.join(error))

    if cv2_load_result != 'true':
      self.log(self.logger.ERROR, '{}. Thumbnail for video will not be created. See http://docs.opencv.org/'.format(cv2_load_result))

    self.sync_on_startup = self.config['sync_on_startup']

    if not self.init_plugin():
      self.should_terminate = True
      return

  def _init_config(self, args, add_default=True):
    cfg_new = dict()
    cfg_def = {
        'sleep_threshold': 10,
        'sleep_time': 0.02,
        'debug': self.logger.INFO,
        'title': 'i.did.not.read.the.config',
        'site_url': 'my-address.i2p',
        'local_dest': 'i.did.not.read.the.config',
        'i2paddresshelper': True,
        'css_file': 'krane.css;user.css',
        'generate_all': True,
        'threads_per_page': 10,
        'pages_per_board': 10,
        'enable_archive': False,
        'enable_rollover': True,
        'enable_recent': True,
        'archive_threads_per_page': 500,
        'archive_pages_per_board': 20,
        'sqlite_synchronous': True,
        'sync_on_startup': True,
        'fake_id': False,
        'bump_limit' : 0,
        'censor_css': 'censor.css',
        'use_unsecure_aliases': False,
        'create_best_video_thumbnail': False,
        'minify_css': False,
        'minify_html': False,
        'replace_root_nope': False,
        'utc_time_offset': 0.0,
        'tz_name': 'UTC',
        'enable_top': False,
        'top_step': 10,
        'top_count': 100,
        'db_maintenance': 3,
        'thumb_maxwh': '180x360'
    }
    # (to self.config['thumbs'], from args, default)
    thumbnail_files = (('no_file', 'no_file', 'nope.png'), ('document', 'document_file', 'document.png'), ('invalid', 'invalid_file', 'invalid.png'), ('audio', 'audio_file', 'audio.png'), \
                       ('video', 'webm_file', 'video.png'), ('censored', 'censored_file', 'censored.png'), ('archive', 'archive_file', 'archive.png'), ('torrent', 'torrent_file', 'torrent.png'),)
    cfg_def.update(dict([[x[1], x[2]] for x in thumbnail_files]))
    for target in args:
      if target in cfg_def:
        try:
          if type(cfg_def[target]) is bool and args[target].lower() in ('false', 'no', '0', 'disable'):
            cfg_new[target] = False
          else:
            cfg_new[target] = type(cfg_def[target])(args[target])
        except ValueError:
          if add_default:
            self.log(self.logger.WARNING, 'Config error: #start_param {} {}, need {}. Use default value: {} '.format(target, type(args[target]), type(cfg_def[target]), cfg_def[target]))
          else:
            self.log(self.logger.WARNING, 'Config error: #start_param {} {}, need {}. Ignored'.format(target, type(args[target]), type(cfg_def[target])))
      else:
        cfg_new[target] = args[target]
    if add_default:
      cfg_new = dict(cfg_def.items() + cfg_new.items())

    # move thumbnails in cfg_new['thumbs']
    cfg_new['thumbs'] = dict([[target[0], cfg_new.pop(target[1])] for target in thumbnail_files if target[1] in cfg_new])
    if len(cfg_new['thumbs']) == 0 and not add_default:
      del cfg_new['thumbs']

    if 'utc_time_offset' in cfg_new:
      if not -15 < cfg_new['utc_time_offset'] < 15:
        self.log(self.logger.ERROR, 'Abnormal UTC offset {}, use 0.0'.format(cfg_new['utc_time_offset']))
        cfg_new['utc_time_offset'] = 0.0
      cfg_new['utc_time_offset'] = int(cfg_new['utc_time_offset'] * 3600)

    if 'tz_name' in cfg_new:
      cfg_new['datetime_format'] = '%d.%m.%Y (%a) %H:%M'
      if cfg_new['tz_name'] not in ('', '%'):
        cfg_new['datetime_format'] += ' ' + cfg_new['tz_name']
      del cfg_new['tz_name']

    if 'debug' in cfg_new and cfg_new['debug'] < 0 or cfg_new['debug'] > 5:
      cfg_new['debug'] = 2
      self.log(self.logger.WARNING, 'invalid value for debug, using default debug level of 2')

    if 'css_file' in cfg_new:
      cfg_new['csss'] = cfg_new.pop('css_file').split(';')
      # for compatibility
      if 'user.css' not in cfg_new['csss'] and len(cfg_new['csss']) == 1:
        cfg_new['csss'].append('user.css')

    w, _, h = cfg_new.get('thumb_maxwh', '180x360').partition('x')
    try:
      cfg_new['thumb_maxwh'] = (int(w), int(h))
    except ValueError:
      cfg_new['thumb_maxwh'] = None
    if cfg_new['thumb_maxwh'] is None or cfg_new['thumb_maxwh'][0] < 1 or cfg_new['thumb_maxwh'][1] < 1:
      self.log(self.logger.WARNING, 'Incorrect thumb_maxwh {}, use default (180, 360)'.format(cfg_new['thumb_maxwh']))
      cfg_new['thumb_maxwh'] = (180, 360)

    self.config.update(cfg_new)

  def init_plugin(self):
    self.log(self.logger.INFO, 'initializing as plugin..')
    try:
      # load required imports for PIL
      something = Image.open(os.path.join(self.config['template_directory'], self.config['thumbs']['no_file']))
      modifier = float(180) / something.size[0]
      x = int(something.size[0] * modifier)
      y = int(something.size[1] * modifier)
      if something.mode == 'RGBA' or something.mode == 'LA':
        thumb_name = 'nope_loading_PIL.png'
      else:
        something = something.convert('RGB')
        thumb_name = 'nope_loading_PIL.jpg'
      something = something.resize((x, y), Image.ANTIALIAS)
      out = os.path.join(self.config['temp_directory'], thumb_name)
      something.save(out, optimize=True)
      del something
      os.remove(out)
    except IOError as e:
      self.die('error: can\'t load PIL library, err %s' %  e)
      return False
    self.queue = Queue.Queue()
    return True

  def gen_template_thumbs(self, sources):
    for source in sources:
      dest = os.path.join(self.config['output_directory'], 'thumbs')
      target = os.path.join(self.config['template_directory'], source)
      dest_link = os.path.join(self.config['output_directory'], 'thumbs', source)
      if not os.path.exists(dest_link):
        thumb_name, info = self._create_thumb(target, dest, source, True)
        if info is None:
          self.log(self.logger.ERROR, 'can\'t template thumb create %s. wtf?' % dest_link)
        else:
          self.sqlite.execute('INSERT OR REPLACE INTO thumb_info VALUES (?, ?, ?, ?)', (thumb_name, info[0], info[1], info[2]))
    self.sqlite.commit()

  def copy_out(self, sources, css=False):
    for source, target in sources:
      try:
        i = open(os.path.join(self.config['template_directory'], source), 'r')
        o = open(os.path.join(self.config['output_directory'], target), 'w')
        if css and self.config['minify_css']:
          read_css = i.read()
          old_size = len(read_css)
          read_css = css_minifer(read_css)
          new_size = len(read_css)
          if new_size > 0:
            diff = -int(float(old_size-new_size)/old_size * 100) if old_size > 0 else 0
            o.write(read_css)
            self.log(self.logger.INFO, 'Minify CSS {0}: old size={1}, new size={2}, difference={3}%'.format(source, old_size, new_size, diff))
        elif not css or os.fstat(i.fileno()).st_size > 0:
          o.write(i.read())
        o.close()
        i.close()
      except IOError as e:
        self.log(self.logger.ERROR, 'can\'t copy %s: %s' % (source, e))

  def past_init(self):
    required_dirs = list()
    required_dirs.append(self.config['output_directory'])
    required_dirs.append(os.path.join(self.config['output_directory'], '..', 'spamprotector'))
    required_dirs.append(os.path.join(self.config['output_directory'], 'img'))
    required_dirs.append(os.path.join(self.config['output_directory'], 'thumbs'))
    required_dirs.append(self.config['temp_directory'])
    for directory in required_dirs:
      if not os.path.exists(directory):
        os.mkdir(directory)
    del required_dirs
    # TODO use softlinks or at least cp instead
    # ^ hardlinks not gonna work because of remote filesystems
    # ^ softlinks not gonna work because of nginx chroot
    # ^ => cp
    self.dropperdb = self.config['db_connector']('dropper', timeout=60)
    self.censordb = self.config['db_connector']('censor', timeout=60)
    self.sqlite = self.config['db_connector']('overchan')
    if not self.config['sqlite_synchronous']:
      self.sqlite.execute("PRAGMA synchronous = OFF")
    self.update_overchandb()

    self.copy_out((
        (self.config['thumbs']['no_file'], os.path.join('img', self.config['thumbs']['no_file'])),
        (self.config['thumbs']['invalid'], os.path.join('img', self.config['thumbs']['invalid'])),
        ('suicide.txt', os.path.join('img', 'suicide.txt')),
        ('playbutton.png', os.path.join('img', 'playbutton.png'))
        ))
    self.copy_out(([(self.config['censor_css'], 'censor.css'),] + [(x, x if self.config['csss'][0] != x else 'styles.css') for x in self.config['csss']]), True)
    self.config['csss'][0] = 'styles.css'
    self.gen_template_thumbs(self.config['thumbs'].values())

    self.delete_messages = set()
    self.missing_parents = dict()
    self.cache = dict()
    self.cache['flags'] = dict()
    self.cache['moder_flags'] = dict()
    self.board_cache = dict()

    if self._need_db_maintenance():
      self._db_maintenance()

    self.cache_init()
    self.markup_parser = OverchanMarkup(overchandb=self.sqlite, dropperdb=self.dropperdb, fake_id=self.config['fake_id'], get_board_data=self.get_board_data)
    db_conns = {'overchandb': self.sqlite, 'dropperdb': self.dropperdb, 'censordb': self.censordb}
    board_cache_conns = {'get_board_list': self.get_board_list, 'get_board_data': self.get_board_data}
    self.overchan_generator = OverchanGeneratorStatic(db_conns=db_conns, log=self.log, logger=self.logger, config=self.config, cache=self.cache, board_cache_conns=board_cache_conns, markup_parser=self.markup_parser)
    self.genegate_first_start()
    if self.config['generate_all']:
      self.regenerate_all_html()

  def update_overchandb(self):
    try:
      db_version = int(self.sqlite.execute('SELECT value FROM config WHERE key = "db_version"').fetchone()[0])
    except (sqlite3.OperationalError, TypeError) as e:
      db_version = 0
      self.log(self.logger.DEBUG, 'error while fetching db_version: {}. assuming new database'.format(e))
    if db_version < self.DATABASE_VERSION:
      self.log(self.logger.INFO, 'should update db from version {}'.format(db_version))
      while db_version < self.DATABASE_VERSION:
        self.log(self.logger.INFO, 'updating db from version {} to version {}'.format(db_version, db_version + 1))
        self._update_db_from(db_version)
        db_version += 1
        self.sqlite.execute('UPDATE config SET value = ? WHERE key = "db_version"', (db_version,))
      self.sqlite.commit()

  def _update_db_from(self, version):
    if version == 0:
      # create configuration
      self.sqlite.execute('''CREATE TABLE IF NOT EXISTS config (key text PRIMARY KEY, value text)''')
      self.sqlite.execute('INSERT INTO config VALUES ("db_version","0")')
      try:
        self.sqlite.execute('INSERT INTO config VALUES ("db_maintenance","0")')
      except sqlite3.IntegrityError:
        pass

      self.sqlite.execute('''CREATE TABLE IF NOT EXISTS groups
                 (group_id INTEGER PRIMARY KEY AUTOINCREMENT, group_name text UNIQUE, article_count INTEGER, last_update INTEGER)''')
      self.sqlite.execute('''CREATE TABLE IF NOT EXISTS articles
                 (article_uid text, group_id INTEGER, sender text, email text, subject text, sent INTEGER, parent text, message text, imagename text, imagelink text, thumblink text, last_update INTEGER, public_key text, PRIMARY KEY (article_uid, group_id))''')

      self.sqlite.execute('''CREATE TABLE IF NOT EXISTS flags
                 (flag_id INTEGER PRIMARY KEY AUTOINCREMENT, flag_name text UNIQUE, flag text)''')

      insert_flags = (("blocked",      0b1),          ("hidden",      0b10),
                      ("no-overview",  0b100),        ("closed",      0b1000),
                      ("moder-thread", 0b10000),      ("moder-posts", 0b100000),
                      ("no-sync",      0b1000000),    ("spam-fix",    0b10000000),
                      ("no-archive",   0b100000000),  ("sage",        0b1000000000),
                      ("news",         0b10000000000),)
      for flag_name, flag in insert_flags:
        try:
          self.sqlite.execute('INSERT INTO flags (flag_name, flag) VALUES (?,?)', (flag_name, str(flag)))
        except sqlite3.IntegrityError:
          pass
      for alias in ('ph_name', 'ph_shortname', 'link', 'tag', 'description',):
        try:
          self.sqlite.execute('ALTER TABLE groups ADD COLUMN {0} text DEFAULT ""'.format(alias))
        except sqlite3.OperationalError:
          pass
      try:
        self.sqlite.execute('ALTER TABLE groups ADD COLUMN flags text DEFAULT "0"')
      except sqlite3.OperationalError:
        pass
      try:
        self.sqlite.execute('ALTER TABLE articles ADD COLUMN public_key text')
      except sqlite3.OperationalError:
        pass
      try:
        self.sqlite.execute('ALTER TABLE articles ADD COLUMN received INTEGER DEFAULT 0')
      except sqlite3.OperationalError:
        pass
      try:
        self.sqlite.execute('ALTER TABLE articles ADD COLUMN closed INTEGER DEFAULT 0')
      except sqlite3.OperationalError:
        pass
      try:
        self.sqlite.execute('ALTER TABLE articles ADD COLUMN sticky INTEGER DEFAULT 0')
      except sqlite3.OperationalError:
        pass
      try:
        self.sqlite.execute('ALTER TABLE articles ADD COLUMN article_hash text')
      except sqlite3.OperationalError:
        pass
      else:
        self.log(self.logger.WARNING, 'Starting db update...')
        try:
          for row in self.sqlite.execute('SELECT article_uid FROM articles').fetchall():
            article_hash = sha1(row[0]).hexdigest()
            self.sqlite.execute('UPDATE articles SET article_hash = ? WHERE article_uid = ?', (article_hash, row[0]))
            self.sqlite.commit()
        except sqlite3.Error as e:
          self.die('DB update status - FAIL. You must fix this error manually. In case this is the first time you are starting SRNd - ignore and restart SRNd. See overchan.py:562 for details. Error: {}'.format(e))
        else:
          self.log(self.logger.WARNING, 'DB update status - OK.')
      self.sqlite.execute('CREATE INDEX IF NOT EXISTS articles_group_idx ON articles(group_id);')
      self.sqlite.execute('CREATE INDEX IF NOT EXISTS articles_parent_idx ON articles(parent);')
      self.sqlite.execute('CREATE INDEX IF NOT EXISTS articles_article_idx ON articles(article_uid);')
      self.sqlite.execute('CREATE INDEX IF NOT EXISTS articles_last_update_idx ON articles(group_id, parent, last_update);')
      self.sqlite.execute('CREATE INDEX IF NOT EXISTS articles_article_hash_idx ON articles(article_hash);')
    elif version == 1:
      self.sqlite.execute('CREATE TABLE thumb_info (name TEXT PRIMARY KEY, x INTEGER, y INTEGER, size INTEGER)')
    else:
      raise Exception('Handler for update from {} version not present in code. Fix it!'.format(version))

  def regenerate_all_html(self):
    for group_row in self.sqlite.execute('SELECT group_id FROM groups WHERE (cast(groups.flags as integer) & ?) = 0', (self.cache['flags']['blocked'],)).fetchall():
      self.overchan_generator.regenerate_boards.add(group_row[0])
    for thread_row in self.sqlite.execute('SELECT article_uid FROM articles WHERE parent = "" OR parent = article_uid ORDER BY last_update DESC').fetchall():
      self.overchan_generator.regenerate_threads.add(thread_row[0])

  def genegate_first_start(self):
    for name, data in self.overchan_generator.generate_first_start():
      self._save_to_disk(name, data)

  def _save_to_disk(self, name, data):
    path = os.path.join(self.config['output_directory'], '.'.join((name, 'html')))
    with codecs.open(path, 'w', 'UTF-8') as f:
      f.write(data)

  def _need_db_maintenance(self):
    result = self.sqlite.execute('SELECT value FROM config WHERE key = "db_maintenance"').fetchone()
    try:
      result = int(result[0])
    except ValueError:
      self.log(self.logger.ERROR, 'Strange value in db_maintenance getting from config table: FIX IT!')
      return False
    if result >= self.config['db_maintenance']:
      self.sqlite.execute('UPDATE config SET value = "0" WHERE key = "db_maintenance"')
      return True
    else:
      self.sqlite.execute('UPDATE config SET value = ? WHERE key = "db_maintenance"', (result + 1,))
      return False

  def _db_maintenance(self):
    self.log(self.logger.INFO, 'db maintenance: VACUUM and REINDEX')
    start_time = time.time()
    self.sqlite.execute('VACUUM;')
    self.sqlite.execute('REINDEX;')
    self.sqlite.commit()
    self.log(self.logger.INFO, 'db maintenance: Complit at {}s'.format(int(time.time() - start_time)))

  def shutdown(self):
    self.running = False

  def add_article(self, message_id, source="article", timestamp=None):
    self.queue.put((source, message_id, timestamp))

  def sticky_processing(self, message_id):
    result = self.sqlite.execute('SELECT sticky, group_id FROM articles WHERE article_uid = ? AND (parent = "" OR parent = article_uid)', (message_id,)).fetchone()
    if not result:
      return 'article not found'
    if result[0] == 1:
      sticky_flag = 0
      sticky_action = 'unsticky thread'
    else:
      sticky_flag = 1
      sticky_action = 'sticky thread'
    try:
      self.sqlite.execute('UPDATE articles SET sticky = ? WHERE article_uid = ? AND (parent = "" OR parent = article_uid)', (sticky_flag, message_id))
      self.sqlite.commit()
    except sqlite3.Error:
      return 'Fail time update'
    self.overchan_generator.regenerate_boards.add(result[1])
    self.overchan_generator.regenerate_threads.add(message_id)
    return sticky_action

  def close_processing(self, message_id):
    result = self.sqlite.execute('SELECT closed, group_id FROM articles WHERE article_uid = ? AND (parent = "" OR parent = article_uid)', (message_id,)).fetchone()
    if not result:
      return 'article not found'
    if result[0] == 0:
      close_status = 1
      close_action = 'close thread'
    else:
      close_status = 0
      close_action = 'open thread'
    try:
      self.sqlite.execute('UPDATE articles SET closed = ? WHERE article_uid = ? AND (parent = "" OR parent = article_uid)', (close_status, message_id))
      self.sqlite.commit()
    except sqlite3.Error:
      return 'Fail db update'
    self.overchan_generator.regenerate_boards.add(result[1])
    self.overchan_generator.regenerate_threads.add(message_id)
    return close_action

  def handle_overchan_massdelete(self):
    orphan_attach = set()
    for message_id in self.delete_messages:
      row = self.sqlite.execute("SELECT imagelink, thumblink, parent, group_id, received FROM articles WHERE article_uid = ?", (message_id,)).fetchone()
      if not row:
        self.log(self.logger.DEBUG, 'should delete message_id %s but there is no article matching this message_id' % message_id)
        continue
      if row[2] == '' or row[2] == message_id:
        # root post
        child_files = self.sqlite.execute("SELECT imagelink, thumblink FROM articles WHERE parent = ? AND article_uid != parent", (message_id,)).fetchall()
        if child_files and len(child_files[0]) > 0:
          orphan_attach.update(child_files)
          # root posts with child posts
          self.log(self.logger.INFO, 'deleting root message_id %s and %s childs' % (message_id, len(child_files[0])))
          # delete child posts
          self.sqlite.execute('DELETE FROM articles WHERE parent = ?', (message_id,))
        else:
          # root posts without child posts
          self.log(self.logger.INFO, 'deleting root message_id %s' % message_id)
        self.sqlite.execute('DELETE FROM articles WHERE article_uid = ?', (message_id,))
        for error_ in overchan_thread_unlink(self.config['output_directory'], 'thread-{}'.format(sha1(message_id).hexdigest()[:10])):
          self.log(self.logger.WARNING, 'could not delete thread for message_id %s, %s' % (message_id, error_))
      else:
        # child post and root not deleting
        if row[2] not in self.delete_messages:
          self.overchan_generator.regenerate_threads.add(row[2])
          # correct root post last_update
          all_child_time = self.sqlite.execute('SELECT article_uid, last_update FROM articles WHERE parent = ? AND last_update >= sent ORDER BY sent DESC LIMIT 2', (row[2],)).fetchall()
          childs_count = len(all_child_time)
          if childs_count > 0 and all_child_time[0][0] == message_id:
            parent_row = self.sqlite.execute('SELECT last_update, sent FROM articles WHERE article_uid = ?', (row[2],)).fetchone()
            if parent_row:
              new_last_update = parent_row[1] if childs_count == 1 else all_child_time[1][1]
              if parent_row[0] > new_last_update:
                self.sqlite.execute('UPDATE articles SET last_update = ? WHERE article_uid = ?', (new_last_update, row[2]))
        self.log(self.logger.INFO, 'deleting child message_id %s' % message_id)
        self.sqlite.execute('DELETE FROM articles WHERE article_uid = ?', (message_id,))
        # FIXME: add detection for parent == deleted message (not just censored) and if true, add to root_posts
      self.sqlite.commit()
      orphan_attach.add((row[0], row[1]))
      self.overchan_generator.regenerate_boards.add(row[3])
    self.delete_messages.clear()
    for child_image, child_thumb in orphan_attach:
      self.delete_orphan_attach(child_image, child_thumb)

  def delete_orphan_attach(self, image, thumb):
    image_link = os.path.join(self.config['output_directory'], 'img', image)
    thumb_link = os.path.join(self.config['output_directory'], 'thumbs', thumb)
    for imagename, imagepath, imagetype in ((image, image_link, 'imagelink'), (thumb, thumb_link, 'thumblink'),):
      if len(imagename) > 40 and os.path.exists(imagepath):
        caringbear = self.sqlite.execute('SELECT article_uid FROM articles WHERE %s = ?' % imagetype, (imagename,)).fetchone()
        if caringbear is not None:
          self.log(self.logger.INFO, 'not deleting %s, %s using it' % (imagename, caringbear[0]))
        else:
          self.log(self.logger.DEBUG, 'nobody not use %s, delete it' % (imagename,))
          if imagetype == 'thumblink':
            self.sqlite.execute('DELETE FROM thumb_info WHERE name = ?', (imagename,))
          try:
            os.unlink(imagepath)
          except OSError as e:
            self.log(self.logger.WARNING, 'could not delete %s: %s' % (imagepath, e))

  def censored_attach_processing(self, image, thumb):
    image_link = os.path.join(self.config['output_directory'], 'img', image)
    thumb_link = os.path.join(self.config['output_directory'], 'thumbs', thumb)
    for imagename, imagepath in ((image, image_link), (thumb, thumb_link),):
      if len(imagename) > 40 and os.path.exists(imagepath):
        os.unlink(imagepath)
        self.log(self.logger.INFO, 'censored and removed: %s' % (imagepath,))
      else:
        self.log(self.logger.DEBUG, 'incorrect filename %s, not delete %s' % (imagename, imagepath))
    if len(image) > 40:
      self.sqlite.execute('UPDATE articles SET thumblink = "censored" WHERE imagelink = ?', (image,))
      self.sqlite.commit()

  def overchan_board_add(self, args):
    group_name = args[0].lower()
    if not valid_group_name(group_name):
      self.log(self.logger.WARNING, 'got overchan-board-add with invalid group name: \'%s\', ignoring' % group_name)
      return
    try:
      flags = int(args[1]) if len(args) > 1 else 0
    except ValueError:
      flags = 0
    result = self.sqlite.execute("SELECT flags FROM groups WHERE group_name=?", (group_name,)).fetchone()
    if result is not None:
      if flags == 0:
        flags = int(result[0])
      flags ^= flags & self.cache['flags']['blocked']
      self.sqlite.execute('UPDATE groups SET flags = ? WHERE group_name = ?', (str(flags), group_name))
      self.log(self.logger.INFO, 'unblocked existing board: \'%s\'' % group_name)
    else:
      self.sqlite.execute('INSERT INTO groups(group_name, article_count, last_update, flags) VALUES (?,?,?,?)', (group_name, 0, int(time.time()), str(flags)))
      self.log(self.logger.INFO, 'added new board: \'%s\'' % group_name)
    if len(args) > 2:
      self.overchan_aliases_update(args[2], group_name)
    self.sqlite.commit()
    self.__flush_board_cache()
    self.regenerate_all_html()

  def overchan_board_del(self, group_name, flags=0):
    try:
      flags = int(flags)
    except ValueError:
      flags = 0
    result = self.sqlite.execute("SELECT flags FROM groups WHERE group_name=?", (group_name,)).fetchone()
    if result is not None:
      flags |= self.cache['flags']['blocked'] if flags == 0 else int(result[0]) | self.cache['flags']['blocked']
      self.sqlite.execute('UPDATE groups SET flags = ? WHERE group_name = ?', (str(flags), group_name))
      self.sqlite.commit()
      self.log(self.logger.INFO, 'blocked board: \'%s\'' % group_name)
      self.__flush_board_cache()
      self.regenerate_all_html()
    else:
      self.log(self.logger.WARNING, 'should delete board %s but there is no board with that name' % group_name)

  def overchan_aliases_update(self, base64_blob, group_name):
    try:
      ph_name, ph_shortname, link, tag, description = [base64.urlsafe_b64decode(x) for x in base64_blob.split(':')]
    except Exception as e:
      self.log(self.logger.WARNING, 'get corrupt data for {}: {}'.format(group_name, e))
      return
    ph_name = basicHTMLencode(ph_name)
    ph_shortname = basicHTMLencode(ph_shortname)
    self.sqlite.execute('UPDATE groups SET ph_name= ?, ph_shortname = ?, link = ?, tag = ?, description = ? \
        WHERE group_name = ?', (ph_name.decode('UTF-8')[:42], ph_shortname.decode('UTF-8')[:42], link.decode('UTF-8')[:1000], tag.decode('UTF-8')[:42], description.decode('UTF-8')[:25000], group_name))

  def handle_control(self, lines, timestamp):
    # FIXME how should board-add and board-del react on timestamps in the past / future
    self.log(self.logger.DEBUG, 'got control message: %s' % lines)
    for line in lines.split("\n"):
      self.log(self.logger.DEBUG, line)
      if line.lower().startswith('overchan-board-mod'):
        get_data = line.split(" ")[1:]
        group_name, flags = get_data[:2]
        flags = int(flags)
        group_id = self.sqlite.execute("SELECT group_id FROM groups WHERE group_name=?", (group_name,)).fetchone()
        group_id = group_id[0] if group_id else ''
        if group_id == '' or ((flags & self.cache['flags']['blocked']) == 0 and self.check_board_flags(group_id, 'blocked')):
          self.overchan_board_add((group_name, flags,))
        elif (flags & self.cache['flags']['blocked']) != 0 and not self.check_board_flags(group_id, 'blocked'):
          self.overchan_board_del(group_name, flags)
        else:
          self.sqlite.execute('UPDATE groups SET flags = ? WHERE group_name = ?', (flags, group_name))
          if len(get_data) > 2:
            self.overchan_aliases_update(get_data[2], group_name)
          self.sqlite.commit()
          self.__flush_board_cache(group_id)
          self.overchan_generator.regenerate_boards.add(group_id)
      elif line.lower().startswith('overchan-board-add'):
        self.overchan_board_add(line.split(" ")[1:])
      elif line.lower().startswith("overchan-board-del"):
        self.overchan_board_del(line.lower().split(" ")[1])
      elif line.lower().startswith("overchan-delete-attachment "):
        message_id = line.split(" ")[1]
        if os.path.exists(os.path.join("articles", "restored", message_id)):
          self.log(self.logger.DEBUG, 'message has been restored: %s. ignoring overchan-delete-attachment' % message_id)
          continue
        row = self.sqlite.execute("SELECT imagelink, thumblink, parent, group_id, received FROM articles WHERE article_uid = ?", (message_id,)).fetchone()
        if not row:
          self.log(self.logger.DEBUG, 'should delete attachments for message_id %s but there is no article matching this message_id' % message_id)
          continue
        if len(row[0]) <= 40:
          self.log(self.logger.WARNING, 'Attach for %s has incorrect file name %s. ignoring' % (message_id, row[0]))
          continue
        #if row[4] > timestamp:
        #  self.log("post more recent than control message. ignoring delete-attachment for %s" % message_id, 2)
        #  continue
        if row[1] == 'censored':
          self.log(self.logger.DEBUG, 'attachment already censored. ignoring delete-attachment for %s' % message_id)
          continue
        self.log(self.logger.INFO, 'deleting attachments for message_id %s' % message_id)
        self.censored_attach_processing(row[0], row[1])
        self.overchan_generator.regenerate_boards.add(row[3])
        if row[2] == '':
          self.overchan_generator.regenerate_threads.add(message_id)
        else:
          self.overchan_generator.regenerate_threads.add(row[2])
      elif line.lower().startswith("delete "):
        message_id = line.split(" ")[1]
        if os.path.exists(os.path.join("articles", "restored", message_id)):
          self.log(self.logger.DEBUG, 'message has been restored: %s. ignoring delete' % message_id)
        else:
          self.delete_messages.add(message_id)
      elif line.lower().startswith("overchan-expire "):
        self.delete_messages.add(line.split(" ")[1])
      elif line.lower().startswith("overchan-sticky "):
        message_id = line.split(" ")[1]
        self.log(self.logger.INFO, 'sticky processing message_id %s, %s' % (message_id, self.sticky_processing(message_id)))
      elif line.lower().startswith("overchan-close "):
        message_id = line.split(" ")[1]
        self.log(self.logger.INFO, 'closing thread processing message_id %s, %s' % (message_id, self.close_processing(message_id)))
      else:
        self.log(self.logger.WARNING, 'Get unknown commandline %s. FIXME!' % (line,))

  def run(self):
    if self.should_terminate:
      return
    self.log(self.logger.INFO, 'starting up as plugin..')
    self.running = True
    self.past_init()
    bump_db = False
    got_control_count = 0
    while self.running:
      try:
        ret = self.queue.get(block=True, timeout=1)
        if ret[0] == "article":
          message_id = ret[1]
          message_thumblink = self.sqlite.execute('SELECT thumblink FROM articles WHERE article_uid = ?', (message_id,)).fetchone()
          if message_thumblink and (message_thumblink[0] != 'censored' or not os.path.exists(os.path.join("articles", "restored", message_id))):
            self.log(self.logger.DEBUG, '%s already in database..' % message_id)
            continue
          self.log(self.logger.DEBUG, 'got article %s' % message_id)
          f = open(os.path.join('articles', message_id), 'r')
          bump_db |= self.parse_message(message_id, f)
        elif ret[0] == "control":
          got_control_count += 1
          self.handle_control(ret[1], ret[2])
          bump_db = True
        else:
          self.log(self.logger.ERROR, 'found article with unknown source: %s' % ret[0])

        if self.queue.qsize() > self.config['sleep_threshold']:
          time.sleep(self.config['sleep_time'])
      except Queue.Empty:
        if bump_db:
          self.sqlite.commit()
          bump_db = False
        if len(self.delete_messages) > 0:
          self.handle_overchan_massdelete()
        if self.overchan_generator.regenerate_boards or self.overchan_generator.regenerate_threads:
          for g_name, g_data in self.overchan_generator.generate_all():
            self._save_to_disk(g_name, g_data)
            if not self.running:
              break
        if got_control_count > 100:
          self.sqlite.execute('VACUUM;')
          self.sqlite.commit()
          got_control_count = 0
    self.censordb.close()
    self.sqlite.commit()
    self.sqlite.close()
    self.dropperdb.close()
    self.log(self.logger.INFO, 'bye')

  def move_bad_article(self, message_id, to_path=os.path.join('articles', 'censored')):
    if os.path.exists(os.path.join(to_path, message_id)):
      self.log(self.logger.DEBUG, "already move, still handing over to redistribute further")
    elif os.path.exists(os.path.join("articles", message_id)):
      self.log(self.logger.DEBUG, 'moving {} to {}/'.format(message_id, to_path))
      os.rename(os.path.join("articles", message_id), os.path.join(to_path, message_id))
      for row in self.dropperdb.execute('SELECT group_name, article_id from articles, groups WHERE message_id=? and groups.group_id = articles.group_id', (message_id,)).fetchall():
        self.log(self.logger.DEBUG, "deleting groups/%s/%i" % (row[0], row[1]))
        try:
          # FIXME race condition with dropper if currently processing this very article
          os.unlink(os.path.join("groups", str(row[0]), str(row[1])))
        except OSError as e:
          self.log(self.logger.WARNING, "could not delete %s: %s" % (os.path.join("groups", str(row[0]), str(row[1])), e))
    elif not os.path.exists(os.path.join(to_path, message_id)):
      f = open(os.path.join(to_path, message_id), 'w')
      f.close()
    return True

  def gen_thumb_from_video(self, target, imagehash):
    if os.path.getsize(target) == 0:
      return 'invalid'
    tmp_image = os.path.join(self.config['temp_directory'], imagehash + '.jpg')
    image_entropy = -1.1
    try:
      video_capture = cv2.VideoCapture(target)
      readable, video_frame = video_capture.read()
      fps = int(video_capture.get(cv2.cv.CV_CAP_PROP_FPS))
      if fps > 61:
        fps = 60
      if fps < 10:
        fps = 10
      video_length = int(video_capture.get(cv2.cv.CV_CAP_PROP_FRAME_COUNT) / fps)
      if video_length > 120:
        video_length = 120
      tmp_video_frame = video_frame
      current_frame = 0
      start_time = time.time()
      while self.config['create_best_video_thumbnail'] and readable and current_frame < video_length and time.time() - start_time < 30:
        histogram = cv2.calcHist(tmp_video_frame, [42], None, [256], [0, 256])
        histogram_length = sum(histogram)
        samples_probability = [float(h) / histogram_length for h in histogram]
        tmp_image_entropy = float(-sum([p * math.log(p, 2) for p in samples_probability if p != 0]))
        if tmp_image_entropy > image_entropy:
          video_frame = tmp_video_frame
          image_entropy = tmp_image_entropy
        current_frame += 1
        video_capture.set(cv2.cv.CV_CAP_PROP_POS_FRAMES, current_frame * fps - 1)
        readable, tmp_video_frame = video_capture.read()
      video_capture.release()
      cv2.imwrite(tmp_image, video_frame)
    except Exception as e:
      self.log(self.logger.WARNING, "error creating image from video %s: %s" % (target, e))
      thumb_data = ('video', None)
    else:
      thumb_data = self.gen_thumb(tmp_image, imagehash)
    try:
      os.remove(tmp_image)
    except OSError:
      pass
    return thumb_data
  
  def gen_thumb(self, target, imagehash):
    return self._create_thumb(target, os.path.join(self.config['output_directory'], 'thumbs'), imagehash)

  def _create_thumb(self, target, dest, name, full_name=False):
    """return thumb filename and update thumb_info table"""
    image_size = os.path.getsize(target)
    if not image_size:
      return 'invalid', None
    try:
      thumb = Image.open(target)
      modifierx = float(self.config['thumb_maxwh'][0]) / thumb.size[0]
      modifiery = float(self.config['thumb_maxwh'][1]) / thumb.size[1]
      modifier = modifierx if modifierx < modifiery else modifiery
      x = int(thumb.size[0] * modifier)
      y = int(thumb.size[1] * modifier)
      self.log(self.logger.DEBUG, 'old image size: %ix%i, new image size: %ix%i' %  (thumb.size[0], thumb.size[1], x, y))
      if os.path.splitext(target)[1].lower() == '.gif' and image_size < (128 * 1024 + 1):
        # small gif. copy is as
        thumb_name = name + '.gif' if not full_name else name
        thumb_link = os.path.join(dest, thumb_name)
        with open(thumb_link, 'w') as o, open(target, 'r') as i:
          o.write(i.read())
      else:
        if thumb.mode == 'P':
          thumb = thumb.convert('RGBA')
        if thumb.mode == 'RGBA' or thumb.mode == 'LA':
          thumb_name = name + '.png' if not full_name else name
        else:
          thumb_name = name + '.jpg' if not full_name else name
          thumb = thumb.convert('RGB')
        thumb_link = os.path.join(dest, thumb_name)
        thumb = thumb.resize((x, y), Image.ANTIALIAS)
        thumb.save(thumb_link, optimize=True)
    except Exception as e:
      self.log(self.logger.WARNING, 'error creating thumb from image {}: {}'.format(target, e))
      return 'invalid', None
    return thumb_name, (x, y, os.path.getsize(thumb_link))

  def _get_exist_thumb_name(self, image_name):
    result = self.sqlite.execute('SELECT thumblink FROM articles WHERE imagelink = ? LIMIT 1', (image_name,)).fetchone()
    if result and len(result[0]) > 40 and os.path.isfile(os.path.join(self.config['output_directory'], 'thumbs', result[0])):
      return result[0]
    return None

  def _attach_processing(self, data, message_id):
    image_name = data['hash'] + data['ext']
    image_name_original = data['name']
    thumb_info = None
    out_link = os.path.join(self.config['output_directory'], 'img', image_name)
    if os.path.isfile(out_link):
      exist_thumb_name = self._get_exist_thumb_name(image_name)
    else:
      exist_thumb_name = None
      with open(out_link, 'w') as f:
        f.write(data['obj'])
    if exist_thumb_name is not None:
      thumb_name = exist_thumb_name
    elif data['hash'] == 'da39a3ee5e6b4b0d3255bfef95601890afd80709':
      thumb_name, image_name = 'invalid', 'invalid'
    elif data['maintype'] == 'image':
      thumb_name, thumb_info = self.gen_thumb(out_link, data['hash'])
    elif data['type'] in ('application/pdf', 'application/postscript', 'application/ps'):
      thumb_name = 'document'
    elif data['type'] in ('audio/ogg', 'audio/mpeg', 'audio/mp3', 'audio/opus'):
      thumb_name = 'audio'
    elif data['maintype'] == 'video' and data['subtype'] in ('webm', 'mp4'):
      thumb_name, thumb_info = self.gen_thumb_from_video(out_link, data['hash']) if cv2_load_result == 'true' else ['video', None]
    elif data['maintype'] == 'application' and data['subtype'] == 'x-bittorrent':
      thumb_name = 'torrent'
    elif data['maintype'] == 'application' and data['subtype'] in ('x-7z-compressed', 'zip', 'x-gzip', 'x-tar', 'rar'):
      thumb_name = 'archive'
    else:
      self.log(self.logger.WARNING, 'Found unknown attach {} in {}. Mimetype local={}'.format(image_name_original, message_id, data['type']))
      if os.path.isfile(out_link):
        os.remove(out_link)
      image_name_original = 'fake.and.gay.txt'
      thumb_name = 'document'
      image_name = 'suicide.txt'
    if len(image_name) > 40 and self._is_censored_attach(message_id, image_name, thumb_name):
      thumb_name = 'censored'
    if thumb_info and len(thumb_name) > 41:
      self.sqlite.execute('INSERT OR REPLACE INTO thumb_info VALUES (?, ?, ?, ?)', (thumb_name, thumb_info[0], thumb_info[1], thumb_info[2]))
    return image_name, thumb_name, image_name_original

  def _is_censored_attach(self, message_id, image_name, thumb_name):
    censored_articles = self.sqlite.execute('SELECT article_uid FROM articles WHERE thumblink = "censored" AND imagelink = ?', (image_name,)).fetchall()
    censored_count = len(censored_articles)
    if censored_count > 0:
      attach_iscensored = None
      for check_article in censored_articles:
        if os.path.exists(os.path.join("articles", "censored", check_article[0])):
          attach_iscensored = check_article[0]
          break
      if attach_iscensored is not None:
        # attach has been censored and not restored. Censoring and this attach
        self.log(self.logger.INFO, 'Message %s contain attach censoring in %s message. %s has been continue censoring' % (message_id, attach_iscensored, image_name))
        censored_attach_path = os.path.join(self.config['output_directory'], 'img', image_name)
        if os.path.exists(censored_attach_path):
          os.remove(censored_attach_path)
        return True
      else:
        # attach has been censored and is now being restored. Restore all thumblink
        self.log(self.logger.INFO, 'Attach %s restored. Restore %s thumblinks for this attach' % (image_name, censored_count))
        self.sqlite.execute('UPDATE articles SET thumblink = ? WHERE imagelink = ?', (thumb_name, image_name))

  def _new_message_first_check(self, headers, group_flags, parent_result, message_id):
    if group_flags & self.cache['flags']['news'] and (not headers['parent'] or headers['parent'] == message_id) \
        and (headers['public_key'] == '' or not self.check_moder_flags(headers['public_key'], 'overchan-news-add')):
      self.log(self.logger.INFO, 'censored article {} to {} - flag news is present.'.format(message_id, headers['group_name']))
    elif group_flags & self.cache['flags']['blocked']:
      self.log(self.logger.INFO, 'censored article {} to {} - flag blocked is present.'.format(message_id, headers['group_name']))
    elif group_flags & self.cache['flags']['closed']:
      self.log(self.logger.INFO, 'censored article {} to {} - flag closed is present.'.format(message_id, headers['group_name']))
    elif group_flags & self.cache['flags']['moder-thread'] and (not headers['parent'] or headers['parent'] == message_id) \
        and (headers['public_key'] == '' or not self._get_moder_flags(headers['public_key'])):
      self.log(self.logger.INFO, 'censored article {} to {} - flag moder-thread is present.'.format(message_id, headers['group_name']))
    elif group_flags & self.cache['flags']['moder-posts'] and (headers['public_key'] == '' or not self._get_moder_flags(headers['public_key'])):
      self.log(self.logger.INFO, 'censored article {} to {} - flag moder-posts is present.'.format(message_id, headers['group_name']))
    elif parent_result and parent_result[0]:
      self.log(self.logger.INFO, 'censored article {} for closed thread.'.format(message_id))
    elif parent_result is None and headers['parent'] != message_id and os.path.isfile(os.path.join('articles', 'censored', headers['parent'])):
      # root post censored. Delete child post
      self.log(self.logger.INFO, 'Thread starting {} deleted. Delete a {}'.format(headers['parent'], message_id))
    else:
      return True

  def _new_message_second_check(self, headers, message, attachments, group_flags, message_id):
    if (not headers['subject'] or headers['subject'] == 'None') and (message == headers['public_key'] == '') and (headers['parent'] and headers['parent'] != message_id) \
        and (not headers['sender'] or headers['sender'] == 'Anonymous') and not attachments:
      self.log(self.logger.INFO, 'censored empty child message  %s' % message_id)
    elif group_flags & self.cache['flags']['spam-fix'] and len(message) < 5:
      self.log(self.logger.INFO, 'Spamprotect group %s, censored %s' % (headers['group_name'], message_id))
    else:
      return True

  def parse_message(self, message_id, fd):
    self.log(self.logger.INFO, 'new message: %s' % message_id)
    parse = MessageParser(fd)
    if not parse.headers:
      fd.close()
      to_path = os.path.join('articles', 'invalid')
      self.log(self.logger.WARNING, '{} malformed article: Header not found. Move in {}'.format(message_id, to_path))
      self.move_bad_article(message_id, to_path)
      return False
    if parse.signature_valid is True:
      self.log(self.logger.INFO, 'Found valid signature in {}'.format(message_id))
    elif parse.signature_valid is False:
      self.log(self.logger.WARNING, 'Found invalid signature in {}'.format(message_id))

    headers = parse.headers
    group_data = self.sqlite.execute("SELECT group_id, flags FROM groups WHERE group_name=?", (headers['group_name'],)).fetchone()
    if group_data is None:
      self.log(self.logger.WARNING, 'Message {} in nonexistent group {}'.format(message_id, headers['group_name']))
      group_flags = 0
      group_id = None
    else:
      group_flags = int(group_data[1])
      group_id = int(group_data[0])
    parent_result = None
    if headers['parent'] and headers['parent'] != message_id:
      parent_result = self.sqlite.execute('SELECT closed FROM articles WHERE article_uid = ?', (headers['parent'],)).fetchone()

    if not self._new_message_first_check(headers, group_flags, parent_result, message_id):
      fd.close()
      self.move_bad_article(message_id)
      return False

    parse.parse_body()
    fd.close()
    if not self._new_message_second_check(headers, parse.message, len(parse.attachments), group_flags, message_id):
      self.move_bad_article(message_id)
      return False

    if group_id is None:
      self.sqlite.execute('INSERT INTO groups(group_name, article_count, last_update) VALUES (?,?,?)', (headers['group_name'], 1, int(time.time())))
      self.__flush_board_cache()
      self.regenerate_all_html()
      group_id = int(self.sqlite.execute('SELECT group_id FROM groups WHERE group_name=?', (headers['group_name'],)).fetchone()[0])
    self.overchan_generator.regenerate_boards.add(group_id)

    if group_flags & self.cache['flags']['sage']:
      headers['sage'] = True

    if headers['parent'] and headers['parent'] != message_id:
      last_update = headers['sent']
      self.overchan_generator.regenerate_threads.add(headers['parent'])
      if headers['sage']:
        # sage mark
        last_update = headers['sent'] - 10
      else:
        if parent_result is not None:
          if self.config['bump_limit'] == 0 or self.sqlite.execute('SELECT count(article_uid) FROM articles WHERE parent = ? AND parent != article_uid ', (headers['parent'],)).fetchone()[0] < self.config['bump_limit']:
            self.sqlite.execute('UPDATE articles SET last_update=? WHERE article_uid=?', (headers['sent'], headers['parent']))
          else:
            last_update = headers['sent'] - 10
        else:
          self.log(self.logger.INFO, 'missing parent %s for post %s' %  (headers['parent'], message_id))
          if headers['parent'] in self.missing_parents:
            if headers['sent'] > self.missing_parents[headers['parent']]:
              self.missing_parents[headers['parent']] = headers['sent']
          else:
            self.missing_parents[headers['parent']] = headers['sent']
    else:
      # root post
      if not message_id in self.missing_parents:
        last_update = headers['sent']
      else:
        if self.missing_parents[message_id] > headers['sent']:
          # obviously the case. still we check for invalid dates here
          last_update = self.missing_parents[message_id]
        else:
          last_update = headers['sent']
        del self.missing_parents[message_id]
        self.log(self.logger.INFO, 'found a missing parent: %s' % message_id)
        if len(self.missing_parents) > 0:
          self.log(self.logger.INFO, 'still missing %i parents' % len(self.missing_parents))
      self.overchan_generator.regenerate_threads.add(message_id)

    if self.sqlite.execute('SELECT article_uid FROM articles WHERE article_uid=?', (message_id,)).fetchone():
      # post has been censored and is now being restored. just delete post for all groups so it can be reinserted
      self.log(self.logger.INFO, 'post has been censored and is now being restored: %s' % message_id)
      self.sqlite.execute('DELETE FROM articles WHERE article_uid=?', (message_id,))

    if parse.attachments:
      if len(parse.attachments) > 1:
        self.log(self.logger.WARNING, '{} contain {} attachments - use first only'.format(message_id, len(parse.attachments)))
      image_name, thumb_name, image_name_original = self._attach_processing(parse.attachments[0], message_id)
      del parse.attachments[:]
    else:
      image_name, thumb_name, image_name_original = '', '', ''

    if image_name == '' and thumb_name == '' and self.config['replace_root_nope'] and (headers['parent'] == '' or headers['parent'] == message_id):
      # Get random image for root post
      result = self.sqlite.fetchone('SELECT imagelink, thumblink FROM articles WHERE group_id = ? AND length(thumblink) > 40 AND imagename != "pic unrelated" ORDER BY RANDOM() LIMIT 1', (group_id,))
      if result:
        image_name, thumb_name = result
        image_name_original = 'pic unrelated'

    insert_list = [
        ('article_uid',  message_id),
        ('sender',       trydecode(headers['sender'])),
        ('email',        trydecode(headers['email'])),
        ('subject',      trydecode(headers['subject'])),
        ('sent',         headers['sent']),
        ('parent',       headers['parent']),
        ('message',      trydecode(parse.message)),
        ('imagename',    trydecode(image_name_original)),
        ('imagelink',    image_name),
        ('thumblink',    thumb_name),
        ('last_update',  last_update),
        ('public_key',   headers['public_key']),
        ('received',     int(time.time())),
        ('article_hash', sha1(message_id).hexdigest()),
        ('group_id',     'dummy')
    ]
    insert_request = 'INSERT INTO articles({}) VALUES ({})'.format(', '.join([x[0] for x in insert_list]), ','.join(['?'] * len(insert_list)))
    del insert_list[-1]
    self.sqlite.execute(insert_request, [x[1] for x in insert_list] + [group_id,])
    self.sqlite.execute('UPDATE groups SET last_update=?, article_count = (SELECT count(article_uid) FROM articles WHERE group_id = ?) WHERE group_id = ?', (int(time.time()), group_id, group_id))
    return True

  def check_board_flags(self, group_id, *args):
    flags = self.get_board_data(group_id, 'flags')
    for flag_name in args:
      if flags & self.cache['flags'][flag_name] == 0:
        return False
    return True

  def _get_moder_flags(self, pubkey):
    result = self.censordb.execute('SELECT flags from keys WHERE key=?', (pubkey,)).fetchone()
    return int(result[0]) if result else 0

  def check_moder_flags(self, full_pubkey_hex, *args):
    flags = self._get_moder_flags(full_pubkey_hex)
    for flag_name in args:
      if flags & self.cache['moder_flags'][flag_name] == 0:
        return False
    return True

  def cache_init(self):
    for row in self.sqlite.execute('SELECT flag_name, cast(flag as integer) FROM flags WHERE flag_name != ""').fetchall():
      self.cache['flags'][row[0]] = row[1]
    for row in self.censordb.execute('SELECT command, cast(flag as integer) FROM commands WHERE command != ""').fetchall():
      self.cache['moder_flags'][row[0]] = row[1]

  def __flush_board_cache(self, group_id=None):
    self.board_cache = dict()
    self.overchan_generator.flush_pagestamp_cache(group_id)

  def get_board_list(self, group_id='selflink'):
    if group_id not in self.board_cache:
      self.board_cache[group_id] = (self.__generate_board_list(group_id))
    return self.board_cache[group_id][0]

  def get_board_data(self, group_id, colname=None):
    if group_id not in self.board_cache:
      self.board_cache[group_id] = (self.__generate_board_list(group_id))
    if colname is None:
      return self.board_cache[group_id][1:-1]
    else:
      name_list = ('full_board', 'board_name_unquoted', 'board', 'board_description', 'flags')
      try:
        return self.board_cache[group_id][name_list.index(colname)+1]
      except IndexError:
        return 'None'

  def __generate_board_list(self, group_id='', selflink=False):
    full_board_name_unquoted, board_name_unquoted, board_name, board_description = '', '', '', ''
    flags = 0
    boardlist = list()
    exclude_flags = self.cache['flags']['hidden'] | self.cache['flags']['blocked']
    for group_row in self.sqlite.execute('SELECT group_name, group_id, ph_name, ph_shortname, link, description, flags FROM groups \
      WHERE ((cast(flags as integer) & ?) = 0 OR group_id = ?) ORDER by group_name ASC', (exclude_flags, group_id)).fetchall():
      current_group_name = group_row[0].split('.', 1)[-1].replace('"', '').replace('/', '')
      if group_row[3] != '':
        current_group_name_encoded = group_row[3]
      else:
        current_group_name_encoded = basicHTMLencode(current_group_name)
      if self.config['use_unsecure_aliases'] and group_row[4] != '':
        board_link = group_row[4]
      else:
        board_link = '%s-1.html' % current_group_name
      if group_row[1] != group_id or selflink:
        boardlist.append(u' <a href="{0}">{1}</a>&nbsp;/'.format(board_link, current_group_name_encoded))
      else:
        boardlist.append(' ' + current_group_name_encoded + '&nbsp;/')
      if group_row[1] == group_id:
        full_board_name_unquoted = group_row[0].replace('"', '').replace('/', '')
        full_board_name = basicHTMLencode(full_board_name_unquoted)
        board_name_unquoted = full_board_name_unquoted.split('.', 1)[-1]
        board_description = group_row[5]
        if group_row[2] != '':
          board_name = group_row[2]
        else:
          board_name = full_board_name.split('.', 1)[-1]
        flags = int(group_row[6])
    if not self.config['use_unsecure_aliases']:
      board_description = self.markup_parser.parse(basicHTMLencode(board_description))
    if boardlist:
      boardlist[-1] = boardlist[-1][:-1]
    return ''.join(boardlist), full_board_name_unquoted, board_name_unquoted, board_name, board_description, flags

if __name__ == '__main__':
  print "[%s] %s. %s" % ("overchan", "this plugin can't run as standalone version.", "bye")
