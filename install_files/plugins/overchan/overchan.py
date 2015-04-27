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
from binascii import unhexlify
from calendar import timegm
from datetime import datetime, timedelta
from email.feedparser import FeedParser
from email.utils import parsedate_tz
from hashlib import sha1, sha512

import Image
import nacl.signing

from srnd.utils import basicHTMLencode, css_minifer, trydecode
from overchan_generator import OverchanGeneratorStatic
from overchan_markup import OverchanMarkup

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
        'enable_archive': True,
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
        'db_maintenance': 3
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
      out = os.path.join(self.config['template_directory'], thumb_name)
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
      link = os.path.join(self.config['output_directory'], 'thumbs', source)
      if not os.path.exists(link):
        try:
          something = Image.open(os.path.join(self.config['template_directory'], source))
          modifier = float(180) / something.size[0]
          x = int(something.size[0] * modifier)
          y = int(something.size[1] * modifier)
          if not (something.mode == 'RGBA' or something.mode == 'LA'):
            something = something.convert('RGB')
          something = something.resize((x, y), Image.ANTIALIAS)
          something.save(link, optimize=True)
          del something
        except IOError as e:
          self.log(self.logger.ERROR, 'can\'t thumb save %s. wtf? %s' % (link, e))

  def copy_out(self, css, sources):
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
    self.copy_out(css=False, sources=((self.config['thumbs']['no_file'], os.path.join('img', self.config['thumbs']['no_file'])), ('suicide.txt', os.path.join('img', 'suicide.txt')), \
      ('playbutton.png', os.path.join('img', 'playbutton.png')),))
    self.copy_out(css=True, sources=([(self.config['censor_css'], 'censor.css'),] + [(x, x if self.config['csss'][0] != x else 'styles.css') for x in self.config['csss']]))
    self.config['csss'][0] = 'styles.css'
    self.gen_template_thumbs(self.config['thumbs'].values())

    self.delete_messages = set()
    self.missing_parents = dict()
    self.cache = dict()
    self.cache['flags'] = dict()
    self.cache['moder_flags'] = dict()
    self.board_cache = dict()

    self.dropperdb = self.config['db_connector']('dropper', timeout=60)
    self.censordb = self.config['db_connector']('censor', timeout=60)
    self.sqlite = self.config['db_connector']('overchan')
    if not self.config['sqlite_synchronous']:
      self.sqlite.execute("PRAGMA synchronous = OFF")
    # FIXME use config table with current db version + def update_db(db_version) like in censor plugin
    self.sqlite.execute('''CREATE TABLE IF NOT EXISTS groups
               (group_id INTEGER PRIMARY KEY AUTOINCREMENT, group_name text UNIQUE, article_count INTEGER, last_update INTEGER)''')
    self.sqlite.execute('''CREATE TABLE IF NOT EXISTS articles
               (article_uid text, group_id INTEGER, sender text, email text, subject text, sent INTEGER, parent text, message text, imagename text, imagelink text, thumblink text, last_update INTEGER, public_key text, PRIMARY KEY (article_uid, group_id))''')
    self.sqlite.execute('''CREATE TABLE IF NOT EXISTS config (key text PRIMARY KEY, value text)''')
    try:
      self.sqlite.execute('INSERT INTO config VALUES ("db_maintenance","0")')
    except sqlite3.IntegrityError:
      pass

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
    db_maintenance = self._need_db_maintenance()
    self.sqlite.commit()

    if db_maintenance:
      self._db_maintenance()

    self.cache_init()

    self.markup_parser = OverchanMarkup(overchandb=self.sqlite, dropperdb=self.dropperdb, fake_id=self.config['fake_id'], get_board_data=self.get_board_data)

    db_conns = {'overchandb': self.sqlite, 'dropperdb': self.dropperdb, 'censordb': self.censordb}
    board_cache_conns = {'get_board_list': self.get_board_list, 'get_board_data': self.get_board_data}
    self.overchan_generator = OverchanGeneratorStatic(db_conns=db_conns, log=self.log, logger=self.logger, config=self.config, cache=self.cache, board_cache_conns=board_cache_conns, markup_parser=self.markup_parser)

    self.genegate_first_start()

    if self.config['generate_all']:
      self.regenerate_all_html()

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
    self.sqlite.commit()
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
        try:
          os.unlink(os.path.join(self.config['output_directory'], "thread-%s.html" % sha1(message_id).hexdigest()[:10]))
        except OSError as e:
          self.log(self.logger.WARNING, 'could not delete thread for message_id %s: %s' % (message_id, e))
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
    if '/' in group_name:
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
    self.past_init()
    self.running = True
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
          #message_id = self.queue.get(block=True, timeout=1)
          self.log(self.logger.DEBUG, 'got article %s' % message_id)
          f = open(os.path.join('articles', message_id), 'r')
          try:
            if not self.parse_message(message_id, f):
              f.close()
          except Exception as e:
            self.log(self.logger.WARNING, 'something went wrong while trying to parse article %s: %s' % (message_id, e))
            self.log(self.logger.WARNING, traceback.format_exc())
            try:
              f.close()
            except IOError:
              pass
        elif ret[0] == "control":
          got_control_count += 1
          self.handle_control(ret[1], ret[2])
          self.sqlite.commit()
        else:
          self.log(self.logger.ERROR, 'found article with unknown source: %s' % ret[0])

        if self.queue.qsize() > self.config['sleep_threshold']:
          time.sleep(self.config['sleep_time'])
      except Queue.Empty:
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
      thumbname = 'video'
    else:
      try:
        thumbname = self.gen_thumb(tmp_image, imagehash)
      except:
        thumbname = 'invalid'
    try:
      os.remove(tmp_image)
    except OSError:
      pass
    return thumbname

  def gen_thumb(self, target, imagehash):
    if os.path.getsize(target) == 0:
      return 'invalid'
    if target.split('.')[-1].lower() == 'gif' and os.path.getsize(target) < (128 * 1024 + 1):
      thumb_name = imagehash + '.gif'
      thumb_link = os.path.join(self.config['output_directory'], 'thumbs', thumb_name)
      o = open(thumb_link, 'w')
      i = open(target, 'r')
      o.write(i.read())
      o.close()
      i.close()
      return thumb_name
    thumb = Image.open(target)
    modifier = float(180) / thumb.size[0]
    x = int(thumb.size[0] * modifier)
    y = int(thumb.size[1] * modifier)
    self.log(self.logger.DEBUG, 'old image size: %ix%i, new image size: %ix%i' %  (thumb.size[0], thumb.size[1], x, y))
    if thumb.mode == 'P':
      thumb = thumb.convert('RGBA')
    if thumb.mode == 'RGBA' or thumb.mode == 'LA':
      thumb_name = imagehash + '.png'
    else:
      thumb_name = imagehash + '.jpg'
      thumb = thumb.convert('RGB')
    thumb_link = os.path.join(self.config['output_directory'], 'thumbs', thumb_name)
    thumb = thumb.resize((x, y), Image.ANTIALIAS)
    thumb.save(thumb_link, optimize=True)
    return thumb_name

  def _get_exist_thumb_name(self, image_name):
    result = self.sqlite.execute('SELECT thumblink FROM articles WHERE imagelink = ? LIMIT 1', (image_name,)).fetchone()
    if result and len(result[0]) > 40 and os.path.isfile(os.path.join(self.config['output_directory'], 'thumbs', result[0])):
      return result[0]
    return None

  def parse_message(self, message_id, fd):
    self.log(self.logger.INFO, 'new message: %s' % message_id)
    subject = 'None'
    sent = 0
    sender = 'Anonymous'
    email = 'nobody@no.where'
    parent = ''
    group_name = ''
    sage = False
    signature = None
    public_key = ''
    header_found = False
    parser = FeedParser()
    line = fd.readline()
    while line != '':
      parser.feed(line)
      lower_line = line.lower()
      if lower_line.startswith('subject:'):
        subject = line.split(' ', 1)[-1][:-1]
        subject = basicHTMLencode(subject[4:]) if subject.lower().startswith('re: ') else basicHTMLencode(subject)
      elif lower_line.startswith('date:'):
        sent = line.split(' ', 1)[1][:-1]
        sent_tz = parsedate_tz(sent)
        if sent_tz:
          offset = 0
          if sent_tz[-1]:
            offset = sent_tz[-1]
          sent = timegm((datetime(*sent_tz[:6]) - timedelta(seconds=offset)).timetuple())
        else:
          sent = int(time.time())
      elif lower_line.startswith('from:'):
        sender = basicHTMLencode(line.split(' ', 1)[1][:-1].split(' <', 1)[0])
        try:
          email = basicHTMLencode(line.split(' ', 1)[1][:-1].split(' <', 1)[1].replace('>', ''))
        except IndexError:
          pass
      elif lower_line.startswith('references:'):
        parent = line[:-1].split(' ')[1]
      elif lower_line.startswith('newsgroups:'):
        group_name = lower_line[:-1].partition(': ')[2].split(';')[0].split(',')[0]
      elif lower_line.startswith('x-sage:'):
        sage = True
      elif lower_line.startswith("x-pubkey-ed25519:"):
        public_key = lower_line[:-1].split(' ', 1)[1]
      elif lower_line.startswith("x-signature-ed25519-sha512:"):
        signature = lower_line[:-1].split(' ', 1)[1]
      elif line == '\n':
        header_found = True
        break
      line = fd.readline()

    if not header_found:
      fd.close()
      to_path = os.path.join('articles', 'invalid')
      self.log(self.logger.WARNING, '{} malformed article: Header not found. Move in {}'.format(message_id, to_path))
      return self.move_bad_article(message_id, to_path)
    if signature:
      if public_key != '':
        self.log(self.logger.DEBUG, 'got signature with length %i and content \'%s\'' % (len(signature), signature))
        self.log(self.logger.DEBUG, 'got public_key with length %i and content \'%s\'' % (len(public_key), public_key))
        if not (len(signature) == 128 and len(public_key) == 64):
          public_key = ''
    #parser = FeedParser()
    if public_key != '':
      bodyoffset = fd.tell()
      hasher = sha512()
      oldline = None
      for line in fd:
        if oldline:
          hasher.update(oldline)
        oldline = line.replace("\n", "\r\n")
      hasher.update(oldline.replace("\r\n", ""))
      fd.seek(bodyoffset)
      self.log(self.logger.INFO, 'trying to validate signature.. ')
      try:
        nacl.signing.VerifyKey(unhexlify(public_key)).verify(hasher.digest(), unhexlify(signature))
      except Exception as e:
        public_key = ''
        self.log(self.logger.INFO, 'failed: %s' % e)
      else:
        self.log(self.logger.INFO, 'validated')
      del hasher
      del signature
    parser.feed(fd.read())
    fd.close()
    result = parser.close()
    del parser
    image_name_original = ''
    image_name = ''
    thumb_name = ''
    message = ''
    if result.is_multipart():
      self.log(self.logger.DEBUG, 'message is multipart, length: %i' % len(result.get_payload()))
      if len(result.get_payload()) == 1 and result.get_payload()[0].get_content_type() == "multipart/mixed":
        result = result.get_payload()[0]
      for part in result.get_payload():
        self.log(self.logger.DEBUG, 'got part == %s' % part.get_content_type())

        if part.get_content_type() == 'text/plain':
          message += part.get_payload(decode=True)
          continue
        deny_extensions = ('.html', '.php', '.phtml', '.php3', '.php4', '.js')
        file_data = part.get_payload(decode=True)
        imagehash = sha1(file_data).hexdigest()
        image_name_original = 'empty_file_name.empty' if part.get_filename() is None or part.get_filename().strip() == '' else basicHTMLencode(part.get_filename().replace('/', '_').replace('"', '_'))
        image_extension = '.' + image_name_original.split('.')[-1].lower()
        if len(image_name_original) > 512:
          image_name_original = image_name_original[:512] + '...'
        local_mime_type = mimetypes.types_map.get(image_extension, '/')
        local_mime_maintype, local_mime_subtype = local_mime_type.split('/', 2)
        image_mime_types = mimetypes.guess_all_extensions(local_mime_type)
        image_name = imagehash + image_extension
        # empty attachment
        if imagehash == 'da39a3ee5e6b4b0d3255bfef95601890afd80709':
          thumb_name, image_name = 'invalid', 'invalid'
          del file_data
          continue
        # Bad file type, unknown or deny type found
        elif local_mime_type == '/' or len((set(image_extension) | set(image_mime_types)) & set(deny_extensions)) > 0:
          self.log(self.logger.WARNING, 'Found bad attach %s in %s. Mimetype local=%s, remote=%s' % (image_name_original, message_id, local_mime_type, part.get_content_type()))
          image_name_original = 'fake.and.gay.txt'
          thumb_name = 'document'
          image_name = 'suicide.txt'
          del file_data
          continue
        out_link = os.path.join(self.config['output_directory'], 'img', image_name)
        if os.path.isfile(out_link):
          exist_thumb_name = self._get_exist_thumb_name(image_name)
        else:
          exist_thumb_name = None
          f = open(out_link, 'w')
          f.write(file_data)
          f.close()
        del file_data
        if exist_thumb_name is not None:
          thumb_name = exist_thumb_name
        elif local_mime_maintype == 'image':
          try:
            thumb_name = self.gen_thumb(out_link, imagehash)
          except Exception as e:
            thumb_name = 'invalid'
            self.log(self.logger.WARNING, 'Error creating thumb in %s: %s' % (image_name, e))
        elif local_mime_type in ('application/pdf', 'application/postscript', 'application/ps'):
          thumb_name = 'document'
        elif local_mime_type in ('audio/ogg', 'audio/mpeg', 'audio/mp3', 'audio/opus'):
          thumb_name = 'audio'
        elif local_mime_maintype == 'video' and local_mime_subtype in ('webm', 'mp4'):
          thumb_name = self.gen_thumb_from_video(out_link, imagehash) if cv2_load_result == 'true' else 'video'
        elif local_mime_maintype == 'application' and local_mime_subtype == 'x-bittorrent':
          thumb_name = 'torrent'
        elif local_mime_maintype == 'application' and local_mime_subtype in ('x-7z-compressed', 'zip', 'x-gzip', 'x-tar', 'rar'):
          thumb_name = 'archive'
        else:
          image_name_original = image_name = thumb_name = ''
          message += '\n----' + part.get_content_type() + '----\n'
          message += 'invalid content type\n'
          message += '----' + part.get_content_type() + '----\n\n'
    else:
      if result.get_content_type().lower() == 'text/plain':
        message += result.get_payload(decode=True)
      else:
        message += '\n-----' + result.get_content_type() + '-----\n'
        message += 'invalid content type\n'
        message += '-----' + result.get_content_type() + '-----\n\n'
    del result
    message = basicHTMLencode(message)

    if (not subject or subject == 'None') and (message == image_name == public_key == '') and (parent and parent != message_id) and (not sender or sender == 'Anonymous'):
      self.log(self.logger.INFO, 'censored empty child message  %s' % message_id)
      self.delete_orphan_attach(image_name, thumb_name)
      return self.move_bad_article(message_id)

    group_flags = self.sqlite.execute("SELECT flags FROM groups WHERE group_name=?", (group_name,)).fetchone()
    if group_flags is None:
      self.log(self.logger.WARNING, 'Message {} in nonexistent group {}'.format(message_id, group_name))
    else:
      group_flags = int(group_flags[0])
      if (group_flags & self.cache['flags']['spam-fix']) != 0 and len(message) < 5:
        self.log(self.logger.INFO, 'Spamprotect group %s, censored %s' % (group_name, message_id))
        self.delete_orphan_attach(image_name, thumb_name)
        return self.move_bad_article(message_id)
      elif (group_flags & self.cache['flags']['news']) != 0 and (not parent or parent == message_id) \
          and (public_key == '' or not self.check_moder_flags(public_key, 'overchan-news-add')):
        self.delete_orphan_attach(image_name, thumb_name)
        return self.move_bad_article(message_id)
      elif (group_flags & self.cache['flags']['sage']) != 0:
        sage = True

    parent_result = None
    if parent != '' and parent != message_id:
      parent_result = self.sqlite.execute('SELECT closed FROM articles WHERE article_uid = ?', (parent,)).fetchone()
      if parent_result and parent_result[0] != 0:
        self.log(self.logger.INFO, 'censored article %s for closed thread.' % message_id)
        self.delete_orphan_attach(image_name, thumb_name)
        return self.move_bad_article(message_id)
      elif parent_result is None and os.path.isfile(os.path.join("articles", "censored", parent)):
        # root post censored. Delete child post
        self.log(self.logger.INFO, 'Thread starting {} deleted. Delete a {}'.format(parent, message_id))
        self.delete_orphan_attach(image_name, thumb_name)
        return self.move_bad_article(message_id)

    group_id = None
    result = self.sqlite.execute('SELECT group_id FROM groups WHERE group_name=? AND (cast(flags as integer) & ?) = 0', (group_name, self.cache['flags']['blocked'])).fetchone()
    if not result:
      try:
        self.sqlite.execute('INSERT INTO groups(group_name, article_count, last_update) VALUES (?,?,?)', (group_name, 1, int(time.time())))
        self.sqlite.commit()
      except sqlite3.Error:
        self.log(self.logger.INFO, 'ignoring message for blocked group %s' % group_name)
      else:
        self.__flush_board_cache()
        self.regenerate_all_html()
        group_id = int(self.sqlite.execute('SELECT group_id FROM groups WHERE group_name=?', (group_name,)).fetchone()[0])
    else:
      group_id = int(result[0])
    if group_id is None:
      self.log(self.logger.DEBUG, 'no group left which are not blocked. ignoring %s' % message_id)
      return False
    self.overchan_generator.regenerate_boards.add(group_id)

    if parent != '' and parent != message_id:
      last_update = sent
      self.overchan_generator.regenerate_threads.add(parent)
      if sage:
        # sage mark
        last_update = sent - 10
      else:
        if parent_result is not None:
          if self.config['bump_limit'] == 0 or self.sqlite.execute('SELECT count(article_uid) FROM articles WHERE parent = ? AND parent != article_uid ', (parent,)).fetchone()[0] < self.config['bump_limit']:
            self.sqlite.execute('UPDATE articles SET last_update=? WHERE article_uid=?', (sent, parent))
            self.sqlite.commit()
          else:
            last_update = sent - 10
        else:
          self.log(self.logger.INFO, 'missing parent %s for post %s' %  (parent, message_id))
          if parent in self.missing_parents:
            if sent > self.missing_parents[parent]:
              self.missing_parents[parent] = sent
          else:
            self.missing_parents[parent] = sent
    else:
      # root post
      if not message_id in self.missing_parents:
        last_update = sent
      else:
        if self.missing_parents[message_id] > sent:
          # obviously the case. still we check for invalid dates here
          last_update = self.missing_parents[message_id]
        else:
          last_update = sent
        del self.missing_parents[message_id]
        self.log(self.logger.INFO, 'found a missing parent: %s' % message_id)
        if len(self.missing_parents) > 0:
          self.log(self.logger.INFO, 'still missing %i parents' % len(self.missing_parents))
      self.overchan_generator.regenerate_threads.add(message_id)

    if self.sqlite.execute('SELECT article_uid FROM articles WHERE article_uid=?', (message_id,)).fetchone():
      # post has been censored and is now being restored. just delete post for all groups so it can be reinserted
      self.log(self.logger.INFO, 'post has been censored and is now being restored: %s' % message_id)
      self.sqlite.execute('DELETE FROM articles WHERE article_uid=?', (message_id,))
      self.sqlite.commit()

    if len(image_name) > 40:
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
          thumb_name = 'censored'
          censored_attach_path = os.path.join(self.config['output_directory'], 'img', image_name)
          if os.path.exists(censored_attach_path):
            os.remove(censored_attach_path)
        else:
          # attach has been censored and is now being restored. Restore all thumblink
          self.log(self.logger.INFO, 'Attach %s restored. Restore %s thumblinks for this attach' % (image_name, censored_count))
          self.sqlite.execute('UPDATE articles SET thumblink = ? WHERE imagelink = ?', (thumb_name, image_name))

    if image_name == '' and thumb_name == '' and self.config['replace_root_nope'] and (parent == '' or parent == message_id):
      # Get random image for root post
      result = self.sqlite.execute('SELECT imagelink, thumblink FROM articles WHERE group_id = ? AND length(thumblink) > 40 ORDER BY RANDOM() LIMIT 1', (group_id,)).fetchone()
      if result:
        image_name, thumb_name = result
        image_name_original = 'pic unrelated'

    insert_list = [
        ('article_uid',  message_id),
        ('sender',       trydecode(sender)),
        ('email',        trydecode(email)),
        ('subject',      trydecode(subject)),
        ('sent',         sent),
        ('parent',       parent),
        ('message',      trydecode(message)),
        ('imagename',    trydecode(image_name_original)),
        ('imagelink',    image_name),
        ('thumblink',    thumb_name),
        ('last_update',  last_update),
        ('public_key',   public_key),
        ('received',     int(time.time())),
        ('article_hash', sha1(message_id).hexdigest()),
        ('group_id',     'dummy')
    ]
    insert_request = 'INSERT INTO articles({}) VALUES ({})'.format(', '.join([x[0] for x in insert_list]), ','.join(['?'] * len(insert_list)))
    del insert_list[-1]
    self.sqlite.execute(insert_request, [x[1] for x in insert_list] + [group_id,])
    self.sqlite.execute('UPDATE groups SET last_update=?, article_count = (SELECT count(article_uid) FROM articles WHERE group_id = ?) WHERE group_id = ?', (int(time.time()), group_id, group_id))
    self.sqlite.commit()
    return True

  def check_board_flags(self, group_id, *args):
    flags = self.get_board_data(group_id, 'flags')
    for flag_name in args:
      if flags & self.cache['flags'][flag_name] == 0:
        return False
    return True

  def check_moder_flags(self, full_pubkey_hex, *args):
    try:
      result = self.censordb.execute('SELECT flags from keys WHERE key=?', (full_pubkey_hex,)).fetchone()
    except sqlite3.Error:
      return False
    else:
      flags = int(result[0]) if result is not None else 0
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
