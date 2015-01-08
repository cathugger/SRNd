#!/usr/bin/python
import base64
import codecs
import os
import re
import sqlite3
import string
import threading
import time
import traceback
import math
import mimetypes
mimetypes.init()
from binascii import unhexlify
from calendar import timegm
from datetime import datetime, timedelta
from email.feedparser import FeedParser
from email.utils import parsedate_tz
from hashlib import sha1, sha512

if __name__ == '__main__':
  import fcntl
  import signal
else:
  import Queue

import Image
import nacl.signing

try:
  import cv2
  cv2_load_result = 'true'
except ImportError as cv2_load_result:
  pass

class main(threading.Thread):

  def log(self, loglevel, message):
    if loglevel >= self.loglevel:
      self.logger.log(self.name, message, loglevel)

  def die(self, message):
    self.log(self.logger.CRITICAL, message)
    self.log(self.logger.CRITICAL, 'terminating..')
    self.should_terminate = True
    if __name__ == '__main__':
      exit(1)
    else:
      raise Exception(message)
      return

  def __init__(self, thread_name, logger, args):
    threading.Thread.__init__(self)
    self.name = thread_name
    self.should_terminate = False
    self.logger = logger

    # TODO: move sleep stuff to config table
    self.sleep_threshold = 10
    self.sleep_time = 0.02
    self.config = dict()

    error = ''
    for arg in ('template_directory', 'output_directory', 'database_directory', 'temp_directory', 'no_file', 'invalid_file', 'css_file', 'title', 'audio_file'):
      if not arg in args:
        error += "%s not in arguments\n" % arg
    if error != '':
      error = error.rstrip("\n")
      self.die(error)
    self.pages = 15
    self.output_directory = args['output_directory']
    self.database_directory = args['database_directory']
    self.template_directory = args['template_directory']
    self.temp_directory = args['temp_directory']
    self.html_title = args['title']
    if not os.path.exists(self.template_directory):
      self.die('error: template directory \'%s\' does not exist' % self.template_directory)
    self.no_file = args['no_file']
    self.invalid_file = args['invalid_file']
    self.document_file = args['document_file']
    self.audio_file = args['audio_file']
    self.webm_file = args['webm_file']
    self.css_file = args['css_file']
    self.loglevel = self.logger.INFO
    if 'debug' in args:
      try:
        self.loglevel = int(args['debug'])
        if self.loglevel < 0 or self.loglevel > 5:
          self.loglevel = 2
          self.log(self.logger.WARNING, 'invalid value for debug, using default debug level of 2')
      except:
        self.loglevel = 2
        self.log(self.logger.WARNING, 'invalid value for debug, using default debug level of 2')

    self.config['site_url'] = 'my-address.i2p'
    if 'site_url' in args:
      self.config['site_url'] = args['site_url']

    self.config['local_dest'] = 'i.did.not.read.the.config'
    if 'local_dest' in args:
      self.config['local_dest'] = args['local_dest']

    self.regenerate_html_on_startup = True
    if 'generate_all' in args:
      if args['generate_all'].lower() in ('false', 'no'):
        self.regenerate_html_on_startup = False

    self.threads_per_page = 10
    if 'threads_per_page' in args:
      try:    self.threads_per_page = int(args['threads_per_page'])
      except: pass

    self.pages_per_board = 10
    if 'pages_per_board' in args:
      try:    self.pages_per_board = int(args['pages_per_board'])
      except: pass

    self.enable_archive = True
    if 'enable_archive' in args:
      try:    self.enable_archive = bool(args['enable_archive'])
      except: pass

    self.enable_recent = True
    if 'enable_recent' in args:
      try:    self.enable_recent = bool(args['enable_recent'])
      except: pass

    self.archive_threads_per_page = 500
    if 'archive_threads_per_page' in args:
      try:    self.archive_threads_per_page = int(args['archive_threads_per_page'])
      except: pass

    self.archive_pages_per_board = 20
    if 'archive_pages_per_board' in args:
      try:    self.archive_pages_per_board = int(args['archive_pages_per_board'])
      except: pass

    self.sqlite_synchronous = True
    if 'sqlite_synchronous' in args:
      try:   self.sqlite_synchronous = bool(args['sqlite_synchronous'])
      except: pass

    self.sync_on_startup = False
    if 'sync_on_startup' in args:
      if args['sync_on_startup'].lower() == 'true':
        self.sync_on_startup = True

    self.fake_id = False
    if 'fake_id' in args:
      if args['fake_id'].lower() == 'true':
        self.fake_id = True

    self.bump_limit = 0
    if 'bump_limit' in args:
      try:    self.bump_limit = int(args['bump_limit'])
      except: pass

    self.censored_file = 'censored.png'
    if 'censored_file' in args:
      self.censored_file = args['censored_file']

    self.archive_file = 'archive.png'
    if 'archive_file' in args:
      self.archive_file = args['archive_file']

    self.torrent_file = 'torrent.png'
    if 'torrent_file' in args:
      self.torrent_file = args['torrent_file']

    self.use_unsecure_aliases = False
    if 'use_unsecure_aliases' in args:
      if args['use_unsecure_aliases'].lower() == 'true':
        self.use_unsecure_aliases = True

    self.create_best_video_thumbnail = False
    if 'create_best_video_thumbnail' in args:
      if args['create_best_video_thumbnail'].lower() == 'true':
        self.create_best_video_thumbnail = True

    self.utc_time_offset = 0.0
    if 'utc_time_offset' in args:
      try:    self.utc_time_offset = float(args['utc_time_offset'])
      except: pass
    if not (-15 < self.utc_time_offset < 15):
      self.log(self.logger.ERROR, 'Abnormal UTC offset %s, use UTC+0' % (self.utc_time_offset,))
      self.utc_time_offset = 0.0
    self.utc_time_offset = int(self.utc_time_offset * 3600)

    tz_name = 'UTC'
    if 'tz_name' in args:
      tz_name = args['tz_name'].replace('%', '')
    if tz_name != '': tz_name = ' ' + tz_name
    self.datetime_format = '%d.%m.%Y (%a) %H:%M' + tz_name

    for x in (self.no_file, self.audio_file, self.invalid_file, self.document_file, self.css_file, self.censored_file):
      cheking_file = os.path.join(self.template_directory, x)
      if not os.path.exists(cheking_file):
        self.die('{0} file not found in {1}'.format(x, cheking_file))

    # statics
    for x in ('help', 'stats_usage', 'stats_usage_row', 'latest_posts', 'latest_posts_row', 'stats_boards', 'stats_boards_row', 'base_pagelist', 'base_postform', 'base_footer'):
      template_file = os.path.join(self.template_directory, '%s.tmpl' % x)
      template_var = 'template_%s' % x
      try:
        f = codecs.open(template_file, "r", "utf-8")
        self.__dict__.setdefault(template_var, f.read())
        f.close()
      except Exception as e:
        self.die('Error loading template {0}: {1}'.format(template_file, e))

    if cv2_load_result != 'true':
      self.log(self.logger.ERROR, '%s. Thumbnail for video not be creating. see http://docs.opencv.org/' % cv2_load_result)

    f = codecs.open(os.path.join(self.template_directory, 'base_help.tmpl'), "r", "utf-8")
    self.template_base_help = string.Template(f.read()).safe_substitute(
      help=self.template_help
    )
    f = codecs.open(os.path.join(self.template_directory, 'base_head.tmpl'), "r", "utf-8")
    self.template_base_head = string.Template(f.read()).safe_substitute(
      title=self.html_title
    )
    f.close()
    # template_engines
    f = codecs.open(os.path.join(self.template_directory, 'board.tmpl'), "r", "utf-8")
    self.t_engine_board = string.Template(
      string.Template(f.read()).safe_substitute(
        base_head=self.template_base_head,
        base_pagelist=self.template_base_pagelist,
        base_postform=self.template_base_postform,
        base_help=self.template_base_help,
        base_footer=self.template_base_footer
      )
    )
    f.close()
    f = codecs.open(os.path.join(self.template_directory, 'board_archive.tmpl'), "r", "utf-8")
    self.t_engine_board_archive = string.Template(
      string.Template(f.read()).safe_substitute(
        base_head=self.template_base_head,
        base_pagelist=self.template_base_pagelist,
        base_postform=self.template_base_postform,
        base_help=self.template_base_help,
        base_footer=self.template_base_footer
      )
    )
    f.close()
    f = codecs.open(os.path.join(self.template_directory, 'board_recent.tmpl'), "r", "utf-8")
    self.t_engine_board_recent = string.Template(
      string.Template(f.read()).safe_substitute(
        base_head=self.template_base_head,
        base_postform=self.template_base_postform,
        base_help=self.template_base_help,
        base_footer=self.template_base_footer
      )
    )
    f.close()

    f = codecs.open(os.path.join(self.template_directory, 'thread_single.tmpl'), "r", "utf-8")
    self.t_engine_thread_single = string.Template(
      string.Template(f.read()).safe_substitute(
        help=self.template_help,
        title=self.html_title
      )
    )
    f.close()
    f = codecs.open(os.path.join(self.template_directory, 'index.tmpl'), "r", "utf-8")
    self.t_engine_index = string.Template(
      string.Template(f.read()).safe_substitute(
        title=self.html_title
      )
    )
    f.close()
    f = codecs.open(os.path.join(self.template_directory, 'menu.tmpl'), "r", "utf-8")
    self.t_engine_menu = string.Template(
      string.Template(f.read()).safe_substitute(
        title=self.html_title,
        site_url=self.config['site_url'],
        local_dest=self.config['local_dest']
      )
    )
    f.close()
    f = codecs.open(os.path.join(self.template_directory, 'menu_entry.tmpl'), "r", "utf-8")
    self.t_engine_menu_entry = string.Template(f.read())
    f.close()
    f = codecs.open(os.path.join(self.template_directory, 'overview.tmpl'), "r", "utf-8")
    self.t_engine_overview = string.Template(
      string.Template(f.read()).safe_substitute(
        help=self.template_help,
        title=self.html_title
      )
    )
    f.close()
    f = codecs.open(os.path.join(self.template_directory, 'board_threads.tmpl'), "r", "utf-8")
    self.t_engine_board_threads = string.Template(f.read())
    f.close()
    f = codecs.open(os.path.join(self.template_directory, 'archive_threads.tmpl'), "r", "utf-8")
    self.t_engine_archive_threads = string.Template(f.read())
    f.close()
    f = codecs.open(os.path.join(self.template_directory, 'message_root.tmpl'), "r", "utf-8")
    self.t_engine_message_root = string.Template(f.read())
    f.close()
    f = codecs.open(os.path.join(self.template_directory, 'message_child_pic.tmpl'), "r", "utf-8")
    self.t_engine_message_pic = string.Template(f.read())
    f.close()
    f = codecs.open(os.path.join(self.template_directory, 'message_child_nopic.tmpl'), "r", "utf-8")
    self.t_engine_message_nopic = string.Template(f.read())
    f.close()
    f = codecs.open(os.path.join(self.template_directory, 'signed.tmpl'), "r", "utf-8")
    self.t_engine_signed = string.Template(f.read())
    f.close()

    self.upper_table = {'0': '1',
                        '1': '2',
                        '2': '3',
                        '3': '4',
                        '4': '5',
                        '5': '6',
                        '6': '7',
                        '7': '8',
                        '8': '9',
                        '9': 'a',
                        'a': 'b',
                        'b': 'c',
                        'c': 'd',
                        'd': 'e',
                        'e': 'f',
                        'f': 'g'}

    if __name__ == '__main__':
      i = open(os.path.join(self.template_directory, self.css_file), 'r')
      o = open(os.path.join(self.output_directory, 'styles.css'), 'w')
      o.write(i.read())
      o.close()
      i.close()
      if not 'watch_dir' in args:
        self.log(self.logger.CRITICAL, 'watch_dir not in args')
        self.log(self.logger.CRITICAL, 'terminating..')
        exit(1)
      else:
        self.watch_dir = args['watch_dir']
      if not self.init_standalone():
        exit(1)
    else:
      if not self.init_plugin():
        self.should_terminate = True
        return

  def init_plugin(self):
    self.log(self.logger.INFO, 'initializing as plugin..')
    try:
      # load required imports for PIL
      something = Image.open(os.path.join(self.template_directory, self.no_file))
      modifier = float(180) / something.size[0]
      x = int(something.size[0] * modifier)
      y = int(something.size[1] * modifier)
      if something.mode == 'RGBA' or something.mode == 'LA':
        thumb_name = 'nope_loading_PIL.png'
      else:
        something = something.convert('RGB')
        thumb_name = 'nope_loading_PIL.jpg'
      something = something.resize((x, y), Image.ANTIALIAS)
      out = os.path.join(self.template_directory, thumb_name)
      something.save(out, optimize=True)
      del something
      os.remove(out)
    except IOError as e:
      self.die('error: can\'t load PIL library, err %s' %  e)
      return False
    self.queue = Queue.Queue()
    return True

  def init_standalone(self):
    self.log(self.logger.INFO, 'initializing as standalone..')
    signal.signal(signal.SIGIO, self.signal_handler)
    try:
      fd = os.open(self.watching, os.O_RDONLY)
    except OSError as e:
      if e.errno == 2:
        self.die(e)
        exit(1)
      else:
        raise e
    fcntl.fcntl(fd, fcntl.F_SETSIG, 0)
    fcntl.fcntl(fd, fcntl.F_NOTIFY,
                fcntl.DN_MODIFY | fcntl.DN_CREATE | fcntl.DN_MULTISHOT)
    self.past_init()
    return True

  def gen_template_thumbs(self, *sources):
    for source in sources:
      link = os.path.join(self.output_directory, 'thumbs', source)
      if not os.path.exists(link):
        try:
          something = Image.open(os.path.join(self.template_directory, source))
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

  def copy_out(self, *sources):
    for source, target in sources:
      try:
        i = open(os.path.join(self.template_directory, source), 'r')
        o = open(os.path.join(self.output_directory, target), 'w')
        o.write(i.read())
        o.close()
        i.close()
      except IOError as e:
        self.log(self.logger.ERROR, 'can\'t copy %s: %s' % (source, e))

  def past_init(self):
    required_dirs = list()
    required_dirs.append(self.output_directory)
    required_dirs.append(os.path.join(self.output_directory, '..', 'spamprotector'))
    required_dirs.append(os.path.join(self.output_directory, 'img'))
    required_dirs.append(os.path.join(self.output_directory, 'thumbs'))
    required_dirs.append(self.database_directory)
    required_dirs.append(self.temp_directory)
    for directory in required_dirs:
      if not os.path.exists(directory):
        os.mkdir(directory)
    del required_dirs
    # TODO use softlinks or at least cp instead
    # ^ hardlinks not gonna work because of remote filesystems
    # ^ softlinks not gonna work because of nginx chroot
    # ^ => cp
    self.copy_out((self.css_file, 'styles.css'), ('user.css', 'user.css'), (self.no_file, os.path.join('img', self.no_file)),
        ('suicide.txt', 'suicide.txt'), ('playbutton.png', os.path.join('img', 'playbutton.png')),
    )
    self.gen_template_thumbs(self.invalid_file, self.document_file, self.audio_file, self.webm_file, self.no_file, self.censored_file, self.torrent_file, self.archive_file)

    self.regenerate_boards = list()
    self.regenerate_threads = list()
    self.missing_parents = dict()
    self.cache = dict()
    self.cache['last_thread'] = dict()
    self.cache['flags'] = dict()
    self.cache['moder_flags'] = dict()

    self.sqlite_dropper_conn = sqlite3.connect('dropper.db3')
    self.dropperdb = self.sqlite_dropper_conn.cursor()
    self.sqlite_censor_conn = sqlite3.connect('censor.db3')
    self.censordb = self.sqlite_censor_conn.cursor()
    self.sqlite_hasher_conn = sqlite3.connect('hashes.db3')
    self.db_hasher = self.sqlite_hasher_conn.cursor()
    self.sqlite_conn = sqlite3.connect(os.path.join(self.database_directory, 'overchan.db3'))
    self.sqlite = self.sqlite_conn.cursor()
    if not self.sqlite_synchronous:
        self.sqlite.execute("PRAGMA synchronous = OFF")
    # FIXME use config table with current db version + def update_db(db_version) like in censor plugin
    self.sqlite.execute('''CREATE TABLE IF NOT EXISTS groups
               (group_id INTEGER PRIMARY KEY AUTOINCREMENT, group_name text UNIQUE, article_count INTEGER, last_update INTEGER)''')
    self.sqlite.execute('''CREATE TABLE IF NOT EXISTS articles
               (article_uid text, group_id INTEGER, sender text, email text, subject text, sent INTEGER, parent text, message text, imagename text, imagelink text, thumblink text, last_update INTEGER, public_key text, PRIMARY KEY (article_uid, group_id))''')

    # TODO add some flag like ability to carry different data for groups like (removed + added manually + public + hidden + whatever)
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
      except:
        pass
    for alias in ('ph_name', 'ph_shortname', 'link', 'tag', 'description',):
      try:
        self.sqlite.execute('ALTER TABLE groups ADD COLUMN {0} text DEFAULT ""'.format(alias))
      except:
        pass
    try:
      self.sqlite.execute('ALTER TABLE groups ADD COLUMN flags text DEFAULT "0"')
    except:
      pass
    try:
      self.sqlite.execute('ALTER TABLE articles ADD COLUMN public_key text')
    except:
      pass
    try:
      self.sqlite.execute('ALTER TABLE articles ADD COLUMN received INTEGER DEFAULT 0')
    except:
      pass
    self.sqlite.execute('CREATE INDEX IF NOT EXISTS articles_group_idx ON articles(group_id);')
    self.sqlite.execute('CREATE INDEX IF NOT EXISTS articles_parent_idx ON articles(parent);')
    self.sqlite.execute('CREATE INDEX IF NOT EXISTS articles_article_idx ON articles(article_uid);')
    self.sqlite.execute('CREATE INDEX IF NOT EXISTS articles_last_update_idx ON articles(group_id, parent, last_update);')
    self.sqlite_conn.commit()

    self.cache_init()

    if self.regenerate_html_on_startup:
      self.regenerate_all_html()

  def regenerate_all_html(self):
    for group_row in self.sqlite.execute('SELECT group_id FROM groups WHERE (cast(groups.flags as integer) & ?) = 0', (self.cache['flags']['blocked'],)).fetchall():
      if group_row[0] not in self.regenerate_boards:
        self.regenerate_boards.append(group_row[0])
    for thread_row in self.sqlite.execute('SELECT article_uid FROM articles WHERE parent = "" OR parent = article_uid ORDER BY last_update DESC').fetchall():
      if thread_row[0] not in self.regenerate_threads:
        self.regenerate_threads.append(thread_row[0])

    # index generation happens only at startup
    self.generate_index()

  def shutdown(self):
    self.running = False

  def add_article(self, message_id, source="article", timestamp=None):
    self.queue.put((source, message_id, timestamp))

  def sticky_processing(self, message_id):
    current_time = int(time.time())
    thread_last_update, group_id = self.sqlite.execute('SELECT last_update, group_id FROM articles WHERE article_uid = ? AND (parent = "" OR parent = article_uid)', (message_id,)).fetchone()
    if not thread_last_update: return 'article not found'
    if thread_last_update > current_time:
      new_thread_last_update = current_time
      sticky_action = 'unsticky thread'
    else:
      new_thread_last_update = current_time + (3600 * 24 * 30 * 6)
      sticky_action = 'sticky thread for half year'
    try:
      self.sqlite.execute('UPDATE articles SET last_update = ? WHERE article_uid = ? AND (parent = "" OR parent = article_uid)', (new_thread_last_update, message_id))
      self.sqlite_conn.commit()
    except:
      return 'Fail time update'
    if group_id not in self.regenerate_boards:
      self.regenerate_boards.append(group_id)
    if not message_id in self.regenerate_threads:
      self.regenerate_threads.append(message_id)
    return sticky_action

  def delete_orphan_attach(self, image, thumb):
    image_link = os.path.join(self.output_directory, 'img', image)
    thumb_link = os.path.join(self.output_directory, 'thumbs', thumb)
    for imagename, imagepath, imagetype in ((image, image_link, 'imagelink'), (thumb, thumb_link, 'thumblink'),):
      if len(imagename) > 40 and os.path.exists(imagepath):
        caringbears = int(self.sqlite.execute('SELECT count(article_uid) FROM articles WHERE %s = ?' % imagetype, (imagename,)).fetchone()[0])
        if caringbears > 0:
          self.log(self.logger.INFO, 'not deleting %s, %s posts using it' % (imagename, caringbears))
        else:
          self.log(self.logger.DEBUG, 'nobody not use %s, delete it' % (imagename,))
          try:
            os.unlink(imagepath)
          except Exception as e:
            self.log(self.logger.WARNING, 'could not delete %s: %s' % (imagepath, e))

  def censored_attach_processing(self, image, thumb):
    image_link = os.path.join(self.output_directory, 'img', image)
    thumb_link = os.path.join(self.output_directory, 'thumbs', thumb)
    for imagename, imagepath in ((image, image_link), (thumb, thumb_link),):
      if len(imagename) > 40 and os.path.exists(imagepath):
        os.unlink(imagepath)
        self.log(self.logger.INFO, 'censored and removed: %s' % (imagepath,))
      else:
        self.log(self.logger.DEBUG, 'incorrect filename %s, not delete %s' % (imagename, imagepath))
    if len(image) > 40:
      self.sqlite.execute('UPDATE articles SET thumblink = "censored" WHERE imagelink = ?', (image,))
      self.sqlite_conn.commit()

  def overchan_board_add(self, args):
    group_name = args[0].lower()
    if '/' in group_name:
      self.log(self.logger.WARNING, 'got overchan-board-add with invalid group name: \'%s\', ignoring' % group_name)
      return
    if len(args) > 1:
      flags = int(args[1])
    else:
      flags = 0
    try:
      flags = int(self.sqlite.execute("SELECT flags FROM groups WHERE group_name=?", (group_name,)).fetchone()[0])
      flags ^= flags & self.cache['flags']['blocked']
      self.sqlite.execute('UPDATE groups SET flags = ? WHERE group_name = ?', (str(flags), group_name))
      self.log(self.logger.INFO, 'unblocked existing board: \'%s\'' % group_name)
    except:
      self.sqlite.execute('INSERT INTO groups(group_name, article_count, last_update, flags) VALUES (?,?,?,?)', (group_name, 0, int(time.time()), flags))
      self.log(self.logger.INFO, 'added new board: \'%s\'' % group_name)
    if len(args) > 2:
      self.overchan_aliases_update(args[2], group_name)
    self.sqlite_conn.commit()
    self.regenerate_all_html()

  def overchan_board_del(self, group_name, flags=0):
    try:
      if flags == 0:
        flags = int(self.sqlite.execute("SELECT flags FROM groups WHERE group_name=?", (group_name,)).fetchone()[0]) | self.cache['flags']['blocked']
      self.sqlite.execute('UPDATE groups SET flags = ? WHERE group_name = ?', (str(flags), group_name))
      self.log(self.logger.INFO, 'blocked board: \'%s\'' % group_name)
      self.sqlite_conn.commit()
      self.regenerate_all_html()
    except:
      self.log(self.logger.WARNING, 'should delete board %s but there is no board with that name' % group_name)

  def overchan_aliases_update(self, base64_blob, group_name):
    try:
      ph_name, ph_shortname, link, tag, description = [base64.urlsafe_b64decode(x) for x in base64_blob.split(':')]
    except:
      self.log(self.logger.WARNING, 'get corrupt data for %s' % group_name)
      return
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
        group_id = self.sqlite.execute("SELECT group_id FROM groups WHERE group_name=?", (group_name,)).fetchone()[0]
        if group_id == '' or ((flags & self.cache['flags']['blocked']) == 0 and self.check_board_flags(group_id, 'blocked')):
          self.overchan_board_add((group_name, flags,))
        elif (flags & self.cache['flags']['blocked']) != 0 and not self.check_board_flags(group_id, 'blocked'):
          self.overchan_board_del(group_name, flags)
        else:
          self.sqlite.execute('UPDATE groups SET flags = ? WHERE group_name = ?', (flags, group_name))
          if len(get_data) > 2:
            self.overchan_aliases_update(get_data[2], group_name)
          self.sqlite_conn.commit()
          if group_id not in self.regenerate_boards:
            self.regenerate_boards.append(group_id)
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
        if row[3] not in self.regenerate_boards:
          self.regenerate_boards.append(row[3])
        if row[2] == '':
          if not message_id in self.regenerate_threads:
            self.regenerate_threads.append(message_id)
        elif not row[2] in self.regenerate_threads:
          self.regenerate_threads.append(row[2])
      elif line.lower().startswith("delete "):
        message_id = line.split(" ")[1]
        if os.path.exists(os.path.join("articles", "restored", message_id)):
          self.log(self.logger.DEBUG, 'message has been restored: %s. ignoring delete' % message_id)
          continue
        row = self.sqlite.execute("SELECT imagelink, thumblink, parent, group_id, received FROM articles WHERE article_uid = ?", (message_id,)).fetchone()
        if not row:
          self.log(self.logger.DEBUG, 'should delete message_id %s but there is no article matching this message_id' % message_id)
          continue
        #if row[4] > timestamp:
        #  self.log("post more recent than control message. ignoring delete for %s" % message_id, 2)
        #  continue
        # FIXME: allow deletion of earlier delete-attachment'ed messages
        #if row[0] == 'invalid':
        #  self.log("message already deleted/censored. ignoring delete for %s" % message_id, 4)
        #  continue
        self.log(self.logger.INFO, 'deleting message_id %s' % message_id)
        with_child = False
        if row[2] == '':
          # root post
          child_files = self.sqlite.execute("SELECT imagelink, thumblink FROM articles WHERE parent = ? AND article_uid != parent", (message_id,)).fetchall()
          if child_files and len(child_files[0]) > 0:
            # root posts with child posts
            self.log(self.logger.DEBUG, 'deleting message_id %s, got a root post with attached child posts' % message_id)
            # delete child posts
            self.sqlite.execute('DELETE FROM articles WHERE parent = ?', (message_id,))
            with_child = True
          else:
            # root posts without child posts
            self.log(self.logger.DEBUG, 'deleting message_id %s, got a root post without any child posts' % message_id)
          self.sqlite.execute('DELETE FROM articles WHERE article_uid = ?', (message_id,))
          try:
            os.unlink(os.path.join(self.output_directory, "thread-%s.html" % sha1(message_id).hexdigest()[:10]))
          except Exception as e:
            self.log(self.logger.WARNING, 'could not delete thread for message_id %s: %s' % (message_id, e))
        else:
          # child post
          self.log(self.logger.DEBUG, 'deleting message_id %s, got a child post' % message_id)
          self.sqlite.execute('DELETE FROM articles WHERE article_uid = ?', (message_id,))
          if row[2] not in self.regenerate_threads:
            self.regenerate_threads.append(row[2])
          # FIXME: add detection for parent == deleted message (not just censored) and if true, add to root_posts
        self.sqlite_conn.commit()
        self.delete_orphan_attach(row[0], row[1])
        # delete child images and thumbs
        if with_child:
          for child_image, child_thumb in child_files:
            self.delete_orphan_attach(child_image, child_thumb)
        if row[3] not in self.regenerate_boards:
          self.regenerate_boards.append(row[3])
      elif line.lower().startswith("overchan-sticky "):
        message_id = line.split(" ")[1]
        self.log(self.logger.INFO, 'sticky processing message_id %s, %s' % (message_id, self.sticky_processing(message_id)))

  def signal_handler(self, signum, frame):
    # FIXME use try: except: around open(), also check for duplicate here
    for item in os.listdir(self.watching):
      link = os.path.join(self.watching, item)
      f = open(link, 'r')
      if not self.parse_message(message_id, f):
        f.close()
      os.remove(link)
    if len(self.regenerate_boards) > 0:
      for board in self.regenerate_boards:
        self.generate_board(board)
      del self.regenerate_boards[:]
    if len(self.regenerate_threads) > 0:
      for thread in self.regenerate_threads:
        self.generate_thread(thread)
      del self.regenerate_threads[:]

  def run(self):
    if self.should_terminate:
      return
    if  __name__ == '__main__':
      return
    self.log(self.logger.INFO, 'starting up as plugin..')
    self.past_init()
    self.running = True
    regen_overview = False
    got_control = False
    while self.running:
      try:
        ret = self.queue.get(block=True, timeout=1)
        if ret[0] == "article":
          message_id = ret[1]
          message_thumblink = self.sqlite.execute('SELECT thumblink FROM articles WHERE article_uid = ? AND imagelink != "invalid"', (message_id,)).fetchone()
          if message_thumblink and (message_thumblink[0] != 'censored' or not os.path.exists(os.path.join("articles", "restored", message_id))):
            self.log(self.logger.DEBUG, '%s already in database..' % message_id)
            continue
          #message_id = self.queue.get(block=True, timeout=1)
          self.log(self.logger.DEBUG, 'got article %s' % message_id)
          try:
            f = open(os.path.join('articles', message_id), 'r')
            if not self.parse_message(message_id, f):
              f.close()
              #self.log(self.logger.WARNING, 'got article %s, parse_message failed. somehow.' % message_id)
          except Exception as e:
            self.log(self.logger.WARNING, 'something went wrong while trying to parse article %s: %s' % (message_id, e))
            self.log(self.logger.WARNING, traceback.format_exc())
            try:
              f.close()
            except:
              pass
        elif ret[0] == "control":
          got_control = True
          self.handle_control(ret[1], ret[2])
        else:
          self.log(self.logger.ERROR, 'found article with unknown source: %s' % ret[0])

        if self.queue.qsize() > self.sleep_threshold:
          time.sleep(self.sleep_time)
      except Queue.Empty:
        if len(self.regenerate_boards) > 0:
          do_sleep = len(self.regenerate_boards) > self.sleep_threshold
          if do_sleep:
            self.log(self.logger.DEBUG, 'boards: should sleep')
          for board in self.regenerate_boards:
            self.generate_board(board)
            if do_sleep: time.sleep(self.sleep_time)
          self.regenerate_boards = list()
          regen_overview = True
        if len(self.regenerate_threads) > 0:
          do_sleep = len(self.regenerate_threads) > self.sleep_threshold
          if do_sleep:
            self.log(self.logger.DEBUG, 'threads: should sleep')
          for thread in self.regenerate_threads:
            self.generate_thread(thread)
            if do_sleep: time.sleep(self.sleep_time)
          self.regenerate_threads = list()
          regen_overview = True
        if regen_overview:
          self.generate_overview()
          # generate menu.html simultaneously with overview
          self.generate_menu()
          regen_overview = False
        if got_control:
          self.sqlite_conn.commit()
          self.sqlite.execute('VACUUM;')
          self.sqlite_conn.commit()
          got_control = False
    self.sqlite_censor_conn.close()
    self.sqlite_conn.close()
    self.sqlite_hasher_conn.close()
    self.sqlite_dropper_conn.close()
    self.log(self.logger.INFO, 'bye')

  def basicHTMLencode(self, inputString):
    return inputString.replace('<', '&lt;').replace('>', '&gt;').strip(' \t\n\r')

  def generate_pubkey_short_utf_8(self, full_pubkey_hex, length=6):
    pub_short = ''
    for x in range(0, length / 2):
      pub_short += '&#%i;' % (9600 + int(full_pubkey_hex[x*2:x*2+2], 16))
    length -= length / 2
    for x in range(0, length):
      pub_short += '&#%i;' % (9600 + int(full_pubkey_hex[-(length*2):][x*2:x*2+2], 16))
    return pub_short

  def message_uid_to_fake_id(self, message_uid):
    fake_id = self.dropperdb.execute('SELECT article_id FROM articles WHERE message_id = ?', (message_uid,)).fetchone()
    if fake_id:
      return fake_id[0]
    else:
      return sha1(message_uid).hexdigest()[:10]

  def get_moder_name(self, full_pubkey_hex):
    try:
      return self.censordb.execute('SELECT local_name from keys WHERE key=? and local_name != ""', (full_pubkey_hex,)).fetchone()
    except:
      return None

  def pubkey_to_name(self, full_pubkey_hex, root_full_pubkey_hex='', sender=''):
    op_flag = nickname = ''
    local_name = self.get_moder_name(full_pubkey_hex)
    if full_pubkey_hex == root_full_pubkey_hex:
      op_flag = '<span class="op-kyn">OP</span> '
      nickname = sender
    if local_name is not None and local_name != '':
      nickname = '<span class="zoi">%s</span>' % local_name
    return '%s%s' % (op_flag, nickname)

  def upp_it(self, data):
    if data[-1] not in self.upper_table:
      return data
    return data[:-1] + self.upper_table[data[-1]]

  def linkit(self, rematch):
    row = self.db_hasher.execute("SELECT message_id FROM article_hashes WHERE message_id_hash >= ? and message_id_hash < ?", (rematch.group(2), self.upp_it(rematch.group(2)))).fetchall()
    if not row or len(row) > 1:
      # hash not found or multiple matches for that 10 char hash
      return rematch.group(0)
    message_id = row[0][0]
    parent_row = self.sqlite.execute("SELECT parent FROM articles WHERE article_uid = ?", (message_id,)).fetchone()
    if not parent_row:
      # not an overchan article (anymore)
      return rematch.group(0)
    parent_id = parent_row[0]
    if self.fake_id:
      article_name = self.message_uid_to_fake_id(message_id)
    else:
      article_name = rematch.group(2)
    if parent_id == "":
      # article is root post
      return '<a onclick="return highlight(\'%s\');" href="thread-%s.html">%s%s</a>' % (rematch.group(2), rematch.group(2), rematch.group(1), article_name)
    # article has a parent
    # FIXME: cache results somehow?
    parent = sha1(parent_id).hexdigest()[:10]
    return '<a onclick="return highlight(\'%s\');" href="thread-%s.html#%s">%s%s</a>' % (rematch.group(2), parent, rematch.group(2), rematch.group(1), article_name)

  def quoteit(self, rematch):
    return '<span class="quote">%s</span>' % rematch.group(0).rstrip("\r")

  def clickit(self, rematch):
    return '<a href="%s%s">%s%s</a>' % (rematch.group(1), rematch.group(2), rematch.group(1), rematch.group(2))

  def codeit(self, text):
    return '<div class="code">%s</div>' % text

  def spoilit(self, rematch):
    return '<span class="spoiler">%s</span>' % rematch.group(1)

  def boldit(self, rematch):
    return '<b>%s</b>' % rematch.group(1)

  def italit(self, rematch):
    return '<i>%s</i>' % rematch.group(1)

  def strikeit(self, rematch):
    return '<strike>%s</strike>' % rematch.group(1)

  def underlineit(self, rematch):
    return '<span style="border-bottom: 1px solid">%s</span>' % rematch.group(1)

  def markup_parser(self, message):
    # make >>post_id links
    linker = re.compile("(&gt;&gt;)([0-9a-f]{10})")
    # make >quotes
    quoter = re.compile("^&gt;(?!&gt;[0-9a-f]{10}).*", re.MULTILINE)
    # Make http:// urls in posts clickable
    clicker = re.compile("(http://|https://|ftp://|mailto:|news:|irc:)([^\s\[\]<>'\"&]*)")
    # make code blocks
    coder = re.compile('\[code](?!\[/code])(.+?)\[/code]', re.DOTALL)
    # make spoilers
    spoiler = re.compile("%% (?!\s) (.+?) (?!\s) %%", re.VERBOSE)
    # make <b>
    bolder1 = re.compile("(?<![0-9a-zA-Z\x80-\x9f\xe0-\xfc*_/()]) \*\* (?![\s*_]) (.+?) (?<![\s*_]) \*\* (?![0-9a-zA-Z\x80-\x9f\xe0-\xfc*_/()])", re.VERBOSE)
    bolder2 = re.compile("(?<![0-9a-zA-Z\x80-\x9f\xe0-\xfc*_/()]) __ (?![\s*_]) (.+?) (?<![\s*_]) __ (?![0-9a-zA-Z\x80-\x9f\xe0-\xfc*_/()])", re.VERBOSE)
    # make <i>
    italer = re.compile("(?<![0-9a-zA-Z\x80-\x9f\xe0-\xfc*_/()]) \* (?![\s*_]) (.+?) (?<![\s*_]) \* (?![0-9a-zA-Z\x80-\x9f\xe0-\xfc*_/()])", re.VERBOSE)
    # make <strike>
    striker = re.compile("(?<![0-9a-zA-Z\x80-\x9f\xe0-\xfc*_/()\-]) -- (?![\s*_-]) (.+?) (?<![\s*_-]) -- (?![0-9a-zA-Z\x80-\x9f\xe0-\xfc*_/()\-])", re.VERBOSE)
    # make underlined text
    underliner = re.compile("(?<![0-9a-zA-Z\x80-\x9f\xe0-\xfc*_/()]) _ (?![\s*_]) (.+?) (?<![\s*_]) _ (?![0-9a-zA-Z\x80-\x9f\xe0-\xfc*_/()])", re.VERBOSE)

    # perform parsing
    if re.search(coder, message):
      # list indices: 0 - before [code], 1 - inside [code]...[/code], 2 - after [/code]
      message_parts = re.split(coder, message, maxsplit=1)
      message = self.markup_parser(message_parts[0]) + self.codeit(message_parts[1]) + self.markup_parser(message_parts[2])
    else:
      message = linker.sub(self.linkit, message)
      message = quoter.sub(self.quoteit, message)
      message = clicker.sub(self.clickit, message)
      message = spoiler.sub(self.spoilit, message)
      message = bolder1.sub(self.boldit, message)
      message = bolder2.sub(self.boldit, message)
      message = italer.sub(self.italit, message)
      message = striker.sub(self.strikeit, message)
      message = underliner.sub(self.underlineit, message)

    return message

  def move_censored_article(self, message_id):
    if os.path.exists(os.path.join('articles', 'censored', message_id)):
      self.log(self.logger.DEBUG, "already move, still handing over to redistribute further")
    elif os.path.exists(os.path.join("articles", message_id)):
      self.log(self.logger.DEBUG, "moving %s to articles/censored/" % message_id)
      os.rename(os.path.join("articles", message_id), os.path.join("articles", "censored", message_id))
      for row in self.dropperdb.execute('SELECT group_name, article_id from articles, groups WHERE message_id=? and groups.group_id = articles.group_id', (message_id,)).fetchall():
        self.log(self.logger.DEBUG, "deleting groups/%s/%i" % (row[0], row[1]))
        try:
          # FIXME race condition with dropper if currently processing this very article
          os.unlink(os.path.join("groups", str(row[0]), str(row[1])))
        except Exception as e:
          self.log(self.logger.WARNING, "could not delete %s: %s" % (os.path.join("groups", str(row[0]), str(row[1])), e))
    elif not os.path.exists(os.path.join('articles', 'censored', message_id)):
      f = open(os.path.join('articles', 'censored', message_id), 'w')
      f.close()
    return True

  def gen_thumb_from_video(self, target, imagehash):
    if os.path.getsize(target) == 0:
      return 'invalid'
    tmp_image = os.path.join(self.temp_directory, imagehash + '.jpg')
    image_entropy = -1.1
    try:
      video_capture = cv2.VideoCapture(target)
      readable, video_frame = video_capture.read()
      fps = int(video_capture.get(cv2.cv.CV_CAP_PROP_FPS))
      if fps > 61: fps = 60
      if fps < 10: fps = 10
      video_length = int(video_capture.get(cv2.cv.CV_CAP_PROP_FRAME_COUNT) / fps)
      if video_length > 120: video_length = 120
      tmp_video_frame = video_frame
      current_frame = 0
      while self.create_best_video_thumbnail and readable and current_frame < video_length:
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
      self.log(self.logger.WARNING, "error create image from video %s: %s" % (target, e))
      thumbname = 'video'
    else:
      try:
        thumbname = self.gen_thumb(tmp_image, imagehash)
      except:
        thumbname = 'invalid'
    try: os.remove(tmp_image)
    except: pass
    return thumbname

  def gen_thumb(self, target, imagehash):
    if os.path.getsize(target) == 0:
      return 'invalid'
    if target.split('.')[-1].lower() == 'gif' and os.path.getsize(target) < (128 * 1024 + 1):
      thumb_name = imagehash + '.gif'
      thumb_link = os.path.join(self.output_directory, 'thumbs', thumb_name)
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
    if thumb.mode == 'P': thumb = thumb.convert('RGBA')
    if thumb.mode == 'RGBA' or thumb.mode == 'LA':
      thumb_name = imagehash + '.png'
    else:
      thumb_name = imagehash + '.jpg'
      thumb = thumb.convert('RGB')
    thumb_link = os.path.join(self.output_directory, 'thumbs', thumb_name)
    thumb = thumb.resize((x, y), Image.ANTIALIAS)
    thumb.save(thumb_link, optimize=True)
    return thumb_name

  def really_os_rename(self, src, dst):
    # TODO: check if out dir is remote fs, use os.rename if not
    c = open(dst, 'w')
    f = open(src, 'r')
    c.write(f.read())
    c.close()
    f.close()
    os.remove(src)

  def parse_message(self, message_id, fd):
    self.log(self.logger.INFO, 'new message: %s' % message_id)
    subject = 'None'
    sent = 0
    sender = 'Anonymous'
    email = 'nobody@no.where'
    parent = ''
    groups = list()
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
        subject = self.basicHTMLencode(line.split(' ', 1)[1][:-1])
      elif lower_line.startswith('date:'):
        sent = line.split(' ', 1)[1][:-1]
        sent_tz = parsedate_tz(sent)
        if sent_tz:
          offset = 0
          if sent_tz[-1]: offset = sent_tz[-1]
          sent = timegm((datetime(*sent_tz[:6]) - timedelta(seconds=offset)).timetuple())
        else:
          sent = int(time.time())
      elif lower_line.startswith('from:'):
        sender = self.basicHTMLencode(line.split(' ', 1)[1][:-1].split(' <', 1)[0])
        try:
          email = self.basicHTMLencode(line.split(' ', 1)[1][:-1].split(' <', 1)[1].replace('>', ''))
        except:
          pass
      elif lower_line.startswith('references:'):
        parent = line[:-1].split(' ')[1]
      elif lower_line.startswith('newsgroups:'):
        group_in = lower_line[:-1].split(' ', 1)[1]
        if ';' in group_in:
          groups_in = group_in.split(';')
          for group_in in groups_in:
            if group_in.startswith('overchan.'):
              groups.append(group_in)
        elif ',' in group_in:
          groups_in = group_in.split(',')
          for group_in in groups_in:
            if group_in.startswith('overchan.'):
              groups.append(group_in)
        else:
          groups.append(group_in)
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
      #self.log(self.logger.WARNING, '%s malformed article' % message_id)
      #return False
      raise Exception('%s malformed article' % message_id)
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
      try:
        self.log(self.logger.INFO, 'trying to validate signature.. ')
        nacl.signing.VerifyKey(unhexlify(public_key)).verify(hasher.digest(), unhexlify(signature))
        self.log(self.logger.INFO, 'validated')
      except Exception as e:
        public_key = ''
        self.log(self.logger.INFO, 'failed: %s' % e)
      del hasher
      del signature
    parser.feed(fd.read())
    fd.close()
    result = parser.close()
    del parser
    out_link = None
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

        deny_extensions = ('.html', '.php', '.phtml', '.php3', '.php4', '.js')
        tmp_attach = os.path.join(self.temp_directory, 'tmp_attach')
        if part.get_content_type() != 'text/plain':
          f = open(tmp_attach, 'w')
          f.write(part.get_payload(decode=True))
          f.close()
          f = open(tmp_attach, 'r')
          imagehash = sha1(f.read()).hexdigest()
          f.close()
          if part.get_filename() is None or part.get_filename().strip() == '':
            image_name_original = 'empty_file_name.empty'
          else:
            image_name_original = self.basicHTMLencode(part.get_filename().replace('/', '_').replace('"', '_'))
          image_extension = '.' + image_name_original.split('.')[-1].lower()
          if len(image_name_original) > 512:
            image_name_original = image_name_original[:512] + '...'
          local_mime_type = mimetypes.types_map.get(image_extension, '/')
          local_mime_maintype, local_mime_subtype = local_mime_type.split('/', 2)
          image_mime_types = mimetypes.guess_all_extensions(local_mime_type)
          image_name = imagehash + image_extension
          out_link = os.path.join(self.output_directory, 'img', image_name)
        if part.get_content_type() == 'text/plain':
          message += part.get_payload(decode=True)
        # Bad file type, unknown or deny type found
        elif local_mime_type == '/' or len((set(image_extension) | set(image_mime_types)) & set(deny_extensions)) > 0:
          self.log(self.logger.WARNING, 'Found bad attach %s in %s. Mimetype local=%s, remote=%s' % (image_name_original, message_id, local_mime_type, part.get_content_type()))
          image_name_original = 'fake.and.gay.txt'
          thumb_name = 'document'
          image_name = 'suicide.txt'
        elif local_mime_maintype == 'image':
          self.really_os_rename(tmp_attach, out_link)
          try:
            thumb_name = self.gen_thumb(out_link, imagehash)
          except Exception as e:
            thumb_name = 'invalid'
            self.log(self.logger.WARNING, 'Error creating thumb in %s: %s' % (image_name, e))
        elif local_mime_type in ('application/pdf', 'application/postscript', 'application/ps'):
          self.really_os_rename(tmp_attach, out_link)
          thumb_name = 'document'
        elif local_mime_type in ('audio/ogg', 'audio/mpeg', 'audio/mp3', 'audio/opus'):
          self.really_os_rename(tmp_attach, out_link)
          thumb_name = 'audio'
        elif local_mime_maintype == 'video' and local_mime_subtype in ('webm', 'mp4'):
          self.really_os_rename(tmp_attach, out_link)
          if cv2_load_result == 'true':
            thumb_name = self.gen_thumb_from_video(out_link, imagehash)
          else:
            thumb_name = 'video'
        elif local_mime_maintype == 'application' and local_mime_subtype == 'x-bittorrent':
          self.really_os_rename(tmp_attach, out_link)
          thumb_name = 'torrent'
        elif local_mime_maintype == 'application' and local_mime_subtype in ('x-7z-compressed', 'zip', 'x-gzip', 'x-tar', 'rar'):
          self.really_os_rename(tmp_attach, out_link)
          thumb_name = 'archive'
        else:
          image_name_original = image_name = thumb_name = ''
          message += '\n----' + part.get_content_type() + '----\n'
          message += 'invalid content type\n'
          message += '----' + part.get_content_type() + '----\n\n'
        if os.path.exists(tmp_attach): os.remove(tmp_attach)
    else:
      if result.get_content_type().lower() == 'text/plain':
        message += result.get_payload(decode=True)
      else:
        message += '\n-----' + result.get_content_type() + '-----\n'
        message += 'invalid content type\n'
        message += '-----' + result.get_content_type() + '-----\n\n'
    del result
    message = self.basicHTMLencode(message)

    if (not subject or subject == 'None') and (message == image_name == public_key == '') and (parent and parent != message_id) and (not sender or sender == 'Anonymous'):
      self.log(self.logger.INFO, 'censored empty child message  %s' % message_id)
      self.delete_orphan_attach(image_name, thumb_name)
      return self.move_censored_article(message_id)

    for group in groups:
      try:
        group_flags = int(self.sqlite.execute("SELECT flags FROM groups WHERE group_name=?", (group,)).fetchone()[0])
        if (group_flags & self.cache['flags']['spam-fix']) != 0 and len(message) < 5:
          self.log(self.logger.INFO, 'Spamprotect group %s, censored %s' % (group, message_id))
          self.delete_orphan_attach(image_name, thumb_name)
          return self.move_censored_article(message_id)
        elif (group_flags & self.cache['flags']['news']) != 0 and (not parent or parent == message_id) \
            and (public_key == '' or not self.check_moder_flags(public_key, 'overchan-news-add')):
          self.delete_orphan_attach(image_name, thumb_name)
          return self.move_censored_article(message_id)
        elif (group_flags & self.cache['flags']['sage']) != 0:
          sage = True
      except Exception as e:
        self.log(self.logger.INFO, 'Processing group %s error message %s %s' % (group, message_id, e))

    group_ids = list()
    for group in groups:
      result = self.sqlite.execute('SELECT group_id FROM groups WHERE group_name=? AND (cast(flags as integer) & ?) = 0', (group, self.cache['flags']['blocked'])).fetchone()
      if not result:
        try:
          self.sqlite.execute('INSERT INTO groups(group_name, article_count, last_update) VALUES (?,?,?)', (group, 1, int(time.time())))
          self.sqlite_conn.commit()
        except:
          self.log(self.logger.INFO, 'ignoring message for blocked group %s' % group)
          continue
        self.regenerate_all_html()
        group_ids.append(int(self.sqlite.execute('SELECT group_id FROM groups WHERE group_name=?', (group,)).fetchone()[0]))
      else:
        group_ids.append(int(result[0]))
    if len(group_ids) == 0:
      self.log(self.logger.DEBUG, 'no groups left which are not blocked. ignoring %s' % message_id)
      return False
    for group_id in group_ids:
      if group_id not in self.regenerate_boards:
        self.regenerate_boards.append(group_id)

    if parent != '' and parent != message_id:
      last_update = sent
      if parent not in self.regenerate_threads:
        self.regenerate_threads.append(parent)
      if not sage:
        result = self.sqlite.execute('SELECT last_update FROM articles WHERE article_uid = ?', (parent,)).fetchone()
        if result:
          parent_last_update = result[0]
          if sent > parent_last_update:
            if self.bump_limit > 0:
              child_count = self.sqlite.execute('SELECT count(article_uid) FROM articles WHERE parent = ? AND parent != article_uid ', (parent,)).fetchone()
              if not (child_count and int(child_count[0]) >= self.bump_limit):
                self.sqlite.execute('UPDATE articles SET last_update=? WHERE article_uid=?', (sent, parent))
                self.sqlite_conn.commit()
            else:
              self.sqlite.execute('UPDATE articles SET last_update=? WHERE article_uid=?', (sent, parent))
              self.sqlite_conn.commit()
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
      if message_id not in self.regenerate_threads:
        self.regenerate_threads.append(message_id)

    if self.sqlite.execute('SELECT article_uid FROM articles WHERE article_uid=?', (message_id,)).fetchone():
      # post has been censored and is now being restored. just delete post for all groups so it can be reinserted
      self.log(self.logger.INFO, 'post has been censored and is now being restored: %s' % message_id)
      self.sqlite.execute('DELETE FROM articles WHERE article_uid=?', (message_id,))
      self.sqlite_conn.commit()

    censored_articles = self.sqlite.execute('SELECT article_uid FROM articles WHERE thumblink = "censored" AND imagelink = ?', (image_name,)).fetchall()
    censored_count = len(censored_articles)
    if censored_count > 0:
      attach_iscensored = False
      for check_article in censored_articles:
        if os.path.exists(os.path.join("articles", "censored", check_article[0])):
          attach_iscensored = True
          break
      if attach_iscensored:
        # attach has been censored and not restored. Censoring and this attach
        self.log(self.logger.INFO, 'Message %s contain attach censoring in %s message. %s has been continue censoring' % (message_id, check_article[0], image_name))
        thumb_name = 'censored'
        censored_attach_path = os.path.join(self.output_directory, 'img', image_name)
        if os.path.exists(censored_attach_path):
          os.remove(censored_attach_path)
      else:
        # attach has been censored and is now being restored. Restore all thumblink
        self.log(self.logger.INFO, 'Attach %s restored. Restore %s thumblinks for this attach' % (image_name, censored_count))
        self.sqlite.execute('UPDATE articles SET thumblink = ? WHERE imagelink = ?', (thumb_name, image_name))
        self.sqlite_conn.commit()

    for group_id in group_ids:
      self.sqlite.execute('INSERT INTO articles(article_uid, group_id, sender, email, subject, sent, parent, message, imagename, imagelink, thumblink, last_update, public_key, received) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)', (message_id, group_id, sender.decode('UTF-8'), email.decode('UTF-8'), subject.decode('UTF-8'), sent, parent, message.decode('UTF-8'), image_name_original.decode('UTF-8'), image_name, thumb_name, last_update, public_key, int(time.time())))
      self.sqlite.execute('UPDATE groups SET last_update=?, article_count = (SELECT count(article_uid) FROM articles WHERE group_id = ?) WHERE group_id = ?', (int(time.time()), group_id, group_id))
    self.sqlite_conn.commit()
    return True

  def generate_board(self, group_id):
    threads_per_page = self.threads_per_page
    pages_per_board = self.pages_per_board
    boardlist, full_board_name_unquoted, board_name_unquoted, board_name, board_description = self.generate_board_list(group_id)

    threads = int(self.sqlite.execute('SELECT count(group_id) FROM (SELECT group_id FROM articles WHERE group_id = ? AND (parent = "" OR parent = article_uid) LIMIT ?)', (group_id, threads_per_page * pages_per_board)).fetchone()[0])
    if self.enable_archive and ((int(self.sqlite.execute("SELECT flags FROM groups WHERE group_id=?", (group_id,)).fetchone()[0]) & self.cache['flags']['no-archive']) == 0):
      total_thread_count = int(self.sqlite.execute('SELECT count(group_id) FROM (SELECT group_id FROM articles WHERE group_id = ? AND (parent = "" OR parent = article_uid))', (group_id,)).fetchone()[0])
      if total_thread_count > threads:
        generate_archive = True
      else:
        generate_archive = False
    else:
      generate_archive = False

    pages = int(threads / threads_per_page)
    if (threads % threads_per_page != 0) or pages == 0:
      pages += 1

    for board in xrange(1, pages + 1):
      board_offset = threads_per_page * (board - 1)
      threads = list()
      self.log(self.logger.INFO, 'generating %s/%s-%s.html' % (self.output_directory, board_name_unquoted, board))
      #TODO: OFFSET decrease performance? This is very bad? Maybe need create index for fix it. If this need fix
      for root_row in self.sqlite.execute('SELECT article_uid, sender, subject, sent, message, imagename, imagelink, thumblink, public_key, last_update \
          FROM articles WHERE group_id = ? AND (parent = "" OR parent = article_uid) ORDER BY last_update DESC LIMIT ? OFFSET ?', (group_id, threads_per_page, board_offset)).fetchall():
        root_message_id_hash = sha1(root_row[0]).hexdigest()
        threads.append(
          self.t_engine_board_threads.substitute(
            message_root=self.get_root_post(root_row, group_id, 4, root_message_id_hash),
            message_childs=''.join(self.get_childs_posts(root_row[0], group_id, root_message_id_hash, root_row[8], 4))
          )
        )
      t_engine_mapper_board = dict()
      t_engine_mapper_board['threads'] = ''.join(threads)
      t_engine_mapper_board['pagelist'] = ''.join(self.generate_pagelist(pages, board, board_name_unquoted, generate_archive))
      t_engine_mapper_board['boardlist'] = ''.join(boardlist)
      t_engine_mapper_board['full_board'] = full_board_name_unquoted
      t_engine_mapper_board['board'] = board_name
      t_engine_mapper_board['target'] = "{0}-1.html".format(board_name_unquoted)
      t_engine_mapper_board['board_description'] = board_description

      f = codecs.open(os.path.join(self.output_directory, '{0}-{1}.html'.format(board_name_unquoted, board)), 'w', 'UTF-8')
      f.write(self.t_engine_board.substitute(t_engine_mapper_board))
      f.close()
    #Fix archive generation
    if generate_archive and (not self.cache['last_thread'].has_key(group_id) or self.cache['last_thread'][group_id] != root_message_id_hash):
      self.cache['last_thread'][group_id] = root_message_id_hash
      self.generate_archive(group_id)
    if self.enable_recent:
      self.generate_recent(group_id)


  def get_root_post(self, data, group_id, child_view=0, message_id_hash='', single=False):
    if message_id_hash == '': message_id_hash = sha1(data[0]).hexdigest()
    return self.t_engine_message_root.substitute(self.get_preparse_post(data, message_id_hash, group_id, 25, 2000, child_view, '', '', single))

  def get_child_post(self, data, message_id_hash, group_id, father, father_pubkey, single):
    if  data[6] != '':
      return self.t_engine_message_pic.substitute  (self.get_preparse_post(data, message_id_hash, group_id, 20, 1500, 0, father, father_pubkey, single))
    else:
      return self.t_engine_message_nopic.substitute(self.get_preparse_post(data, message_id_hash, group_id, 20, 1500, 0, father, father_pubkey, single))

  def get_childs_posts(self, parent, group_id, father, father_pubkey, child_count=4, single=False):
    childs = list()
    childs.append('') # FIXME: the fuck is this for?
    for child_row in self.sqlite.execute('SELECT * FROM (SELECT article_uid, sender, subject, sent, message, imagename, imagelink, thumblink, public_key \
        FROM articles WHERE parent = ? AND parent != article_uid AND group_id = ? ORDER BY sent DESC LIMIT ?) ORDER BY sent ASC', (parent, group_id, child_count)).fetchall():
      childs.append(self.get_child_post(child_row, sha1(child_row[0]).hexdigest(), group_id, father, father_pubkey, single))
    return childs

  def generate_pagelist(self, count, current, board_name_unquoted, archive_link=False):
    if count < 2: return ''
    pagelist = list()
    pagelist.append('Pages: ')
    for page in xrange(1, count + 1):
      if page != current:
        pagelist.append('<a href="{0}-{1}.html">[{1}]</a> '.format(board_name_unquoted, page))
      else:
        pagelist.append('[{0}] '.format(page))
    if archive_link: pagelist.append('<a href="{0}-archive-1.html">[Archive]</a> '.format(board_name_unquoted))
    return pagelist

  def get_preparse_post(self, data, message_id_hash, group_id, max_row, max_chars, child_view, father='', father_pubkey='', single=False):
    #father initiate parsing child post and contain root_post_hash_id
        #data = 0 - article_uid 1- sender 2 - subject 3 - sent 4 - message 5 - imagename 6 - imagelink 7 - thumblink -8 public_key for root post add 9-lastupdate
    #message_id_hash = sha1(data[0]).hexdigest() #use globally for decrease sha1 root post uid iteration
    is_playable = False
    parsed_data = dict()
    if data[6] != '':
        imagelink = data[6]
        if data[7] == 'document':
          thumblink = self.document_file
        elif data[7] == 'invalid':
          thumblink = self.invalid_file
        elif data[7] == 'audio':
          thumblink = self.audio_file
        elif data[7] == 'video':
          thumblink = self.webm_file
        elif data[7] == 'censored':
          thumblink = self.censored_file
        elif data[7] == 'archive':
          thumblink = self.archive_file
        elif data[7] == 'torrent':
          thumblink = self.torrent_file
        else:
          thumblink = data[7]
          if data[6] != data[7] and data[6].rsplit('.', 1)[-1] in ('gif', 'webm', 'mp4'):
            is_playable = True
    else:
      imagelink = thumblink = self.no_file
    if data[8] != '':
      parsed_data['signed'] = self.t_engine_signed.substitute(
        articlehash=message_id_hash[:10],
        pubkey=data[8],
        pubkey_short=self.generate_pubkey_short_utf_8(data[8])
      )
      author = self.pubkey_to_name(data[8], father_pubkey, data[1])
      if author == '': author = data[1]
    else:
      parsed_data['signed'] = ''
      author = data[1]
    if not single and len(data[4].split('\n')) > max_row:
      if father != '':
        message = '\n'.join(data[4].split('\n')[:max_row]) + '\n[..] <a href="thread-%s.html#%s"><i>message too large</i></a>' % (father[:10], message_id_hash[:10])
      else:
        message = '\n'.join(data[4].split('\n')[:max_row]) + '\n[..] <a href="thread-%s.html"><i>message too large</i></a>' % message_id_hash[:10]
    elif not single and len(data[4]) > max_chars:
      if father != '':
        message = data[4][:max_chars] + '\n[..] <a href="thread-%s.html#%s"><i>message too large</i></a>' % (father[:10], message_id_hash[:10])
      else:
        message = data[4][:max_chars] + '\n[..] <a href="thread-%s.html"><i>message too large</i></a>' % message_id_hash[:10]
    else:
      message = data[4]
    message = self.markup_parser(message)
    if father == '':
      child_count = int(self.sqlite.execute('SELECT count(article_uid) FROM articles WHERE parent = ? AND parent != article_uid AND group_id = ?', (data[0], group_id)).fetchone()[0])
      if child_count > child_view:
        missing = child_count - child_view
        if missing == 1:
          post = "post"
        else:
          post = "posts"
        message += '\n\n<a href="thread-{0}.html">{1} {2} omitted</a>'.format(message_id_hash[:10], missing, post)
        if child_view < 10000 and child_count > 80:
          start_link = child_view / 50 * 50 + 50
          if start_link % 100 == 0: start_link += 50
          if child_count - start_link > 0:
            message += ' [%s ]' % ''.join(' <a href="thread-{0}-{1}.html">{1}</a>'.format(message_id_hash[:10], x) for x in range(start_link, child_count, 100))
    parsed_data['frontend'] = self.frontend(data[0])
    parsed_data['message'] = message
    parsed_data['articlehash'] = message_id_hash[:10]
    parsed_data['articlehash_full'] = message_id_hash
    parsed_data['author'] = author
    if father != '' and data[2] == 'None':
      parsed_data['subject'] = ''
    else:
      parsed_data['subject'] = data[2]
    parsed_data['sent'] = datetime.utcfromtimestamp(data[3] + self.utc_time_offset).strftime(self.datetime_format)
    parsed_data['imagelink'] = imagelink
    parsed_data['thumblink'] = thumblink
    parsed_data['imagename'] = data[5]
    if father != '':
      parsed_data['parenthash'] = father[:10]
      parsed_data['parenthash_full'] = father
    else:
      if data[9] > time.time():
        parsed_data['sticky_mark'] = ' [x]'
        parsed_data['sticky_prefix'] = 'un'
      else:
        parsed_data['sticky_mark'] = parsed_data['sticky_prefix'] = ''
    if self.fake_id:
      parsed_data['article_id'] = self.message_uid_to_fake_id(data[0])
    else:
      parsed_data['article_id'] = message_id_hash[:10]
    if is_playable:
      parsed_data['play_button'] = '<span class="play_button"></span>'
    else:
      parsed_data['play_button'] = ''
    return parsed_data

  def generate_archive(self, group_id):
    boardlist, full_board_name_unquoted, board_name_unquoted, board_name, board_description = self.generate_board_list(group_id, True)
    # Get threads count offsetting threads in main board pages
    offset = self.threads_per_page * self.pages_per_board
    # we want anoter threads_per_page setting for archive pages
    threads_per_page = self.archive_threads_per_page
    pages_per_board = self.archive_pages_per_board
    threads = int(self.sqlite.execute('SELECT count(group_id) FROM (SELECT group_id FROM articles WHERE group_id = ? AND (parent = "" OR parent = article_uid) LIMIT ? OFFSET ?)', (group_id, threads_per_page * pages_per_board, offset)).fetchone()[0])
    pages = int(threads / threads_per_page)
    if threads % threads_per_page != 0:
      pages += 1

    for board in xrange(1, pages + 1):
      board_offset = threads_per_page * (board - 1) + offset
      threads = list()
      self.log(self.logger.INFO, 'generating %s/%s-archive-%s.html' % (self.output_directory, board_name_unquoted, board))
      for root_row in self.sqlite.execute('SELECT article_uid, sender, subject, sent, message, imagename, imagelink, thumblink, public_key, last_update FROM \
        articles WHERE group_id = ? AND (parent = "" OR parent = article_uid) ORDER BY last_update DESC LIMIT ? OFFSET ?', (group_id, threads_per_page, board_offset)).fetchall():
        threads.append(
          self.t_engine_archive_threads.substitute(
            message_root=self.get_root_post(root_row, group_id)
          )
        )
      t_engine_mapper_board = dict()
      t_engine_mapper_board['threads'] = ''.join(threads)
      t_engine_mapper_board['pagelist'] = ''.join(self.generate_pagelist(pages, board, board_name_unquoted+'-archive'))
      t_engine_mapper_board['boardlist'] = ''.join(boardlist)
      t_engine_mapper_board['full_board'] = full_board_name_unquoted
      t_engine_mapper_board['board'] = board_name
      t_engine_mapper_board['target'] = "{0}-archive-1.html".format(board_name_unquoted)
      t_engine_mapper_board['board_description'] = board_description

      f = codecs.open(os.path.join(self.output_directory, '{0}-archive-{1}.html'.format(board_name_unquoted, board)), 'w', 'UTF-8')
      f.write(self.t_engine_board_archive.substitute(t_engine_mapper_board))
      f.close()

  def generate_recent(self, group_id):
    boardlist, full_board_name_unquoted, board_name_unquoted, board_name, board_description = self.generate_board_list(group_id, True)
    # get only freshly updated threads
    timestamp = int(time.time()) - 3600*24
    threads = list()
    self.log(self.logger.INFO, 'generating %s/%s-recent.html' % (self.output_directory, board_name_unquoted))
    for root_row in self.sqlite.execute('SELECT article_uid, sender, subject, sent, message, imagename, imagelink, thumblink, public_key, last_update \
        FROM articles WHERE group_id = ? AND (parent = "" OR parent = article_uid) AND last_update > ? ORDER BY last_update DESC', (group_id, timestamp)).fetchall():
      root_message_id_hash = sha1(root_row[0]).hexdigest()
      threads.append(
        self.t_engine_board_threads.substitute(
          message_root=self.get_root_post(root_row, group_id, 4, root_message_id_hash),
          message_childs=''.join(self.get_childs_posts(root_row[0], group_id, root_message_id_hash, root_row[8], 4))
        )
      )
    t_engine_mapper_board_recent = dict()
    t_engine_mapper_board_recent['threads'] = ''.join(threads)
    t_engine_mapper_board_recent['boardlist'] = ''.join(boardlist)
    t_engine_mapper_board_recent['full_board'] = full_board_name_unquoted
    t_engine_mapper_board_recent['board'] = board_name
    t_engine_mapper_board_recent['target'] = "{0}-recent.html".format(board_name_unquoted)
    t_engine_mapper_board_recent['board_description'] = board_description

    f = codecs.open(os.path.join(self.output_directory, '{0}-recent.html'.format(board_name_unquoted)), 'w', 'UTF-8')
    f.write(self.t_engine_board_recent.substitute(t_engine_mapper_board_recent))
    f.close()
    del boardlist
    del threads

  def frontend(self, uid):
    if '@' in uid:
      frontend = uid.split('@')[1][:-1]
    else:
      frontend = 'nntp'
    return frontend

  def generate_thread(self, root_uid, thread_page=0):
    root_row = self.sqlite.execute('SELECT article_uid, sender, subject, sent, message, imagename, imagelink, thumblink, public_key, last_update, group_id \
        FROM articles WHERE article_uid = ?', (root_uid,)).fetchone()
    if not root_row:
      # FIXME: create temporary root post here? this will never get called on startup because it checks for root posts only
      # FIXME: ^ alternatives: wasted threads in admin panel? red border around images in pic log? actually adding temporary root post while processing?
      #root_row = (root_uid, 'none', 'root post not yet available', 0, 'root post not yet available', '', '', 0, '')
      self.log(self.logger.INFO, 'root post not yet available: %s, should create temporary root post here' % root_uid)
      return
    root_message_id_hash = sha1(root_uid).hexdigest()#self.sqlite_hashes.execute('SELECT message_id_hash from article_hashes WHERE message_id = ?', (root_row[0],)).fetchone()
    # FIXME: benchmark sha1() vs hasher_db_query
    if thread_page > 0:
      thread_postfix = '-%s' % (thread_page * 50)
      max_child_view = thread_page * 50
    else:
      thread_postfix = ''
      max_child_view = 10000
    if self.check_board_flags(root_row[10], 'blocked'):
      path = os.path.join(self.output_directory, 'thread-%s%s.html' % (root_message_id_hash[:10], thread_postfix))
      if os.path.isfile(path):
        self.log(self.logger.INFO, 'this thread belongs to some blocked board. deleting %s.' % path)
        try:
          os.unlink(path)
        except Exception as e:
          self.log(self.logger.ERROR, 'could not delete %s: %s' % (path, e))
      return
    if thread_page == 0:
      child_count = int(self.sqlite.execute('SELECT count(article_uid) FROM articles WHERE parent = ? AND parent != article_uid AND group_id = ?', (root_row[0], root_row[10])).fetchone()[0])
      if child_count > 80:
        thread_page = child_count / 50
    else:
      thread_page -= 1
    if thread_page > 0 and thread_page % 2 == 0:
      thread_page -= 1
    self.log(self.logger.INFO, 'generating %s/thread-%s%s.html' % (self.output_directory, root_message_id_hash[:10], thread_postfix))
    boardlist, full_board_name_unquoted, board_name_unquoted, board_name, board_description = self.generate_board_list(root_row[10], True)

    threads = list()
    threads.append(
      self.t_engine_board_threads.substitute(
        message_root=self.get_root_post(root_row[:-1], root_row[10], max_child_view, root_message_id_hash, True),
        message_childs=''.join(self.get_childs_posts(root_row[0], root_row[10], root_message_id_hash, root_row[8], max_child_view, True))
      )
    )
    t_engine_mappings_thread_single = dict()
    t_engine_mappings_thread_single['boardlist'] = ''.join(boardlist)
    t_engine_mappings_thread_single['thread_id'] = root_message_id_hash
    t_engine_mappings_thread_single['board'] = board_name
    t_engine_mappings_thread_single['full_board'] = full_board_name_unquoted
    t_engine_mappings_thread_single['target'] = "{0}-1.html".format(board_name_unquoted)
    t_engine_mappings_thread_single['subject'] = root_row[2][:60]
    t_engine_mappings_thread_single['thread_single'] = ''.join(threads)
    t_engine_mappings_thread_single['board_description'] = board_description

    f = codecs.open(os.path.join(self.output_directory, 'thread-{0}{1}.html'.format(root_message_id_hash[:10], thread_postfix)), 'w', 'UTF-8')
    f.write(self.t_engine_thread_single.substitute(t_engine_mappings_thread_single))
    f.close()
    if thread_page > 0: self.generate_thread(root_uid, thread_page)

  def generate_index(self):
    self.log(self.logger.INFO, 'generating %s/index.html' % self.output_directory)
    f = codecs.open(os.path.join(self.output_directory, 'index.html'), 'w', 'UTF-8')
    f.write(self.t_engine_index.substitute())
    f.close()

  def generate_menu(self):
    self.log(self.logger.INFO, 'generating %s/menu.html' % self.output_directory)
    t_engine_mappings_menu = dict()
    t_engine_mappings_menu_entry = dict()
    menu_entries = list()
    menu_entries.append('<li><a href="/" target="_top">Main</a></li><br />\n')
    exclude_flags = self.cache['flags']['hidden'] | self.cache['flags']['blocked']
    for group_row in self.sqlite.execute('SELECT group_name, group_id, ph_name, link FROM groups WHERE \
      (cast(groups.flags as integer) & ?) = 0 ORDER by group_name ASC', (exclude_flags,)).fetchall():
      group_name = group_row[0].split('.', 1)[1].replace('"', '').replace('/', '')
      if self.use_unsecure_aliases and group_row[3] != '':
        group_link = group_row[3]
      else:
        group_link = '%s-1.html' % group_name
      if group_row[2] != '':
        group_name_encoded = self.basicHTMLencode(group_row[2].replace('"', '').replace('/', ''))
      else:
        group_name_encoded = self.basicHTMLencode(group_row[0].split('.', 1)[1].replace('"', '').replace('/', ''))
      t_engine_mappings_menu_entry['group_link'] = group_link
      t_engine_mappings_menu_entry['group_name'] = group_name
      t_engine_mappings_menu_entry['group_name_encoded'] = group_name_encoded
      # get fresh posts count
      timestamp = int(time.time()) - 3600*24
      t_engine_mappings_menu_entry['postcount'] = self.sqlite.execute('SELECT count(article_uid) FROM articles WHERE group_id = ? AND sent > ?', (group_row[1], timestamp)).fetchone()[0]
      menu_entries.append(self.t_engine_menu_entry.substitute(t_engine_mappings_menu_entry))
    t_engine_mappings_menu['menu_entries'] = ''.join(menu_entries)

    f = codecs.open(os.path.join(self.output_directory, 'menu.html'), 'w', 'UTF-8')
    f.write(self.t_engine_menu.substitute(t_engine_mappings_menu))
    f.close()

  def check_board_flags(self, group_id, *args):
    try:
      flags = int(self.sqlite.execute('SELECT flags FROM groups WHERE group_id = ?', (group_id,)).fetchone()[0])
      for flag_name in args:
        if flags & self.cache['flags'][flag_name] == 0:
          return False
    except Exception as e:
      self.log(self.logger.WARNING, "error board flags check: %s" % e)
      return False
    return True

  def check_moder_flags(self, full_pubkey_hex, *args):
    try:
      flags = int(self.censordb.execute('SELECT flags from keys WHERE key=?', (full_pubkey_hex,)).fetchone()[0])
      for flag_name in args:
        if flags & self.cache['moder_flags'][flag_name] == 0:
          return False
    except:
      return False
    return True

  def cache_init(self):
    for row in self.sqlite.execute('SELECT flag_name, cast(flag as integer) FROM flags WHERE flag_name != ""').fetchall():
      self.cache['flags'][row[0]] = row[1]
    for row in self.censordb.execute('SELECT command, cast(flag as integer) FROM commands WHERE command != ""').fetchall():
      self.cache['moder_flags'][row[0]] = row[1]

  def generate_board_list(self, group_id='', selflink=False):
    full_board_name_unquoted = board_name_unquoted = board_name = board_description = ''
    boardlist = list()
    # FIXME: cache this shit somewhere
    exclude_flags = self.cache['flags']['hidden'] | self.cache['flags']['blocked']
    for group_row in self.sqlite.execute('SELECT group_name, group_id, ph_name, ph_shortname, link, description FROM groups \
      WHERE ((cast(flags as integer) & ?) = 0 OR group_id = ?) ORDER by group_name ASC', (exclude_flags, group_id)).fetchall():
      current_group_name = group_row[0].split('.', 1)[1].replace('"', '').replace('/', '')
      if group_row[3] != '':
        current_group_name_encoded = self.basicHTMLencode(group_row[3])
      else:
        current_group_name_encoded = self.basicHTMLencode(current_group_name)
      if self.use_unsecure_aliases and group_row[4] != '':
        board_link = group_row[4]
      else:
        board_link = '%s-1.html' % current_group_name
      if group_row[1] != group_id or selflink:
        boardlist.append(u' <a href="{0}">{1}</a> /'.format(board_link, current_group_name_encoded))
      else:
        boardlist.append(' ' + current_group_name_encoded + ' /')
      if group_row[1] == group_id:
        full_board_name_unquoted = group_row[0].replace('"', '').replace('/', '')
        full_board_name = self.basicHTMLencode(full_board_name_unquoted)
        board_name_unquoted = full_board_name_unquoted.split('.', 1)[1]
        board_description = group_row[5]
        if group_row[2] != '':
          board_name = self.basicHTMLencode(group_row[2])
        else:
          board_name = full_board_name.split('.', 1)[1]
    if not self.use_unsecure_aliases:
      board_description = self.markup_parser(self.basicHTMLencode(board_description))
    if boardlist: boardlist[-1] = boardlist[-1][:-1]
    if group_id != '':
      return boardlist, full_board_name_unquoted, board_name_unquoted, board_name, board_description
    else:
      return boardlist

  def generate_overview(self):
    self.log(self.logger.INFO, 'generating %s/overview.html' % self.output_directory)
    t_engine_mappings_overview = dict()
    t_engine_mappings_overview['boardlist'] = ''.join(self.generate_board_list())
    news_board_link = 'overview.html'
    news_board = self.sqlite.execute('SELECT group_id, group_name FROM groups WHERE \
        (cast(flags as integer) & ?) != 0 AND (cast(flags as integer) & ?) = 0', (self.cache['flags']['news'], self.cache['flags']['blocked'])).fetchone()
    if news_board:
      news_board_link = '{0}-1.html'.format(news_board[1].replace('"', '').replace('/', '').split('.', 1)[1])
      row = self.sqlite.execute('SELECT subject, message, sent, public_key, article_uid, sender FROM articles \
          WHERE group_id = ? AND (parent = "" OR parent = article_uid) ORDER BY last_update DESC LIMIT 1', (news_board[0], )).fetchone()
    if not (news_board and row):
      t_engine_mappings_overview['subject'] = ''
      t_engine_mappings_overview['sent'] = ''
      t_engine_mappings_overview['author'] = ''
      t_engine_mappings_overview['pubkey_short'] = ''
      t_engine_mappings_overview['pubkey'] = ''
      t_engine_mappings_overview['parent'] = 'does_not_exist_yet'
      t_engine_mappings_overview['message'] = 'once upon a time there was a news post'
      t_engine_mappings_overview['allnews_link'] = news_board_link
      t_engine_mappings_overview['comment_count'] = ''
    else:
      moder_name = ''
      news_board_link = '{0}-1.html'.format(news_board[1].replace('"', '').replace('/', '').split('.', 1)[1])
      parent = sha1(row[4]).hexdigest()[:10]
      if len(row[1].split('\n')) > 5:
        message = '\n'.join(row[1].split('\n')[:5]) + '\n[..] <a href="thread-%s.html"><i>message too large</i></a>' % parent
      elif len(row[1]) > 1000:
        message = row[1][:1000] + '\n[..] <a href="thread-%s.html"><i>message too large</i></a>' % parent
      else:
        message = row[1]
      message = self.markup_parser(message)
      if row[0] == 'None' or row[0] == '':
        t_engine_mappings_overview['subject'] = 'Breaking news'
      else:
        t_engine_mappings_overview['subject'] = row[0]
      t_engine_mappings_overview['sent'] = datetime.utcfromtimestamp(row[2] + self.utc_time_offset).strftime(self.datetime_format)
      if not row[3] == '':
          t_engine_mappings_overview['pubkey_short'] = self.generate_pubkey_short_utf_8(row[3])
          moder_name = self.pubkey_to_name(row[3])
      else:
          t_engine_mappings_overview['pubkey_short'] = ''
      if moder_name: t_engine_mappings_overview['author'] = moder_name
      else: t_engine_mappings_overview['author'] = row[5]
      t_engine_mappings_overview['pubkey'] = row[3]
      t_engine_mappings_overview['parent'] = parent
      t_engine_mappings_overview['message'] = message
      t_engine_mappings_overview['allnews_link'] = news_board_link
      t_engine_mappings_overview['comment_count'] = self.sqlite.execute('SELECT count(article_uid) FROM articles WHERE \
          parent = ? AND parent != article_uid AND group_id = ?', (row[4], news_board[0])).fetchone()[0]
    weekdays = ('Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday')
    max_post = 0
    stats = list()
    bar_length = 20
    days = 30
    utc_offset = str(self.utc_time_offset) + ' seconds'
    totals = int(self.sqlite.execute('SELECT count(1) FROM articles WHERE sent > strftime("%s", "now", "-' + str(days) + ' days")').fetchone()[0])
    stats.append(self.template_stats_usage_row.replace('%%postcount%%', str(totals)).replace('%%date%%', 'all posts').replace('%%weekday%%', '').replace('%%bar%%', 'since %s days' % days))
    for row in self.sqlite.execute('SELECT count(1) as counter, strftime("%Y-%m-%d", sent, "unixepoch", "' + utc_offset + '") as day, strftime("%w", sent, "unixepoch", "' + utc_offset + '") as weekday FROM articles WHERE sent > strftime("%s", "now", "-' + str(days) + ' days") GROUP BY day ORDER BY day DESC').fetchall():
      if row[0] > max_post:
        max_post = row[0]
      stats.append((row[0], row[1], weekdays[int(row[2])]))
    for index in range(1, len(stats)):
      graph = '=' * int(float(stats[index][0])/max_post*bar_length)
      if len(graph) == 0:
        graph = '&nbsp;'
      stats[index] = self.template_stats_usage_row.replace('%%postcount%%', str(stats[index][0])).replace('%%date%%', stats[index][1]).replace('%%weekday%%', stats[index][2]).replace('%%bar%%', graph)
    overview_stats_usage = self.template_stats_usage
    overview_stats_usage = overview_stats_usage.replace('%%stats_usage_rows%%', ''.join(stats))
    t_engine_mappings_overview['stats_usage'] = overview_stats_usage
    del stats[:]

    postcount = 50
    exclude_flags = self.cache['flags']['hidden'] | self.cache['flags']['no-overview'] | self.cache['flags']['blocked']
    for row in self.sqlite.execute('SELECT sent, group_name, sender, subject, article_uid, parent, ph_name FROM articles, groups WHERE \
      (cast(groups.flags as integer) & ?) = 0 AND articles.group_id = groups.group_id AND \
      (articles.parent = "" OR articles.parent = articles.article_uid OR articles.parent IN (SELECT article_uid FROM articles)) \
      ORDER BY sent DESC LIMIT ?', (exclude_flags, str(postcount))).fetchall():
      sent = datetime.utcfromtimestamp(row[0] + self.utc_time_offset).strftime(self.datetime_format)
      if row[6] != '':
        board = self.basicHTMLencode(row[6].replace('"', ''))
      else:
        board = self.basicHTMLencode(row[1].replace('"', '')).split('.', 1)[1]
      author = row[2][:12]
      articlehash = sha1(row[4]).hexdigest()[:10]
      if row[5] in ('', row[4]):
        # root post
        parent = articlehash
        subject = row[3][:60]
        if subject in ('', 'None'):
          subject = self.sqlite.execute('SELECT message FROM articles WHERE article_uid = ?', (row[4],)).fetchone()[0][:60]
      else:
        parent = sha1(row[5]).hexdigest()[:10]
        subject = self.sqlite.execute('SELECT subject FROM articles WHERE article_uid = ?', (row[5],)).fetchone()[0][:60]
        if subject in ('', 'None'):
          subject = self.sqlite.execute('SELECT message FROM articles WHERE article_uid = ?', (row[5],)).fetchone()[0][:60]
      if subject == '':
        subject = 'None'
      stats.append(self.template_latest_posts_row.replace('%%sent%%', sent).replace('%%board%%', board).replace('%%parent%%', parent).replace('%%articlehash%%', articlehash).replace('%%author%%', author).replace('%%subject%%', subject))
    overview_latest_posts = self.template_latest_posts
    overview_latest_posts = overview_latest_posts.replace('%%latest_posts_rows%%', ''.join(stats))
    t_engine_mappings_overview['latest_posts'] = overview_latest_posts
    del stats[:]

    exclude_flags = self.cache['flags']['hidden'] | self.cache['flags']['blocked']
    for row in self.sqlite.execute('SELECT count(1) as counter, group_name, ph_name FROM articles, groups WHERE \
      (cast(groups.flags as integer) & ?) = 0 AND articles.group_id = groups.group_id GROUP BY \
      articles.group_id ORDER BY counter DESC', (exclude_flags,)).fetchall():
      if row[2] != '':
        board = self.basicHTMLencode(row[2].replace('"', ''))
      else:
        board = self.basicHTMLencode(row[1].replace('"', ''))
      stats.append(self.template_stats_boards_row.replace('%%postcount%%', str(row[0])).replace('%%board%%', board))
    overview_stats_boards = self.template_stats_boards
    overview_stats_boards = overview_stats_boards.replace('%%stats_boards_rows%%', ''.join(stats))
    t_engine_mappings_overview['stats_boards'] = overview_stats_boards

    f = codecs.open(os.path.join(self.output_directory, 'overview.html'), 'w', 'UTF-8')
    f.write(self.t_engine_overview.substitute(t_engine_mappings_overview))
    f.close()

if __name__ == '__main__':
  # FIXME fix this shit
  overchan = main('overchan', args)
  while True:
    try:
      print "signal.pause()"
      signal.pause()
    except KeyboardInterrupt as e:
      print
      self.sqlite_conn.close()
      self.log('bye', 2)
      exit(0)
    except Exception as e:
      print "Exception:", e
      self.sqlite_conn.close()
      self.log('bye', 2)
      exit(0)
