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
import json
from srnd.utils import basicHTMLencode, generate_pubkey_short_utf_8, html_minifer, css_minifer
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
    if __name__ == '__main__':
      exit(1)
    else:
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

    self._compite_regexp()

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
      self._load_templates()
      i = open(os.path.join(self.config['template_directory'], self.config['csss'][0]), 'r')
      o = open(os.path.join(self.config['output_directory'], 'styles.css'), 'w')
      o.write(i.read())
      o.close()
      i.close()
      if not self.init_standalone():
        exit(1)
    else:
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

  def _css_headers_construct(self):
    with codecs.open(os.path.join(self.config['template_directory'], 'base_css_head.tmpl'), "r", "utf-8") as f:
      css_header = string.Template(f.read().rstrip())
    return '\n'.join([css_header.substitute(stylesheet=css) for css in self.config['csss'] \
                      if os.path.isfile(os.path.join(self.config['output_directory'], css)) and os.stat(os.path.join(self.config['output_directory'], css)).st_size > 0])

  def _load_templates(self):
    start_time = time.time()
    self.t_engine = dict()
    for x in ('stats_usage_row', 'latest_posts_row', 'stats_boards_row', 'news'):
      template_file = os.path.join(self.config['template_directory'], '%s.tmpl' % x)
      try:
        f = codecs.open(template_file, "r", "utf-8")
      except IOError as e:
        self.die('Error loading template {0}: {1}'.format(template_file, e))
      else:
        self.t_engine[x] = string.Template(f.read())
        f.close()

    # temporary templates
    template_brick = dict()
    for x in ('help', 'base_pagelist', 'base_postform', 'base_footer', 'dummy_postform', 'message_child_quickreply', 'message_root_quickreply', 'stats_usage', \
      'latest_posts', 'stats_boards', 'base_help', 'base_js_head'):
      template_file = os.path.join(self.config['template_directory'], '%s.tmpl' % x)
      try:
        f = codecs.open(template_file, "r", "utf-8")
      except IOError as e:
        self.die('Error loading template {0}: {1}'.format(template_file, e))
      else:
        template_brick[x] = f.read()
        f.close()

    evil_cmd = self._load_evil_commands()
    css_headers = self._css_headers_construct()
    for target, evil_inject in (('message_root', 'root'), ('message_child_pic', 'child_pic'), ('message_child_nopic', 'child_nopic')):
      with codecs.open(os.path.join(self.config['template_directory'], '{}.tmpl'.format(target)), "r", "utf-8") as f:
        template_brick[target] = string.Template(f.read()).safe_substitute(
            {'evil_{}'.format(evil_inject): evil_cmd.get(evil_inject, 'Internal error')}
        )
    with codecs.open(os.path.join(self.config['template_directory'], 'base_head.tmpl'), "r", "utf-8") as f:
      template_brick['base_head'] = string.Template(f.read()).safe_substitute(
          stylesheet=css_headers,
          title=self.config['title']
      )
    template_brick['base_head_prep'] = string.Template(template_brick['base_head']).safe_substitute(
        head_title=string.Template('${title} :: ${board}').safe_substitute(title=self.config['title']),
        javascript=template_brick['base_js_head']
    )
    f = codecs.open(os.path.join(self.config['template_directory'], 'thread_single.tmpl'), "r", "utf-8")
    template_brick['thread_single'] = string.Template(
        string.Template(f.read()).safe_substitute(
            head_single=string.Template(template_brick['base_head']).safe_substitute(
                head_title=string.Template('${title} :: ${board} :: ${subject}').safe_substitute(title=self.config['title']),
                javascript=template_brick['base_js_head']
            ),
            base_help=template_brick['base_help']
        )
    )
    f.close()
    # template_engines
    f = codecs.open(os.path.join(self.config['template_directory'], 'board.tmpl'), "r", "utf-8")
    self.t_engine['board'] = string.Template(
        string.Template(f.read()).safe_substitute(
            base_head=template_brick['base_head_prep'],
            base_pagelist=template_brick['base_pagelist'],
            base_help=template_brick['base_help'],
            base_footer=template_brick['base_footer'],
            base_postform=string.Template(template_brick['base_postform']).safe_substitute(
                postform_action='new thread',
                thread_id='',
                new_thread_id='id="newthread" '
            )
        )
    )
    f.close()
    self.t_engine['thread_single'] = string.Template(
        template_brick['thread_single'].safe_substitute(
            single_postform=string.Template(template_brick['base_postform']).safe_substitute(
                postform_action='reply',
                new_thread_id=''
            )
        )
    )
    self.t_engine['thread_single_closed'] = string.Template(
        template_brick['thread_single'].safe_substitute(
            single_postform=template_brick['dummy_postform']
        )
    )
    f = codecs.open(os.path.join(self.config['template_directory'], 'index.tmpl'), "r", "utf-8")
    self.t_engine['index'] = string.Template(
        string.Template(f.read()).safe_substitute(
            title=self.config['title']
        )
    )
    f.close()
    f = codecs.open(os.path.join(self.config['template_directory'], 'menu.tmpl'), "r", "utf-8")
    self.t_engine['menu'] = string.Template(
        string.Template(f.read()).safe_substitute(
            title=self.config['title'],
            stylesheet=css_headers,
            site_url=self.config['site_url'],
            local_dest=self.config['local_dest']
        )
    )
    f.close()
    f = codecs.open(os.path.join(self.config['template_directory'], 'menu_entry.tmpl'), "r", "utf-8")
    self.t_engine['menu_entry'] = string.Template(f.read())
    f.close()
    f = codecs.open(os.path.join(self.config['template_directory'], 'overview.tmpl'), "r", "utf-8")
    self.t_engine['overview'] = string.Template(
        string.Template(f.read()).safe_substitute(
            stats_usage=template_brick['stats_usage'],
            latest_posts=template_brick['latest_posts'],
            stats_boards=template_brick['stats_boards'],
            head_overview=string.Template(template_brick['base_head']).safe_substitute(
                head_title='{} :: Overview'.format(self.config['title']),
                javascript=''
            )
        )
    )
    f.close()
    f = codecs.open(os.path.join(self.config['template_directory'], 'board_threads.tmpl'), "r", "utf-8")
    self.t_engine['board_threads'] = string.Template(f.read())
    f.close()
    f = codecs.open(os.path.join(self.config['template_directory'], 'archive_threads.tmpl'), "r", "utf-8")
    self.t_engine['archive_threads'] = string.Template(f.read())
    f.close()
    self.t_engine['message_root'] = string.Template(
        string.Template(template_brick['message_root']).safe_substitute(
            root_quickreply=template_brick['message_root_quickreply'],
            click_action='Reply'
        )
    )
    self.t_engine['message_root_closed'] = string.Template(
        string.Template(template_brick['message_root']).safe_substitute(
            root_quickreply='&#8470;  ${article_id}',
            click_action='View'
        )
    )
    self.t_engine['message_pic'] = string.Template(
        string.Template(template_brick['message_child_pic']).safe_substitute(
            child_quickreply=template_brick['message_child_quickreply']
        )
    )
    self.t_engine['message_pic_closed'] = string.Template(
        string.Template(template_brick['message_child_pic']).safe_substitute(
            child_quickreply='${article_id}'
        )
    )
    self.t_engine['message_nopic'] = string.Template(
        string.Template(template_brick['message_child_nopic']).safe_substitute(
            child_quickreply=template_brick['message_child_quickreply']
        )
    )
    self.t_engine['message_nopic_closed'] = string.Template(
        string.Template(template_brick['message_child_nopic']).safe_substitute(
            child_quickreply='${article_id}'
        )
    )
    f = codecs.open(os.path.join(self.config['template_directory'], 'signed.tmpl'), "r", "utf-8")
    self.t_engine['signed'] = string.Template(f.read())
    f.close()
    f = codecs.open(os.path.join(self.config['template_directory'], 'help_page.tmpl'), "r", "utf-8")
    self.t_engine['help_page'] = string.Template(
        string.Template(f.read()).safe_substitute(
            base_head=string.Template(template_brick['base_head_prep']).safe_substitute(board='help'),
            help=template_brick['help'],
            base_footer=template_brick['base_footer']
        )
    )
    f.close()
    if self.config['minify_html']:
      self.t_engine, msg = html_minifer(self.t_engine, ('help_page',))
      self.log(self.logger.INFO, msg)
    self.log(self.logger.INFO, 'Templates loaded at {} seconds'.format(int(time.time() - start_time)))

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

  def init_standalone(self):
    self.log(self.logger.INFO, 'initializing as standalone..')
    signal.signal(signal.SIGIO, self.signal_handler)
    try:
      fd = os.open(self.config['watching'], os.O_RDONLY)
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

  def _load_evil_commands(self, evil_conf='evil_cmd.json'):
    with codecs.open(os.path.join(self.config['template_directory'], evil_conf), 'r', 'UTF-8') as f:
      evil_cmd = json.load(f)
    # Load only enabled commands
    # FIXME: first start table maybe not created. What check it? Re-load templates if values changed?
    try:
      allow_cmd = [x[0] for x in self.censordb.execute('SELECT evil FROM evil_to_srnd, cmd_map WHERE srnd = command AND (send = 1 or send = 0)').fetchall()]
    except sqlite3.Error:
      allow_cmd = ['purge', 'purge_root']
    injected_cmd = {'root': [], 'child_pic': [], 'child_nopic': []}
    for cmd in allow_cmd:
      for target in injected_cmd:
        if target in evil_cmd[cmd]['target']:
          formatting_cmd = '{0}{1}\n{0}{2}'.format(evil_cmd['_base']['html_sugar'], evil_cmd['_base']['input'], evil_cmd['_base']['label'])
          formatting_cmd = string.Template(formatting_cmd).safe_substitute(
              evil_cmd=cmd,
              input_title=evil_cmd[cmd]['input_title'],
              label_txt=evil_cmd[cmd]['label_txt']
          )
          injected_cmd[target].append((formatting_cmd, evil_cmd[cmd]['pos']))
   # sort and join
    for target in injected_cmd:
      injected_cmd[target] = '\n'.join(y[0] for y in sorted(injected_cmd[target], key=lambda x_: x_[1]))
    return injected_cmd

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

    self.regenerate_boards = set()
    self.regenerate_threads = set()
    self.delete_messages = set()
    self.missing_parents = dict()
    self.cache = dict()
    self.cache['page_stamp_archiv'] = dict()
    self.cache['page_stamp'] = dict()
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

    self._load_templates()
    self.cache_init()

    # index generation happens only at startup
    self.generate_index()

    if self.config['generate_all']:
      self.regenerate_all_html()

  def regenerate_all_html(self):
    for group_row in self.sqlite.execute('SELECT group_id FROM groups WHERE (cast(groups.flags as integer) & ?) = 0', (self.cache['flags']['blocked'],)).fetchall():
      self.regenerate_boards.add(group_row[0])
    for thread_row in self.sqlite.execute('SELECT article_uid FROM articles WHERE parent = "" OR parent = article_uid ORDER BY last_update DESC').fetchall():
      self.regenerate_threads.add(thread_row[0])

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
    self.regenerate_boards.add(result[1])
    self.regenerate_threads.add(message_id)
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
    self.regenerate_boards.add(result[1])
    self.regenerate_threads.add(message_id)
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
          self.regenerate_threads.add(row[2])
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
      self.regenerate_boards.add(row[3])
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
    flags = int(args[1]) if len(args) > 1 else 0
    try:
      result = self.sqlite.execute("SELECT flags FROM groups WHERE group_name=?", (group_name,)).fetchone()
      if result is not None:
        flags = int(result[0])
      flags ^= flags & self.cache['flags']['blocked']
      self.sqlite.execute('UPDATE groups SET flags = ? WHERE group_name = ?', (str(flags), group_name))
      self.log(self.logger.INFO, 'unblocked existing board: \'%s\'' % group_name)
    except sqlite3.Error:
      self.sqlite.execute('INSERT INTO groups(group_name, article_count, last_update, flags) VALUES (?,?,?,?)', (group_name, 0, int(time.time()), flags))
      self.log(self.logger.INFO, 'added new board: \'%s\'' % group_name)
    if len(args) > 2:
      self.overchan_aliases_update(args[2], group_name)
    self.sqlite.commit()
    self.__flush_board_cache()
    self.regenerate_all_html()

  def overchan_board_del(self, group_name, flags=0):
    try:
      if flags == 0:
        result = self.sqlite.execute("SELECT flags FROM groups WHERE group_name=?", (group_name,)).fetchone()
        flags |= self.cache['flags']['blocked'] if result is None else int(result[0]) | self.cache['flags']['blocked']
      self.sqlite.execute('UPDATE groups SET flags = ? WHERE group_name = ?', (str(flags), group_name))
      self.sqlite.commit()
    except sqlite3.Error:
      self.log(self.logger.WARNING, 'should delete board %s but there is no board with that name' % group_name)
    else:
      self.log(self.logger.INFO, 'blocked board: \'%s\'' % group_name)
      self.__flush_board_cache()
      self.regenerate_all_html()

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
          self.regenerate_boards.add(group_id)
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
        self.regenerate_boards.add(row[3])
        if row[2] == '':
          self.regenerate_threads.add(message_id)
        else:
          self.regenerate_threads.add(row[2])
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

  def signal_handler(self, signum, frame):
    # FIXME use try: except: around open(), also check for duplicate here
    for item in os.listdir(self.config['watching']):
      link = os.path.join(self.config['watching'], item)
      f = open(link, 'r')
      if not self.parse_message(item, f):
        f.close()
      os.remove(link)
    if len(self.regenerate_boards) > 0:
      for board in self.regenerate_boards:
        self.generate_board(board)
      self.regenerate_boards.clear()
    if len(self.regenerate_threads) > 0:
      for thread in self.regenerate_threads:
        self.generate_thread(thread, False)
      self.regenerate_threads.clear()

  def run(self):
    if self.should_terminate:
      return
    if  __name__ == '__main__':
      return
    self.log(self.logger.INFO, 'starting up as plugin..')
    self.past_init()
    self.running = True
    regen_overview = True
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
        if len(self.regenerate_boards) > 0:
          do_sleep = len(self.regenerate_boards) > self.config['sleep_threshold']
          if do_sleep:
            self.log(self.logger.DEBUG, 'boards: should sleep')
          for board in self.regenerate_boards:
            if not self.running:
              break
            self.generate_board(board)
            if do_sleep:
              time.sleep(self.config['sleep_time'])
          self.regenerate_boards.clear()
          regen_overview = True
        if len(self.regenerate_threads) > 0:
          self._generate_threads()
          regen_overview = True
        if regen_overview:
          self.generate_overview()
          # generate menu.html simultaneously with overview
          self.generate_menu()
          if self.config['enable_top']:
            self.generate_top_page()
          regen_overview = False
        if got_control_count > 100:
          self.sqlite.execute('VACUUM;')
          self.sqlite.commit()
          got_control_count = 0
    self.censordb.close()
    self.sqlite.close()
    self.dropperdb.close()
    self.log(self.logger.INFO, 'bye')

  def _generate_threads(self):
    thread_count = len(self.regenerate_threads)
    step_say = thread_count / 50
    silence = thread_count >= step_say and thread_count > 100
    do_sleep = thread_count > self.config['sleep_threshold']
    if do_sleep:
      self.log(self.logger.DEBUG, 'threads: should sleep')
    start_time = time.time()
    result_time = 0.0
    result_counter = 0
    counter = 0
    for thread in self.regenerate_threads:
      if self.running:
        self.generate_thread(thread, silence)
        if do_sleep:
          time.sleep(self.config['sleep_time'])
        counter += 1
        result_counter += 1
      if silence and (counter >= step_say or ((not self.running or thread_count == result_counter) and counter > 0)):
        all_time = time.time() - start_time
        result_time += all_time
        sleep_time = self.config['sleep_time'] * counter if do_sleep else 0
        percentage = (100 * result_counter) / thread_count
        self.log(self.logger.INFO, 'generating {} [{:3}%] threads at {:0.4f}s [work:{:0.4f}s, sleep:{:0.4f}s]'.format(counter, percentage, all_time, (all_time - sleep_time), sleep_time))
        start_time = time.time()
        counter = 0
      if not self.running:
        break
    if silence and result_counter > 0:
      sleep_time = self.config['sleep_time'] * result_counter if do_sleep else 0
      work_time = result_time - sleep_time
      percentage = (100 * result_counter) / thread_count
      self.log(self.logger.INFO, 'result generating [{}/{}] [{}%] threads {:0.4f}s [work:{:0.4f}s, sleep:{:0.4f}s]'.format(result_counter, thread_count, percentage, result_time, work_time, sleep_time))
      self.log(self.logger.INFO, 'average generating 1 thread {:0.4f}s [work:{:0.4f}s, sleep:{:0.4f}s]'.format(result_time/result_counter, work_time/result_counter, sleep_time/result_counter))
    self.regenerate_threads.clear()

  def message_uid_to_fake_id(self, message_uid):
    fake_id = self.dropperdb.execute('SELECT article_id FROM articles WHERE message_id = ?', (message_uid,)).fetchone()
    return fake_id[0] if fake_id is not None else sha1(message_uid).hexdigest()[:10]

  def get_moder_name(self, full_pubkey_hex):
    try:
      result = self.censordb.execute('SELECT local_name from keys WHERE key=? and local_name != ""', (full_pubkey_hex,)).fetchone()
    except sqlite3.Error:
      return None
    else:
      return result[0] if result is not None else None

  def pubkey_to_name(self, full_pubkey_hex, root_full_pubkey_hex='', sender=''):
    op_flag, nickname = '', ''
    local_name = self.get_moder_name(full_pubkey_hex)
    if full_pubkey_hex == root_full_pubkey_hex:
      op_flag = '<span class="op-kyn">OP</span> '
      nickname = sender
    if local_name is not None:
      nickname = '<span class="zoi">%s</span>' % local_name
    return '%s%s' % (op_flag, nickname)

  def upp_it(self, data):
    if data[-1] not in self.upper_table:
      return data
    return data[:-1] + self.upper_table[data[-1]]

  def linkit(self, rematch):
    row = self.sqlite.execute("SELECT article_uid, parent, group_id FROM articles WHERE article_hash >= ? and article_hash < ?", (rematch.group(2), self.upp_it(rematch.group(2)))).fetchall()
    if not row or len(row) > 1:
      # hash not found or multiple matches for that 10 char hash
      return rematch.group(0)
    message_id, parent_id, group_id = row[0]
    if self.__current_markup_parser_group_id is not None and group_id != self.__current_markup_parser_group_id:
      another_board = u' [%s]' % self.get_board_data(int(group_id), 'board')[:20]
    else:
      another_board = ''
    if self.config['fake_id']:
      article_name = self.message_uid_to_fake_id(message_id)
    else:
      article_name = rematch.group(2)
    if parent_id == "":
      # article is root post
      return u'<a onclick="return highlight(\'{0}\');" href="thread-{0}.html">{1}{2}{3}</a>'.format(rematch.group(2), rematch.group(1), article_name, another_board)
    # article has a parent
    # FIXME: cache results somehow?
    parent = sha1(parent_id).hexdigest()[:10]
    return u'<a onclick="return highlight(\'{0}\');" href="thread-{1}.html#{0}">{2}{3}{4}</a>'.format(rematch.group(2), parent, rematch.group(1), article_name, another_board)

  @staticmethod
  def quoteit(rematch):
    return u'<span class="quote">%s</span>' % rematch.group(0).rstrip("\r")

  @staticmethod
  def clickit(rematch):
    return u'<a href="%s%s">%s%s</a>' % (rematch.group(1), rematch.group(2), rematch.group(1), rematch.group(2))

  @staticmethod
  def codeit(text):
    return u'<pre class="code">{}</pre>'.format(text)

  @staticmethod
  def sjisit(text):
    return u'<pre class="aa">{}</pre>'.format(text)

  @staticmethod
  def spoilit(rematch):
    return u'<span class="spoiler">%s</span>' % rematch.group(1)

  @staticmethod
  def _regexp_large_spoiler(rematch):
    return u'<details class="details">{}</details>'.format(rematch.group(1))

  @staticmethod
  def boldit(rematch):
    return u'<b>%s</b>' % rematch.group(1)

  @staticmethod
  def italit(rematch):
    return u'<i>%s</i>' % rematch.group(1)

  @staticmethod
  def strikeit(rematch):
    return u'<strike>%s</strike>' % rematch.group(1)

  @staticmethod
  def underlineit(rematch):
    return u'<span style="border-bottom: 1px solid">%s</span>' % rematch.group(1)

  def markup_parser(self, message, group_id=None):
    self.__current_markup_parser_group_id = group_id
    # perform parsing
    for regexp, handler in self._regexp['unbreakable_markup']:
      if re.search(regexp, message):
        # list indices: 0 - before [code], 1 - inside [code]...[/code], 2 - after [/code]
        message_parts = re.split(regexp, message, maxsplit=1)
        message = self.markup_parser(message_parts[0], group_id) + handler(message_parts[1]) + self.markup_parser(message_parts[2], group_id)
        return message
    for regexp, handler in self._regexp['regular_markup']:
      message = regexp.sub(handler, message)
    return message

  def _compite_regexp(self):
    self._regexp = dict()
    # AHTUNG: consistency is important!
    self._regexp['unbreakable_markup'] = (
        # make code blocks
        (re.compile(r'\[code](?!\[/code])(.+?)\[/code]', re.DOTALL), self.codeit),
        # make aa blocks
        (re.compile(r'\[aa](?!\[/aa])(.+?)\[/aa]', re.DOTALL), self.sjisit)
    )
    self._regexp['regular_markup'] = (
        # make [aa][/aa]
        # make >>post_id links
        (re.compile(r"(&gt;&gt;)([0-9a-f]{10})"), self.linkit),
        # make >quotes
        (re.compile(r"^&gt;(?!&gt;[0-9a-f]{10}).*", re.MULTILINE), self.quoteit),
        # make spoilers
        (re.compile(r"%% (?!\s) (.+?) (?!\s) %%", re.VERBOSE), self.spoilit),
        # make <details> for [spoiler]
        (re.compile(r'\[spoiler](?!\[/spoiler])(.+?)\[/spoiler]', re.DOTALL), self._regexp_large_spoiler),
        # make <b>
        (re.compile(r"(?<![0-9a-zA-Z\x80-\x9f\xe0-\xfc*_/()]) \*\* (?![\s*_]) (.+?) (?<![\s*_]) \*\* (?![0-9a-zA-Z\x80-\x9f\xe0-\xfc*_/()])", re.VERBOSE), self.boldit),
        (re.compile(r"(?<![0-9a-zA-Z\x80-\x9f\xe0-\xfc*_/()]) __ (?![\s*_]) (.+?) (?<![\s*_]) __ (?![0-9a-zA-Z\x80-\x9f\xe0-\xfc*_/()])", re.VERBOSE), self.boldit),
        # make <i>
        (re.compile(r"(?<![0-9a-zA-Z\x80-\x9f\xe0-\xfc*_/()]) \* (?![\s*_]) (.+?) (?<![\s*_]) \* (?![0-9a-zA-Z\x80-\x9f\xe0-\xfc*_/()])", re.VERBOSE), self.italit),
        # make <strike>
        (re.compile(r"(?<![0-9a-zA-Z\x80-\x9f\xe0-\xfc*_/()\-]) -- (?![\s*_-]) (.+?) (?<![\s*_-]) -- (?![0-9a-zA-Z\x80-\x9f\xe0-\xfc*_/()\-])", re.VERBOSE), self.strikeit),
        # make underlined text
        (re.compile(r"(?<![0-9a-zA-Z\x80-\x9f\xe0-\xfc*_/()]) _ (?![\s*_]) (.+?) (?<![\s*_]) _ (?![0-9a-zA-Z\x80-\x9f\xe0-\xfc*_/()])", re.VERBOSE), self.underlineit),
        # Make http:// urls in posts clickable
        (re.compile(r"(http://|https://|ftp://|mailto:|news:|irc:|magnet:\?|maggot://)([^\s\[\]<>'\"]*)"), self.clickit)
    )

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
        except OSError as e:
          self.log(self.logger.WARNING, "could not delete %s: %s" % (os.path.join("groups", str(row[0]), str(row[1])), e))
    elif not os.path.exists(os.path.join('articles', 'censored', message_id)):
      f = open(os.path.join('articles', 'censored', message_id), 'w')
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
      return self.move_censored_article(message_id)

    for group in groups:
      group_flags = self.sqlite.execute("SELECT flags FROM groups WHERE group_name=?", (group,)).fetchone()
      if group_flags is None:
        self.log(self.logger.WARNING, 'Message {} in nonexistent group {}'.format(message_id, group))
      else:
        group_flags = int(group_flags[0])
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

    parent_result = None
    if parent != '' and parent != message_id:
      parent_result = self.sqlite.execute('SELECT closed FROM articles WHERE article_uid = ?', (parent,)).fetchone()
      if parent_result and parent_result[0] != 0:
        self.log(self.logger.INFO, 'censored article %s for closed thread.' % message_id)
        self.delete_orphan_attach(image_name, thumb_name)
        return self.move_censored_article(message_id)
      elif parent_result is None and os.path.isfile(os.path.join("articles", "censored", parent)):
        # root post censored. Delete child post
        self.log(self.logger.INFO, 'Thread starting {} deleted. Delete a {}'.format(parent, message_id))
        self.delete_orphan_attach(image_name, thumb_name)
        return self.move_censored_article(message_id)

    group_ids = list()
    for group in groups:
      result = self.sqlite.execute('SELECT group_id FROM groups WHERE group_name=? AND (cast(flags as integer) & ?) = 0', (group, self.cache['flags']['blocked'])).fetchone()
      if not result:
        try:
          self.sqlite.execute('INSERT INTO groups(group_name, article_count, last_update) VALUES (?,?,?)', (group, 1, int(time.time())))
          self.sqlite.commit()
        except sqlite3.Error:
          self.log(self.logger.INFO, 'ignoring message for blocked group %s' % group)
          continue
        self.__flush_board_cache()
        self.regenerate_all_html()
        group_ids.append(int(self.sqlite.execute('SELECT group_id FROM groups WHERE group_name=?', (group,)).fetchone()[0]))
      else:
        group_ids.append(int(result[0]))
    if len(group_ids) == 0:
      self.log(self.logger.DEBUG, 'no groups left which are not blocked. ignoring %s' % message_id)
      return False
    for group_id in group_ids:
      self.regenerate_boards.add(group_id)

    if parent != '' and parent != message_id:
      last_update = sent
      self.regenerate_threads.add(parent)
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
      self.regenerate_threads.add(message_id)

    if self.sqlite.execute('SELECT article_uid FROM articles WHERE article_uid=?', (message_id,)).fetchone():
      # post has been censored and is now being restored. just delete post for all groups so it can be reinserted
      self.log(self.logger.INFO, 'post has been censored and is now being restored: %s' % message_id)
      self.sqlite.execute('DELETE FROM articles WHERE article_uid=?', (message_id,))
      self.sqlite.commit()

    if len(image_name) > 40:
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
          censored_attach_path = os.path.join(self.config['output_directory'], 'img', image_name)
          if os.path.exists(censored_attach_path):
            os.remove(censored_attach_path)
        else:
          # attach has been censored and is now being restored. Restore all thumblink
          self.log(self.logger.INFO, 'Attach %s restored. Restore %s thumblinks for this attach' % (image_name, censored_count))
          self.sqlite.execute('UPDATE articles SET thumblink = ? WHERE imagelink = ?', (thumb_name, image_name))

    if image_name == '' and thumb_name == '' and self.config['replace_root_nope'] and (parent == '' or parent == message_id) and len(group_ids) > 0:
      # Get random image for root post
      result = self.sqlite.execute('SELECT imagelink, thumblink FROM articles WHERE group_id = ? AND length(thumblink) > 40 ORDER BY RANDOM() LIMIT 1', (group_ids[0],)).fetchone()
      if result:
        image_name, thumb_name = result
        image_name_original = 'pic unrelated'

    insert_list = [\
        ('article_uid',  message_id),
        ('sender',       sender.decode('UTF-8')),
        ('email',        email.decode('UTF-8')),
        ('subject',      subject.decode('UTF-8')),
        ('sent',         sent),
        ('parent',       parent),
        ('message',      message.decode('UTF-8')),
        ('imagename',    image_name_original.decode('UTF-8')),
        ('imagelink',    image_name),
        ('thumblink',    thumb_name),
        ('last_update',  last_update),
        ('public_key',   public_key),
        ('received',     int(time.time())),
        ('article_hash', sha1(message_id).hexdigest()),
        ('group_id',     'dummy')]
    insert_request = 'INSERT INTO articles({}) VALUES ({})'.format(', '.join([x[0] for x in insert_list]), ','.join(['?'] * len(insert_list)))
    del insert_list[-1]
    for group_id in group_ids:
      self.sqlite.execute(insert_request, [x[1] for x in insert_list] + [group_id,])
      self.sqlite.execute('UPDATE groups SET last_update=?, article_count = (SELECT count(article_uid) FROM articles WHERE group_id = ?) WHERE group_id = ?', (int(time.time()), group_id, group_id))
    self.sqlite.commit()
    return True

  def _get_board_root_posts(self, group_id, post_count, offset=0):
    return self.sqlite.execute('SELECT article_uid, sender, subject, sent, message, imagename, imagelink, thumblink, public_key, last_update, closed, sticky FROM \
      articles WHERE group_id = ? AND (parent = "" OR parent = article_uid) ORDER BY sticky DESC, last_update DESC LIMIT ? OFFSET ?', (group_id, post_count, offset)).fetchall()

  def _board_root_post_iter(self, board_data, group_id, pages, threads_per_page, cache_target='page_stamp'):
    if group_id not in self.cache[cache_target]:
      self.cache[cache_target][group_id] = dict()
    for page in xrange(1, pages + 1):
      page_data = board_data[threads_per_page*(page-1):threads_per_page*(page-1)+threads_per_page]
      first_last_parent = sha1(page_data[0][0] + page_data[-1][0]).hexdigest()[:10] if len(page_data) > 0 else None
      if self.cache[cache_target][group_id].get(page, '') != first_last_parent or \
          len(self.regenerate_threads & set(x[0] for x in page_data)) > 0:
        self.cache[cache_target][group_id][page] = first_last_parent
        yield page, page_data

  @staticmethod
  def _get_page_count(thread_count, threads_per_page):
    pages = int(thread_count / threads_per_page)
    if (thread_count % threads_per_page != 0) or pages == 0:
      pages += 1
    return pages

  def generate_board(self, group_id):
    start_time = time.time()
    threads_per_page = self.config['threads_per_page']
    pages_per_board = self.config['pages_per_board']
    board_data = self._get_board_root_posts(group_id, threads_per_page * pages_per_board)
    thread_count = len(board_data)
    pages = self._get_page_count(thread_count, threads_per_page)
    if self.config['enable_archive'] and ((int(self.sqlite.execute("SELECT flags FROM groups WHERE group_id=?", (group_id,)).fetchone()[0]) & self.cache['flags']['no-archive']) == 0) and \
        int(self.sqlite.execute('SELECT count(group_id) FROM (SELECT group_id FROM articles WHERE group_id = ? AND (parent = "" OR parent = article_uid))', (group_id,)).fetchone()[0]) > thread_count:
      generate_archive = True
    else:
      generate_archive = False

    generation = list()
    basic_board = dict()
    basic_board['board_subtype'] = ''
    basic_board['boardlist'] = self.get_board_list(group_id)
    basic_board['full_board'], \
    board_name_unquoted, \
    basic_board['board'], \
    basic_board['board_description'] = self.get_board_data(group_id)
    prepared_template = string.Template(self.t_engine['board'].safe_substitute(basic_board))
    t_engine_mapper_board = dict()
    isgenerated = False
    for board, page_data in self._board_root_post_iter(board_data, group_id, pages, threads_per_page):
      isgenerated = True
      threads = list()
      generation.append(str(board))
      for root_row in page_data:
        root_message_id_hash = sha1(root_row[0]).hexdigest()
        threads.append(
            self.t_engine['board_threads'].substitute(
                self.get_base_thread(root_row, root_message_id_hash, group_id, 4)
            )
        )
      t_engine_mapper_board['threads'] = ''.join(threads)
      t_engine_mapper_board['pagelist'] = self.generate_pagelist(pages, board, board_name_unquoted, generate_archive)
      t_engine_mapper_board['target'] = "{0}-1.html".format(board_name_unquoted)

      f = codecs.open(os.path.join(self.config['output_directory'], '{0}-{1}.html'.format(board_name_unquoted, board)), 'w', 'UTF-8')
      f.write(prepared_template.substitute(t_engine_mapper_board))
      f.close()
    last_root_message = board_data[-1][0] if thread_count > 0 else None
    del board_data, t_engine_mapper_board, prepared_template
    if len(generation) > 0:
      self.log(self.logger.INFO, 'generating {}/{}-({}).html at {:0.4f}s'.format(self.config['output_directory'], board_name_unquoted, ','.join(generation), (time.time() - start_time)))
    if generate_archive and (self.cache['page_stamp'][group_id].get(0, '') != last_root_message or (not isgenerated and len(self.regenerate_threads) > 0)):
      self.cache['page_stamp'][group_id][0] = last_root_message
      self.generate_archive(group_id)
    if isgenerated and self.config['enable_recent']:
      self.generate_recent(group_id)

  def get_base_thread(self, root_row, root_message_id_hash, group_id, child_count=4, single=False):
    if root_row[10] != 0:
      isclosed = True
    else:
      isclosed = False
    if root_message_id_hash == '':
      root_message_id_hash = sha1(root_row[0]).hexdigest()
    message_root = self.get_root_post(root_row, group_id, child_count, root_message_id_hash, single, isclosed)
    if child_count == 0:
      return {'message_root': message_root}
    message_childs = ''.join(self.get_childs_posts(root_row[0], group_id, root_message_id_hash, root_row[8], child_count, single, isclosed))
    return {'message_root': message_root, 'message_childs': message_childs}

  def get_root_post(self, data, group_id, child_count, message_id_hash, single, isclosed):
    root_data = self.get_preparse_post(data[:9], message_id_hash, group_id, 25, 2000, child_count, '', '', single)
    if data[11] != 0:
      root_data['thread_status'] += '[&#177;]'
      root_data['sticky_prefix'] = 'un'
    else:
      root_data['sticky_prefix'] = ''
    if isclosed:
      root_data['close_action'] = 'open'
      root_data['thread_status'] += '[closed]'
      return self.t_engine['message_root_closed'].substitute(root_data)
    else:
      root_data['close_action'] = 'close'
      return self.t_engine['message_root'].substitute(root_data)

  def get_childs_posts(self, parent, group_id, father, father_pubkey, child_count, single, isclosed):
    childs = list()
    childs.append('') # FIXME: the fuck is this for?
    for child_row in self.sqlite.execute('SELECT * FROM (SELECT article_uid, sender, subject, sent, message, imagename, imagelink, thumblink, public_key \
        FROM articles WHERE parent = ? AND parent != article_uid AND group_id = ? ORDER BY sent DESC LIMIT ?) ORDER BY sent ASC', (parent, group_id, child_count)).fetchall():
      childs_message = self.get_preparse_post(child_row, sha1(child_row[0]).hexdigest(), group_id, 20, 1500, 0, father, father_pubkey, single)
      nopic = '' if child_row[6] != '' else 'no'
      closed = '' if not isclosed else '_closed'
      childs.append(self.t_engine['message_'+ nopic +'pic'+ closed].substitute(childs_message))
    return childs

  @staticmethod
  def generate_pagelist(count, current, board_name_unquoted, archive_link=False):
    if count < 2:
      return ''
    pagelist = list()
    pagelist.append('Pages: ')
    for page in xrange(1, count + 1):
      if page != current:
        pagelist.append('<a href="{0}-{1}.html">[{1}]</a> '.format(board_name_unquoted, page))
      else:
        pagelist.append('[{0}] '.format(page))
    if archive_link:
      pagelist.append('<a href="{0}-archive-1.html">[Archive]</a> '.format(board_name_unquoted))
    return ''.join(pagelist)

  def get_preparse_post(self, data, message_id_hash, group_id, max_row, max_chars, child_view, father='', father_pubkey='', single=False):
    #father initiate parsing child post and contain root_post_hash_id
        #data = 0 - article_uid 1- sender 2 - subject 3 - sent 4 - message 5 - imagename 6 - imagelink 7 - thumblink -8 public_key
    #message_id_hash = sha1(data[0]).hexdigest() #use globally for decrease sha1 root post uid iteration
    is_playable = False
    parsed_data = dict()
    if data[6] != '':
      imagelink = data[6]
      if data[7] in self.config['thumbs']:
        thumblink = self.config['thumbs'][data[7]]
      else:
        thumblink = data[7]
        if data[6] != data[7] and data[6].rsplit('.', 1)[-1] in ('gif', 'webm', 'mp4'):
          is_playable = True
    else:
      imagelink = thumblink = self.config['thumbs'].get('no_file', 'error')
    if data[8] != '':
      parsed_data['signed'] = self.t_engine['signed'].substitute(
          articlehash=message_id_hash[:10],
          pubkey=data[8],
          pubkey_short=generate_pubkey_short_utf_8(data[8])
      )
      author = self.pubkey_to_name(data[8], father_pubkey, data[1])
      if author == '':
        author = data[1]
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
    message = self.markup_parser(message, group_id)
    if father == '':
      child_count = int(self.sqlite.execute('SELECT count(article_uid) FROM articles WHERE parent = ? AND parent != article_uid', (data[0],)).fetchone()[0])
      if self.config['bump_limit'] > 0 and child_count >= self.config['bump_limit']:
        parsed_data['thread_status'] = '[fat]'
      else:
        parsed_data['thread_status'] = ''
      if child_count > child_view:
        missing = child_count - child_view
        if missing == 1:
          post = "post"
        else:
          post = "posts"
        message += '\n\n<a href="thread-{0}.html">{1} {2} omitted</a>'.format(message_id_hash[:10], missing, post)
        if child_view < 10000 and child_count > 80:
          start_link = child_view / 50 * 50 + 50
          if start_link % 100 == 0:
            start_link += 50
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
    parsed_data['sent'] = datetime.utcfromtimestamp(data[3] + self.config['utc_time_offset']).strftime(self.config['datetime_format'])
    parsed_data['imagelink'] = imagelink
    parsed_data['thumblink'] = thumblink
    parsed_data['imagename'] = data[5]
    if father != '':
      parsed_data['parenthash'] = father[:10]
      parsed_data['parenthash_full'] = father
    if self.config['fake_id']:
      parsed_data['article_id'] = self.message_uid_to_fake_id(data[0])
    else:
      parsed_data['article_id'] = message_id_hash[:10]
    if is_playable:
      parsed_data['play_button'] = '<span class="play_button"></span>'
    else:
      parsed_data['play_button'] = ''
    return parsed_data

  def generate_archive(self, group_id):
    start_time = time.time()
    threads_per_page = self.config['archive_threads_per_page']
    pages_per_board = self.config['archive_pages_per_board']
    board_data = self._get_board_root_posts(group_id, threads_per_page * pages_per_board, self.config['threads_per_page'] * self.config['pages_per_board'])
    thread_count = len(board_data)
    if thread_count == 0:
      return
    pages = self._get_page_count(thread_count, threads_per_page)

    generation = list()
    basic_board = dict()
    basic_board['board_subtype'] = ' :: archive'
    basic_board['boardlist'] = self.get_board_list()
    basic_board['full_board'], \
    board_name_unquoted, \
    basic_board['board'], \
    basic_board['board_description'] = self.get_board_data(group_id)
    prepared_template = string.Template(self.t_engine['board'].safe_substitute(basic_board))
    t_engine_mapper_board = dict()
    for board, page_data in self._board_root_post_iter(board_data, group_id, pages, threads_per_page, 'page_stamp_archiv'):
      threads = list()
      generation.append(str(board))
      for root_row in page_data:
        threads.append(
            self.t_engine['archive_threads'].substitute(
                self.get_base_thread(root_row, '', group_id, child_count=0)
            )
        )
      t_engine_mapper_board['threads'] = ''.join(threads)
      t_engine_mapper_board['pagelist'] = self.generate_pagelist(pages, board, board_name_unquoted+'-archive')
      t_engine_mapper_board['target'] = "{0}-archive-1.html".format(board_name_unquoted)

      f = codecs.open(os.path.join(self.config['output_directory'], '{0}-archive-{1}.html'.format(board_name_unquoted, board)), 'w', 'UTF-8')
      f.write(prepared_template.substitute(t_engine_mapper_board))
      f.close()
    if len(generation) > 0:
      self.log(self.logger.INFO, 'generating {}/{}-archive-({}).html at {:0.4f}s'.format(self.config['output_directory'], board_name_unquoted, ','.join(generation), (time.time() - start_time)))

  def generate_recent(self, group_id):
    # get only freshly updated threads
    timestamp = int(time.time()) - 3600*24
    threads = list()
    t_engine_mapper_board_recent = dict()
    t_engine_mapper_board_recent['board_subtype'] = ' :: recent'
    t_engine_mapper_board_recent['boardlist'] = self.get_board_list()
    t_engine_mapper_board_recent['full_board'], \
    board_name_unquoted, \
    t_engine_mapper_board_recent['board'], \
    t_engine_mapper_board_recent['board_description'] = self.get_board_data(group_id)
    self.log(self.logger.INFO, 'generating %s/%s-recent.html' % (self.config['output_directory'], board_name_unquoted))
    for root_row in self.sqlite.execute('SELECT article_uid, sender, subject, sent, message, imagename, imagelink, thumblink, public_key, last_update, closed, sticky \
        FROM articles WHERE group_id = ? AND (parent = "" OR parent = article_uid) AND last_update > ? ORDER BY sticky DESC, last_update DESC', (group_id, timestamp)).fetchall():
      root_message_id_hash = sha1(root_row[0]).hexdigest()
      threads.append(
          self.t_engine['board_threads'].substitute(
              self.get_base_thread(root_row, root_message_id_hash, group_id, 4)
          )
      )
    t_engine_mapper_board_recent['threads'] = ''.join(threads)
    t_engine_mapper_board_recent['target'] = "{0}-recent.html".format(board_name_unquoted)
    t_engine_mapper_board_recent['pagelist'] = ''

    f = codecs.open(os.path.join(self.config['output_directory'], '{0}-recent.html'.format(board_name_unquoted)), 'w', 'UTF-8')
    f.write(self.t_engine['board'].substitute(t_engine_mapper_board_recent))
    f.close()

  @staticmethod
  def frontend(uid):
    if '@' in uid:
      frontend = uid.split('@')[1][:-1]
    else:
      frontend = 'nntp'
    return frontend

  def delete_thread_page(self, thread_path):
    if os.path.isfile(thread_path):
      self.log(self.logger.INFO, 'this page belongs to some blocked board. deleting %s.' % thread_path)
      try:
        os.unlink(thread_path)
      except OSError as e:
        self.log(self.logger.ERROR, 'could not delete %s: %s' % (thread_path, e))

  def generate_thread(self, root_uid, silence):
    root_row = self.sqlite.execute('SELECT article_uid, sender, subject, sent, message, imagename, imagelink, thumblink, public_key, last_update, closed, sticky, group_id \
        FROM articles WHERE article_uid = ?', (root_uid,)).fetchone()
    if not root_row:
      # FIXME: create temporary root post here? this will never get called on startup because it checks for root posts only
      # FIXME: ^ alternatives: wasted threads in admin panel? red border around images in pic log? actually adding temporary root post while processing?
      #root_row = (root_uid, 'none', 'root post not yet available', 0, 'root post not yet available', '', '', 0, '')
      self.log(self.logger.INFO, 'root post not yet available: %s, should create temporary root post here' % root_uid)
      return
    group_id = root_row[-1]
    root_message_id_hash = sha1(root_uid).hexdigest()#self.sqlite_hashes.execute('SELECT message_id_hash from article_hashes WHERE message_id = ?', (root_row[0],)).fetchone()
    # FIXME: benchmark sha1() vs hasher_db_query
    child_count = int(self.sqlite.execute('SELECT count(article_uid) FROM articles WHERE parent = ? AND parent != article_uid AND group_id = ?', (root_row[0], group_id)).fetchone()[0])
    isblocked_board = self.check_board_flags(group_id, 'blocked')
    thread_path = os.path.join(self.config['output_directory'], 'thread-%s.html' % (root_message_id_hash[:10],))
    if isblocked_board:
      self.delete_thread_page(thread_path)
    else:
      self.create_thread_page(root_row[:-1], thread_path, 10000, root_message_id_hash, group_id, silence)
    if child_count > 80:
      for max_child_view in range(50, child_count, 100):
        thread_path = os.path.join(self.config['output_directory'], 'thread-%s-%s.html' % (root_message_id_hash[:10], max_child_view))
        if isblocked_board:
          self.delete_thread_page(thread_path)
        else:
          self.create_thread_page(root_row[:-1], thread_path, max_child_view, root_message_id_hash, group_id, silence)

  def create_thread_page(self, root_row, thread_path, max_child_view, root_message_id_hash, group_id, silence):
    if not silence:
      self.log(self.logger.INFO, 'generating %s' % (thread_path,))
    t_engine_mappings_thread_single = dict()
    t_engine_mappings_thread_single['thread_single'] = self.t_engine['board_threads'].substitute(self.get_base_thread(root_row, root_message_id_hash, group_id, max_child_view, True))
    t_engine_mappings_thread_single['boardlist'] = self.get_board_list()
    t_engine_mappings_thread_single['full_board'], \
    board_name_unquoted, \
    t_engine_mappings_thread_single['board'], \
    t_engine_mappings_thread_single['board_description'] = self.get_board_data(group_id)
    t_engine_mappings_thread_single['thread_id'] = root_message_id_hash
    t_engine_mappings_thread_single['target'] = "{0}-1.html".format(board_name_unquoted)
    t_engine_mappings_thread_single['subject'] = root_row[2][:60]

    f = codecs.open(thread_path, 'w', 'UTF-8')
    if root_row[10] == 0:
      f.write(self.t_engine['thread_single'].substitute(t_engine_mappings_thread_single))
    else:
      f.write(self.t_engine['thread_single_closed'].substitute(t_engine_mappings_thread_single))
    f.close()

  def generate_index(self):
    self.log(self.logger.INFO, 'generating %s/index.html' % self.config['output_directory'])
    f = codecs.open(os.path.join(self.config['output_directory'], 'index.html'), 'w', 'UTF-8')
    f.write(self.t_engine['index'].substitute())
    f.close()

  def generate_menu(self):
    self.log(self.logger.INFO, 'generating %s/menu.html' % self.config['output_directory'])
    menu_entry = dict()
    menu_entries = list()
    exclude_flags = self.cache['flags']['hidden'] | self.cache['flags']['blocked']
    # get fresh posts count
    timestamp = int(time.time()) - 3600*24
    for group_row in self.sqlite.execute('SELECT group_name, group_id, ph_name, link FROM groups WHERE \
      (cast(groups.flags as integer) & ?) = 0 ORDER by group_name ASC', (exclude_flags,)).fetchall():
      menu_entry['group_name'] = group_row[0].split('.', 1)[-1].replace('"', '').replace('/', '')
      menu_entry['group_link'] = group_row[3] if self.config['use_unsecure_aliases'] and group_row[3] != '' else '%s-1.html' % menu_entry['group_name']
      menu_entry['group_name_encoded'] = group_row[2] if group_row[2] != '' else basicHTMLencode(menu_entry['group_name'])
      menu_entry['postcount'] = self.sqlite.execute('SELECT count(article_uid) FROM articles WHERE group_id = ? AND sent > ?', (group_row[1], timestamp)).fetchone()[0]
      menu_entries.append(self.t_engine['menu_entry'].substitute(menu_entry))

    f = codecs.open(os.path.join(self.config['output_directory'], 'menu.html'), 'w', 'UTF-8')
    f.write(self.t_engine['menu'].substitute(menu_entries='\n'.join(menu_entries)))
    f.close()

  def check_board_flags(self, group_id, *args):
    try:
      result = self.sqlite.execute('SELECT flags FROM groups WHERE group_id = ?', (group_id,)).fetchone()
    except sqlite3.Error as e:
      self.log(self.logger.WARNING, 'error board_id={} flags check: {}'.format(group_id, e))
      return False
    else:
      if result is None:
        self.log(self.logger.WARNING, 'error board_id={} flags check: board not found'.format(group_id))
        return False
      flags = int(result[0])
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
    if group_id:
      self.cache['page_stamp'][group_id] = dict()
      self.cache['page_stamp_archiv'][group_id] = dict()
    else:
      self.cache['page_stamp'] = dict()
      self.cache['page_stamp_archiv'] = dict()

  def get_board_list(self, group_id='selflink'):
    if group_id not in self.board_cache:
      self.board_cache[group_id] = (self.__generate_board_list(group_id))
    return self.board_cache[group_id][0]

  def get_board_data(self, group_id, colname=None):
    if group_id not in self.board_cache:
      self.board_cache[group_id] = (self.__generate_board_list(group_id))
    if colname is None:
      return self.board_cache[group_id][1:]
    else:
      name_list = ('full_board', 'board_name_unquoted', 'board', 'board_description')
      try:
        return self.board_cache[group_id][name_list.index(colname)+1]
      except IndexError:
        return 'None'

  def __generate_board_list(self, group_id='', selflink=False):
    full_board_name_unquoted = board_name_unquoted = board_name = board_description = ''
    boardlist = list()
    exclude_flags = self.cache['flags']['hidden'] | self.cache['flags']['blocked']
    for group_row in self.sqlite.execute('SELECT group_name, group_id, ph_name, ph_shortname, link, description FROM groups \
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
    if not self.config['use_unsecure_aliases']:
      board_description = self.markup_parser(basicHTMLencode(board_description))
    if boardlist:
      boardlist[-1] = boardlist[-1][:-1]
    return ''.join(boardlist), full_board_name_unquoted, board_name_unquoted, board_name, board_description

  def generate_overview(self):
    self.log(self.logger.INFO, 'generating %s/overview.html' % self.config['output_directory'])
    t_engine_mappings_overview = dict()
    t_engine_mappings_overview['boardlist'] = self.get_board_list()
    t_engine_mappings_overview['news'] = self.generate_news_data()

    weekdays = ('Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday')
    max_post = 0
    stats = list()
    bar_length = 20
    days = 30
    utc_offset = str(self.config['utc_time_offset']) + ' seconds'
    totals = int(self.sqlite.execute('SELECT count(1) FROM articles WHERE sent > strftime("%s", "now", "-' + str(days) + ' days")').fetchone()[0])
    stats.append(self.t_engine['stats_usage_row'].substitute({'postcount': totals, 'date': 'all posts', 'weekday': '', 'bar': 'since %s days' % days}))
    datarow = list()
    for row in self.sqlite.execute('SELECT count(1) as counter, strftime("%Y-%m-%d", sent, "unixepoch", "' + utc_offset + '") as day, strftime("%w", sent, "unixepoch", "' + utc_offset + '") as weekday FROM articles WHERE sent > strftime("%s", "now", "-' + str(days) + ' days") GROUP BY day ORDER BY day DESC').fetchall():
      if row[0] > max_post:
        max_post = row[0]
      datarow.append((row[0], row[1], weekdays[int(row[2])]))
    for row in datarow:
      graph = '=' * int(float(row[0])/max_post*bar_length)
      if len(graph) == 0:
        graph = '&nbsp;'
      stats.append(self.t_engine['stats_usage_row'].substitute({'postcount': row[0], 'date': row[1], 'weekday': row[2], 'bar': graph}))
    t_engine_mappings_overview['stats_usage_rows'] = '\n'.join(stats)

    postcount = 50
    stats = list()
    exclude_flags = self.cache['flags']['hidden'] | self.cache['flags']['no-overview'] | self.cache['flags']['blocked']
    for row in self.sqlite.execute('SELECT articles.last_update, group_name, subject, message, article_uid, ph_name FROM groups, articles WHERE \
      groups.group_id = articles.group_id AND (cast(groups.flags as integer) & ?) = 0 AND \
      (articles.parent = "" OR articles.parent = articles.article_uid) ORDER BY articles.last_update DESC LIMIT ?', (exclude_flags, str(postcount))).fetchall():
      latest_posts_row = dict()
      latest_posts_row['last_update'] = datetime.utcfromtimestamp(row[0] + self.config['utc_time_offset']).strftime(self.config['datetime_format'])
      latest_posts_row['board'] = row[5] if row[5] != '' else basicHTMLencode(row[1].split('.', 1)[-1].replace('"', ''))
      latest_posts_row['articlehash'] = sha1(row[4]).hexdigest()[:10]
      latest_posts_row['subject'] = row[2] if row[2] not in ('', 'None') else row[3]
      latest_posts_row['subject'] = latest_posts_row['articlehash'] if latest_posts_row['subject'] == '' else latest_posts_row['subject'].replace('\n', ' ')[:55]
      stats.append(self.t_engine['latest_posts_row'].substitute(latest_posts_row))
    t_engine_mappings_overview['latest_posts_rows'] = '\n'.join(stats)

    stats = list()
    exclude_flags = self.cache['flags']['hidden'] | self.cache['flags']['blocked']
    for row in self.sqlite.execute('SELECT count(1) as counter, group_name, ph_name FROM groups, articles WHERE \
      groups.group_id = articles.group_id AND (cast(groups.flags as integer) & ?) = 0 GROUP BY \
      groups.group_id ORDER BY counter DESC', (exclude_flags,)).fetchall():
      board = row[2] if row[2] != '' else basicHTMLencode(row[1].replace('"', ''))
      stats.append(self.t_engine['stats_boards_row'].substitute({'postcount': row[0], 'board': board}))
    t_engine_mappings_overview['stats_boards_rows'] = '\n'.join(stats)
    f = codecs.open(os.path.join(self.config['output_directory'], 'overview.html'), 'w', 'UTF-8')
    f.write(self.t_engine['overview'].substitute(t_engine_mappings_overview))
    f.close()
    self.generate_help(t_engine_mappings_overview['news'])

  def generate_help(self, news_data):
    f = codecs.open(os.path.join(self.config['output_directory'], 'help.html'), 'w', 'UTF-8')
    f.write(self.t_engine['help_page'].substitute({'boardlist': self.get_board_list(), 'news': news_data}))
    f.close()

  def generate_news_data(self):
    t_engine_mappings_news = {'subject': '', 'sent': '', 'author': '', 'pubkey_short': '', 'pubkey': '', 'comment_count': ''}
    news_board = self.sqlite.execute('SELECT group_id, group_name FROM groups WHERE \
        (cast(flags as integer) & ?) != 0 AND (cast(flags as integer) & ?) = 0', (self.cache['flags']['news'], self.cache['flags']['blocked'])).fetchone()
    if news_board:
      t_engine_mappings_news['allnews_link'] = '{0}-1.html'.format(news_board[1].split('.', 1)[-1].replace('"', '').replace('/', ''))
      row = self.sqlite.execute('SELECT subject, message, sent, public_key, article_uid, sender FROM articles \
          WHERE (parent = "" OR parent = article_uid) AND group_id = ? ORDER BY sticky DESC, last_update DESC', (news_board[0],)).fetchone()
    else:
      t_engine_mappings_news['allnews_link'] = 'overview.html'
    if not (news_board and row):
      t_engine_mappings_news['parent'] = 'does_not_exist_yet'
      t_engine_mappings_news['message'] = 'once upon a time there was a news post'
    else:
      parent = sha1(row[4]).hexdigest()[:10]
      if len(row[1].split('\n')) > 5:
        message = '\n'.join(row[1].split('\n')[:5]) + '\n[..] <a href="thread-%s.html"><i>message too large</i></a>' % parent
      elif len(row[1]) > 1000:
        message = row[1][:1000] + '\n[..] <a href="thread-%s.html"><i>message too large</i></a>' % parent
      else:
        message = row[1]
      message = self.markup_parser(message)
      t_engine_mappings_news['subject'] = 'Breaking news' if row[0] == 'None' or row[0] == '' else row[0]
      t_engine_mappings_news['sent'] = datetime.utcfromtimestamp(row[2] + self.config['utc_time_offset']).strftime(self.config['datetime_format'])
      if row[3] != '':
        t_engine_mappings_news['pubkey_short'] = generate_pubkey_short_utf_8(row[3])
        moder_name = self.pubkey_to_name(row[3])
      else:
        moder_name = ''
      t_engine_mappings_news['author'] = moder_name if moder_name else row[5]
      t_engine_mappings_news['pubkey'] = row[3]
      t_engine_mappings_news['parent'] = parent
      t_engine_mappings_news['message'] = message
      t_engine_mappings_news['comment_count'] = self.sqlite.execute('SELECT count(article_uid) FROM articles WHERE \
          parent = ? AND parent != article_uid AND group_id = ?', (row[4], news_board[0])).fetchone()[0]
    return self.t_engine['news'].substitute(t_engine_mappings_news)

  def generate_top_page(self):
    if self.config['top_counter'] >= self.config['top_step']:
      self.config['top_counter'] = 0
    else:
      self.config['top_counter'] += 1
      return

    start_time = time.time()
    top_list = list()
    exclude_flags = self.cache['flags']['hidden'] | self.cache['flags']['blocked']
    for row in self.sqlite.execute('SELECT article_uid, sender, subject, sent, message, imagename, imagelink, thumblink, public_key, parent, article_hash, articles.group_id \
        FROM groups, articles WHERE groups.group_id = articles.group_id AND (cast(groups.flags as integer) & ?) = 0 ORDER BY sent DESC LIMIT ?', (exclude_flags, self.config['top_count'])).fetchall():
      if row[9] in ('', row[0]):
        # root
        data = self.get_preparse_post(row[:9], row[10], -1, 15, 2000, 0)
        data['parenthash_full'] = row[10]
        data['parenthash'] = row[10][:10]
      else:
        data = self.get_preparse_post(row[:9], row[10], -1, 15, 2000, 0, sha1(row[9]).hexdigest())
      data['frontend'] = u'{} => {}'.format(data['frontend'], self.get_board_data(row[11], 'board')[:20])
      nopic = '' if row[7] != '' else 'no'
      top_list.append(self.t_engine['message_'+ nopic +'pic_closed'].substitute(data))

    t_engine_mapper_top = {\
       'thread_single': ''.join(top_list),
       'subject': self.config['top_count'],
       'boardlist': self.get_board_list(),
       'board': 'top ',
       'board_description': '',
       'target': ''}
    with codecs.open(os.path.join(self.config['output_directory'], 'top.html'), 'w', 'UTF-8') as f:
      f.write(self.t_engine['thread_single_closed'].substitute(t_engine_mapper_top))
    self.log(self.logger.INFO, 'generating {}/top.html at {:0.4f}s'.format(self.config['output_directory'], (time.time() - start_time)))

if __name__ == '__main__':
  # FIXME fix this shit
  overchan = main('overchan', None, {'watching': 'test-articles'})
  while True:
    try:
      print "signal.pause()"
      signal.pause()
    except KeyboardInterrupt as e:
      print 'bye'
      exit(0)
    except Exception as e:
      print "Exception:", e
      exit(0)
