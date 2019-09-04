#!/usr/bin/env python2

import codecs
import os
import sqlite3
import threading
import time
import traceback
import string
import Queue
from calendar import timegm
from datetime import datetime, timedelta
from email.utils import parsedate_tz
from hashlib import sha1

from pygments import highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers import guess_lexer, guess_lexer_for_filename, get_lexer_by_name, ClassNotFound, get_all_lexers

from srnd.utils import basicHTMLencode, css_minifer, html_minifer

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
    self.logger = logger
    self._db_connector = args['db_connector']
    self.should_terminate = False
    self.config = dict()
    self._init_config(args)
    self.sync_on_startup = self.config['sync_on_startup']
    self._check_errors()
    self.log(self.logger.INFO, 'initializing as plugin..')
    self.queue = Queue.Queue()
    # needed for working inside a chroot to recognize latin1 charset
    try:
      guess_lexer("svmmsjj".encode('latin1'), encoding='utf-8')
    except ClassNotFound:
      pass
    self.formatter = HtmlFormatter(linenos=True, cssclass="source", anchorlinenos=True, lineanchors='line', full=False, cssfile="./styles.css", noclobber_cssfile=True)
    self.recognized_extenstions = ('sh', 'py', 'pyx', 'pl', 'hs', 'haskell', 'js', 'php', 'html', 'c', 'cs')
    self.t_engine = self._load_templates()

  def _init_config(self, args, add_default=True):
    cfg_new = dict()
    cfg_def = {
        'sleep_threshold': 10,
        'sleep_time': 0.02,
        'debug': self.logger.INFO,
        'title': 'paste.i.did.not.read.the.config',
        'css_file': 'master.css',
        'generate_all': False,
        'sync_on_startup': True,
        'minify_css': False,
        'minify_html': False,
        'max_recent': 200
    }
    for target in args:
      if target in cfg_def:
        try:
          if isinstance(cfg_def[target], bool):
            cfg_new[target] = True if args[target].lower() in ('true', 'yes', '1', 'enable') else False
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

    if 'debug' in cfg_new and cfg_new['debug'] < 0 or cfg_new['debug'] > 5:
      cfg_new['debug'] = self.logger.INFO
      self.log(self.logger.WARNING, 'invalid value for debug, using default debug level of {}'.format(self.logger.INFO))
    self.config.update(cfg_new)

  def _check_errors(self):
    error = list()
    for arg in ('template_directory', 'output_directory', 'css_file', 'title'):
      if arg not in self.config:
        error.append('{} not in arguments'.format(arg))
    if error:
      self.die('\n'.join(error))
    if not os.path.exists(self.config['template_directory']):
      self.die('template directory \'%s\' does not exist' % self.config['template_directory'])
    if not os.path.exists(os.path.join(self.config['template_directory'], self.config['css_file'])):
      self.die('specified CSS file not found in template directory: \'%s\' does not exist' % os.path.join(self.config['template_directory'], self.config['css_file']))

  def _load_templates(self):
    t_engine = dict()
    with codecs.open(os.path.join(self.config['template_directory'], 'single_paste.tmpl'), 'r', 'UTF-8') as f:
      t_engine['single'] = string.Template(
          string.Template(f.read()).safe_substitute(
              title=self.config['title']
          )
      )
    with codecs.open(os.path.join(self.config['template_directory'], 'index.tmpl'), 'r', 'UTF-8') as f:
      t_engine['index'] = string.Template(
          string.Template(f.read()).safe_substitute(
              title=self.config['title'],
              language=self._create_lang_selector()
          )
      )
    if self.config['minify_html']:
      t_engine, msg = html_minifer(t_engine)
      self.log(self.logger.INFO, msg)
    return t_engine

  @staticmethod
  def _create_lang_selector():
    option = '<option value="{}">{}</option>'
    all_lexers = sorted([(xx[0], xx[1][0]) for xx in get_all_lexers() if len(xx) > 1 and xx[0] and xx[1][0] and xx[1][0] != 'text'], key=lambda name: name[0])
    all_lexers.insert(0, ('Text only', 'text'))
    all_lexers.insert(0, ('Auto', 'auto'))
    return '\n'.join([option.format(xx[1], xx[0]) for xx in all_lexers])

  def add_article(self, message_id, source="article", timestamp=None):
    self.queue.put((source, message_id, timestamp))

  def shutdown(self):
    self.running = False

  def _post_init(self):
    if not os.path.exists(self.config['output_directory']):
      os.mkdir(self.config['output_directory'])
    with open(os.path.join(self.config['template_directory'], self.config['css_file']), 'r') as i, \
        open(os.path.join(self.config['output_directory'], 'styles.css'), 'w') as o:
      css = i.read()
      if self.config['minify_css']:
        old_size = len(css)
        css = css_minifer(css)
        new_size = len(css)
        diff = -int(float(old_size-new_size)/old_size * 100) if old_size > 0 else 0
        self.log(self.logger.INFO, 'Minify CSS {0}: old size={1}, new size={2}, difference={3}%'.format(self.config['css_file'], old_size, new_size, diff))
      o.write(css)

  def update_pastesdb(self):
    self.sqlite.execute('''CREATE TABLE IF NOT EXISTS pastes
                  (article_uid text, hash text PRIMARY KEY, sender text, email text, subject text, sent INTEGER, body text, root text, received INTEGER)''')
    try:
      self.sqlite.execute('ALTER TABLE pastes ADD COLUMN lang text DEFAULT ""')
    except sqlite3.OperationalError:
      pass
    try:
      self.sqlite.execute('ALTER TABLE pastes ADD COLUMN hidden INTEGER DEFAULT 0')
    except sqlite3.OperationalError:
      pass
    self.sqlite.commit()

  def run(self):
    if self.should_terminate:
      self.shutdown()
      return
    self._post_init()
    self.sqlite = self._db_connector('pastes')
    self.update_pastesdb()
    self.running = True
    self.regenerate_index = False
    self.log(self.logger.INFO, 'starting up as plugin..')
    if self.config['generate_all']:
      self.log(self.logger.INFO, 'regenerating all HTML files..')
      for row in self.sqlite.execute('SELECT hash, sender, subject, sent, body, lang, hidden FROM pastes ORDER BY sent ASC').fetchall():
        self.generate_paste(row[0][:10], row[4], row[2], row[1], row[3], row[5], int(row[6]))
      self.regenerate_index = False
    self.recreate_index()
    got_control = False
    while self.running:
      try:
        ret = self.queue.get(block=True, timeout=1)
        if ret[0] == "article":
          message_id = ret[1]
          if self.sqlite.execute('SELECT hash FROM pastes WHERE article_uid = ?', (message_id,)).fetchone():
            self.log(self.logger.DEBUG, '%s already in database..' % message_id)
            continue
          try:
            with open(os.path.join('articles', message_id), 'r') as fd:
              if not self.parse_message(message_id, fd):
                continue
          except Exception as e:
            self.log(self.logger.WARNING, 'something went wrong while parsing new article {}: {}'.format(message_id, e))
            self.log(self.logger.WARNING, traceback.format_exc())
        elif ret[0] == "control":
          got_control |= self.handle_control(ret[1], ret[2])
        else:
          self.log(self.logger.WARNING, 'got article with unknown source: %s' % ret[0])
        if self.queue.qsize() > self.config['sleep_threshold']:
          time.sleep(self.config['sleep_time'])
      except Queue.Empty as e:
        if got_control:
          self.sqlite.execute('VACUUM;')
          self.sqlite.commit()
          got_control = False
          self.regenerate_index = True
        if self.regenerate_index:
          self.recreate_index()
          self.regenerate_index = False
    self.sqlite.close()
    self.log(self.logger.INFO, 'bye')

  def generate_paste(self, identifier, paste_content, subject, sender, sent, lang, ishidden):
    if not lang:
      lang = self._detect_lang_name(subject, paste_content)
    if not lang:
      return

    page_link = os.path.join(self.config['output_directory'], '{}.html'.format(identifier))
    self.log(self.logger.INFO, 'generating {} & {}.txt'.format(page_link, identifier))
    with codecs.open(os.path.join(self.config['output_directory'], identifier + '.txt'), 'w', encoding='utf-8') as f:
      f.write(paste_content)
    lexer = get_lexer_by_name(lang, encoding='utf-8')
    data = {
        'paste_title': subject,
        'sender': sender,
        'sent': datetime.utcfromtimestamp(sent).strftime('%Y/%m/%d %H:%M UTC'),
        'identifier': identifier,
        'paste': highlight(paste_content, lexer, self.formatter),
        'lang': lang
    }
    with codecs.open(page_link, 'w', 'UTF-8') as f:
      f.write(self.t_engine['single'].substitute(data))
    self.regenerate_index |= ishidden == 0

  def parse_message(self, message_id, fd):
    hash_message_uid = sha1(message_id).hexdigest()
    subject = 'No Title'
    sent = 0
    sender = 'None'
    email = 'non@giv.en'
    body = list()
    ishidden = 0
    lang = ''
    body_found = False
    for line in fd:
      line = line.rstrip('\n\r')
      if not body_found:
        key = line.split(': ')[0].lower()
        value = line.split(': ', 1)[-1]
        if not line:
          body_found = True
        elif key == 'subject':
          subject = basicHTMLencode(value.decode('UTF-8')[:65])
        elif key == 'date':
          sent_tz = parsedate_tz(value)
          if sent_tz:
            offset = sent_tz[-1] if sent_tz[-1] else 0
            sent = timegm((datetime(*sent_tz[:6]) - timedelta(seconds=offset)).timetuple())
          else:
            sent = int(time.time())
        elif key == 'from':
          data = value.decode('UTF-8').rsplit(' <', 1)
          if len(data) > 1:
            sender = basicHTMLencode(data[0][:30])
            email = basicHTMLencode(data[1].replace('>', '')[:50])
        elif key == 'hidden':
          if value.lower() in ('true', 'yes'):
            ishidden = 1
        elif key == 'language':
          lang = self._lang_by_name(basicHTMLencode(value.lower())) if value.lower() != 'auto' else ''
      else:
        body.append(line)

    if not body_found or not body:
      self.log(self.logger.ERROR, 'empty NNTP message \'%s\'. wtf?' % message_id)
      return False

    body = '\n'.join(body)

    if not lang:
      lang = self._detect_lang_name(subject, body)

    body = body.decode('UTF-8')
    self.generate_paste(hash_message_uid[:10], body, subject, sender, sent, lang, ishidden)
    self.sqlite.execute('INSERT INTO pastes VALUES (?,?,?,?,?,?,?,?,?,?,?)', (message_id, hash_message_uid, sender, email, subject, sent, body, '', int(time.time()), lang, ishidden))
    self.sqlite.commit()
    return True

  def _lang_by_name(self, lang_name):
    try:
      get_lexer_by_name(lang_name, encoding='utf-8')
      return lang_name
    except (ClassNotFound, ImportError) as e:
      self.log(self.logger.WARNING, '%s: %s' % (lang_name, e))
      return ''

  def _detect_lang_name(self, subject, paste_content):
    lexer = None
    if '.' in subject:
      if subject[-1] == ')':
        if ' (' in subject:
          name = subject.split(' (')[0]
        elif '(' in subject:
          name = subject.split('(')[0]
        else:
          name = subject
      else:
        name = subject
      if name.split('.')[-1] in self.recognized_extenstions:
        try:
          lexer = guess_lexer_for_filename(name, paste_content, encoding='utf-8')
        except (ClassNotFound, ImportError):
          pass
    if lexer is None and len(paste_content) >= 20:
      try:
        lexer = guess_lexer(paste_content, encoding='utf-8')
      except (ClassNotFound, ImportError):
        pass
    if lexer is None:
      try:
        lexer = get_lexer_by_name('text', encoding='utf-8')
      except (ClassNotFound, ImportError) as e:
        self.log(self.logger.WARNING, '%s: %s' % (subject, e))
        return ''
    return lexer.aliases[0]

  def recreate_index(self):
    self.log(self.logger.INFO, 'generating %s' % os.path.join(self.config['output_directory'], 'index.html'))
    paste_recent = list()
    index_row = u'<tr><td><a href="{}.html">{}</a></td><td>{}</td><td>{}</td><td>{}</td></tr>'
    for row in self.sqlite.execute('SELECT hash, subject, sender, sent, lang FROM pastes WHERE hidden = 0 ORDER by sent DESC LIMIT ?', (self.config['max_recent'],)).fetchall():
      paste_recent.append(index_row.format(row[0][:10], row[1], row[2], datetime.utcfromtimestamp(row[3]).strftime('%Y/%m/%d %H:%M UTC'), row[4]))
    with codecs.open(os.path.join(self.config['output_directory'], 'index.html'), 'w', 'UTF-8') as f:
      f.write(self.t_engine['index'].substitute(pasterows='\n'.join(paste_recent)))

  def handle_control(self, lines, timestamp):
    self.log(self.logger.DEBUG, 'got control message: %s' % lines)
    db_change = False
    for line in lines.split("\n"):
      if line.lower().startswith("delete "):
        message_id = line.lower().split(" ")[1]
        if os.path.exists(os.path.join("articles", "restored", message_id)):
          self.log(self.logger.DEBUG, 'message has been restored: %s. ignoring delete' % message_id)
          continue
        if not self.sqlite.execute('SELECT count(article_uid) FROM pastes WHERE article_uid = ?', (message_id,)).fetchone()[0]:
          self.log(self.logger.DEBUG, 'should delete message_id %s but there is no article matching this message_id' % message_id)
          continue
        self.log(self.logger.INFO, 'deleting message_id %s' % message_id)
        try:
          self.sqlite.execute('DELETE FROM pastes WHERE article_uid = ?', (message_id,))
        except sqlite3.Error as e:
          self.log(self.logger.ERROR, 'could not delete database entry for message_id %s: %s' % (message_id, e))
        else:
          db_change |= True
        short_hash = sha1(message_id).hexdigest()[:10]
        self.log(self.logger.INFO, 'deleting {0}.html & {0}.txt'.format(short_hash))
        try:
          os.unlink(os.path.join(self.config['output_directory'], "%s.html" % short_hash))
          os.unlink(os.path.join(self.config['output_directory'], "%s.txt" % short_hash))
        except OSError as e:
          self.log(self.logger.WARNING, 'could not delete paste for message_id %s: %s' % (message_id, e))
      else:
        self.log(self.logger.WARNING, 'unknown control message: %s' % line)
    if db_change:
      self.sqlite.commit()
    return db_change


if __name__ == '__main__':
  print "[%s] %s. %s" % ("paste", "this plugin can't run as standalone version.", "bye")
