#!/usr/bin/python
import os
import sqlite3
import time
import threading
from hashlib import sha1
from datetime import datetime, timedelta
from email.utils import parsedate_tz
from calendar import timegm
from pygments import highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers import guess_lexer, guess_lexer_for_filename, get_lexer_by_name, ClassNotFound
import codecs
import traceback

if __name__ == '__main__':
  import signal
  import fcntl
else:
  import Queue


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
    self.logger = logger
    self.should_terminate = False
    self.loglevel = self.logger.INFO
    # TODO: move sleep stuff to config table    
    self.sleep_threshold = 10
    self.sleep_time = 0.02
    error = ''
    for arg in ('template_directory', 'output_directory', 'database_directory', 'css_file', 'title'):
      if not arg in args:
        error += '%s not in arguments\n' % arg
    if error != '':
      self.die(error.rstrip('\n'))
    self.outputDirectory = args['output_directory']
    self.database_directory = args['database_directory']
    self.templateDirectory = args['template_directory']
    self.css_file = args['css_file']
    self.html_title = args['title']
    self.sync_on_startup = False
    if 'sync_on_startup' in args:
      if args['sync_on_startup'].lower() == 'true':
        self.sync_on_startup = True
    if not os.path.exists(self.templateDirectory):
      self.die('template directory \'%s\' does not exist' % self.templateDirectory)
    if not os.path.exists(os.path.join(self.templateDirectory, self.css_file)):
      self.die('specified CSS file not found in template directory: \'%s\' does not exist' % os.path.join(self.templateDirectory, self.css_file))

    if __name__ == '__main__':
      self.log(self.logger.INFO, 'initializing as standalone application..')
      if 'watch_directory' not in args:
        self.die('called without watch_directory and thus should receive articles via .add_article() but this class runs as own application')
      self.watching = args['watch_directory']
      self.log(self.logger.INFO, 'creating directory watcher..')
      signal.signal(signal.SIGIO, self.handle_new)
      try:
        fd = os.open(self.watching, os.O_RDONLY)
      except OSError as e:
        if e.errno == 2:
          self.die(e)
        else:
          raise e
      fcntl.fcntl(fd, fcntl.F_SETSIG, 0)
      fcntl.fcntl(fd, fcntl.F_NOTIFY,
                  fcntl.DN_MODIFY | fcntl.DN_CREATE | fcntl.DN_MULTISHOT)
      if not os.path.exists(self.database_directory):
        os.mkdir(self.database_directory)
      self.sqlite_conn = sqlite3.connect(os.path.join(self.database_directory, 'pastes.db3'))
      self.sqlite = self.sqlite_conn.cursor()
      self.sqlite.execute('''CREATE TABLE IF NOT EXISTS pastes
                    (article_uid text, hash text PRIMARY KEY, sender text, email text, subject text, sent INTEGER, body text, root text, received INTEGER)''')
      self.sqlite_conn.commit()
    else:
      self.log(self.logger.INFO, 'initializing as plugin..')
      if 'watch_directory' in args:
        self.die('called with watch_directory and thus should watch a directory for changes but this class does not run as own application')

      self.queue = Queue.Queue()
      # needed for working inside a chroot to recognize latin1 charset
      try:
        lexer = guess_lexer("svmmsjj".encode('latin1'), encoding='utf-8')
      except ClassNotFound as e:
        pass
    if 'debug' not in args:
      self.log(self.logger.INFO, 'debuglevel not defined, using default of debug = %i' % self.logger.INFO)
    else:
      try:
        self.loglevel = int(args['debug'])
        if self.loglevel < 0 or self.loglevel > 5:
          self.loglevel = self.logger.INFO
          self.log(self.logger.WARNING, 'debuglevel not between 0 and 5, using default of debug = %i' % self.logger.INFO)
        else:
          self.log(self.logger.DEBUG, 'using debuglevel %i' % self.loglevel)
      except ValueError as e:
        self.loglevel = self.logger.INFO
        self.log(self.logger.WARNING, 'debuglevel not between 0 and 5, using default of debug = %i' % self.logger.INFO)
    if 'generate_all' in args:
      if args['generate_all'].lower() == 'true': 
        self.generate_full_html_on_start = True
      else:
        self.generate_full_html_on_start = False
    else:
      self.generate_full_html_on_start = False
    self.formatter = HtmlFormatter(linenos=True, cssclass="source", encoding='utf-8', anchorlinenos=True, lineanchors='line', full=False, cssfile="./styles.css", noclobber_cssfile=True)
    self.lexers = dict()
    #allowed_lexers = ('Bash', 'HTML+Lasso', 'NumPy')
    self.allowed_lexers = ('Bash', 'NumPy', 'Perl') # TODO: add php because of shebang line?
    self.recognized_extenstions = ('sh', 'py', 'pyx', 'pl', 'hs', 'haskell', 'js', 'php', 'html', 'c', 'cs')
    f = open(os.path.join(self.templateDirectory, 'single_paste.tmpl'), 'r')
    self.template_single_paste = f.read()
    f.close()
    f = open(os.path.join(self.templateDirectory, 'index.tmpl'), 'r')
    self.template_index = f.read()
    f.close()
    if __name__ == '__main__':
      self.busy = False
      self.retry = False
      i = open(os.path.join(self.templateDirectory, self.css_file), 'r')
      o = open(os.path.join(self.outputDirectory, 'styles.css'), 'w')
      o.write(i.read())
      o.close()
      i.close()
      self.handle_new(None, None)

  def add_article(self, message_id, source="article", timestamp=None):
    self.queue.put((source, message_id, timestamp))

  def shutdown(self):
    self.running = False

  def run(self):
    if self.should_terminate:
      self.shutdown()
      return
    if  __name__ == '__main__':
      return
    if not os.path.exists(self.outputDirectory):
      os.mkdir(self.outputDirectory)
    if not os.path.exists(self.database_directory):
      os.mkdir(self.database_directory)
    i = open(os.path.join(self.templateDirectory, self.css_file), 'r')
    o = open(os.path.join(self.outputDirectory, 'styles.css'), 'w')
    o.write(i.read())
    o.close()
    i.close()
    self.sqlite_conn = sqlite3.connect(os.path.join(self.database_directory, 'pastes.db3'))
    self.sqlite = self.sqlite_conn.cursor()
    self.sqlite.execute('''CREATE TABLE IF NOT EXISTS pastes
                  (article_uid text, hash text PRIMARY KEY, sender text, email text, subject text, sent INTEGER, body text, root text, received INTEGER)''')
    self.sqlite_conn.commit()
    self.running = True
    self.regenerate_index = False
    self.log(self.logger.INFO, 'starting up as plugin..')
    if self.generate_full_html_on_start:
      self.log(self.logger.INFO, 'regenerating all HTML files..')
      for row in self.sqlite.execute('SELECT hash, sender, subject, sent, body FROM pastes ORDER BY sent ASC').fetchall():
        self.generate_paste(row[0][:10], row[4], row[2], row[1], row[3])
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
            f = open(os.path.join('articles', message_id), 'r')
            message_content = f.readlines()
            f.close()
            if len(message_content) == 0:
              self.log(self.logger.ERROR, 'empty NNTP message \'%s\'. wtf?' % message_id)
              continue
            if not self.parse_message(message_id, message_content):
              continue
            self.regenerate_index = True
          except Exception as e:
            self.log(self.logger.WARNING, 'something went wrong while parsing new article %s:' % message_id)
            self.log(self.logger.WARNING, traceback.format_exc())
            try:
              f.close()
            except:
              pass
        elif ret[0] == "control":
          got_control = True
          self.handle_control(ret[1], ret[2])
        else:
          self.log(self.logger.WARNING, 'got article with unknown source: %s' % ret[0])
        if self.queue.qsize() > self.sleep_threshold:
          time.sleep(self.sleep_time)
      except Queue.Empty as e:
        if got_control:
          self.sqlite_conn.commit()
          self.sqlite.execute('VACUUM;')
          self.sqlite_conn.commit()
          got_control = False
          self.regenerate_index = True
        if self.regenerate_index:
          self.recreate_index()
          self.regenerate_index = False
    self.sqlite_conn.close()
    self.log(self.logger.INFO, 'bye')

  def basicHTMLencode(self, input):
    return input.replace('<', '&lt;').replace('>', '&gt;')

  def generate_paste(self, identifier, paste_content, subject, sender, sent):
    self.log(self.logger.INFO, 'new paste: %s' % subject)
    self.log(self.logger.INFO, 'generating %s' % os.path.join(self.outputDirectory, identifier + '.txt'))
    f = codecs.open(os.path.join(self.outputDirectory, identifier + '.txt'), 'w', encoding='utf-8')
    f.write(paste_content)
    f.close()
    self.log(self.logger.INFO, 'generating %s' % os.path.join(self.outputDirectory, identifier + '.html'))
    found = False
    try:
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
          lexer = guess_lexer_for_filename(name, paste_content, encoding='utf-8')
          found = True
      if not found:
        if len(paste_content) >= 2:
          if paste_content[:2] == '#!':
            lexer = guess_lexer(paste_content, encoding='utf-8')
            if lexer.name not in self.allowed_lexers:
              lexer = get_lexer_by_name('text', encoding='utf-8')
          else:
            lexer = get_lexer_by_name('text', encoding='utf-8')
        else:
          lexer = get_lexer_by_name('text', encoding='utf-8')
    except ClassNotFound as e:
      self.log(self.logger.WARNING, '%s: %s' % (subject, e))
      lexer = get_lexer_by_name('text', encoding='utf-8')
    except ImportError as e:
      self.log(self.logger.WARNING, '%s: %s' % (subject, e))
      lexer = get_lexer_by_name('text', encoding='utf-8')
    result = highlight(paste_content, lexer, self.formatter)
    template = self.template_single_paste.replace('%%paste_title%%', subject)
    template = template.replace('%%title%%', self.html_title)
    template = template.replace('%%sender%%', sender)
    template = template.replace('%%sent%%', datetime.utcfromtimestamp(sent).strftime('%Y/%m/%d %H:%M UTC'))
    template = template.replace('%%identifier%%', identifier)
    template = template.replace('%%paste%%', result)
    f = open(os.path.join(self.outputDirectory, identifier + '.html'), 'w')
    f.write(template)
    f.close()
    del result, template

  def parse_message(self, message_id, message_content):
    hash_message_uid = sha1(message_id).hexdigest()
    identifier = hash_message_uid[:10]
    subject = 'No Title'
    sent = 0
    sender = 'None'
    email = 'non@giv.en'
    for index in xrange(0, len(message_content)):
      if message_content[index].lower().startswith('subject:'):
        subject = self.basicHTMLencode(message_content[index].split(' ', 1)[1][:-1])
      elif message_content[index].lower().startswith('date:'):
        sent = message_content[index].split(' ', 1)[1][:-1]
        sent_tz = parsedate_tz(sent)
        if sent_tz:
          offset = 0
          if sent_tz[-1]: offset = sent_tz[-1]
          sent = timegm((datetime(*sent_tz[:6]) - timedelta(seconds=offset)).timetuple())
        else:
          sent = int(time.time())
      elif message_content[index].lower().startswith('from:'):
        sender = self.basicHTMLencode(message_content[index].split(' ', 1)[1][:-1].split(' <', 1)[0])
        try:
          email = self.basicHTMLencode(message_content[index].split(' ', 1)[1][:-1].split(' <', 1)[1].replace('>', ''))
        except:
          pass
      elif message_content[index] == '\n':
        bar = message_content[index+1:]
        break
    self.generate_paste(identifier, ''.join(bar).decode('UTF-8'), subject, sender, sent)
    self.sqlite.execute('INSERT INTO pastes VALUES (?,?,?,?,?,?,?,?,?)', (message_id, hash_message_uid, sender.decode('UTF-8'), email.decode('UTF-8'), subject.decode('UTF-8'), sent, ''.join(bar).decode('UTF-8'), '', int(time.time())))
    self.sqlite_conn.commit()
    del bar
    return True

  def recreate_index(self):
    self.log(self.logger.INFO, 'generating %s' % os.path.join(self.outputDirectory, 'index.html'))
    paste_recent = list()
    for row in self.sqlite.execute('SELECT hash, subject, sender, sent FROM pastes ORDER by sent DESC').fetchall():
      paste_recent.append('<tr><td><a href="{0}.html">{1}</a></td><td>{2}</td><td>{3}</td></tr>\n'.format(row[0][:10], row[1].encode('UTF-8'), row[2].encode('UTF-8'), datetime.utcfromtimestamp(row[3]).strftime('%Y/%m/%d %H:%M UTC')))
    f = open(os.path.join(self.outputDirectory, 'index.html'), 'w')
    template = self.template_index.replace("%%title%%", self.html_title)
    template = template.replace('%%reply%%', '')
    template = template.replace('%%target%%', '')
    template = template.replace('%%pasterows%%', ''.join(paste_recent))
    f.write(template)
    f.close()

  def handle_control(self, lines, timestamp):
    self.log(self.logger.DEBUG, 'got control message: %s' % lines)
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
        try: self.sqlite.execute('DELETE FROM pastes WHERE article_uid = ?', (message_id,))
        except Exception as e:
          self.log(self.logger.ERROR, 'could not delete database entry for message_id %s: %s' % (message_id, e))
        try:
          self.log(self.logger.INFO, 'deleting %s.html..' % sha1(message_id).hexdigest()[:10])
          os.unlink(os.path.join(self.outputDirectory, "%s.html" % sha1(message_id).hexdigest()[:10]))
        except Exception as e:
          self.log(self.logger.WARNING, 'could not delete paste for message_id %s: %s' % (message_id, e))
        self.sqlite_conn.commit()
      else:
        self.log(self.logger.WARNING, 'unknown control message: %s' % line)

  def handle_new(self, signum, frame):
    # only standalone
    # FIXME use try: except around open(), also check for duplicate here
    if self.busy:
      self.retry = True
      return
    self.busy = True
    something_new = False
    for message_id in os.listdir(self.watching):
      f = open(os.path.join(self.watching, message_id), 'r')
      message_content = f.readlines()
      f.close()
      if len(message_content) == 0:
        self.log(self.logger.WARNING, 'empty NNTP message \'%s\'. wtf?' % message_id)
        os.remove(os.path.join(self.watching, message_id))
        continue
      if not self.parse_message(message_id, message_content):
        os.remove(os.path.join(self.watching, message_id))
        continue
      something_new = True
      os.remove(os.path.join(self.watching, message_id))
    if something_new:
      self.recreate_index()
    self.busy = False
    if self.retry:
      self.retry = False
      self.handle_new(None, None)

if __name__ == '__main__':
  args = dict()
  args['watch_directory'] = 'hooks/paste'
  args['template_directory'] = 'plugins/paste/templates'
  args['output_directory'] = 'plugins/paste/out'
  args['database_directory'] = 'plugins/paste'
  args['debug'] = '5'
  foo = main('paster', args)
  foo.start()
  while True:
    try:
      #time.sleep(3600)
      signal.pause()
    except:
      print
      foo.shutdown()
      exit(0)
