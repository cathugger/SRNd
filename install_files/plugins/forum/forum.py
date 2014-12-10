#!/usr/bin/python
import sqlite3
import time
from datetime import datetime, timedelta
from email.utils import parsedate_tz
from calendar import timegm
import string
import os
import threading
from hashlib import sha1, sha512
from email.feedparser import FeedParser
import Image
import codecs
import nacl.signing
from binascii import unhexlify
import re
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
    self.should_terminate = False
    self.logger = logger
    
    # TODO: move sleep stuff to config table
    self.sleep_threshold = 10
    self.sleep_time = 0.02

    error = ''
    for arg in ('template_directory', 'output_directory', 'database_directory', 'temp_directory', 'document_file', 'invalid_file', 'css_file', 'title'):
      if not arg in args:
        error += "%s not in arguments\n" % arg
    if error != '':
      error = error.rstrip("\n")
      self.die(error)
    self.output_directory = args['output_directory']
    self.database_directory = args['database_directory']
    self.template_directory = args['template_directory']
    self.temp_directory = args['temp_directory']
    self.html_title = args['title']
    if not os.path.exists(self.template_directory):
      self.die('error: template directory \'%s\' does not exist' % self.template_directory)
    self.invalid_file = args['invalid_file']
    self.document_file = args['document_file']
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

    # FIXME messy code is messy

    if not os.path.exists(os.path.join(self.template_directory, self.invalid_file)):
      self.die('replacement for posts with invalid pictures not found: %s' % os.path.join(self.template_directory, self.invalid_file))
    if not os.path.exists(os.path.join(self.template_directory, self.document_file)):
      self.die('replacement for posts with documents attached (.pdf, .ps) not found: %s' % os.path.join(self.template_directory, self.document_file))
    if not os.path.exists(os.path.join(self.template_directory, self.css_file)):
      self.die('specified CSS file not found in template directory: %s' % os.path.join(self.template_directory, self.css_file))
    error = ''
    for template in ('boards.tmpl', 'boards_list.tmpl', 'threads.tmpl', 'threads_list.tmpl', 'posts.tmpl', 'posts_list.tmpl'):#, 'help.tmpl'):
      template_file = os.path.join(self.template_directory, template)
      if not os.path.exists(template_file):
        error += '%s missing\n' % template_file
        continue
      f = codecs.open(os.path.join(self.template_directory, template), 'r', 'UTF-8')
      self.__dict__['t_engine_%s' % template.replace('.tmpl', '')] = string.Template(
        string.Template(f.read()).safe_substitute(
          title=self.html_title
        )
      )
      f.close()
    if error != '':
      error = error.rstrip("\n")
      self.die(error)
    self.sync_on_startup = False
    if 'sync_on_startup' in args:
      if args['sync_on_startup'].lower() == 'true':
        self.sync_on_startup = True
    
    self.linker = re.compile("(&gt;&gt;)([0-9a-f]{10})")
    self.quoter = re.compile("^&gt;(?!&gt;).*", re.MULTILINE)
    self.coder = re.compile('\[code](?!\[/code])(.+?)\[/code]', re.DOTALL)
    
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
      something = Image.open(os.path.join(self.template_directory, self.invalid_file))
      modifier = float(180) / something.size[0]
      x = int(something.size[0] * modifier)
      y = int(something.size[1] * modifier)
      if something.mode == 'RGBA' or something.mode == 'LA':
        thumb_name = 'nope_loading_PIL.png'
      else:
        something = something.convert('RGB')
        thumb_name = 'nope_loading_PIL.jpg'
      something = something.resize((x,y), Image.ANTIALIAS)
      out = os.path.join(self.template_directory, thumb_name)
      something.save(out, optimize=True)
      del something
      os.remove(out)
    except IOError as e:
      self.die('error: can\'t load PIL library')
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
    # FIXME messy code is messy
    for file_source, file_target in (
        (self.css_file, 'styles.css'),
        ('user.css', 'user.css')
      ):
        i = open(os.path.join(self.template_directory, file_source), 'r')
        o = open(os.path.join(self.output_directory, file_target), 'w')
        o.write(i.read())
        o.close()
        i.close()

    # TODO: generate gen_thumbnail(source, dest) returning true/false
    link = os.path.join(self.output_directory, 'thumbs', self.invalid_file)
    if not os.path.exists(link):
      try:
        something = Image.open(os.path.join(self.template_directory, self.invalid_file))
        modifier = float(180) / something.size[0]
        x = int(something.size[0] * modifier)
        y = int(something.size[1] * modifier)
        if not (something.mode == 'RGBA' or something.mode == 'LA'):
          something = something.convert('RGB')
        something = something.resize((x,y), Image.ANTIALIAS)
        something.save(link, optimize=True)
        del something
      except IOError as e:
        self.log(self.logger.ERROR, 'can\'t save %s. wtf? %s' % (link, e))
    link = os.path.join(self.output_directory, 'thumbs', self.document_file)
    if not os.path.exists(link):
      try:
        something = Image.open(os.path.join(self.template_directory, self.document_file))
        modifier = float(180) / something.size[0]
        x = int(something.size[0] * modifier)
        y = int(something.size[1] * modifier)
        if not (something.mode == 'RGBA' or something.mode == 'LA'):
          something = something.convert('RGB')
        something = something.resize((x,y), Image.ANTIALIAS)
        something.save(link, optimize=True)
        del something
      except IOError as e:
        self.log(self.logger.ERROR, 'can\'t save %s. wtf? %s' % (link, e))
    self.regenerate_boards = list()
    self.regenerate_threads = list()
    self.missing_parents = dict()
    self.sqlite_hasher_conn = sqlite3.connect('hashes.db3')
    self.db_hasher = self.sqlite_hasher_conn.cursor() 
    self.sqlite_conn = sqlite3.connect(os.path.join(self.database_directory, 'forum.db3'))
    self.sqlite_conn.row_factory = sqlite3.Row
    self.sqlite = self.sqlite_conn.cursor()
    # FIXME use config table with current db version + def update_db(db_version) like in censor plugin
    self.sqlite.execute('''CREATE TABLE IF NOT EXISTS groups
               (group_id INTEGER PRIMARY KEY AUTOINCREMENT, group_name text UNIQUE, article_count INTEGER, last_update INTEGER)''')
    self.sqlite.execute('''CREATE TABLE IF NOT EXISTS articles
               (article_uid text, group_id INTEGER, sender text, email text, subject text, sent INTEGER, parent text, message text, imagename text, imagelink text, thumblink text, last_update INTEGER, public_key text, PRIMARY KEY (article_uid, group_id))''')
    
    # TODO add some flag like ability to carry different data for groups like (removed + added manually + public + hidden + whatever)
    #self.sqlite.execute('''CREATE TABLE IF NOT EXISTS flags
    #           (flag_id INTEGER PRIMARY KEY AUTOINCREMENT, flag_name text UNIQUE, flag text)''')
    #try:
    #  self.sqlite.execute('INSERT INTO flags (flag_name, flag) VALUES (?,?)', ('removed', str(0b1)))
    #except:
    #  pass
    try:
      self.sqlite.execute('ALTER TABLE articles ADD COLUMN public_key text')
    except:
      pass
    try:
      self.sqlite.execute('ALTER TABLE articles ADD COLUMN received INTEGER DEFAULT 0')
    except:
      pass
    try:
      self.sqlite.execute('ALTER TABLE groups ADD COLUMN blocked INTEGER DEFAULT 0')
    except:
      pass
    self.sqlite.execute('CREATE INDEX IF NOT EXISTS articles_group_idx ON articles(group_id);')
    self.sqlite.execute('CREATE INDEX IF NOT EXISTS articles_parent_idx ON articles(parent);')
    self.sqlite.execute('CREATE INDEX IF NOT EXISTS articles_article_idx ON articles(article_uid);')
    self.sqlite_conn.commit()
    
    if self.regenerate_html_on_startup:
      self.regenerate_all_html()

  def regenerate_all_html(self):
    for group_row in self.sqlite.execute('SELECT group_id FROM groups WHERE blocked != 1').fetchall():
      if group_row[0] not in self.regenerate_boards:
        self.regenerate_boards.append(group_row[0])
    for thread_row in self.sqlite.execute('SELECT article_uid FROM articles WHERE parent = "" OR parent = article_uid ORDER BY last_update DESC').fetchall():
      if thread_row[0] not in self.regenerate_threads:
        self.regenerate_threads.append(thread_row[0])

  def shutdown(self):
    self.running = False

  def add_article(self, message_id, source="article", timestamp=None):
    self.queue.put((source, message_id, timestamp))
    
  def handle_control(self, lines, timestamp):
    # FIXME how should board-add and board-del react on timestamps in the past / future
    self.log(self.logger.DEBUG, 'got control message: %s' % lines)
    root_posts = list()
    for line in lines.split("\n"):
      if line.lower().startswith('overchan-board-add'):
        group_name = line.lower().split(" ")[1]
        if '/' in group_name:
          self.log(self.logger.WARNING, 'got overchan-board-add with invalid group name: \'%s\', ignoring' % group_name)
          continue
        try:
          self.sqlite.execute('UPDATE groups SET blocked = 0 WHERE group_name = ?', (group_name,))
          self.log(self.logger.INFO, 'unblocked existing board: \'%s\'' % group_name)
        except:
          self.sqlite.execute('INSERT INTO groups(group_name, article_count, last_update) VALUES (?,?,?)', (group_name, 0, int(time.time())))
          self.log(self.logger.INFO, 'added new board: \'%s\'' % group_name)
        self.sqlite_conn.commit()
        self.regenerate_all_html()
      elif line.lower().startswith("overchan-board-del"):
        group_name = line.lower().split(" ")[1]
        try:
          self.sqlite.execute('UPDATE groups SET blocked = 1 WHERE group_name = ?', (group_name,))
          self.log(self.logger.INFO, 'blocked board: \'%s\'' % group_name)
          self.sqlite_conn.commit()
          self.regenerate_all_html()
        except:
          self.log(self.logger.WARNING, 'should delete board %s but there is no board with that name' % group_name)
      elif line.lower().startswith("overchan-delete-attachment "):
        message_id = line.lower().split(" ")[1]
        if os.path.exists(os.path.join("articles", "restored", message_id)):
          self.log(self.logger.DEBUG, 'message has been restored: %s. ignoring overchan-delete-attachment' % message_id)
          continue
        row = self.sqlite.execute("SELECT imagelink, thumblink, parent, group_id, received FROM articles WHERE article_uid = ?", (message_id,)).fetchone()
        if not row:
          self.log(self.logger.DEBUG, 'should delete attachments for message_id %s but there is no article matching this message_id' % message_id)
          continue
        #if row[4] > timestamp:
        #  self.log("post more recent than control message. ignoring delete-attachment for %s" % message_id, 2)
        #  continue
        if row[0] == 'invalid':
          self.log(self.logger.DEBUG, 'attachment already deleted. ignoring delete-attachment for %s' % message_id)
          continue
        self.log(self.logger.INFO, 'deleting attachments for message_id %s' % message_id)
        if row[3] not in self.regenerate_boards:
          self.regenerate_boards.append(row[3])
        if row[2] == '':
          if not message_id in self.regenerate_threads:
            self.regenerate_threads.append(message_id)
        elif not row[2] in self.regenerate_threads:
          self.regenerate_threads.append(row[2])
        if len(row[0]) > 0:
          self.log(self.logger.INFO, 'deleting attachment for message_id %s: img/%s' % (message_id, row[0]))
          try:
            os.unlink(os.path.join(self.output_directory, "img", row[0]))
          except Exception as e:
            self.log(self.logger.WARNING, 'could not delete attachment %s: %s' % (row[0], e))
        if len(row[1]) > 0 and row[1] != "invalid":
          self.log(self.logger.INFO, 'deleting attachment for message_id %s: thumbs/%s' % (message_id, row[1]))
          try:
            os.unlink(os.path.join(self.output_directory, "thumbs", row[1]))
          except Exception as e:
            self.log(self.logger.WARNING, 'could not delete attachment %s: %s' % (row[1], e))
        self.sqlite.execute('UPDATE articles SET imagelink = "invalid", thumblink = "invalid", imagename = "invalid", public_key = "" WHERE article_uid = ?', (message_id,))
        self.sqlite_conn.commit()
      elif line.lower().startswith("delete "):
        message_id = line.lower().split(" ")[1]
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
        if row[3] not in self.regenerate_boards:
          self.regenerate_boards.append(row[3])
        if row[2] == '':
          # root post
          if int(self.sqlite.execute("SELECT count(article_uid) FROM articles WHERE parent = ?", (message_id,)).fetchone()[0]) > 0:
            # root posts with child posts
            self.log(self.logger.DEBUG, 'deleting message_id %s, got a root post with attached child posts' % message_id)
            root_posts.append(message_id)
            self.sqlite.execute('UPDATE articles SET imagelink = "invalid", thumblink = "invalid", imagename = "invalid", message = "this post has been deleted by some evil mod", sender = "deleted", email = "deleted", subject = "deleted", public_key = "" WHERE article_uid = ?', (message_id,))
            if message_id not in self.regenerate_threads:
              self.regenerate_threads.append(message_id)
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
        if len(row[0]) > 0 and row[0] != "invalid":
          self.log(self.logger.INFO, 'deleting message_id %s, attachment %s' % (message_id, row[0]))
          try:
            os.unlink(os.path.join(self.output_directory, "img", row[0]))
          except Exception as e:
            self.log(self.logger.WARNING, 'could not delete img/%s: %s' % (row[0], e))
        if len(row[1]) > 0 and row[1] != "invalid":
          self.log(self.logger.INFO, 'deleting message_id %s, thumb %s' % (message_id, row[1]))
          try:
            os.unlink(os.path.join(self.output_directory, "thumbs", row[1]))
          except Exception as e:
            self.log(self.logger.WARNING, 'could not delete thumbs/%s: %s' % (row[1], e))
        self.sqlite_conn.commit()
    for post in root_posts:
      if int(self.sqlite.execute("SELECT count(article_uid) FROM articles WHERE parent = ? and parent != article_uid", (message_id,)).fetchone()[0]) == 0:
        self.log(self.logger.DEBUG, 'deleting message_id %s, root_post has no more childs' % message_id)
        self.sqlite.execute('DELETE FROM articles WHERE article_uid = ?', (message_id,))
        self.sqlite_conn.commit()
        try:
          os.unlink(os.path.join(self.output_directory, "thread-%s" % sha1(message_id).hexdigest()[:10]))
        except Exception as e:
          self.log(self.logger.WARNING, 'could not delete thread for message_id %s: %s' % (message_id, e))
      else:
        self.log(self.logger.DEBUG, 'deleting message_id %s, root_post still has childs' % message_id)

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
          if self.sqlite.execute('SELECT subject FROM articles WHERE article_uid = ? AND imagelink != "invalid"', (message_id,)).fetchone():
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
            self.log(self.logger.WARNING, 'something went wrong while trying to parse article %s:' % message_id)
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
      except Queue.Empty as e:
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
          self.generate_boardview()
          regen_overview = False
        if got_control:
          self.sqlite_conn.commit()
          self.sqlite.execute('VACUUM;')
          self.sqlite_conn.commit()
          got_control = False
    self.sqlite_conn.close()
    self.sqlite_hasher_conn.close()
    self.log(self.logger.INFO, 'bye')

  def basicHTMLencode(self, inputString):
    return inputString.replace('<', '&lt;').replace('>', '&gt;')
  
  def generate_pubkey_short_utf_8(self, full_pubkey_hex, length=6):
    pub_short = ''
    if len(full_pubkey_hex) == 0:
      return pub_short
    for x in range(0, length / 2):
      pub_short +=  '&#%i;' % (9600 + int(full_pubkey_hex[x*2:x*2+2], 16))
    length = length - (length / 2)
    for x in range(0, length):
      pub_short += '&#%i;' % (9600 + int(full_pubkey_hex[-(length*2):][x*2:x*2+2], 16))
    return pub_short

  def upp_it(self, data):
    if data[-1] not in self.upper_table:
      return data
    return data[:-1] + self.upper_table[data[-1]]
    
  def linkit(self, rematch):
    row = self.db_hasher.execute("SELECT message_id FROM article_hashes WHERE message_id_hash >= ? and message_id_hash < ?", (rematch.group(2), self.upp_it(rematch.group(2)))).fetchall()
    if not row:
      # hash not found
      return rematch.group(0)
    if len(row) > 1:
      # multiple matches for that 10 char hash
      return rematch.group(0)
    message_id = row[0][0]
    parent_row = self.sqlite.execute("SELECT parent FROM articles WHERE article_uid = ?", (message_id,)).fetchone()
    if not parent_row:
      # not an overchan article (anymore)
      return rematch.group(0)
    parent_id = parent_row[0]
    if parent_id == "":
      # article is root post
      return '%s<a href="thread-%s.html">%s</a>' % (rematch.group(1), rematch.group(2), rematch.group(2))
    # article has a parent
    # FIXME: cache results somehow?
    parent = sha1(parent_id).hexdigest()[:10]
    return '%s<a href="thread-%s.html#%s">%s</a>' % (rematch.group(1), parent, rematch.group(2), rematch.group(2))
  
  def quoteit(self, rematch):
    return '<span class="quote">%s</span>' % rematch.group(0).rstrip("\r")

  def codeit(self, rematch):
    return '<div class="code">%s</div>' % rematch.group(1)

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
        parent = line[len('references:'):-1].replace('\t', ' ').strip().split(' ')[0]
      elif lower_line.startswith('newsgroups:'):
        group_in = lower_line[:-1].split(' ', 1)[1]
        if ';' in group_in:
          groups_in = group_in.split(';')
          for group_in in groups_in:
            groups.append(group_in)
        elif ',' in group_in:
          groups_in = group_in.split(',')
          for group_in in groups_in:
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
    group_ids = list()
    for group in groups:
      result = self.sqlite.execute('SELECT group_id FROM groups WHERE group_name=? AND blocked = 0', (group,)).fetchone()
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
      update_dat_thread = parent
      if not sage:
        result = self.sqlite.execute('SELECT last_update FROM articles WHERE article_uid = ?', (parent,)).fetchone()
        if result:
          parent_last_update = result[0]
          if sent > parent_last_update:
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
      update_dat_thread = message_id
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
    image_name_original = ''
    image_name = ''
    thumb_name = ''
    message = ''
    # TODO: check if out dir is remote fs, use os.rename if not
    if result.is_multipart():
      self.log(self.logger.DEBUG, 'message is multipart, length: %i' % len(result.get_payload()))
      if len(result.get_payload()) == 1 and result.get_payload()[0].get_content_type() == "multipart/mixed":
        result = result.get_payload()[0]
      for part in result.get_payload():
        self.log(self.logger.DEBUG, 'got part == %s' % part.get_content_type())
        if part.get_content_type().startswith('image/'):
          tmp_link = os.path.join(self.temp_directory, 'tmpImage')
          f = open(tmp_link, 'w')
          f.write(part.get_payload(decode=True))
          f.close()
          # get hash for filename
          f = open(tmp_link, 'r')
          image_name_original = self.basicHTMLencode(part.get_filename().replace('/', '_').replace('"', '_'))
          # FIXME read line by line and use hasher.update(line)
          imagehash = sha1(f.read()).hexdigest()
          image_name = image_name_original.split('.')[-1].lower()
          if image_name in ('html', 'php'):
            image_name = 'txt'
          image_name = imagehash + '.' + image_name
          out_link = os.path.join(self.output_directory, 'img', image_name)
          f.close()
          # copy to out directory with new filename
          # FIXME use os.rename() for the sake of good
          c = open(out_link, 'w')
          f = open(tmp_link, 'r')
          c.write(f.read())
          c.close()
          f.close()
          if image_name_original.split('.')[-1].lower() == 'gif':
            # copy to thumb directory with new filename
            # FIXME: use relative link instead
            thumb_link = os.path.join(self.output_directory, 'thumbs', image_name)
            thumb_name = image_name
            c = open(thumb_link, 'w')
            f = open(tmp_link, 'r')
            c.write(f.read())
            c.close()
            f.close()
          else:
            # create thumb, convert to RGB and use jpeg if no transparency involved, png if it is
            try:
              thumb = Image.open(out_link)
              # always use width for modifier
              modifier = float(180) / thumb.size[0]
              #if thumb.size[0] > thumb.size[1]:
              #  modifier = float(200) / thumb.size[0]
              #else:
              #  modifier = float(200) / thumb.size[1]
              x = int(thumb.size[0] * modifier)
              y = int(thumb.size[1] * modifier)
              self.log(self.logger.DEBUG, 'old image size: %ix%i, new image size: %ix%i' %  (thumb.size[0], thumb.size[1], x, y))
              if thumb.mode == 'RGBA' or thumb.mode == 'LA':
                thumb_name = imagehash + '.png'
              else:
                thumb = thumb.convert('RGB')
                thumb_name = imagehash + '.jpg'
              thumb_link = os.path.join(self.output_directory, 'thumbs', thumb_name)
              thumb = thumb.resize((x,y), Image.ANTIALIAS)
              #thumb.thumbnail((200, 200), Image.ANTIALIAS)
              thumb.save(thumb_link, optimize=True)
              del thumb
            except Exception as e:
              self.log(e, 3)
              thumb_name = 'invalid'
          os.remove(tmp_link)
          #os.rename('tmp/tmpImage', 'html/img/' + imagelink) # damn remote file systems and stuff
        elif part.get_content_type().lower() in ('application/pdf', 'application/postscript', 'application/ps'):
          tmp_link = os.path.join(self.temp_directory, 'tmpImage')
          f = open(tmp_link, 'w')
          f.write(part.get_payload(decode=True))
          f.close()
          # get hash for filename
          f = open(tmp_link, 'r')
          image_name_original = self.basicHTMLencode(part.get_filename().replace('/', '_').replace('"', '_'))
          imagehash = sha1(f.read()).hexdigest()
          image_name = image_name_original.split('.')[-1].lower()
          if image_name in ('html', 'php'):
            image_name = 'txt'
          image_name = imagehash + '.' + image_name
          out_link = os.path.join(self.output_directory, 'img', image_name)
          f.close()
          # copy to out directory with new filename
          c = open(out_link, 'w')
          f = open(tmp_link, 'r')
          c.write(f.read())
          c.close()
          f.close()
          thumb_name = 'document'
          os.remove(tmp_link)
        elif part.get_content_type().lower() == 'text/plain':
          message += part.get_payload(decode=True)
        else:
          message += '\n----' + part.get_content_type() + '----\n'
          message += 'invalid content type\n'
          message += '----' + part.get_content_type() + '----\n\n'
    else:
      if result.get_content_type().lower() == 'text/plain':
        message += result.get_payload(decode=True)
      else:
        message += '\n----' + result.get_content_type() + '----\n'
        message += 'invalid content type\n'
        message += '----' + result.get_content_type() + '----\n\n'
    del result
    message = self.basicHTMLencode(message)
    if self.sqlite.execute('SELECT article_uid FROM articles WHERE article_uid=?', (message_id,)).fetchone():
      # post has been censored and is now being restored. just delete post for all groups so it can be reinserted
      self.log(self.logger.INFO, 'post has been censored and is now being restored: %s' % message_id) 
      self.sqlite.execute('DELETE FROM articles WHERE article_uid=?', (message_id,))
      self.sqlite_conn.commit()
    for group_id in group_ids:
      self.sqlite.execute('INSERT INTO articles(article_uid, group_id, sender, email, subject, sent, parent, message, imagename, imagelink, thumblink, last_update, public_key, received) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)', (message_id, group_id, sender.decode('UTF-8'), email.decode('UTF-8'), subject.decode('UTF-8'), sent, parent, message.decode('UTF-8'), image_name_original.decode('UTF-8'), image_name, thumb_name, last_update, public_key, int(time.time())))
      self.sqlite.execute('UPDATE groups SET last_update=?, article_count = (SELECT count(article_uid) FROM articles WHERE group_id = ?) WHERE group_id = ?', (int(time.time()), group_id, group_id))
    self.sqlite_conn.commit()
    if update_dat_thread not in self.regenerate_threads:
      self.regenerate_threads.append(update_dat_thread)
    return True
  
  def generate_boardview(self):
    self.log(self.logger.INFO, 'generating %s/boards.html' % self.output_directory)
    mapper = dict()
    boardlist = list()
    for row in self.sqlite.execute('SELECT group_name, group_id, article_count FROM groups WHERE blocked = 0 ORDER by group_name ASC').fetchall():
      #current_group_name = row['group_name'].split('.', 1)[-1].replace('"', '').replace('/', '')
      current_group_name = row['group_name'].replace('"', '').replace('/', '')
      current_group_name_encoded = self.basicHTMLencode(current_group_name)
      mapper['board_link']   = '%s.html' % current_group_name
      mapper['board_name']   = current_group_name_encoded
      mapper['thread_count'] = str(self.sqlite.execute('SELECT count(1) FROM articles WHERE group_id = ? AND (parent = "" OR parent = article_uid)', (row['group_id'],)).fetchone()[0])
      mapper['post_count']   = str(row['article_count'])
      latest_post = self.sqlite.execute('SELECT article_uid, parent, sent, subject, sender FROM articles WHERE group_id = ? ORDER BY sent DESC LIMIT 1', (row['group_id'],)).fetchone()
      mapper['last_post_date']    = datetime.utcfromtimestamp(latest_post['sent']).strftime('%Y/%m/%d %H:%M')
      mapper['last_post_sender']  = latest_post['sender']
      mapper['last_post_anchor']  = sha1(latest_post['article_uid']).hexdigest()[:10]
      if latest_post['parent'] == '' or latest_post['parent'] == latest_post['article_uid']:
        # latest post is a root post
        mapper['thread_link']       = 'thread-%s.html' % sha1(latest_post['article_uid']).hexdigest()[:10]
        mapper['last_post_subject'] = latest_post['subject']
      else:
        mapper['thread_link']         = 'thread-%s.html' % sha1(latest_post['parent']).hexdigest()[:10]
        try:
          mapper['last_post_subject'] = self.sqlite.execute('SELECT subject FROM articles WHERE article_uid = ?', (latest_post['parent'],)).fetchone()[0]
        except:
          mapper['last_post_subject'] = 'root post for latest thread not yet available'
      boardlist.append(self.t_engine_boards_list.substitute(mapper))

    f = codecs.open(os.path.join(self.output_directory, 'boards.html'), 'w', 'UTF-8')
    f.write(self.t_engine_boards.substitute(title="foobar test", boards_list=u"".join(boardlist)))
    f.close()
    
  def generate_board(self, board_id):
    board_name = self.sqlite.execute('SELECT group_name FROM groups WHERE group_id = ?', (board_id,)).fetchone()[0]
    self.log(self.logger.INFO, 'generating %s/%s.html' % (self.output_directory, board_name))
    mapper = dict()
    threadlist = list()
    for row in self.sqlite.execute('SELECT article_uid, subject, sender, sent FROM articles WHERE group_id = ? AND (parent = "" OR parent = article_uid) ORDER BY last_update DESC', (board_id,)).fetchall():
      mapper['thread_link']       = 'thread-%s.html' % sha1(row['article_uid']).hexdigest()[:10]
      mapper['thread_subject']    = row['subject']
      mapper['thread_starter']    = row['sender']
      mapper['thread_replies']    = self.sqlite.execute('SELECT count(1) FROM articles WHERE parent = ?', (row['article_uid'],)).fetchone()[0]
      if mapper['thread_replies'] > 0:
        latest_post = self.sqlite.execute('SELECT article_uid, sent, sender FROM articles WHERE parent = ? ORDER BY sent DESC LIMIT 1', (row['article_uid'],)).fetchone()
        mapper['last_post_date']    = datetime.utcfromtimestamp(latest_post['sent']).strftime('%Y/%m/%d %H:%M')      
        mapper['last_post_anchor']  = sha1(latest_post['article_uid']).hexdigest()[:10]
        mapper['last_post_sender'] = latest_post['sender']
      else: 
        mapper['last_post_date']    = datetime.utcfromtimestamp(row['sent']).strftime('%Y/%m/%d %H:%M')
        mapper['last_post_anchor']  = sha1(row['article_uid']).hexdigest()[:10]
        mapper['last_post_sender']  = row['sender']
      threadlist.append(self.t_engine_threads_list.substitute(mapper))

    f = codecs.open(os.path.join(self.output_directory, '%s.html' % board_name), 'w', 'UTF-8')
    f.write(self.t_engine_threads.substitute(
      title="foobar test",
      current_board_link=('%s.html' % board_name),
      current_board_name=board_name,
      new_thread_link='new_thread.html',
      threads_list=u"".join(threadlist)
    ))
    f.close()
    
  def generate_thread(self, root_uid):
    root_sha = sha1(root_uid).hexdigest()[:10]
    self.log(self.logger.INFO, 'generating %s/thread-%s.html' % (self.output_directory, root_sha))
    mapper = dict()
    postlist = list()
    root_post = self.sqlite.execute('SELECT article_uid, sender, subject, sent, message, public_key, imagename, imagelink, thumblink, group_id FROM articles WHERE article_uid = ?', (root_uid,)).fetchone()
    if root_post == None:
      self.log(self.logger.WARNING, "root post not yet available: %s" % root_uid)
      return
    mapper['anchor']  = root_sha
    mapper['sender']  = root_post['sender']
    mapper['trip']    = self.generate_pubkey_short_utf_8(root_post['public_key'])
    mapper['subject'] = root_post['subject']
    mapper['date']    = datetime.utcfromtimestamp(root_post['sent']).strftime('%Y/%m/%d %H:%M')
    mapper['message'] = root_post['message']
    if root_post['thumblink'] == '':
      mapper['imagelink'] = ''
    else:
      if root_post['thumblink'] == 'document':
        thumb = self.document_file
      elif root_post['thumblink'] == 'invalid':
        thumb = self.invalid_file
      else:
        thumb = root_post['thumblink']
      mapper['imagelink'] = '<i>%s</i><br /><a href="img/%s"><img src="thumbs/%s" /></a>' % (root_post['imagename'], root_post['imagelink'], thumb)
    postlist.append(self.t_engine_posts_list.substitute(mapper))
    for child_post in self.sqlite.execute('SELECT article_uid, sender, subject, sent, message, public_key, imagename, imagelink, thumblink FROM articles WHERE parent = ? ORDER BY sent ASC', (root_uid,)).fetchall():
      mapper['anchor']  = sha1(child_post['article_uid']).hexdigest()[:10]
      mapper['sender']  = child_post['sender']
      mapper['trip']    = self.generate_pubkey_short_utf_8(child_post['public_key'])
      mapper['subject'] = child_post['subject']
      mapper['date']    = datetime.utcfromtimestamp(child_post['sent']).strftime('%Y/%m/%d %H:%M')
      
      last_quote_level=0
      current_quote_level=0
      lines = child_post['message'].split('\n')
      for index, line in enumerate(lines):
        current_quote_level = 0
        if line.startswith('&gt;'):
          char_index = 0
          while char_index < len(line):
            if line[char_index:char_index+4] != '&gt;': break
            current_quote_level += 1
            char_index += 4
        if current_quote_level > last_quote_level:
          lines[index] = '<div class="quote">'*(current_quote_level-last_quote_level)
        elif current_quote_level < last_quote_level:
          lines[index] = '</div>'*(last_quote_level-current_quote_level)
        else:
          lines[index] = ''
        lines[index] += line[current_quote_level*4:]
        last_quote_level = current_quote_level
      if current_quote_level != 0:
        lines[-1] += '</div>'*(last_quote_level-current_quote_level)

      mapper['message'] = u'\n'.join(lines)
      if child_post['thumblink'] == '':
        mapper['imagelink'] = ''
      else:
        if child_post['thumblink'] == 'document':
          thumb = self.document_file
        elif child_post['thumblink'] == 'invalid':
          thumb = self.invalid_file
        else:
          thumb = child_post['thumblink']
        mapper['imagelink'] = '<i>%s</i><br /><a href="img/%s"><img src="thumbs/%s" /></a>' % (child_post['imagename'], child_post['imagelink'], thumb)
      postlist.append(self.t_engine_posts_list.substitute(mapper))

    board_name = self.sqlite.execute('SELECT group_name FROM groups WHERE group_id = ?', (root_post['group_id'],)).fetchone()[0]
    f = codecs.open(os.path.join(self.output_directory, 'thread-%s.html' % root_sha), 'w', 'UTF-8')
    f.write(self.t_engine_posts.substitute(
      title="foobar test",
      current_board_link=('%s.html' % board_name),
      current_board_name=board_name,
      current_thread=sha1(root_uid).hexdigest(),
      current_thread_link='thread-%s.html' % root_sha,
      current_thread_subject=root_post['subject'],
      reply_link='reply.html',
      posts_list=u"".join(postlist)
    ))
    f.close()

  def generate_overview_old(self):
    self.log(self.logger.INFO, 'generating %s/overview.html' % self.output_directory)
    t_engine_mappings_overview = dict()
    boardlist = list()
    news_uid = '<lwmueokaxt1389929084@web.overchan.sfor.ano>'
    # FIXME: cache this shit somewhere
    for group_row in self.sqlite.execute('SELECT group_name, group_id FROM groups WHERE blocked = 0 ORDER by group_name ASC').fetchall():
      current_group_name = group_row[0].split('.', 1)[1].replace('"', '').replace('/', '')
      current_group_name_encoded = self.basicHTMLencode(current_group_name)
      boardlist.append('&nbsp;<a href="%s-1.html">%s</a>&nbsp;|' % (current_group_name, current_group_name_encoded))
    boardlist[-1] = boardlist[-1][:-1]
    t_engine_mappings_overview['boardlist'] = ''.join(boardlist)
    row = self.sqlite.execute('SELECT subject, message, sent, public_key, parent, sender FROM articles WHERE article_uid = ?', (news_uid, )).fetchone()
    if not row:
      t_engine_mappings_overview['subject'] = ''
      t_engine_mappings_overview['sent'] = ''
      t_engine_mappings_overview['author'] = ''
      t_engine_mappings_overview['pubkey_short'] = ''
      t_engine_mappings_overview['pubkey'] = ''
      t_engine_mappings_overview['postid'] = ''
      t_engine_mappings_overview['parent'] = 'does_not_exist_yet'
      t_engine_mappings_overview['message'] = 'once upon a time there was a news post'
    else:
      postid = sha1(news_uid).hexdigest()[:10]
      if row[4] == '' or row[4] == news_uid:
        parent = postid
      else:
        parent = sha1(row[4]).hexdigest()[:10]
      if len(row[1].split('\n')) > 5:
        message = '\n'.join(row[1].split('\n')[:5]) + '\n[..] <a href="thread-%s.html#%s"><i>message too large</i></a>\n' % (parent, postid)
      elif len(row[1]) > 1000:
        message = row[1][:1000] + '\n[..] <a href="thread-%s.html#%s"><i>message too large</i></a>\n' % (parent, postid)
      else:
        message = row[1]
      t_engine_mappings_overview['subject'] = row[0]
      t_engine_mappings_overview['sent'] = datetime.utcfromtimestamp(row[2]).strftime('%Y/%m/%d %H:%M')
      t_engine_mappings_overview['author'] = row[5]
      t_engine_mappings_overview['pubkey_short'] = self.generate_pubkey_short_utf_8(row[3])
      t_engine_mappings_overview['pubkey'] = row[3]
      t_engine_mappings_overview['postid'] = postid
      t_engine_mappings_overview['parent'] = parent
      t_engine_mappings_overview['message'] = message
    
    weekdays = ('Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday')
    max = 0
    stats = list()
    bar_length = 20
    days = 21
    totals = int(self.sqlite.execute('SELECT count(1) FROM articles WHERE sent > strftime("%s", "now", "-' + str(days) + ' days")').fetchone()[0])
    stats.append(self.template_stats_usage_row.replace('%%postcount%%', str(totals)).replace('%%date%%', 'all posts').replace('%%weekday%%', '').replace('%%bar%%', 'since %s days' % days))
    for row in self.sqlite.execute('SELECT count(1) as counter, strftime("%Y-%m-%d",  sent, "unixepoch") as day, strftime("%w", sent, "unixepoch") as weekday FROM articles WHERE sent > strftime("%s", "now", "-' + str(days) + ' days") GROUP BY day ORDER BY day DESC').fetchall():
      if row[0] > max:
        max = row[0]
      stats.append((row[0], row[1], weekdays[int(row[2])]))
    for index in range(1, len(stats)):
      graph = ''
      for x in range(0, int(float(stats[index][0])/max*bar_length)):
        graph += '='
      if len(graph) == 0:
        graph = '&nbsp;'
      stats[index] = self.template_stats_usage_row.replace('%%postcount%%', str(stats[index][0])).replace('%%date%%', stats[index][1]).replace('%%weekday%%', stats[index][2]).replace('%%bar%%', graph)
    overview_stats_usage = self.template_stats_usage
    overview_stats_usage = overview_stats_usage.replace('%%stats_usage_rows%%', ''.join(stats))
    t_engine_mappings_overview['stats_usage'] = overview_stats_usage
    del stats[:]

    postcount = 23
    for row in self.sqlite.execute('SELECT sent, group_name, sender, subject, article_uid, parent FROM articles, groups WHERE groups.blocked = 0 AND articles.group_id = groups.group_id ORDER BY sent DESC LIMIT ' + str(postcount)).fetchall():
      sent = datetime.utcfromtimestamp(row[0]).strftime('%Y/%m/%d %H:%M UTC')
      board = self.basicHTMLencode(row[1].replace('"', '')).split('.', 1)[1]
      author = row[2]
      articlehash = sha1(row[4]).hexdigest()[:10]
      if row[5] == '' or row[5] == row[4]:
        # root post
        subject = row[3]
        parent = articlehash
      else:
        parent = sha1(row[5]).hexdigest()[:10]
        try:
          subject = self.sqlite.execute('SELECT subject FROM articles WHERE article_uid = ?', (row[5],)).fetchone()[0] 
        except:
          subject = 'root post not yet available'
      if len(subject) > 60:
        subject = subject[:60] + ' [..]'
      if len(author) > 20:
        author = author[:20] + ' [..]'
      stats.append(self.template_latest_posts_row.replace('%%sent%%', sent).replace('%%board%%', board).replace('%%parent%%', parent).replace('%%articlehash%%', articlehash).replace('%%author%%', author).replace('%%subject%%', subject))
    #for row in self.sqlite.execute('SELECT articles.last_update, group_name, sender, subject, article_uid FROM articles, groups WHERE (parent = "" or parent = article_uid) AND articles.group_id = groups.group_id ORDER BY articles.last_update DESC LIMIT ' + str(postcount)).fetchall():
    #  last_update = datetime.utcfromtimestamp(row[0]).strftime('%Y/%m/%d %H:%M UTC')
    #  board = self.basicHTMLencode(row[1].replace('"', '')).split('.', 1)[1]
    #  subject = row[3]
    #  parent = sha1(row[4]).hexdigest()[:10]
    #  try:
    #    childrow = self.sqlite.execute('SELECT sender, article_uid FROM articles WHERE parent = ? ORDER BY sent DESC LIMIT 1', (row[4],)).fetchone()
    #    articlehash = sha1(childrow[1]).hexdigest()[:10]
    #    author = childrow[0]
    #  except:
    #    articlehash = parent
    #    author = row[2]
    #  stats.append(self.template_latest_posts_row.replace('%%sent%%', last_update).replace('%%board%%', board).replace('%%parent%%', parent).replace('%%articlehash%%', articlehash).replace('%%author%%', author).replace('%%subject%%', subject))
    overview_latest_posts = self.template_latest_posts
    overview_latest_posts = overview_latest_posts.replace('%%latest_posts_rows%%', ''.join(stats))
    t_engine_mappings_overview['latest_posts'] = overview_latest_posts
    del stats[:]

    for row in self.sqlite.execute('SELECT count(1) as counter, group_name FROM articles, groups WHERE groups.blocked = 0 AND articles.group_id = groups.group_id GROUP BY articles.group_id ORDER BY counter DESC').fetchall():
      stats.append(self.template_stats_boards_row.replace('%%postcount%%', str(row[0])).replace('%%board%%', self.basicHTMLencode(row[1])))
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
