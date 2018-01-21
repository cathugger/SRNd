#!/usr/bin/python

import base64
import io
import os
import random
import re
import socket
import sqlite3
import string
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler
from http.server import HTTPServer as HTTPD

try:
  from socketserver import ThreadingMixIn
  class ThreadedHTTPServer(ThreadingMixIn, HTTPD):
    """
    multithreaded http server
    """
except ImportError:
  HTTPServer = HTTPD
else:
  HTTPServer = HTTPD
  
from binascii import hexlify
from cgi import FieldStorage
from datetime import datetime
from hashlib import sha1, sha256, sha512
from urllib.parse import unquote

import nacl.signing

from srnd.utils import chrootRandom, str_reaper
from captcha import Captcha

class postman(BaseHTTPRequestHandler):

  def __init__(self, request, client_address, origin):
    self.origin = origin
    #if __name__ != '__main__':
    #  self.origin.log('postman initializing as plugin..', 2)
    #else:
    #  self.origin.log('postman initializing as standalone application..', 2)
    # ^ works
    BaseHTTPRequestHandler.__init__(self, request, client_address, origin)

  def do_POST(self):
    cookie = self.get_cookie('sid')
    if cookie and cookie in self.origin.spammers:
      self.origin.log(self.origin.logger.WARNING, 'POST recognized an earlier spammer! %s' % cookie)
      self.origin.log(self.origin.logger.WARNING, self.headers)
      if self.origin.fake_ok:
        self.exit_redirect(2, '/')
      else:
        self._spammers_spam()
      return
      # TODO: trap it: while True; wfile.write(random*x); sleep 1; done
      # TODO: ^ requires multithreaded BaseHTTPServer
    self.path = unquote(self.path)
    if self.path == '/incoming':
      if self.origin.captcha_verification:
        self.send_captcha(message=self.get_random_quote())
      else:
        self.handleNewArticle()
    elif self.path == '/incoming/verify':
      self.handleVerify()
    else:
      self.origin.log(self.origin.logger.WARNING, "illegal POST access: %s" % self.path)
      self.origin.log(self.origin.logger.WARNING, self.headers)
      self.exit_redirect(9, '/overview.html', False, 'nope')

  def do_GET(self):
    cookie = self.get_cookie('sid')
    if cookie and cookie in self.origin.spammers:
      self.origin.log(self.origin.logger.VERBOSE, 'GET recognized an earlier spammer trying to access %s! %s' % (self.path, cookie))
      self._spammers_spam()
      return
    self.path = unquote(self.path)
    if self.path == '/incoming/verify':
      self.send_captcha()
    else:
      self.origin.log(self.origin.logger.WARNING, "illegal GET access: %s" % self.path)
      self.origin.log(self.origin.logger.WARNING, self.headers)
      self.exit_redirect(9, '/overview.html', False, 'nope')

  def die(self, message=''):
    self.origin.log(self.origin.logger.WARNING, "%s:%i wants to fuck around, %s" % (self.client_address[0], self.client_address[1], message))
    self.origin.log(self.origin.logger.WARNING, self.headers)
    if self.origin.reject_debug:
      self.exit_redirect(9, '/overview.html', False, 'don\'t fuck around here mkay\n{0}'.format(message))
    else:
      self.exit_redirect(9, '/overview.html', False, 'don\'t fuck around here mkay')

  def exit_redirect(self, redirect_duration, redirect_target, add_spamheader=False, message='your message has been received.'):
    self.send_response(200)
    if add_spamheader:
      if len(self.origin.spammers) > 255:
        self.origin.spammers = list()
      cookie = ''.join(random.choice(self.origin.alphabet) for x in range(16))
      self.origin.spammers.append(cookie)
      self.send_header('Set-Cookie', 'sid=%s; path=/incoming' % cookie)
    self.send_header('Content-type', 'text/html')
    self.end_headers()
    self.write_data(self.origin.template_redirect.format(redirect_duration, redirect_target, message))

  def write_data(self, data):
    self.wfile.write(data.encode('utf-8'))
    
  def log_request(self, *code):
    return

  def log_message(self, _, *args):
    return

  def get_random_quote(self):
    return random.choice(self.origin.quotes)

  def failCaptcha(self, vars_):
    msg = self.get_random_quote()
    msg += '<br/><b><font style="color: red;">failed. hard.</font></b>'
    self.send_captcha(msg, vars_)

  def _get_post_vars(self):
    contentType = 'Content-Type' in self.headers and self.headers['Content-Type'] or 'text/plain'
    post_vars = FieldStorage(
        fp=self.rfile,
        headers=self.headers,
        environ={
            'REQUEST_METHOD': 'POST',
            'CONTENT_TYPE': contentType
        }
    )
    return post_vars

  def handleVerify(self):
    post_vars = self._get_post_vars()
    for item in ('expires', 'hash', 'solution'):
      if item not in post_vars:
        self.failCaptcha(post_vars)
        return
    if not self.origin.captcha_require_cookie:
      if self.origin.captcha.captcha_verify(post_vars['expires'].value, post_vars['hash'].value, post_vars['solution'].value):
        self.handleNewArticle(post_vars)
        return
      self.failCaptcha(post_vars)
      return
    cookie = self.headers.get('Cookie')
    if not cookie:
      self.failCaptcha(post_vars)
      return
    cookie = cookie.strip()
    for item in cookie.split(';'):
      if item.startswith('session='):
        cookie = item
    cookie = cookie.strip().split('=', 1)[1]
    if len(cookie) != 32:
      self.failCaptcha(post_vars)
      return
    if self.origin.captcha.captcha_verify(post_vars['expires'].value, post_vars['hash'].value, post_vars['solution'].value, cookie):
      self.handleNewArticle(post_vars)
      return
    self.failCaptcha(post_vars)

  def _spammers_spam(self):
    self.send_response(200)
    self.send_header('Content-type', 'text/html')
    self.end_headers()
    self.write_data('<html><body>')
    for y in range(0, 100):
      #self.wfile.write('<img src="/img/%s.png" style="width: 100px;" />' % ''.join(random.choice(self.origin.alphabet) for x in range(16)))
      self.write_data('<iframe src="/incoming/%s"></iframe>' % ''.join(random.choice(self.origin.alphabet) for x in range(16)))
      #time.sleep(0.1)
    self.write_data('</body></html>')

  def get_cookie(self, cookie_name):
    cookie = self.headers.get('Cookie')
    if cookie:
      cookie = cookie.strip()
      for item in cookie.split(';'):
        if item.startswith('%s=' % cookie_name):
          cookie = item
          break
      return cookie.strip().split('=', 1)[1]
    return ''

  def send_captcha(self, message='', post_vars=None):
    failed = True
    if not post_vars:
      failed = False
      post_vars = self._get_post_vars()
    # someone wants to fuck around
    if not 'frontend' in post_vars:
      self.die('frontend not in post_vars')
      return
    #if frontend == 'overchan' and reply != '':
    #  # FIXME add ^ allow_reply_bypass to frontend configuration
    #  if self.origin.captcha_bypass_after_timestamp_reply < int(time.time()):
    #    self.origin.log(self.origin.logger.INFO, 'bypassing captcha for reply')
    #    self.handleNewArticle(post_vars)
    #    return
    if self.origin.receive_from_friends > 0:
      user_cookie = self.get_cookie('ananas')
      if self.origin.allow_this_cookie(user_cookie):
        self.handleNewArticle(post_vars, user_cookie)
        return
      elif self.origin.receive_from_friends == 2:
        self.die('Anonymous posting is not allowed on this frontend.')
        return
    data = self._extract_base_headers(post_vars)
    data['message'] = message
    if failed:
      identifier = sha256()
      identifier.update(''.join((data['frontend'], data['board'], data['reply'], data['target'], data['name'], data['email'], data['subject'])))
      identifier.update(data['comment'])
      self.origin.log(self.origin.logger.WARNING, 'failed capture try for %s' % identifier.hexdigest())
      self.origin.log(self.origin.logger.WARNING, self.headers)
    self.send_response(200)
    self.send_header('Content-type', 'text/html')
    if self.origin.captcha_require_cookie:
      cookie = ''.join(random.choice(self.origin.alphabet) for x in range(32))
      self.send_header('Set-Cookie', 'session=%s; path=/incoming/verify' % cookie)
    else:
      cookie = ''
    data['b64'], data['expires'], data['solution_hash'] = self.origin.captcha.get_captcha(cookie)
    self.end_headers()
    # use file_name as key and file content + current time as value
    if self.origin.fast_uploads:
      if data['file_b64']:
        # we can have empty file_b64 here whether captcha was entered wrong first time
        self.origin.temp_file_obj[data['file_name']] = [data.pop('file_b64'), int(time.time())]
      self.write_data(self.origin.t_engine['verify_fast'].substitute(data))
    else:
      self.write_data(self.origin.t_engine['verify_slow'].substitute(data))
    return self.origin.captcha.cache_bump()

  def _extract_base_headers(self, post_vars):
    data = {
        'frontend': post_vars.getvalue('frontend', '').replace('"', '&quot;'),
        'reply': post_vars.getvalue('reply', '').replace('"', '&quot;'),
        'board': post_vars.getvalue('board', '').replace('"', '&quot;'),
        'target': post_vars.getvalue('target', '').replace('"', '&quot;'),
        'name': post_vars.getvalue('name', '').replace('"', '&quot;'),
        'email': post_vars.getvalue('email', '').replace('"', '&quot;'),
        'subject': post_vars.getvalue('subject', '').replace('"', '&quot;')
    }
    data['custom_headers'] = self._custom_headers_to_html(self._get_custom_headers(post_vars, data['frontend']))
    if post_vars.getvalue('hash', '') != '':
      data['comment'] = post_vars.getvalue('comment', '').replace('"', '&quot;')
      data['file_name'] = post_vars.getvalue('file_name', '').replace('"', '&quot;')
      data['file_ct'] = post_vars.getvalue('file_ct', '').replace('"', '&quot;')
      data['file_b64'] = post_vars.getvalue('file_b64', '').replace('"', '&quot;')
    else:
      data['comment'] = base64.encodestring(post_vars.getvalue('comment', ''))
      data['file_name'], data['file_ct'], data['file_b64'] = '', '', ''
      if 'allowed_files' in self.origin.frontends[data['frontend']]:
        try:
          data['file_name'] = post_vars['file'].filename.replace('"', '&quot;')
        except KeyError:
          pass
        if data['file_name']:
          data['file_ct'] = post_vars['file'].type.replace('"', '&quot;')
          f = io.StringIO()
          base64.encode(post_vars['file'].file, f)
          data['file_b64'] = f.getvalue()
          f.close()
    return data

  @staticmethod
  def _custom_headers_to_article(custom_headers):
    """return headers to insert into the article. Also, bump first letter in key"""
    form_ = '\n{}: {}'
    return ''.join(form_.format(key.capitalize(), str_reaper(value)) for key, value in list(custom_headers.items()))

  @staticmethod
  def _custom_headers_to_html(custom_headers):
    """return headers to insert into the captcha page"""
    form_ = '\n        <input type="hidden" name="{}" value="{}" />'
    return ''.join(form_.format(key, value.replace('"', '&quot;')) for key, value in list(custom_headers.items()))

  def _get_custom_headers(self, post_vars, frontend):
    """extract custom headers. If header empty or missing - use default value if default value not empty. Return header: value dict"""
    custom_headers = dict()
    if 'custom' not in self.origin.frontends[frontend]:
      return custom_headers
    for key, def_val in list(self.origin.frontends[frontend]['custom'].items()):
      value = post_vars.getvalue(key, def_val).split('\n')[0].strip()
      if not value:
        value = def_val
      if value:
        custom_headers[key] = value
    return custom_headers

  def fake_id_to_overchan_id(self, comment, board):
    def reverse_mapping(rematch):
      message_id = self.origin.dropperdb.execute('SELECT message_id FROM articles, groups WHERE \
          groups.group_name = ? AND groups.group_id = articles.group_id AND articles.article_id = ?', (board, rematch.group(2))).fetchall()
      if not message_id or len(message_id) > 1: return rematch.group(0)
      return '{0}{1}'.format(rematch.group(1), sha1(message_id[0][0]).hexdigest()[:10])

    def check_overchan_id(rematch):
      if len(rematch.group(2)) == 10 and self.origin.sqlite.execute("SELECT message_id FROM article_hashes WHERE message_id_hash LIKE ?", (rematch.group(2)+'%',)).fetchone():
        return rematch.group(0)
      return re.compile("(>>)([0-9]{1,10})").sub(reverse_mapping, rematch.group(0))

    return re.compile("(>>)([0-9a-f]{1,10})").sub(check_overchan_id, comment)

  def handleNewArticle(self, post_vars=None, user_cookie=None):
    if not post_vars:
      post_vars = self._get_post_vars()
    if not 'frontend' in post_vars:
      self.die('frontend not in post_vars')
      return
    frontend = post_vars['frontend'].value
    if not 'target' in post_vars:
      self.die('target not in post_vars')
      return
    if not frontend in self.origin.frontends:
      self.die('{0} not in configured frontends'.format(frontend))
      return
    for key in self.origin.frontends[frontend]['required_fields']:
      if not key in post_vars:
        self.die('{0} required but missing'.format(key))
        return
    if 'hash' in post_vars:
      comment = base64.decodestring(post_vars.getvalue('comment', ''))
    else:
      comment = post_vars['comment'].value
    #TODO: UTF-8 strip?
    if comment.strip(' \t\n\r') == '':
      self.exit_redirect(9, '/overview.html', False, 'no message received. nothing to say?')
      return
    if 'enforce_board' in self.origin.frontends[frontend]:
      group = self.origin.frontends[frontend]['enforce_board']
    else:
      group = post_vars['board'].value.split('\n')[0]
      if group == '':
        self.die('board is empty')
        return
      found = False
      for board in self.origin.frontends[frontend]['allowed_boards']:
        if (board[-1] == '*' and group.startswith(board[:-1])) or group == board:
          found = True
          break
      if not found:
        self.die('{0} not in allowed_boards'.format(group))
        return
    redirect_duration = 4
    if not 'allowed_files' in self.origin.frontends[frontend]:
      file_name = ''
    else:
      if 'hash' in post_vars:
        file_name = post_vars.getvalue('file_name', '')
      else:
        file_name = post_vars['file'].filename.split('\n')[0]
      # FIXME: add (allowed_extensions) to frontend config, remove this check once implemented
      if len(file_name) > 100:
        self.die('filename too large')
        return
      if file_name != '':
        if 'hash' in post_vars:
          content_type = post_vars.getvalue('file_ct', '')
        else:
          content_type = post_vars['file'].type
        allowed = False
        for mime in self.origin.frontends[frontend]['allowed_files']:
          if (mime[-1] == '*' and content_type.startswith(mime[:-1])) or content_type == mime:
            allowed = True
            break
        if not allowed:
          self.die('{0} not in allowed_files'.format(content_type))
          return
        redirect_duration = 4
    if self.origin.overchan_fake_id and frontend.lower() == 'overchan':
      comment = self.fake_id_to_overchan_id(comment, group)

    uid_host = self.origin.frontends[frontend]['uid_host']

    name = self.origin.frontends[frontend]['defaults']['name']
    email = self.origin.frontends[frontend]['defaults']['email']
    subject = self.origin.frontends[frontend]['defaults']['subject']

    if 'name' in post_vars:
      if post_vars['name'].value.split('\n')[0] != '':
        name = post_vars['name'].value.split('\n')[0]

    signature = False
    if 'allow_signatures' in self.origin.frontends[frontend]:
      if self.origin.frontends[frontend]['allow_signatures'].lower() in ('true', 'yes'):
        if '#' in name:
          if len(name) >= 65 and name[-65] == '#':
            try:
              keypair = nacl.signing.SigningKey(name[-64:], encoder=nacl.encoding.HexEncoder)
              signature = True
            except Exception as e:
              self.origin.log(self.origin.logger.INFO, "can't create keypair from user supplied secret key: %s" % e)
            name = name[:-65]
          else:
            parts = name.split('#', 1)
            if len(parts[1]) > 0:
              name = parts[0]
              try:
                private = parts[1][:32]
                out = list()
                counter = 0
                for char in private:
                  out.append(chr(ord(self.origin.seed[counter]) ^ ord(char)))
                  counter += 1
                for x in range(counter, 32):
                  out.append(self.origin.seed[x])
                del counter
                keypair = nacl.signing.SigningKey(sha256("".join(out)).digest())
                del out
                signature = True
              except Exception as e:
                # FIXME remove "secret" trip? disable signature?
                self.origin.log(self.origin.logger.INFO, "can't create keypair from user supplied short trip: %s" % e)
            del parts
          if name == '':
            name = self.origin.frontends[frontend]['defaults']['name']

    if 'email' in post_vars:
      #FIXME add email validation: .+@.+\..+
      if post_vars['email'].value.split('\n')[0] != '':
        email = post_vars['email'].value.split('\n')[0]

    if 'subject' in post_vars:
      if post_vars['subject'].value.split('\n')[0] != '':
        subject = str_reaper(post_vars['subject'].value.split('\n')[0], 128)

    sage = ''
    if 'allow_sage' in self.origin.frontends[frontend]:
      if self.origin.frontends[frontend]['allow_sage'].lower() in ('true', 'yes'):
        if (subject.lower().startswith('sage') or subject.lower().startswith('saging') or
            name.lower().startswith('sage') or name.lower().startswith('saging')):
          sage = "\nX-Sage: True"

    sender = '{0} <{1}>'.format(str_reaper(name, 64), str_reaper(email, 64))
    reply = ''
    if 'reply' in post_vars:
      reply = post_vars['reply'].value

    if reply != '':
      result = self.origin.sqlite.execute('SELECT message_id FROM article_hashes WHERE message_id_hash = ?', (reply,)).fetchone()
      if not result:
        self.die('hash {0} is not a valid hash'.format(reply))
        return
      else:
        reply = result[0]
        self.origin.captcha_bypass_after_timestamp_reply = int(time.time()) + self.origin.captcha_bypass_after_seconds_reply
    uid_rnd = ''.join(random.choice(string.ascii_lowercase) for x in range(10))
    uid_time = int(time.time())
    message_uid = '<{0}{1}@{2}>'.format(uid_rnd, uid_time, self.origin.frontends[frontend]['uid_host'])
    if 'enforce_target' in self.origin.frontends[frontend]:
      redirect_target = self.origin.frontends[frontend]['enforce_target'].replace('%%sha1_message_uid_10%%', sha1(message_uid).hexdigest()[:10])
    else:
      redirect_target = post_vars['target'].value.replace('%%sha1_message_uid_10%%', sha1(message_uid).hexdigest()[:10])
    if 'hash' in post_vars:
      redirect_target = '/' + redirect_target
    boundary = ''.join(random.choice(string.ascii_letters + string.digits) for x in range(40))
    date = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S +0000')
    i2p_desthash = self.headers.get('X-I2P-DestHash', 'non-i2p')
    if self.origin.i2p_spamprotect and user_cookie is None:
      if i2p_desthash == 'non-i2p' or not self.origin.allow_this_desthash(i2p_desthash):
        self.die('This frontend uses hardened spamprotect. Come back one hour later.')
        return

    custom_headers = self._get_custom_headers(post_vars, frontend)
    if custom_headers:
      head_info = ' Custom headers: {}'.format(', '.join(list(custom_headers.keys())))
      custom_headers = self._custom_headers_to_article(custom_headers)
    else:
      head_info = ''
      custom_headers = ''
    self.origin.log(self.origin.logger.INFO, "got incoming {} from {}:{} for frontend '{}'.{}".format(message_uid, self.client_address[0], self.client_address[1], frontend, head_info))

    link = os.path.join('incoming', 'tmp', boundary + '_') if signature else os.path.join('incoming', 'tmp', boundary)
    f = open(link, 'w')
    if file_name == '':
      f.write(self.origin.template_message_nopic.format(sender, date, group, subject, message_uid, reply, uid_host, comment, sage, i2p_desthash, custom_headers).replace('\r', ''))
    else:
      f.write(self.origin.template_message_pic.format(sender, date, group, subject, message_uid, reply, uid_host, boundary, comment, content_type, file_name, sage, i2p_desthash, custom_headers).replace('\r', ''))
      if 'hash' in post_vars:
        if self.origin.fast_uploads:
          # get file looking by file_name
          if file_name not in self.origin.temp_file_obj:
            self.origin.temp_file_obj[file_name] = ['', '']
          f.write(self.origin.temp_file_obj[file_name][0].replace('\r', ''))
          del self.origin.temp_file_obj[file_name]
          self.cleanup_uploads()
        else:
          f.write(post_vars.getvalue('file_b64', '').replace('\r', ''))
      else:
        base64.encode(post_vars['file'].file, f)
      f.write('--{0}--\n'.format(boundary))
    f.close()
    if signature:
      hasher = sha512()
      f = open(link, 'r')
      oldline = None
      for line in f:
        if oldline:
          hasher.update(oldline)
        oldline = line.replace("\n", "\r\n")
      #f.close()
      oldline = oldline.replace("\r\n", "")
      hasher.update(oldline)
      signature = hexlify(keypair.sign(hasher.digest()).signature)
      pubkey = hexlify(keypair.verify_key.encode())
      signed = open(link[:-1], 'w')
      f = open(link, 'r')
      link = link[:-1]
      signed.write(self.origin.template_message_signed.format(sender, date, group, subject, message_uid, reply, uid_host, pubkey, signature, sage, i2p_desthash, custom_headers))
      f.seek(0)
      for line in f:
        signed.write(line)
      f.close()
      signed.close()
      # FIXME unlink f() a.k.a. incoming/tmp/*_
      del hasher
      del keypair
      del pubkey
      del signature
    try:
      if len(comment) > 40 and self.origin.spamprot_base64.match(comment):
        os.rename(link, os.path.join('incoming', 'spam', message_uid))
        self.origin.log(self.origin.logger.WARNING, "caught some new base64 spam for frontend %s: incoming/spam/%s" % (frontend, message_uid))
        self.origin.log(self.origin.logger.WARNING, self.headers)
        #if self.origin.fake_ok:
        self.exit_redirect(redirect_duration, redirect_target, add_spamheader=True)
      elif len(subject) > 80 and self.origin.spamprot_base64.match(subject):
        os.rename(link, os.path.join('incoming', 'spam', message_uid))
        self.origin.log(self.origin.logger.WARNING, "caught some new large subject spam for frontend %s: incoming/spam/%s" % (frontend, message_uid))
        self.origin.log(self.origin.logger.WARNING, self.headers)
        #if self.origin.fake_ok:
        self.exit_redirect(redirect_duration, redirect_target, add_spamheader=True)
      elif len(name) > 80 and self.origin.spamprot_base64.match(name):
        os.rename(link, os.path.join('incoming', 'spam', message_uid))
        self.origin.log(self.origin.logger.WARNING, "caught some new large name spam for frontend %s: incoming/spam/%s" % (frontend, message_uid))
        self.origin.log(self.origin.logger.WARNING, self.headers)
        #if self.origin.fake_ok:
        self.exit_redirect(redirect_duration, redirect_target, add_spamheader=True)
      else:
        os.rename(link, os.path.join('incoming', boundary))
        if user_cookie is not None:
          self.origin.update_this_cookie(user_cookie, message_uid, uid_time)
        #os.rename(link, os.path.join('incoming', 'spam', message_uid))
        self.exit_redirect(redirect_duration, redirect_target)
    except socket.error as e:
      if e.errno == 32:
        self.origin.log(self.origin.logger.DEBUG, 'broken pipe: %s' % e)
        # Broken pipe
      else:
        self.origin.log(self.origin.logger.WARNING, 'unhandled exception while processing new post: %s' % e)
        self.origin.log(self.origin.logger.WARNING, traceback.format_exc())

  def cleanup_uploads(self):
    """ delete old uploads """
    l = list()
    timestamp = int(time.time()) - 3600
    for key in self.origin.temp_file_obj:
      if self.origin.temp_file_obj[key][1] < timestamp:
        l.append(key)
    for k in l:
      del self.origin.temp_file_obj[k]

class main(threading.Thread):

  def log(self, loglevel, message):
    if loglevel >= self.loglevel:
      self.logger.log(self.name, message, loglevel)

  def __init__(self, thread_name, logger, args):
    threading.Thread.__init__(self)
    self.name = thread_name
    self.logger = logger
    self.serving = False
    self.sync_on_startup = False
    self._db_connector = args['db_connector']
    self.httpd = None
    if 'debug' not in args:
      self.loglevel = self.logger.INFO
      self.log(self.logger.DEBUG, 'debuglevel not defined, using default of debug = %i' % self.loglevel)
    else:
      try:
        self.loglevel = int(args['debug'])
        if self.loglevel < 0 or self.loglevel > 5:
          self.loglevel = self.logger.INFO
          self.log(self.logger.WARNING, 'debuglevel not between 0 and 5, using default of debug = %i' % self.loglevel)
        else:
          self.log(self.logger.DEBUG, 'using debuglevel %i' % self.loglevel)
      except ValueError:
        self.loglevel = self.logger.INFO
        self.log(self.logger.WARNING, 'debuglevel not between 0 and 5, using default of debug = %i' % self.loglevel)
    if __name__ != '__main__':
      self.log(self.logger.INFO, 'initializing as plugin..')
    else:
      self.log(self.logger.INFO, 'initializing as standalone application..')
    self.should_terminate = False
    for key in ('bind_ip', 'bind_port', 'template_directory', 'frontend_directory'):
      if not key in args:
        self.log(self.logger.CRITICAL, '%s not in args' % key)
        self.should_terminate = True
    if self.should_terminate:
      self.log(self.logger.CRITICAL, 'terminating..')
      return
    self.ip = args['bind_ip']
    try:
      self.port = int(args['bind_port'])
    except ValueError:
      self.log(self.logger.CRITICAL, "%s is not a valid bind_port" % args['bind_port'])
      self.should_terminate = True
      self.log(self.logger.CRITICAL, 'terminating..')
      return
    if 'bind_use_ipv6' in args:
      tmp = args['bind_use_ipv6']
      if tmp.lower() == 'true':
        self.ipv6 = True
      elif tmp.lower() == 'false':
        self.ipv6 = False
      else:
        self.log(self.logger.CRITICAL, "%s is not a valid value for bind_use_ipv6. only true and false allowed." % tmp)
        self.should_terminate = True
        self.log(self.logger.CRITICAL, 'terminating..')
        return

    self.log(self.logger.INFO, 'using {}'.format(HTTPServer.__name__))

    self.httpd = HTTPServer((self.ip, self.port), postman)
    self.httpd.seed = chrootRandom(32)

    new_captcha = None
    if 'new_captcha' in args:
      if args['new_captcha'].lower() in ('true', 'yes'):
        new_captcha = 2
      else:
        try:
          new_captcha = int(args['new_captcha'])
        except ValueError:
          pass
        if new_captcha is not None and (new_captcha < 0 or new_captcha > 100):
          new_captcha = 2

    self.httpd.receive_from_friends = 0
    if 'receive_from_friends' in args:
      if args['receive_from_friends'].lower() in ('true', 'yes', '1'):
        self.httpd.receive_from_friends = 1
      elif args['receive_from_friends'].lower() in ('2', 'only'):
        self.httpd.receive_from_friends = 2

    self.httpd.fast_uploads = False
    if 'fast_uploads' in args:
      if args['fast_uploads'].lower() in ('true', 'yes', '1'):
        self.httpd.fast_uploads = True
        self.httpd.temp_file_obj = dict()

    self.httpd.overchan_fake_id = False
    if 'overchan_fake_id' in args:
      if args['overchan_fake_id'].lower() == 'true':
        self.httpd.overchan_fake_id = True

    self.httpd.i2p_spamprotect = False
    if 'i2p_spamprotect' in args:
      if args['i2p_spamprotect'].lower() == 'true':
        self.httpd.i2p_spamprotect = True

    if 'reject_debug' in args:
      tmp = args['reject_debug']
      if tmp.lower() == 'true':
        self.httpd.reject_debug = True
      elif tmp.lower() == 'false':
        self.httpd.reject_debug = False
      else:
        self.log(self.logger.WARNING, "%s is not a valid value for reject_debug. only true and false allowed. setting value to false." % tmp)
    self.httpd.log = self.log
    self.httpd.logger = self.logger

    # read templates
    self.log(self.logger.DEBUG, 'reading templates..')
    template_directory = args['template_directory']
    f = open(os.path.join(template_directory, 'message_nopic.template'), 'r')
    self.httpd.template_message_nopic = f.read()
    f.close()
    f = open(os.path.join(template_directory, 'message_pic.template'), 'r')
    self.httpd.template_message_pic = f.read()
    f.close()
    f = open(os.path.join(template_directory, 'message_signed.template'), 'r')
    self.httpd.template_message_signed = f.read()
    f.close()
    f = open(os.path.join(template_directory, 'redirect.template'), 'r')
    self.httpd.template_redirect = f.read()
    f.close()
    self.httpd.t_engine = dict()
    if self.httpd.fast_uploads:
      with open(os.path.join(template_directory, 'verify_fast.tmpl'), 'r') as f:
        self.httpd.t_engine['verify_fast'] = string.Template(f.read())
    else:
      with open(os.path.join(template_directory, 'verify_slow.tmpl'), 'r') as f:
        self.httpd.t_engine['verify_slow'] = string.Template(f.read())

    # read frontends
    self.httpd.frontends = self._read_frontends(args['frontend_directory'])
    self._sanitize_frontends(self.httpd.frontends)

    if len(self.httpd.frontends) > 0:
      self.log(self.logger.INFO, 'added %i frontends: %s' % (len(self.httpd.frontends), ', '.join(list(self.httpd.frontends.keys()))))
    else:
      self.log(self.logger.WARNING, 'no valid frontends found in %s.' % args['frontend_directory'])
      self.log(self.logger.WARNING, 'terminating..')
      self.should_terminate = True
      return

    self.httpd.cookie_disallow = set()
    self.httpd.cookie_disallow_len = 512
    # 0 - userkey, 1 - current_postcount, 2 - last_message_time, 3 - last_message_id, 4 - expires
    self.httpd.cookie_cache = dict()
    self.httpd.cookie_db_last_update = 0
    # if user send more 10 message in 5 minut - autodisallow user key
    self.httpd.userkey_timelimit = 60 * 5
    self.httpd.userkey_messagelimit = 10
    self.httpd.userkey_list = dict()
    self.httpd.userkey_timestamp = 0
    self.httpd.allow_this_cookie = self.allow_this_cookie
    self.httpd.update_this_cookie = self.update_this_cookie
    if self.httpd.i2p_spamprotect:
      spamprot_cfg = dict()
      # allow new desthash no more
      spamprot_cfg['allow_time'] = 60 * 5
      spamprot_cfg['last_allow'] = 0
      # if new dest add +- allow_time*border +- allow_time*allow_time_modify
      spamprot_cfg['allow_time_border'] = 0.25
      spamprot_cfg['allow_time_modify'] = 0.3
      # time limits
      spamprot_cfg['allow_time_min'] = 60 * 5
      spamprot_cfg['allow_time_max'] = 60 * 60
      spamprot_cfg['dest_expires'] = 3600 * 24 * 4
      # max desthash saving
      spamprot_cfg['dest_limit'] = 4096
      # max 5 posts in 20 minut.
      spamprot_cfg['dest_time_limit'] = 60 * 20
      spamprot_cfg['dest_post_limit'] = 5
      self.httpd.spamprot_cfg = spamprot_cfg
      # [count, expires limit, expires]
      self.httpd.dest_cache = dict()
      self.httpd.allow_this_desthash = self.allow_this_desthash
    self.httpd.spamprot_base64 = re.compile('^[a-zA-Z0-9]*$')
    self.httpd.spammers = list()
    self.httpd.fake_ok = False
    self.httpd.captcha_verification = True
    self.httpd.captcha_require_cookie = False
    self.httpd.captcha_bypass_after_seconds_reply = 60 * 10
    self.httpd.captcha_bypass_after_timestamp_reply = int(time.time())

    self.httpd.captcha = Captcha(log=self.log, logger=self.logger, diff_mode=new_captcha)
    self.alphabet = string.ascii_uppercase + string.digits
    foobar = self.httpd.captcha.get_captcha('cookie')
    del foobar

    # read captcha quotes from file
    qoutefile = 'plugins/postman/quotes.txt'
    if os.path.exists(qoutefile):
      with open(qoutefile) as f:
        self.httpd.quotes = [q for q in f]
    else:
      self.httpd.quotes = (
          '''<i>"Being stupid for no reason is very human-like. I will continue to spam."</i> <b>Spammer-kun</b>''',
          '''<i>"I bet the jews did this..."</i> <b>wowaname</b>''',
          '''<i>"Put a Donk on it."</i> <b>Krane</b>''',
          '''<i>"All You're Base are belong to us."</i> <b>Eric Schmit</b>''',
          '''<i>"I was just pretending to be retarded!!"</i> <b>Anonymous</b>''',
          '''<i>"Sometimes I wish I didn't have a diaper fetish."</i> <b>wowaname</b>''',
          '''<i>"DOES. HE. LOOK. LIKE. A BITCH?"</i> <b>Jesus Christ our Lord And Savior</b>''',
          '''<i>"ENGLISH MOTHERFUCKA DO YOU SPEAK IT?"</i> <b>Jesus Christ our Lord And Savior</b>''',
          '''<i>"We are watching you masturbate"</i> <b>NSA Internet Anonymity Specialist and Privacy Expert</b>''',
          '''<i>"I want to eat apples and bananas"</i> <b>Cookie Monster</b>''',
          '''<i>"Ponies are red, Twilight is blue, I have a boner, and so do you</i> <b>TriPh0rce, Maintainer of All You're Wiki</b>''',
          '''<i>"C++ is a decent language and there is almost no reason to use C in the modern age"</i> <b>psi</b>''',
          '''<i>"windows is full of aids"</i> <b>wowaname</b>'''
      )

  def _read_frontends(self, frontend_directory):
    # read frontends
    self.log(self.logger.DEBUG, 'reading frontend configuration..')
    frontends = dict()
    # list\dict switcher
    selector = {
        ('(', ')'): list,
        ('[', ']'): dict
    }
    if not os.path.isdir(frontend_directory):
      self.log(self.logger.WARNING, '%s is not a directory' % frontend_directory)
      return frontends
    for frontend in os.listdir(frontend_directory):
      link = os.path.join(frontend_directory, frontend)
      if frontend.startswith('.') or not os.path.isfile(link):
        continue
      frontends[frontend] = dict()
      root = ''
      this_is = dict
      with open(os.path.join(frontend_directory, frontend), 'r') as fd:
        for line in fd:
          line = line.rstrip('\r\n')
          if not line:
            # empty line, reinit
            root = ''
            this_is = dict
          elif line.startswith('#'):
            # ignore comments
            pass
          elif len(line) > 2 and (line[0], line[-1]) in selector:
            # detect list\dict block
            root = line[1:-1]
            this_is = selector[(line[0], line[-1])]
            frontends[frontend][root] = this_is()
          elif this_is is list:
            # list block
            frontends[frontend][root].append(line)
          elif this_is is dict:
            key, _, value = line.partition('=')
            if key and value:
              if root == '':
                # oneline value
                frontends[frontend][key] = value
              else:
                # block
                frontends[frontend][root][key] = value
            else:
              self.log(self.logger.DEBUG, "error while parsing frontend '%s': no = in '%s' which was defined as dict." % (frontend, line))
    return frontends

  def _sanitize_frontends(self, frontends):
    for frontend in [xx for xx in frontends]:
      error = ''
      for key in ('uid_host', 'required_fields', 'defaults'):
        if key not in frontends[frontend]:
          error += '  {0} not in frontend configuration file\n'.format(key)
      if 'defaults' in frontends[frontend]:
        for key in ('name', 'email', 'subject'):
          if key not in frontends[frontend]['defaults']:
            error += '  {0} not in defaults section of frontend configuration file\n'.format(key)
      if error != '':
        del frontends[frontend]
        self.log(self.logger.WARNING, "removed frontend configuration for %s:\n%s" % (frontend, error[:-1]))

  def shutdown(self):
    if self.serving:
      self.httpd.shutdown()
      self.httpd.socket.close()
    else:
      self.log(self.logger.INFO, 'bye')

  def add_article(self, message_id, source=None, timestamp=None):
    self.log(self.logger.WARNING, 'this plugin does not handle any article. remove hook parts from %s' % os.path.join('config', 'plugins', self.name.split('-', 1)[1]))



  def update_db(self, current_version):
    self.log(self.logger.INFO, "should update db from version %i" % current_version)
    if current_version == 0:
      self.log(self.logger.INFO, "updating db from version %i to version %i" % (current_version, 1))
      # create configuration
      self.httpd.postmandb.execute("CREATE TABLE config (key text PRIMARY KEY, value text)")
      self.httpd.postmandb.execute('INSERT INTO config VALUES ("db_version","1")')

      self.httpd.postmandb.execute('CREATE TABLE userkey (userkey text PRIMARY KEY, \
        local_name text, expires INTEGER, allow INTEGER, cookie text, last_login INTEGER, postcount INTEGER DEFAULT 0, last_message INTEGER, last_message_id text)')
      self.httpd.postmandb.execute("CREATE INDEX IF NOT EXISTS userkey_cookie_idx ON userkey(cookie, allow, expires)")
      self.httpd.postmandb.commit()
      current_version = 1
    if current_version == 1:
      self.log(self.logger.INFO, "updating db from version %i to version %i" % (current_version, 2))
      self.httpd.postmandb.execute("CREATE TABLE modifications (table_name TEXT NOT NULL PRIMARY KEY ON CONFLICT REPLACE, action TEXT NOT NULL, changed_at TIMESTAMP DEFAULT (strftime('%s', 'now')))")
      self.httpd.postmandb.execute('CREATE TRIGGER IF NOT EXISTS userkey_ondelete AFTER DELETE ON userkey BEGIN \
        INSERT INTO modifications (table_name, action) VALUES ("userkey","DELETE"); END')
      self.httpd.postmandb.execute('CREATE TRIGGER IF NOT EXISTS userkey_onupdate AFTER UPDATE ON userkey BEGIN \
        INSERT INTO modifications (table_name, action) VALUES ("userkey","UPDATE"); END')
      self.httpd.postmandb.execute('CREATE TRIGGER IF NOT EXISTS userkey_oninsert AFTER INSERT ON userkey BEGIN \
        INSERT INTO modifications (table_name, action) VALUES ("userkey","INSERT"); END')
      self.httpd.postmandb.execute('UPDATE config SET value = "2" WHERE key = "db_version"')
      self.httpd.postmandb.commit()
      current_version = 2
    if current_version == 2:
      self.log(self.logger.INFO, "updating db from version %i to version %i" % (current_version, 3))
      self.httpd.postmandb.execute('CREATE TABLE i2p_desthash (desthash text PRIMARY KEY, expires INTEGER)')
      self.httpd.postmandb.execute('UPDATE config SET value = "3" WHERE key = "db_version"')
      self.httpd.postmandb.commit()
      current_version = 3

  def run(self):
    if self.should_terminate:
      if self.httpd is not None:
        # close socket
        self.httpd.socket.close()
      return
    self.db_version = 3
    self.httpd.sqlite = self._db_connector('hashes', timeout=60)
    if self.httpd.overchan_fake_id:
      self.httpd.dropperdb = self._db_connector('dropper', timeout=60)
    self.httpd.postmandb = self._db_connector('postman', timeout=60)
    try:
      db_version = int(self.httpd.postmandb.execute("SELECT value FROM config WHERE key = ?", ("db_version",)).fetchone()[0])
    except sqlite3.OperationalError as e:
      self.log(self.logger.DEBUG, "error while fetching db_version: %s. assuming new database" % e)
      db_version = 0
    if db_version < self.db_version:
      self.update_db(db_version)
    if self.httpd.i2p_spamprotect:
      self.load_i2p_spamprotect_cache()
    self.log(self.logger.INFO, 'start listening at http://%s:%i' % (self.ip, self.port))
    self.serving = True
    self.httpd.serve_forever()
    if self.httpd.receive_from_friends > 0:
      self.save_cookie()
    if self.httpd.i2p_spamprotect:
      self.save_i2p_spamprotect_cache()
    self.log(self.logger.INFO, 'bye')

  def allow_this_cookie(self, cookie):
    if cookie == '' or cookie in self.httpd.cookie_disallow:
      return False
    if self.cookie_is_legal(cookie):
      return True
    self.log(self.logger.WARNING, "cookie %s not found - blocking" % cookie)
    if len(self.httpd.cookie_disallow) > self.httpd.cookie_disallow_len:
      self.httpd.cookie_disallow.pop()
    self.httpd.cookie_disallow.add(cookie)
    return False

  def cookie_is_legal(self, cookie):
    cookie_db_last_update = self.get_db_last_update()
    if cookie_db_last_update > self.httpd.cookie_db_last_update:
      if self.save_cookie():
        self.httpd.cookie_db_last_update = self.get_db_last_update()
      else:
        self.httpd.cookie_db_last_update = cookie_db_last_update
      self.load_cookie()
    if cookie in self.httpd.cookie_cache and self.httpd.cookie_cache[cookie][4] > int(time.time()):
      return True
    return False

  def load_cookie(self):
    self.log(self.logger.INFO, "Load cookies from db")
    cookie_cache = dict()
    for row in self.httpd.postmandb.execute('SELECT cookie, userkey, expires FROM userkey WHERE cookie !="" AND allow = 1 AND expires > ?', (int(time.time()),)).fetchall():
      cookie_cache[row[0]] = [row[1], 0, '', '', int(row[2])]
    self.httpd.cookie_cache = cookie_cache

  def save_cookie(self):
    if not self.httpd.cookie_cache:
      return
    db_update = False
    for cookie in self.httpd.cookie_cache:
      if self.httpd.cookie_cache[cookie][1] > 0:
        db_update = True
        self.httpd.postmandb.execute('UPDATE userkey SET postcount = postcount + ?, last_message = ?, last_message_id = ? WHERE userkey = ?',\
            (self.httpd.cookie_cache[cookie][1], self.httpd.cookie_cache[cookie][2], self.httpd.cookie_cache[cookie][3], self.httpd.cookie_cache[cookie][0]))
    if db_update:
      self.log(self.logger.INFO, "Save cookies to db")
      self.httpd.cookie_cache = dict()
      self.httpd.postmandb.commit()
    return db_update

  def load_i2p_spamprotect_cache(self):
    current_time = int(time.time())
    for row in self.httpd.postmandb.execute('SELECT desthash, expires FROM i2p_desthash WHERE expires > ?', (current_time,)).fetchall():
      self.httpd.dest_cache[row[0]] = [0, current_time, int(row[1])]
    self.httpd.postmandb.execute('DELETE FROM i2p_desthash')
    self.httpd.postmandb.commit()
    self.log(self.logger.INFO, "Hardened i2p spamprotect enabled. Loaded {0} desthashes. If you're hosting non-i2p site, disable this".format(len(self.httpd.dest_cache)))

  def save_i2p_spamprotect_cache(self):
    current_time = int(time.time())
    for desthash in self.httpd.dest_cache:
      if current_time < self.httpd.dest_cache[desthash][2]:
        self.httpd.postmandb.execute("INSERT INTO i2p_desthash (desthash, expires) VALUES (?, ?)", (desthash, self.httpd.dest_cache[desthash][2]))
    self.httpd.postmandb.commit()

  def allow_this_desthash(self, desthash):
    if desthash not in self.httpd.dest_cache:
      return self.add_this_desthash(desthash)
    current_time = int(time.time())
    if self.httpd.dest_cache[desthash][0] >= self.httpd.spamprot_cfg['dest_post_limit'] or self.httpd.dest_cache[desthash][2] <= current_time:
      self.httpd.dest_cache.pop(desthash, None)
      return False
    if self.httpd.dest_cache[desthash][1] <= current_time:
      self.httpd.dest_cache[desthash][1] = current_time + self.httpd.spamprot_cfg['dest_time_limit']
      self.httpd.dest_cache[desthash][0] = 0
    self.httpd.dest_cache[desthash][0] += 1
    return True

  def add_this_desthash(self, desthash):
    current_time = int(time.time())
    time_diff = current_time - (self.httpd.spamprot_cfg['last_allow'] + self.httpd.spamprot_cfg['allow_time'])
    if time_diff < 0:
      return False
    if len(self.httpd.dest_cache) >= self.httpd.spamprot_cfg['dest_limit']:
      self.clean_overload_dest_cache()
    self.httpd.dest_cache[desthash] = [1, current_time + self.httpd.spamprot_cfg['dest_time_limit'], current_time + self.httpd.spamprot_cfg['dest_expires']]
    self.httpd.spamprot_cfg['last_allow'] = current_time
    # decreace or increce time
    new_allow_time = self.httpd.spamprot_cfg['allow_time']
    if time_diff > int(self.httpd.spamprot_cfg['allow_time'] * self.httpd.spamprot_cfg['allow_time_border']):
      new_allow_time -= int(self.httpd.spamprot_cfg['allow_time'] * self.httpd.spamprot_cfg['allow_time_modify'])
    else:
      new_allow_time += int(self.httpd.spamprot_cfg['allow_time'] * self.httpd.spamprot_cfg['allow_time_modify'])
    if new_allow_time > self.httpd.spamprot_cfg['allow_time_max']:
      new_allow_time = self.httpd.spamprot_cfg['allow_time_max']
    elif new_allow_time < self.httpd.spamprot_cfg['allow_time_min']:
      new_allow_time = self.httpd.spamprot_cfg['allow_time_min']
    if new_allow_time != self.httpd.spamprot_cfg['allow_time']:
      self.log(self.logger.INFO, "Hardened i2p spamprotect: timelimit changed from {0} to {1} seconds. ".format(self.httpd.spamprot_cfg['allow_time'], new_allow_time))
      self.httpd.spamprot_cfg['allow_time'] = new_allow_time
    return True

  def clean_overload_dest_cache(self):
    need_removed = self.httpd.spamprot_cfg['dest_limit'] / 10
    current_time = int(time.time())
    # remove expired ...
    for desthash in self.httpd.dest_cache:
      if self.httpd.dest_cache[desthash][2] <= current_time:
        self.httpd.dest_cache.pop(desthash, None)
        need_removed -= 1
    # .. and random
    if need_removed > 0:
      for x in range(need_removed):
        self.httpd.dest_cache.pop(random.choice(list(self.httpd.dest_cache.keys())))

  def get_db_last_update(self):
    db_last_update = self.httpd.postmandb.execute("SELECT changed_at FROM modifications WHERE table_name = 'userkey'").fetchone()
    if db_last_update:
      return int(db_last_update[0])
    return 0

  def update_this_cookie(self, cookie, message_id, message_time):
    if cookie not in self.httpd.cookie_cache:
      self.log(self.logger.ERROR, "cookie %s allow and not found in cache. Fix me" % cookie)
      return
    self.httpd.cookie_cache[cookie][1] += 1
    self.httpd.cookie_cache[cookie][2] = message_time
    self.httpd.cookie_cache[cookie][3] = message_id
    self.userkey_spamprotect(message_time, self.httpd.cookie_cache[cookie][0])
    # FIXME: BAD method.
    if not self.httpd.cookie_cache[cookie][1] % 5:
      self.save_cookie()
      self.httpd.cookie_db_last_update = self.get_db_last_update()
      self.load_cookie()

  def userkey_spamprotect(self, message_time, pubkey):
    if message_time - self.httpd.userkey_timestamp > self.httpd.userkey_timelimit:
      self.httpd.userkey_timestamp = message_time
      self.httpd.userkey_list = dict()
    if pubkey in self.httpd.userkey_list:
      self.httpd.userkey_list[pubkey] += 1
    else:
      self.httpd.userkey_list[pubkey] = 1
    if self.httpd.userkey_list[pubkey] > self.httpd.userkey_messagelimit:
      self.log(self.logger.WARNING, "Key %s sent %s messages in %s seconds. Spamprotect auto-disallowed this key for stopping spam" % (pubkey, self.httpd.userkey_list[pubkey], self.httpd.userkey_timelimit))
      del self.httpd.userkey_list[pubkey]
      self.httpd.postmandb.execute('UPDATE userkey SET allow = 0 WHERE userkey = ?', (pubkey,))
      self.httpd.postmandb.commit()

if __name__ == '__main__':
  args = dict()
  args['bind_ip'] = "1.4.7.101"
  args['bind_port'] = "58425"
  args['bind_use_ipv6'] = "False"
  args['template_directory'] = "plugins/postman/templates"
  args['frontend_directory'] = "plugins/postman/frontends"
  poster = main("poster", None, args)
  poster.start()
  try:
    time.sleep(3600)
  except KeyboardInterrupt as e:
    print()
    poster.shutdown()
  except Exception as e:
    print()
    print("Exception:", e)
    raise e
