#!/usr/bin/python

import base64
import cStringIO
import os
import random
import re
import socket
import sqlite3
import string
import threading
import time
import traceback
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from binascii import hexlify
from cgi import FieldStorage
from datetime import datetime
from hashlib import sha1, sha256, sha512
from urllib import unquote

import Image, ImageDraw, ImageFilter, ImageFont
import nacl.signing

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
    cookie = self.headers.get('Cookie')
    if cookie:
      cookie = cookie.strip()
      for item in cookie.split(';'):
        if item.startswith('sid='):
          cookie = item
      cookie = cookie.strip().split('=', 1)[1]
      if cookie in self.origin.spammers:
        self.origin.log(self.origin.logger.WARNING, 'POST recognized an earlier spammer! %s' % cookie)
        self.origin.log(self.origin.logger.WARNING, self.headers)
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write('<html><body>')
        for y in range(0,100):
          #self.wfile.write('<img src="/img/%s.png" style="width: 100px;" />' % ''.join(random.choice(self.origin.captcha_alphabet) for x in range(16)))
          self.wfile.write('<iframe src="/incoming/%s"></iframe>' % ''.join(random.choice(self.origin.captcha_alphabet) for x in range(16)))
          #time.sleep(0.1)
        self.wfile.write('</body></html>')
        return
        # TODO: trap it: while True; wfile.write(random*x); sleep 1; done
        # TODO: ^ requires multithreaded BaseHTTPServer
        if self.origin.fake_ok:
          self.exit_redirect(2, '/')
        return
    self.path = unquote(self.path)
    if self.path == '/incoming':
      if self.origin.captcha_verification:
        self.send_captcha(message=self.get_random_quote())
      else:
        self.handleNewArticle()
      return
    if self.path == '/incoming/verify':
      self.handleVerify()
      return
    self.origin.log(self.origin.logger.WARNING, "illegal POST access: %s" % self.path)
    self.origin.log(self.origin.logger.WARNING, self.headers)
    self.exit_redirect(9, '/overview.html', False, 'nope')

  def do_GET(self):
    cookie = self.headers.get('Cookie')
    if cookie:
      cookie = cookie.strip()
      for item in cookie.split(';'):
        if item.startswith('sid='):
          cookie = item
      cookie = cookie.strip().split('=', 1)[1]
      if cookie in self.origin.spammers:
        self.origin.log(self.origin.logger.WARNING, 'GET recognized an earlier spammer trying to access %s! %s' % (self.path, cookie))
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write('<html><body>')
        for y in range(0,100):
          #self.wfile.write('<img src="/img/%s.png" style="width: 100px;" />' % ''.join(random.choice(self.origin.captcha_alphabet) for x in range(16)))
          self.wfile.write('<iframe src="/incoming/%s"></iframe>' % ''.join(random.choice(self.origin.captcha_alphabet) for x in range(16)))
          #time.sleep(0.1)
        self.wfile.write('</body></html>')
        return
    self.path = unquote(self.path)
    if self.path == '/incoming/verify':
      self.send_captcha()
      return
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
      cookie = ''.join(random.choice(self.origin.captcha_alphabet) for x in range(16))
      self.origin.spammers.append(cookie)
      self.send_header('Set-Cookie', 'sid=%s; path=/incoming' % cookie)
    self.send_header('Content-type', 'text/html')
    self.end_headers()
    self.wfile.write(self.origin.template_redirect.format(redirect_duration, redirect_target, message))

  def log_request(self, code):
    return

  def log_message(self, format):
    return

  def get_random_quote(self):
    return random.choice(self.origin.quotes)

  def failCaptcha(self, vars):
    msg = self.get_random_quote()
    msg += '<br/><b><font style="color: red;">failed. hard.</font></b>'
    self.send_captcha(msg, vars)
    
  def handleVerify(self):
    post_vars = FieldStorage(
      fp=self.rfile,
      headers=self.headers,
      environ={
        'REQUEST_METHOD':'POST',
        'CONTENT_TYPE':self.headers['Content-Type'],
      }
    )
    for item in ('expires', 'hash', 'solution'):
      if item not in post_vars:
        self.failCaptcha(post_vars)
        return
    if not self.origin.captcha_require_cookie:
      if self.origin.captcha_verify(post_vars['expires'].value, post_vars['hash'].value, post_vars['solution'].value, self.origin.captcha_secret):
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
    if self.origin.captcha_verify(post_vars['expires'].value, post_vars['hash'].value, post_vars['solution'].value, self.origin.captcha_secret + cookie):
      self.handleNewArticle(post_vars)
      return
    self.failCaptcha(post_vars)
  
  def send_captcha(self, message='', post_vars=None):
    failed = True
    if not post_vars:
      failed = False
      contentType = 'Content-Type' in self.headers and self.headers['Content-Type'] or 'text/plain'
      post_vars = FieldStorage(
        fp=self.rfile,
        headers=self.headers,
        environ={
          'REQUEST_METHOD':'POST',
          'CONTENT_TYPE': contentType
        }
      )
    # someone wants to fuck around
    if not 'frontend' in post_vars:
      self.die('frontend not in post_vars')
      return
    else:
      frontend = post_vars.getvalue('frontend', '').replace('"', '&quot;')
    reply = post_vars.getvalue('reply', '').replace('"', '&quot;')
    #if frontend == 'overchan' and reply != '':
    #  # FIXME add ^ allow_reply_bypass to frontend configuration
    #  if self.origin.captcha_bypass_after_timestamp_reply < int(time.time()):
    #    self.origin.log(self.origin.logger.INFO, 'bypassing captcha for reply')
    #    self.handleNewArticle(post_vars) 
    #    return
    board = post_vars.getvalue('board', '').replace('"', '&quot;')
    target = post_vars.getvalue('target', '').replace('"', '&quot;')
    name = post_vars.getvalue('name', '').replace('"', '&quot;')
    email = post_vars.getvalue('email', '').replace('"', '&quot;')
    subject = post_vars.getvalue('subject', '').replace('"', '&quot;')
    if post_vars.getvalue('hash', '') != '':
      comment = post_vars.getvalue('comment', '').replace('"', '&quot;')
      file_name = post_vars.getvalue('file_name', '').replace('"', '&quot;')
      file_ct = post_vars.getvalue('file_ct', '').replace('"', '&quot;')
      file_b64 = post_vars.getvalue('file_b64', '').replace('"', '&quot;')
    else:
      comment = base64.encodestring(post_vars.getvalue('comment', ''))
      if not 'allowed_files' in self.origin.frontends[frontend]:
        file_name = ''
        file_ct = ''
        file_b64 = ''
      else:
        try:
          file_name = post_vars['file'].filename.replace('"', '&quot;')
        except KeyError:
          file_name = ''
        if file_name == '':
          file_ct = ''
          file_b64 = ''
        else:
          file_ct = post_vars['file'].type.replace('"', '&quot;')
          f = cStringIO.StringIO()
          base64.encode(post_vars['file'].file, f)
          file_b64 = f.getvalue()
          f.close()
    if failed:
      identifier = sha256()
      identifier.update(frontend + board + reply + target + name + email + subject)
      identifier.update(comment)
      self.origin.log(self.origin.logger.WARNING, 'failed capture try for %s' % identifier.hexdigest())
      self.origin.log(self.origin.logger.WARNING, self.headers)
    passphrase = ''.join([random.choice(self.origin.captcha_alphabet) for i in xrange(self.origin.captcha_len)])
    #passphrase += ' ' + ''.join([random.choice(self.origin.captcha_alphabet) for i in xrange(6)])
    b64 = self.origin.captcha_render_b64(passphrase, self.origin.captcha_tiles, self.origin.get_captcha_font(), self.origin.captcha_filter)
    if self.origin.captcha_require_cookie:
      cookie = ''.join(random.choice(self.origin.captcha_alphabet) for x in range(32))
      expires, solution_hash = self.origin.captcha_generate(passphrase, self.origin.captcha_secret + cookie)
      self.send_response(200)
      self.send_header('Content-type', 'text/html')
      self.send_header('Set-Cookie', 'session=%s; path=/incoming/verify' % cookie)
    else:
      expires, solution_hash = self.origin.captcha_generate(passphrase, self.origin.captcha_secret)
      self.send_response(200)
      self.send_header('Content-type', 'text/html')
    self.end_headers()
    # use file_name as key and file content + current time as value
    if self.origin.fast_uploads:
      if file_b64 != '':
        # we can have empty file_b64 here whether captcha was entered wrong first time
        self.origin.temp_file_obj[file_name] = [file_b64, int(time.time())]
      self.wfile.write(self.origin.template_verify_fast.format(message, b64, solution_hash, expires, frontend, board, reply, target, name, email, subject, comment, file_name, file_ct))
    else:
      self.wfile.write(self.origin.template_verify_slow.format(message, b64, solution_hash, expires, frontend, board, reply, target, name, email, subject, comment, file_name, file_ct, file_b64))
    return self.origin.captcha_cache_bump()

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

  def handleNewArticle(self, post_vars=None):
    if not post_vars:
      contentType = 'Content-Type' in self.headers and self.headers['Content-Type'] or 'text/plain'
      post_vars = FieldStorage(
        fp=self.rfile,
        headers=self.headers,
        environ={
          'REQUEST_METHOD':'POST',
          'CONTENT_TYPE': contentType
        }
      )
    if not 'frontend' in post_vars:
      self.die('frontend not in post_vars')
      return
    frontend = post_vars['frontend'].value
    self.origin.log(self.origin.logger.INFO, "got incoming article from %s:%i for frontend '%s'" % (self.client_address[0], self.client_address[1], frontend))
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
        subject = post_vars['subject'].value.split('\n')[0]

    sage = ''
    if 'allow_sage' in self.origin.frontends[frontend]:
      if self.origin.frontends[frontend]['allow_sage'].lower() in ('true', 'yes'):
        if (subject.lower().startswith('sage') or subject.lower().startswith('saging') or 
            name.lower().startswith('sage') or name.lower().startswith('saging')):
          sage = "\nX-Sage: True"

    sender = '{0} <{1}>'.format(name, email)
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
    try:
      i2p_desthash = self.headers.get('X-I2P-DestHash')
    except:
      i2p_desthash = 'non-i2p'
    #f = open('tmp/' + boundary, 'w')
    if signature:
      link = os.path.join('incoming', 'tmp', boundary + '_')
    else:
      link = os.path.join('incoming', 'tmp', boundary)
    f = open(link, 'w')
    if file_name == '':
      f.write(self.origin.template_message_nopic.format(sender, date, group, subject, message_uid, reply, uid_host, comment, sage, i2p_desthash).replace('\r', ''))
    else:
      f.write(self.origin.template_message_pic.format(sender, date, group, subject, message_uid, reply, uid_host, boundary, comment, content_type, file_name, sage, i2p_desthash).replace('\r', ''))
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
      signed.write(self.origin.template_message_signed.format(sender, date, group, subject, message_uid, reply, uid_host, pubkey, signature, sage, i2p_desthash))
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
        #os.rename(link, os.path.join('incoming', 'spam', message_uid))
        self.exit_redirect(redirect_duration, redirect_target)
    except socket.error as e:
      if e.errno == 32:
        self.origin.log(self.origin.logger.DEBUG, 'broken pipe: %s' % e)
        # Broken pipe
        pass
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
      except ValueError as e:
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
    except ValueError as e:
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

    self.log(self.logger.DEBUG, 'initializing httpserver..')
    self.httpd = HTTPServer((self.ip, self.port), postman)
    if os.path.exists('seed'):
      f = open('seed', 'r')
      self.httpd.seed = f.read()
      f.close()
    else:
      f = open('/dev/urandom', 'r')
      self.httpd.seed = f.read(32)
      f.close()
      f = open('seed', 'w')
      f.write(self.httpd.seed)
      f.close()
      os.chmod('seed', 0o600)

    self.new_captcha = None
    if 'new_captcha' in args:
      if args['new_captcha'].lower() in ('true', 'yes'):
        self.new_captcha = 2
      else:
        try: self.new_captcha = int(args['new_captcha'])
        except: pass
        if self.new_captcha is not None and (self.new_captcha < 0 or self.new_captcha > 100):
          self.new_captcha = 2

    self.httpd.fast_uploads = False
    if 'fast_uploads' in args:
      if args['fast_uploads'].lower() in ('true', 'yes', '1'):
        self.httpd.fast_uploads = True
        self.httpd.temp_file_obj = dict()

    self.httpd.overchan_fake_id = False
    if 'overchan_fake_id' in args:
      if args['overchan_fake_id'].lower() == 'true':
        self.httpd.overchan_fake_id = True

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
    if self.httpd.fast_uploads:
      f = open(os.path.join(template_directory, 'verify_fast.template'), 'r')
      self.httpd.template_verify_fast = f.read()
      f.close()
    else:
      f = open(os.path.join(template_directory, 'verify_slow.template'), 'r')
      self.httpd.template_verify_slow = f.read()
      f.close()

    # read frontends
    self.log(self.logger.DEBUG, 'reading frontend configuration..')
    frontend_directory = args['frontend_directory']
    if not os.path.isdir(frontend_directory):
      self.log(self.logger.WARNING, '%s is not a directory' % frontend_directory)
      # FIXME: die?
    self.httpd.frontends = dict()
    frontends = list()
    for frontend in os.listdir(frontend_directory):
      link = os.path.join(frontend_directory, frontend)
      if not os.path.isfile(link):
        continue
      self.httpd.frontends[frontend] = dict()
      f = open(link, 'r')
      line = f.readline()
      root = ''
      this_is = 'dict'
      while line != "":
        if line[0] == '#' or line == '\n':
          line = f.readline()
          continue
        line = line[:-1]
        if line[0] == '(' and line[-1] == ')':
          root = line[1:-1]
          this_is = 'list'
          self.httpd.frontends[frontend][root] = list()
          line = f.readline()
          continue
        elif line[0] == '[' and line[-1] == ']':
          root = line[1:-1]
          self.httpd.frontends[frontend][root] = dict()
          this_is = 'dict'
          line = f.readline()
          continue
        if this_is == 'list':
          self.httpd.frontends[frontend][root].append(line)
        elif this_is == 'dict':
          if not '=' in line:
            self.log(self.logger.DEBUG, "error while parsing frontend '%s': no = in '%s' which was defined as dict." % (frontend, line))
            continue
          key = line.split('=', 1)[0]
          value = line.split('=', 1)[1]
          if root == '':
            self.httpd.frontends[frontend][key] = value
          else:
            self.httpd.frontends[frontend][root][key] = value
        line = f.readline()
      f.close()
      error = ''
      for key in ('uid_host', 'required_fields', 'defaults'):
        if key not in self.httpd.frontends[frontend]:
          error += '  {0} not in frontend configuration file\n'.format(key)
      if 'defaults' in self.httpd.frontends[frontend]:
        for key in ('name', 'email', 'subject'):
          if key not in self.httpd.frontends[frontend]['defaults']:
            error += '  {0} not in defaults section of frontend configuration file\n'.format(key)
      if error != '':
        del self.httpd.frontends[frontend]
        self.log(self.logger.WARNING, "removed frontend configuration for %s:\n%s" % (frontend, error[:-1]))
      else:
        frontends.append(frontend)

    if len(frontends) > 0:
      self.log(self.logger.INFO, 'added %i frontends: %s' % (len(frontends), ', '.join(frontends)))
    else:
      self.log(self.logger.WARNING, 'no valid frontends found in %s.' % frontend_directory)
      self.log(self.logger.WARNING, 'terminating..')
      self.should_terminate = True
      return
    self.httpd.spamprot_base64 = re.compile('^[a-zA-Z0-9]*$')
    self.httpd.spammers = list()
    self.httpd.fake_ok = False
    self.httpd.captcha_verification = True
    self.httpd.captcha_require_cookie = False
    self.httpd.captcha_len = 6
    self.httpd.captcha_bypass_after_seconds_reply = 60 * 10
    self.httpd.captcha_bypass_after_timestamp_reply = int(time.time()) 
    self.httpd.captcha_generate = self.captcha_generate
    if self.new_captcha is not None:
      self.httpd.captcha_filter = ImageFilter.GaussianBlur(4)
      self.httpd.captcha_verify = self.new_captcha_verify
      self.httpd.captcha_alphabet = string.ascii_uppercase + string.digits
      for char in ('I', 'O', '0', '1'):
        self.httpd.captcha_alphabet = self.httpd.captcha_alphabet.replace(char, '')
      self.captcha_alt = new_captcha(self.new_captcha, self.httpd.captcha_filter)
      self.log(self.logger.INFO, self.captcha_alt.init_cache())
      self.httpd.captcha_render_b64 = self.captcha_alt.captcha_render_b64
      self.httpd.get_captcha_font = self.captcha_alt.get_captcha_font
      self.httpd.captcha_cache_bump = self.captcha_alt.captcha_cache_bump
    else:
      self.httpd.captcha_filter = ImageFilter.EMBOSS
      self.httpd.captcha_verify = self.captcha_verify
      self.httpd.captcha_alphabet = string.ascii_letters + string.digits
      for char in ('I', 'l', 'O', '0', 'k', 'K'):
        self.httpd.captcha_alphabet = self.httpd.captcha_alphabet.replace(char, '')
      self.httpd.captcha_render_b64 = self.captcha_render_b64
      self.httpd.get_captcha_font = self.get_captcha_font
      self.httpd.captcha_cache_bump = self.captcha_cache_bump
    self.httpd.captcha_tiles = list()
    self.httpd.captcha_backlog = list()
    self.httpd.captcha_backlog_maxlen = 100
    for item in os.listdir('plugins/postman/tiles'):
      self.httpd.captcha_tiles.append(Image.open('plugins/postman/tiles/%s' % item))
    foobar = self.captcha_render_b64('abc', self.httpd.captcha_tiles, self.httpd.get_captcha_font(), self.httpd.captcha_filter)
    del foobar
    f = open('/dev/urandom', 'r')
    self.httpd.captcha_secret = f.read(32)
    f.close() 
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

  def shutdown(self):
    if self.serving:
      self.httpd.shutdown()
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
      self.httpd.postmandb_conn.commit()
      current_version = 1

  def run(self):
    if self.should_terminate:
      return
    # connect to hasher database
    # FIXME: add database_directory to postman?
    self.database_directory = ''
    self.db_version = 0
    self.httpd.sqlite_conn = sqlite3.connect(os.path.join(self.database_directory, 'hashes.db3'))
    self.httpd.sqlite = self.httpd.sqlite_conn.cursor()
    if self.httpd.overchan_fake_id:
      self.httpd.dropperdb_conn = sqlite3.connect(os.path.join(self.database_directory, 'dropper.db3'))
      self.httpd.dropperdb = self.httpd.dropperdb_conn.cursor()
    self.httpd.postmandb_conn = sqlite3.connect(os.path.join(self.database_directory, 'postman.db3'))
    self.httpd.postmandb = self.httpd.postmandb_conn.cursor()
    try:
      db_version = int(self.httpd.postmandb.execute("SELECT value FROM config WHERE key = ?", ("db_version",)).fetchone()[0])
      if db_version < self.db_version:
        self.update_db(db_version)
    except Exception as e:
      self.log(self.logger.DEBUG, "error while fetching db_version: %s. assuming new database" % e)
      self.update_db(0)
    self.log(self.logger.INFO, 'start listening at http://%s:%i' % (self.ip, self.port))
    self.serving = True
    self.httpd.serve_forever()
    self.log(self.logger.INFO, 'bye')

  def captcha_generate(self, text, secret, expires=300):
    expires += int(time.time())
    if not expires % 3: solution_hash = sha256('%s%s%i' % (text, secret, expires)).hexdigest()
    elif expires % 2: solution_hash = sha256('%i%s%s' % (expires, text, secret)).hexdigest()
    else: solution_hash = sha256('%s%i%s' % (secret, expires, text)).hexdigest()
    return (expires, solution_hash)

  def captcha_check_backlog(self, expires, solution_hash):
    insert_at = len(self.httpd.captcha_backlog)
    for index, solution in enumerate(self.httpd.captcha_backlog):
      if expires == solution[0] and solution_hash == solution[1]:
        self.log(self.logger.WARNING, "captcha replay detected: %s" % solution_hash)
        return False
      if solution[0] < expires:
        insert_at = index
        break
    if insert_at != self.httpd.captcha_backlog_maxlen:
      self.httpd.captcha_backlog.insert(insert_at, (expires, solution_hash))
      if len(self.httpd.captcha_backlog) > self.httpd.captcha_backlog_maxlen:
        self.httpd.captcha_backlog.pop()
    return True

  def new_captcha_verify(self, expires, solution_hash, guess, secret):
    return self.captcha_verify(expires, solution_hash, guess.upper(), secret)

  def captcha_verify(self, expires, solution_hash, guess, secret):
    try: expires = int(expires)
    except: return False
    if int(time.time()) > expires or len(guess) != self.httpd.captcha_len or expires - int(time.time()) > 3600:
      return False
    if not expires % 3:
      if solution_hash != sha256('%s%s%i' % (guess, secret, expires)).hexdigest(): return False
      return self.captcha_check_backlog(expires, solution_hash)
    if expires % 2:
      if solution_hash != sha256('%i%s%s' % (expires, guess, secret)).hexdigest(): return False
      return self.captcha_check_backlog(expires, solution_hash)
    if solution_hash != sha256('%s%i%s' % (secret, expires, guess)).hexdigest(): return False
    return self.captcha_check_backlog(expires, solution_hash)
  
  def get_captcha_font(self, fontdir='plugins/postman/fonts/' ):
    """ get random font """
    font = random.choice(os.listdir(fontdir))
    font = fontdir+font
    return ImageFont.truetype(font, random.randint(32, 48) )

  def captcha_render_b64(self, guess, tiles, font, filter=None):
    """ generate captcha """
    #if self.captcha_size is None: size = self.defaultSize
    #img = Image.new("RGB", (256,96))
    w , h , x , y = 300, 100, 30, 25
    w += random.randint(4, 50)
    h += random.randint(4, 50)
    x += random.randint(4, 50)
    y += random.randint(4, 50)
    tile = random.choice(tiles)
    img = Image.new("RGB", (w,h))
    for n in range(10):
      offset = (random.uniform(0, 1), random.uniform(0, 1))
      for j in xrange(-1, int(img.size[1] / tile.size[1]) + 1):
        for i in xrange(-1, int(img.size[0] / tile.size[0]) + 1):
          dest = (int((offset[0] + i) * tile.size[0]),
                  int((offset[1] + j) * tile.size[1]))
          img.paste(tile, dest)
    draw = ImageDraw.Draw(img)
    #draw.text((40,20), guess, font=font, fill='white')
    draw.text((x,y), guess, font=font, fill='black')
    if filter:
      img = img.filter(filter)
    f = cStringIO.StringIO()
    img.save(f, 'PNG')
    content = f.getvalue()
    f.close()
    return content.encode("base64").replace("\n", "")

  def captcha_cache_bump(self):
    # TODO: create captcha before query
    return True

class new_captcha:
  def __init__(self, diff=2, img_filter=None):
    self.img_filter = img_filter
    self.gauss = diff
    self.plazma_cache = dict()
    self.plazma_cache_size = 15
    self.plazma_cache['reusage'] = 0
    self.plazma_cache['plazma'] = [None] * self.plazma_cache_size
    self.plazma_cache['size'] = list()

  def init_cache(self):
    check_time = time.time()
    self.__init_cache()
    return 'new_captcha: init %s plazma cache in %s seconds...' % (self.plazma_cache_size, int(time.time() - check_time))

  def __init_cache(self):
    self.plazma_cache['size'] = [
      300 + random.randint(4, 50),
      100 + random.randint(4, 50)
    ]
    for x in xrange(self.plazma_cache_size):
      self.plazma_cache['plazma'][x] = self.__plazma(self.plazma_cache['size'][0], self.plazma_cache['size'][1])
    self.plazma_cache['reusage'] = random.randint(2, 5) * self.plazma_cache_size

  def get_captcha_font(self, fontdir='plugins/postman/fonts/' ):
    #font = random.choice(os.listdir(fontdir))
    #font = fontdir + font
    font_list = ('FreeSansBold.ttf', 'FreeSerifBold.ttf', 'FreeMonoBold.ttf')
    font = fontdir + font_list[random.randint(0, 2)]
    return ImageFont.truetype(font, random.randint(43, 54) )

  def captcha_render_b64(self, guess, tiles, font, filter=None):
    img_to_str = cStringIO.StringIO()
    self.captcha(guess, font).save(img_to_str, 'PNG')
    content = img_to_str.getvalue()
    img_to_str.close()
    return content.encode("base64").replace("\n", "")

  def captcha_cache_bump(self):
    if self.plazma_cache['reusage'] <= 0:
      self.__init_cache()
    return True

  def captcha(self, guess, font):
    if self.plazma_cache['reusage'] <= -5:
      self.__init_cache()
    self.plazma_cache['reusage'] -=1
    mask = Image.new('RGBA', (self.plazma_cache['size'][0], self.plazma_cache['size'][1]))
    font_width, font_height = font.getsize(guess)
    font_width /= len(guess)

    x_offset = random.randint(-1, 1) * 5

    draw = ImageDraw.Draw(mask)
    for i in guess:
      x_offset += font_width + random.randint(1, 5)
      y_offset = random.randint(1, 7) * 5
      draw.text((x_offset + random.randint(-(font_width / 10), (font_width / 10)) * 2, y_offset), i, font=font)

    angle = random.randint(-2, 3) * 5
    mask = mask.rotate(angle)

    pattern_1 = pattern_2 = None
    while pattern_1 is pattern_2:
      pattern_1 = self.plazma_cache['plazma'][random.randint(0, self.plazma_cache_size - 1)]
      pattern_2 = self.plazma_cache['plazma'][random.randint(0, self.plazma_cache_size - 1)]

    result = Image.composite(pattern_1, pattern_2, mask)

    if self.img_filter is not None:
      for x in range(self.gauss):
        result = result.filter(self.img_filter)

    return result

  def __plazma(self, width, height):
    plazma = Image.new('RGB', (width, height))
    pix = plazma.load()

    for xy in [(0,0), (width-1, 0), (0, height-1), (width-1, height-1)]:
      rgb = []
      for i in xrange(3):
        rgb.append(int(random.random()*256))
      pix[xy[0],xy[1]] = (rgb[0], rgb[1], rgb[2])

    self.__plazmaRec(pix, 0, 0, width-1, height-1)
    return plazma

  def __plazmaRec(self, pix, x1, y1, x2, y2):
    if (abs(x1 - x2) <= 1) and (abs(y1 - y2) <= 1):
      return
    rgb = []
    for i in xrange(3):
      rgb.append((pix[x1, y1][i] + pix[x1, y2][i])/2)
      rgb.append((pix[x2, y1][i] + pix[x2, y2][i])/2)
      rgb.append((pix[x1, y1][i] + pix[x2, y1][i])/2)
      rgb.append((pix[x1, y2][i] + pix[x2, y2][i])/2)

      tmp = (pix[x1, y1][i] + pix[x1, y2][i] +
             pix[x2, y1][i] + pix[x2, y2][i])/4
      diagonal =  ((x1-x2)**2 + (y1-y2)**2)**0.5
      while True:
        delta = int ( ((random.random() - 0.5)/100 * min(100, diagonal))*255 )
        if (tmp + delta >= 0) and (tmp + delta <= 255):
          tmp += delta
          break
      rgb.append(tmp)

    pix[x1, (y1 + y2)/2] = (rgb[0], rgb[5], rgb[10])
    pix[x2, (y1 + y2)/2]= (rgb[1], rgb[6], rgb[11])
    pix[(x1 + x2)/2, y1] = (rgb[2], rgb[7], rgb[12])
    pix[(x1 + x2)/2, y2] = (rgb[3], rgb[8], rgb[13])
    pix[(x1 + x2)/2, (y1 + y2)/2] = (rgb[4], rgb[9], rgb[14])

    self.__plazmaRec(pix, x1, y1, (x1+x2)/2, (y1+y2)/2)
    self.__plazmaRec(pix, (x1+x2)/2, y1, x2, (y1+y2)/2)
    self.__plazmaRec(pix, x1, (y1+y2)/2, (x1+x2)/2, y2)
    self.__plazmaRec(pix, (x1+x2)/2, (y1+y2)/2, x2, y2)

if __name__ == '__main__':
  args = dict()
  args['bind_ip'] = "1.4.7.101"
  args['bind_port'] = "58425"
  args['bind_use_ipv6'] = "False"
  args['template_directory'] = "plugins/postman/templates"
  args['frontend_directory'] = "plugins/postman/frontends"
  poster = main("poster", args)
  poster.start()
  try:
    time.sleep(3600)
  except KeyboardInterrupt as e:
    print
    poster.shutdown()
  except Exception as e:
    print
    print "Exception:", e
    raise e
