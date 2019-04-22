#!/usr/bin/env python2

import base64
import codecs
import os
import random
import re
import socket
import sqlite3
import string
import threading
import time
import json
import urlparse

from BaseHTTPServer import BaseHTTPRequestHandler
from BaseHTTPServer import HTTPServer as HTTPD

try:
  from SocketServer import ThreadingMixIn
  class ThreadedHTTPServer(ThreadingMixIn, HTTPD):
    """
    multithreaded http server
    """
except ImportError:
  HTTPServer = HTTPD
else:
  HTTPServer = HTTPD


from binascii import hexlify, unhexlify
from cgi import FieldStorage
from datetime import datetime, timedelta
from hashlib import sha1, sha512
from urllib import unquote, urlencode

from srnd.utils import basicHTMLencode, basicHTMLencodeNoStrip

import nacl.signing


class censor(BaseHTTPRequestHandler):

  def __init__(self, request, client_address, origin):
    self.origin = origin
    #if __name__ != '__main__':
    #  self.origin.log('postman initializing as plugin..', 2)
    #else:
    #  self.origin.log('postman initializing as standalone application..', 2)
    # ^ works
    BaseHTTPRequestHandler.__init__(self, request, client_address, origin)

  def do_POST(self):
    self.path = unquote(self.path)
    if self.path == '/moderate?evil':
      self.handle_moderation_request()
      return
    if self.path == '/moderate?auth':
      public = self.check_login()
      if public:
        session = hexlify(self.origin.rnd.read(24))
        self.origin.sessions[session] = [int(time.time()) + 3600, public, self.get_senderhash()]
        self.send_redirect('/moderate/%s/' % session, 'access granted. this time.')
      else:
        self.send_login("totally not")
      return
    elif self.path == '/moderate?login':
      is_success, new_cookie = self.user_login('ananas')
      if is_success:
        self.send_redirect('/', 'Welcome, again!', 3, new_cookie)
      else:
        self.send_redirect('/img/suicide.txt', 'totally not', 1)
      return
    elif self.path.startswith("/moderate"):
      if not self.legal_session(self.path[10:58]):
        self.send_login()
        return
      self.session = self.path[10:58]
      self.root_path = self.path[:58] + '/'
      self.origin.sessions[self.session][0] = int(time.time()) + 3600
      path = self.path[58:]
      if path.startswith('/modify?'):
        key = path[8:]
        if key == 'create':
          if self.__check_legal_access('srnd-acl-mod'):
            self.send_modify_key(key, create_key=True)
          else:
            self.send_redirect(self.root_path, "not authorized, flag srnd-acl-mod flag missing.<br />redirecting you in a moment.", 7)
          return
        self.post_page_handler('key_stats', key, 'srnd-acl-mod', self.handle_update_key)
      elif path.startswith('/settings?'):
        self.post_page_handler('settings', path[10:], 'overchan-board-mod', self.handle_update_board)
      elif path.startswith('/postman?'):
        self.post_page_handler('postman', path[9:], 'handle-postman-mod', self.handle_update_postman)
      elif path.startswith('/commands?'):
        self.post_page_handler('commands', path[10:], 'handle-srnd-cmd', self.handle_update_commands)
      else:
        self.send_keys()
      return
    self.origin.log(self.origin.logger.WARNING, "illegal access: %s" % self.path)
    self.send_response(200)
    self.send_header('Content-type', 'text/plain')
    self.end_headers()
    self.wfile.write('nope')

  def do_GET(self):
    self.path = unquote(self.path)
    if self.path == '/moderate?getkey':
      secret = self.origin.rnd.read(32)
      public = nacl.signing.SigningKey(secret).verify_key.encode()
      self._send_error("secret: %s\npublic: %s" % (hexlify(secret), hexlify(public)))
      return
    elif self.path == '/moderate?login':
      cookie = self.get_cookie('ananas')
      self.send_login(self.get_name_by_cookie(cookie), '/moderate?login')
      return
    elif self.path.startswith("/moderate"):
      if not self.legal_session(self.path[10:58]):
        self.send_login()
        return
      self.session = self.path[10:58]
      self.root_path = self.path[:58] + '/'
      self.origin.sessions[self.session][0] = int(time.time()) + 3600
      path = self.path[58:]
      if path.startswith('/modify?'):
        self.send_modify_key(path[8:])
      elif path.startswith('/pic_log'):
        page = self._get_positive_int(path[9:], 1)
        self.send_piclog(page)
      elif path.startswith('/moderation_log'):
        try:
          page = int(path[16:])
        except ValueError:
          page = 1
        if page == 0:
          page = 1
        self.send_log(page)
      elif path.startswith('/message_log'):
        data = dict(urlparse.parse_qsl(urlparse.urlsplit(unquote(path)).query))
        self.send_messagelog(data, path[12:])
      elif path.startswith('/stats'):
        self.send_stats()
      elif path.startswith('/settings'):
        self.send_settings(path[10:])
      elif path.startswith('/commands'):
        self.send_commands(path[10:])
      elif path.startswith('/postman'):
        self.send_postman_settings(path[9:])
      elif path.startswith('/showmessage?'):
        self.send_message(path[13:])
      elif path.startswith('/delete?'):
        self.handle_delete(path[8:])
      elif path.startswith('/restore?'):
        self.handle_restore(path[9:])
      elif path.startswith('/info'):
        data = urlparse.parse_qs(urlparse.urlparse(unquote(path)).query)
        data = {x: ''.join(data[x]).encode('ascii', 'ignore') for x in data}
        self.send_info(data)
      elif path.startswith('/notimplementedyet'):
        self._send_error('not implemented yet')
      else:
        self.send_keys()
      return
    self.origin.log(self.origin.logger.WARNING, "illegal access: %s" % self.path)
    self.send_response(200)
    self.send_header('Content-type', 'text/plain')
    self.end_headers()
    self.wfile.write('nope')

  def post_page_handler(self, target, key, command, handler):
    if not self.__check_legal_access(command):
      self.send_redirect(self.root_path + target, "not authorized, flag %s missing.<br />redirecting you in a moment." % command, 7)
      return
    post_vars = self.post_vars_init()
    if 'secret' in post_vars and len(post_vars['secret'].value) > 5:
      secret = post_vars['secret'].value
      public = self.key_from_secret(secret)
      if public is None:
        self.send_redirect(self.root_path + target, "processing %s failed: invalid secret key<br />redirecting you in a moment." % (target,), 9)
        return
      elif public != self.origin.sessions[self.session][1]:
        self.send_redirect(self.root_path + target, "processing %s failed: you logged using another secret key. Reject.<br />redirecting you in a moment." % (target,), 9)
        return
    else:
      public = self.origin.sessions[self.session][1]
      secret = None
    try:
      handler(post_vars, public, secret, key)
      self.send_redirect(self.root_path + target, "update ok<br />redirecting you in a moment.", 4)
    except Exception as e:
      self.send_redirect(self.root_path + target, "processing %s failed: %s<br />redirecting you in a moment." % (target, e), 9)

  @staticmethod
  def key_from_secret(secret):
    try:
      public = hexlify(nacl.signing.SigningKey(unhexlify(secret)).verify_key.encode())
    except:
      return None
    else:
      return public

  def __check_legal_access(self, flag_name):
    flags_available = int(self.origin.sqlite_censor.execute('SELECT flags FROM keys WHERE key = ?', (self.origin.sessions[self.session][1],)).fetchone()[0])
    flag_required = int(self.origin.sqlite_censor.execute('SELECT flag FROM commands WHERE command = ?', (flag_name,)).fetchone()[0])
    return (flags_available & flag_required) == flag_required

  def post_vars_init(self):
    post_vars = FieldStorage(
        fp=self.rfile,
        headers=self.headers,
        environ={
            'REQUEST_METHOD':'POST',
            'CONTENT_TYPE':self.headers['Content-Type'],
        }
    )
    return post_vars

  def console_headers_dump(self, message='unhandled warning'):
    self.origin.log(self.origin.logger.WARNING, message)
    self.origin.log(self.origin.logger.WARNING, self.headers)

  def handle_update_key(self, post_vars, public, secret, key):
    flags = post_vars.getlist("flags")
    if 'local_nick' in post_vars:
      local_nick = basicHTMLencode(post_vars['local_nick'].value.replace("#", ""))
    else:
      local_nick = ''
    result = sum([int(flag) for flag in flags])
    comment = '#'
    if int(self.origin.sqlite_censor.execute('SELECT count(id) FROM keys WHERE key = ?', (key,)).fetchone()[0]):
      old_nick, old_flags = self.origin.sqlite_censor.execute('SELECT local_name, flags FROM keys WHERE key = ?', (key,)).fetchone()
      old_nick = old_nick.encode('UTF-8')
      old_flags = int(old_flags)
      if local_nick != old_nick:
        comment += '%s rename to %s' % (old_nick, local_nick)
      if old_flags != result:
        comment += ' change flag %s->%s ' % (old_flags, result)
    else:
      comment += 'add new key %s, flags %s' % (local_nick, result)
    if comment == '#':
      comment = ''
    cmd_line = {'srnd-acl-mod': ('{0} {1} {2}{3}'.format(key, result, local_nick, comment),)}
    self.handle_commands(cmd_line, public, secret)

  def handle_update_board(self, post_vars, public, secret, board_id):
    flags = post_vars.getlist("flags")
    comment = ''
    aliases = ('ph_name', 'ph_shortname', 'link', 'tag', 'description',)
    if 'board_name' in post_vars:
      new_board = post_vars['board_name'].value.replace("<", "&lt;").replace(">", "&gt;").replace("#", "-").strip().lower()
      if new_board != '' and not new_board.startswith('overchan.'):
        new_board = 'overchan.' + new_board
    else:
      new_board = ''
    aliases_new = tuple([post_vars.getvalue(x, '').strip().decode('utf-8') for x in aliases])
    aliases_blob = ':'.join([base64.urlsafe_b64encode(post_vars.getvalue(x, '').strip()) for x in aliases])
    result = sum([int(flag) for flag in flags])
    if new_board != '' and board_id == 'new':
      cmd_line = {'overchan-board-add': ('{0} {1} {2}#request for create {0}, flags {1}'.format(new_board, result, aliases_blob),)}
      self.handle_commands(cmd_line, self.origin.sessions[self.session][1], None)
      return
    row = self.origin.sqlite_overchan.execute('SELECT group_name, flags, ph_name, ph_shortname, link, tag, description FROM groups WHERE group_id = ?', (board_id,)).fetchone()
    (board_name, old_flags), aliases_old = row[:2], row[2:]
    if int(old_flags) != result:
      comment = 'Change flags {1}->{0}'.format(result, old_flags)
    if aliases_old != aliases_new:
      comment += ' change alias'
    else:
      aliases_blob = ''
    if comment == '': return
    cmd_line = {'overchan-board-mod': ('{0} {1} {2}#{3}'.format(board_name, result, aliases_blob, comment),)}
    self.handle_commands(cmd_line, public, secret)

  def handle_update_postman(self, post_vars, public, secret, userkey_new):
    userkey = post_vars.getvalue('userkey', userkey_new)
    try:
      vk = nacl.signing.VerifyKey(unhexlify(userkey))
      del vk
    except Exception as e:
      raise Exception("invalid key: %s" % e)

    data_row = ('local_name', 'allow', 'expires', 'logout',)
    data_blob = ':'.join([base64.urlsafe_b64encode(post_vars.getvalue(x, '').strip()) for x in data_row])
    if userkey_new == 'new':
      comment = 'add new key'
    else:
      comment = 'modify key, sign: %s' % sha1(data_blob).hexdigest()[:6]
    cmd_line = {'handle-postman-mod': ('{0} {1}#{2}'.format(userkey, data_blob, comment),)}
    self.handle_commands(cmd_line, public, secret)

  def handle_update_commands(self, post_vars, public, secret, command):
    command = post_vars.getvalue('command', command)
    if len(command) < 3:
      raise Exception("invalid command name")

    data_row = ('send', 'received', 'replayable',)
    data_blob = ':'.join([base64.urlsafe_b64encode(post_vars.getvalue(x, '').strip()) for x in data_row])
    comment = 'modify command, sign: %s' % sha1(data_blob).hexdigest()[:6]
    cmd_line = {'handle-srnd-cmd': ('{0} {1}#{2}'.format(command, data_blob, comment),)}
    self.handle_commands(cmd_line, public, secret)

  def get_senderhash(self):
    if 'X-I2P-DestHash' in self.headers:
      return sha512(self.headers['X-I2P-DestHash'] + self.origin.runtime_salt).hexdigest()[:32]
    elif False:
      return sha512('TODO: add tor desthash or remove this' + self.origin.runtime_salt).hexdigest()[:32]
    return sha512(self.client_address[0] + self.origin.runtime_salt).hexdigest()[:32]

  def legal_session(self, session_id):
    if session_id in self.origin.sessions:
      if self.origin.sessions[session_id][2] != self.get_senderhash():
        self.console_headers_dump('Destanation change! Maybe sessionkey leak.')
      elif self.origin.sessions[session_id][0] > int(time.time()):
        return True
      del self.origin.sessions[session_id]
    return False

  def check_login(self):
    current_date = int(time.time())
    todelete = list()
    for key in self.origin.sessions:
      if self.origin.sessions[key][0] <= current_date:
        todelete.append(key)
    for key in todelete:
      del self.origin.sessions[key]
    del todelete
    post_vars = self.post_vars_init()
    if not 'secret' in post_vars:
      self.console_headers_dump('admin panel login: no secret key received')
      return False
    public = self.key_from_secret(post_vars['secret'].value)
    if public is None:
      self.console_headers_dump('admin panel login: invalid secret key received')
      return False
    try:
      flags_available = int(self.origin.sqlite_censor.execute("SELECT flags FROM keys WHERE key=?", (public,)).fetchone()[0])
      flag_required = int(self.origin.sqlite_censor.execute('SELECT flag FROM commands WHERE command="srnd-acl-view"').fetchone()[0])
      if (flags_available & flag_required) == flag_required:
        return public
      else:
        return False
    except Exception as e:
      self.console_headers_dump('admin panel login: key not present in db: %s' % e)
      return False

  def user_login(self, cookie_name='Error'):
    current_time = int(time.time())
    post_vars = self.post_vars_init()

    if not 'secret' in post_vars:
      self.console_headers_dump('user login: no secret key received')
      return False, None
    public = self.key_from_secret(post_vars['secret'].value)
    if public is None:
      self.console_headers_dump('user login: invalid secret key received')
      return False, None
    expires = self.origin.postmandb.execute('SELECT expires FROM userkey WHERE userkey = ? AND allow = 1 AND expires > ?', (public, current_time)).fetchone()
    if expires:
      new_cookie = hexlify(self.origin.rnd.read(24))
      set_cookie = '{0}={1}; expires={2}; path=/;'.format(cookie_name, new_cookie, datetime.utcfromtimestamp(expires[0]).strftime('%a, %d-%b-%Y %T GMT'))
      try:
        self.origin.postmandb.execute('UPDATE userkey SET last_login = ?, cookie = ? WHERE userkey = ?', (current_time, new_cookie, public))
        self.origin.postmandb.commit()
      except Exception as e:
        self.origin.log(self.origin.logger.WARNING, 'user login: error database update %s' % e)
        return False, set_cookie
      return True, set_cookie
    else:
      self.console_headers_dump('user login: disallow user key %s' % public)
      return False, None

  def send_redirect(self, target, message, wait=0, set_cookie=''):
    self.send_response(200)
    self.send_header('Content-type', 'text/html')
    if set_cookie != '':
      self.send_header('Set-Cookie', set_cookie)
    self.end_headers()
    self.wfile.write('<html><head><link type="text/css" href="/styles.css" rel="stylesheet"><META HTTP-EQUIV="Refresh" CONTENT="%i; URL=%s"></head><body class="mod"><center><br /><b>%s</b></center></body></html>' % (wait, target, message))
    return

  def send_login(self, message='', target='/moderate?auth'):
    self.send_response(200)
    self.send_header('Content-type', 'text/html')
    self.end_headers()
    self.wfile.write(self.origin.t_engine_send_login.substitute({'message': message, 'target': target}).encode('UTF-8'))

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

  @staticmethod
  def get_name_by_cookie(cookie):
    if cookie != '':
      return 'What you want?'
    return 'Hello $username'

  def __remote_sending_str(self, command):
    if self.origin.sqlite_censor.execute('SELECT count(command) from cmd_map WHERE command = ? AND send = 1', (command,)).fetchone()[0] == 1:
      return self.origin.template_send_remote
    else:
      return ''

  def send_modify_key(self, key, create_key=False):
    if create_key:
      post_vars = self.post_vars_init()
      key = post_vars.getvalue('new_key', '')
      try:
        vk = nacl.signing.VerifyKey(unhexlify(key))
        del vk
      except Exception as e:
        self.die("invalid key: %s" % e)
        return

    row = self.origin.sqlite_censor.execute("SELECT key, local_name, flags, id FROM keys WHERE key = ?", (key,)).fetchone()
    if not row:
      if not create_key:
        self.die("key not found")
        return
      row = (key, '', 0, 0)

    flags = self.origin.sqlite_censor.execute("SELECT command, flag FROM commands").fetchall()
    out = self.origin.template_modify_key.replace("%%key%%", row[0]).replace("%%nick%%", row[1])
    out = out.replace("%%send_remote%%", self.__remote_sending_str('srnd-acl-mod'))
    out = out.replace("%%modify_key_flagset%%", self.modify_key_flagset_construct(row[2], flags))
    self.send_response(200)
    self.send_header('Content-type', 'text/html')
    self.end_headers()
    self.wfile.write(out.encode('UTF-8'))

  def send_modify_board(self, board_id):
    if board_id.startswith('id='):
      row = self.origin.sqlite_overchan.execute("SELECT group_id, group_name, flags, ph_name, ph_shortname, link, tag, description \
          FROM groups WHERE group_id = ?", (board_id[3:],)).fetchone()
    elif board_id.startswith('name='):
      row = self.origin.sqlite_overchan.execute("SELECT group_id, group_name, flags, ph_name, ph_shortname, link, tag, description \
        FROM groups WHERE group_name = ?", (board_id[5:],)).fetchone()
    elif board_id == 'new':
      row = ('new', 'overchan.<input type="text" name="board_name" value=""/>', '0', '', '', '', '', '')
    else:
      return ''
    if not row:
      return 'Board not found'

    flags = self.origin.sqlite_overchan.execute("SELECT flag_name, flag FROM flags").fetchall()
    form_data = dict()
    form_data['send_remote'] = self.__remote_sending_str('overchan-board-add') if board_id == 'new' else self.__remote_sending_str('overchan-board-mod')
    form_data['modify_key_flagset'] = self.modify_key_flagset_construct(row[2], flags)
    form_data['board_id'] = str(row[0])
    form_data['board'] = row[1]
    form_data['ph_name'] = row[3]
    form_data['ph_shortname'] = row[4]
    form_data['link'] = row[5]
    form_data['tag'] = row[6]
    form_data['description'] = row[7]
    return self.origin.t_engine_modify_board.substitute(form_data)

  def modify_key_flagset_construct(self, target, flags):
    flagset_template = self.origin.template_modify_key_flagset
    target = int(target)
    flaglist = list()
    counter = 0
    for flag in flags:
      counter += 1
      if (target & int(flag[1])) == int(flag[1]):
        checked = 'checked="checked"'
      else:
        checked = ''
      cur_template = flagset_template.replace("%%flag%%", flag[1])
      cur_template = cur_template.replace("%%flag_name%%", flag[0])
      cur_template = cur_template.replace("%%checked%%", checked)
      if counter == 5:
        cur_template += "<br />"
      else:
        cur_template += "&nbsp;"
      flaglist.append(cur_template)
    return ''.join(flaglist)

  def flaglist_construct(self, target, flags):
    flagset_template = self.origin.template_log_flagset
    flaglist = list()
    target = int(target)
    for flag in flags:
      if (target & int(flag[1])) == int(flag[1]):
        flaglist.append(flagset_template.replace("%%flag%%", '<b style="color: #00E000;">y</b>'))
      else:
        flaglist.append(flagset_template.replace("%%flag%%", "n"))
    return "\n".join(flaglist)

  def send_keys(self):
    out = self.origin.template_keys
    create_key = '<div style="float:right;"><form action="modify?create" enctype="multipart/form-data" method="POST"><input name="new_key" type="text" class="posttext"><input type="submit" class="postbutton" value="add key"></form></div>'
    out = out.replace("%%navigation%%", self.__get_navigation('key_stats', add_after=create_key))
    table = list()
    flags = self.origin.sqlite_censor.execute("SELECT command, flag FROM commands").fetchall()
    cur_template = self.origin.template_log_flagnames
    for flag in flags:
      current_flag = flag[0]
      if "-" in current_flag:
        current_flag = current_flag.split("-", 1)[1]
      table.append(cur_template.replace("%%flag%%", current_flag))
    out = out.replace("%%flag_names%%", "\n".join(table))
    del table[:]
    for row in self.origin.sqlite_censor.execute('SELECT key, local_name, flags FROM keys WHERE flags != 0 OR local_name != "" ORDER BY abs(flags) DESC, local_name ASC').fetchall():
      cur_template = self.origin.template_log_whitelist
      cur_template = cur_template.replace("%%key%%", row[0])
      cur_template = cur_template.replace("%%nick%%", self.hidden_line(row[1], 30))
      cur_template = cur_template.replace("%%flagset%%", self.flaglist_construct(row[2], flags))
      table.append(cur_template)
    out = out.replace("%%mod_whitelist%%", "\n".join(table))
    del table[:]
    #for row in self.origin.sqlite_censor.execute("SELECT key, local_name, flags, id FROM keys WHERE flags = 0").fetchall():
    for row in self.origin.sqlite_censor.execute('SELECT local_name, key, count(key_id) as counter, key_id FROM log, keys WHERE data in (SELECT data FROM log WHERE accepted = 1) AND keys.id = key_id GROUP by key_id ORDER BY counter DESC').fetchall():
      cur_template = self.origin.template_log_unknown
      cur_template = cur_template.replace("%%key%%", row[1])
      if row[0] != "":
        cur_template = cur_template.replace("%%nick%%", self.hidden_line(row[0], 30))
      else:
        cur_template = cur_template.replace("%%nick%%", "&nbsp;")
      count = self.origin.sqlite_censor.execute("SELECT count(data) FROM log WHERE key_id = ?", (row[3],)).fetchone()
      cur_template = cur_template.replace("%%accepted_by_trusted_count%%", str(row[2]))
      cur_template = cur_template.replace("%%accepted_by_trusted_total%%", str(count[0]))
      cur_template = cur_template.replace("%%accepted_by_trusted_percentage%%", "%.2f" % (float(row[2]) / count[0] * 100))
      table.append(cur_template)
    out = out.replace("%%mod_unknown%%", "\n".join(table))
    self.send_response(200)
    self.send_header('Content-type', 'text/html')
    self.end_headers()
    self.wfile.write(out.encode('UTF-8'))

  @staticmethod
  def hidden_line(line, max_len=60):
    if 16 < max_len < len(line):
      return '%s[..]%s' % (line[:6], line[-6:])
    else:
      return line

  @staticmethod
  def _pagination_construct(backward=None, forward=None):
    link_ = u'<a href="{}">{}</a>'
    titles = (u'previous', u'next')
    backward = link_.format(backward, titles[0]) if backward else titles[0]
    forward = link_.format(forward, titles[1]) if forward else titles[1]
    return u'<div style="float:right;">{}&nbsp;{}</div>'.format(backward, forward)

  def send_log(self, page=1, pagecount=100):
    log_body = dict()
    if page < 0:
      page *= -1
      log_accepted = 0
      page_corrector = -1
      log_body['accepted_log'] = '<a href="moderation_log?1">accepted log</a>'
      log_body['ignored_log'] = 'ignored log'
      help_target = 'moderation_ignored_log'
    else:
      page_corrector = 1
      log_accepted = 1
      log_body['accepted_log'] = 'accepted log'
      log_body['ignored_log'] = '<a href="moderation_log?-1">ignored log</a>'
      help_target = 'moderation_accepted_log'
    backward = 'moderation_log?%i' % ((page-1)*page_corrector) if page > 1 else None
    log_body['pagination'] = self._pagination_construct(backward, 'moderation_log?%i' % ((page+1)*page_corrector))
    log_body['navigation'] = self.__get_navigation('moderation_log', add_after=log_body['pagination'])
    table = list()
    for row in self.origin.sqlite_censor.execute("SELECT key, local_name, command, data, reason, comment, timestamp, log.source FROM log, commands, keys, reasons WHERE\
        log.accepted = ? AND keys.id = log.key_id AND commands.id = log.command_id AND reasons.id = log.reason_id ORDER BY log.id DESC LIMIT ?, ?", \
        (log_accepted, (page-1)*pagecount, pagecount)).fetchall():
      log_row = dict()
      if row[1] != '':
        log_row['key_or_nick'] = basicHTMLencode(self.hidden_line(row[1], 30))
      else:
        log_row['key_or_nick'] = self.hidden_line(row[0])
      log_row['key'] = row[0]
      log_row['action'] = row[2]
      log_row['reason'] = row[4] if row[7] == 'local' else '<a href="showmessage?{}" target="_blank">{}</a>'.format(row[7], row[4])
      log_row['comment'] = row[5][:60]
      log_row['date'] = datetime.utcfromtimestamp(row[6]).strftime('%d.%m.%y %H:%M')
      data = basicHTMLencode(self.hidden_line(row[3], 64))
      if row[2] in ('delete', 'overchan-delete-attachment', 'overchan-sticky', 'overchan-close'):
        message_id = row[3].replace("<", "&lt;").replace(">", "&gt;")
        try:
          if os.stat(os.path.join('articles', 'censored', row[3])).st_size > 0:
            log_row['postid'] = '<a href="showmessage?%s" target="_blank">%s</a>' % (message_id, data)
            if row[2] in ('delete', 'overchan-delete-attachment'):
              log_row['restore_link'] = '<a href="restore?%s">restore</a>&nbsp;' % message_id
            else:
              log_row['restore_link'] = ''
            log_row['delete_link'] = '<a href="delete?%s">delete</a>&nbsp;' % message_id
          else:
            log_row['postid'] = data
            log_row['restore_link'] = ''
            log_row['delete_link'] = ''
        except:
          log_row['postid'] = data
          log_row['delete_link'] = ''
          if os.path.isfile(os.path.join('articles', row[3])):
            item_row = self.origin.sqlite_overchan.execute('SELECT parent FROM articles WHERE article_uid = ?', (row[3],)).fetchone()
            if item_row:
              if item_row[0] == '':
                log_row['restore_link'] = '<a href="/thread-%s.html" target="_blank">view thread</a>&nbsp;' % sha1(row[3]).hexdigest()[:10]
              else:
                log_row['restore_link'] = '<a href="/thread-%s.html#%s" target="_blank">view post</a>&nbsp;' % (sha1(item_row[0]).hexdigest()[:10], sha1(row[3]).hexdigest()[:10])
            else:
              log_row['restore_link'] = 'restored&nbsp;'
          else:
            log_row['restore_link'] = ''
      else:
        log_row['postid'] = data
        log_row['delete_link'] = ''
        if row[2] == 'srnd-acl-mod':
          log_row['restore_link'] = '<a href="modify?%s">modify key</a>' % row[3]
        elif row[2] == 'handle-postman-mod':
          log_row['restore_link'] = '<a href="postman?%s">modify userkey</a>' % row[3]
        elif row[2] == 'handle-srnd-cmd':
          log_row['restore_link'] = '<a href="commands?%s">modify command</a>' % row[3]
        elif row[2] in ('overchan-board-mod', 'overchan-board-add', 'overchan-board-del'):
          log_row['restore_link'] = '<a href="settings?name=%s">modify board</a>' % basicHTMLencode(row[3])
        else:
          log_row['restore_link'] = ''
      if log_accepted == 1:
        table.append(self.origin.t_engine_log_accepted.substitute(log_row))
      else:
        table.append(self.origin.t_engine_log_ignored.substitute(log_row))

    log_body['mod_log'] = ''.join(table).rstrip()

    self._substitute_and_send(self.origin.t_engine_log, log_body, help_target)

  def send_piclog(self, page=1, pagecount=30):
    out = '<html><head><title>piclog</title><link type="text/css" href="/styles.css" rel="stylesheet"></head>\n<body class="mod">\n%%navigation%%\n'
    pagination = '<div style="float:right;">'
    if page > 1:
      pagination += '<a href="pic_log?%i">previous</a>' % (page-1)
    else:
      pagination += 'previous'
    pagination += '&nbsp;<a href="pic_log?%i">next</a></div>' % (page+1)
    out = out.replace("%%navigation%%", self.__get_navigation('pic_log', add_after=pagination))
    table = list()
    table.append(out.replace("%%pagination%%", pagination))
    for row in self.origin.sqlite_overchan.fetchall('SELECT thumblink, parent, article_uid FROM articles WHERE length(thumblink) > 40 GROUP BY thumblink ORDER BY last_update DESC, sent DESC LIMIT ?, ?', ((page-1)*pagecount, pagecount)):
      cur_template = '<a href="/%%target%%" target="_blank"><img src="%%thumblink%%" class="image" width="150" max-height="300" /></a>'
      if row[1] == '' or row[1] == row[2]:
        target = 'thread-%s.html' % sha1(row[2]).hexdigest()[:10]
      else:
        target = 'thread-%s.html#%s' % (sha1(row[1]).hexdigest()[:10], sha1(row[2]).hexdigest()[:10])
      cur_template = cur_template.replace("%%target%%", target)
      cur_template = cur_template.replace("%%thumblink%%", '/thumbs/' + row[0])
      table.append(cur_template)
    table.append('<br />' + pagination + '<br />')
    table.append('</body></html>')
    self.send_response(200)
    self.send_header('Content-type', 'text/html')
    self.end_headers()
    self.wfile.write("\n".join(table))

  @staticmethod
  def _get_positive_int(data, default=100):
    try:
      data = int(data)
    except ValueError:
      return default
    else:
      return data if data > 0 else 1

  def send_messagelog(self, data, raw_data):
    message_log = dict()
    message_log['search_target'] = data.get('q', '').decode('UTF-8', errors='replace')
    message_log['count'] = self._get_positive_int(data.get('c', 100))
    page = self._get_positive_int(data.get('page', 1), 1)
    message_log['search_action'] = ''
    db_target = data.get('db', 'overchan').encode('ascii', errors='replace')
    dbs = {'overchan': 'Overchan', 'pastes': 'Pastes'}
    if db_target not in dbs:
      db_target = 'overchan'
    message_log['more'] = ' db: <select name="db">{}<select>'.format(self.__selector_construct(dbs, db_target))
    message_log['content'] = self.send_messagelog_construct(message_log['count'], message_log['search_target'], db_target, page)

    backward, forward = '', ''
    if page > 1:
      data2 = data.copy()
      data2['page'] = page - 1
      backward = 'message_log?{}'.format(urlencode(data2))
    if message_log['content']:
      data2 = data.copy()
      data2['page'] = page + 1
      forward = 'message_log?{}'.format(urlencode(data2))
    message_log['pagination'] = self._pagination_construct(backward, forward)
    message_log['navigation'] = self.__get_navigation('message_log', add_after=message_log['pagination'])
    message_log['target'] = u'{}{}{}'.format(self.root_path, 'message_log', raw_data.decode('UTF-8', errors='replace'))
    self._substitute_and_send(self.origin.t_engine_message_log, message_log, 'send_messagelog')

  def _messagelog_iterator(self, count, find_me, db_target, page):
    handler = self.origin.pastesdb if db_target == 'pastes' else self.origin.sqlite_overchan
    if len(find_me) < 3:
      params = ((page - 1) * count, count)
      if db_target == 'pastes':
        query = 'SELECT article_uid, "", sender, subject, body, sent, case when hidden = 0 then lang else "[private]" || lang end FROM pastes ORDER BY sent DESC LIMIT ?, ?'
      else:
        query = 'SELECT article_uid, parent, sender, subject, message, sent, group_name FROM articles, groups WHERE groups.group_id = articles.group_id ORDER BY articles.sent DESC LIMIT ?, ?'
    else:
      params = (u'%{}%'.format(find_me), (page - 1) * count, count)
      if db_target == 'pastes':
        query = 'SELECT article_uid, "", sender, subject, body, sent, case when hidden = 0 then lang else "[private]" || lang end FROM pastes WHERE body LIKE ? ORDER BY sent DESC LIMIT ?, ?'
      else:
        query = 'SELECT article_uid, parent, sender, subject, message, sent, group_name FROM articles, groups WHERE groups.group_id = articles.group_id AND message LIKE ? ORDER BY articles.sent DESC LIMIT ?, ?'
    for row in handler.execute(query, params).fetchall():
      yield row

  def send_messagelog_construct(self, count, find_me, db_target, page):
    table = list()
    link_ = 'paste/' if db_target == 'pastes' else 'thread-'
    for row in self._messagelog_iterator(count, find_me, db_target, page):
      message_log_row = dict()
      articlehash_full = sha1(row[0]).hexdigest()
      if row[1] == '' or row[1] == row[0]:
        # parent
        message_log_row['link'] = "%s%s.html" % (link_, articlehash_full[:10])
        message_log_row['delete_taget'] = 'thread'
      else:
        message_log_row['link'] = "%s%s.html#%s" % (link_, sha1(row[1]).hexdigest()[:10], articlehash_full[:10])
        message_log_row['delete_taget'] = 'post'
      message_log_row['sender'] = row[2][:15]
      message_log_row['subject'] = row[3][:38] + '..' if len(row[3]) > 40 else row[3]
      message_ = row[4][:200] + ' [..]' if len(row[4]) > 205 else row[4]
      message_log_row['message'] = basicHTMLencode(message_) if db_target == 'pastes' else message_
      message_log_row['group_name'] = row[6]
      message_log_row['sent'] = datetime.utcfromtimestamp(row[5]).strftime('%Y/%m/%d %H:%M')
      message_log_row['articlehash_full'] = articlehash_full
      message_log_row['articlehash'] = articlehash_full[:10]
      table.append(self.origin.t_engine_message_log_row.substitute(message_log_row))
    return '\n'.join(table)

  def send_stats(self):
    stats_data = dict()
    t_2_rows = '<tr><td class="right">%s</td><td>%s</td></tr>'
    t_3_rows = '<tr><td>%s</td><td class="right">%s</td><td>%s</td></tr>'
    t_g_stat = '<tr><td class="right">%s</td><td>%s</td><td class="right">%s</td></tr>'

    stats_data['navigation']             = self.__get_navigation('stats')
    stats_data['stats_usage']            = ''.join( t_3_rows % x for x in self.__stats_usage(31, 30)    )
    stats_data['stats_fronteds']         = ''.join( t_2_rows % x for x in self.__stats_frontends()      )
    stats_data['stats_groups']           = ''.join( t_g_stat % x for x in self.__stats_groups()         )
    stats_data['stats_usage_month']      = ''.join( t_3_rows % x for x in self.__stats_usage_month(30)  )
    stats_data['stats_usage_weekday_28'] = ''.join( t_3_rows % x for x in self.__stats_usage_weekday(28))
    stats_data['stats_usage_weekday']    = ''.join( t_3_rows % x for x in self.__stats_usage_weekday()  )

    self._substitute_and_send(self.origin.t_engine_stats, stats_data, 'send_stats')

  def send_message(self, message_id):
    message_id = os.path.basename(message_id)
    self.send_response(200)
    self.send_header('Content-type', 'text/html')
    self.end_headers()
    out = '<html><head><title>view message</title><link type="text/css" href="/styles.css" rel="stylesheet"></head><body class="mod">%%navigation%%<pre>\n'
    out = out.replace("%%navigation%%", self.__get_navigation(''))
    self.wfile.write(out.encode('UTF-8'))

    if os.path.isfile(os.path.join('articles', 'censored', message_id)):
      f = codecs.open(os.path.join('articles', 'censored', message_id), 'r', 'UTF-8')
      self.__write_nntp_article(f)
    elif os.path.isfile(os.path.join('articles', message_id)):
      f = codecs.open(os.path.join('articles', message_id), 'r', 'UTF-8')
      self.__write_nntp_article(f)
    else:
      self.wfile.write('message_id \'%s\' not found' % basicHTMLencode(message_id))
    self.wfile.write('</pre></body></html>')

  def send_settings(self, board_id=''):
    data = dict()
    data['navigation'] = self.__get_navigation('settings')
    flags = self.origin.sqlite_overchan.execute("SELECT flag_name, flag FROM flags").fetchall()
    data['flag_names'] = '\n'.join((self.origin.template_log_flagnames.replace("%%flag%%", flag[0]) for flag in flags))
    table = list()
    for row in self.origin.sqlite_overchan.execute('SELECT group_name, article_count, group_id, flags FROM groups WHERE group_name != "" ORDER BY abs(article_count) DESC, group_name ASC').fetchall():
      data_row = {\
         'board': row[0], 'posts': row[1], 'board_id': row[2],
         'flagset': self.flaglist_construct(row[3], flags)}
      table.append(self.origin.t_engine_settings_list.substitute(data_row))
    data['board_list'] = '\n'.join(table)
    if board_id:
      help_target = 'send_modify_settings'
      data['post_form'] = self.send_modify_board(board_id)
    else:
      help_target = 'send_settings'
      data['post_form'] = ''
    self._substitute_and_send(self.origin.t_engine_settings, data, help_target)

  def send_postman_settings(self, userkey=''):
    data = dict()
    data['navigation'] = self.__get_navigation('postman')
    allow_table = list()
    disallow_table = list()
    current_time = int(time.time())
    modify_user = list()
    for row in self.origin.postmandb.execute('SELECT userkey, local_name, postcount, last_login, expires, allow FROM userkey ORDER BY abs(postcount) DESC, last_login ASC').fetchall():
      if row[0] == userkey:
        modify_user = (row[0], row[1], row[4], row[5])
      postman_row = dict()
      postman_row['userkey'] = row[0]
      postman_row['local_name'] = row[1]
      postman_row['postcount'] = row[2]
      try:
        postman_row['last_login'] = datetime.utcfromtimestamp(row[3]).strftime('%d.%m.%y %H:%M')
      except TypeError:
        postman_row['last_login'] = 'None'
      postman_row['expires'] = datetime.utcfromtimestamp(row[4]).strftime('%d.%m.%y %H:%M')
      if row[5]:
        if int(row[4]) < current_time:
          postman_row['status'] = '\n          <td class="bad">expired</td>'
        else:
          postman_row['status'] = '\n          <td class="good">OK</td>'
        allow_table.append(self.origin.t_engine_postman_row.substitute(postman_row))
      else:
        postman_row['status'] = ''
        disallow_table.append(self.origin.t_engine_postman_row.substitute(postman_row))

    data['allow_userkey'] = '\n'.join(allow_table)
    data['disallow_userkey'] = '\n'.join(disallow_table)

    help_target = 'send_modify_postman_settings'
    if len(modify_user) > 0:
      data['modify_user'] = self.postman_modify_user(modify_user)
    elif userkey == 'new':
      data['modify_user'] = self.postman_modify_user(('new', '', 0, 0))
    else:
      data['modify_user'] = ''
      help_target = 'send_postman_settings'

    self._substitute_and_send(self.origin.t_engine_postman, data, help_target)

  def postman_modify_user(self, user_data):
    current_time = int(time.time())
    form_data = dict()
    form_data['send_remote'] = self.__remote_sending_str('handle-postman-mod')
    form_data['userkey'] = user_data[0]
    if user_data[0] == 'new':
      form_data['action'] = 'add'
      form_data['userkey_edit'] = '<input type="text" name="userkey" value="" class="posttext" maxlength="64"/>'
    else:
      form_data['action'] = 'modify'
      form_data['userkey_edit'] = user_data[0]
    form_data['local_name'] = user_data[1]
    try:
      form_data['expires'] = int(round((user_data[2] - current_time) / (24 * 3600.0)))
      if form_data['expires'] < 0:
        form_data['expires'] = 0
    except ValueError:
      form_data['expires'] = 0
    try:
      if int(user_data[3]) > 0:
        form_data['allow'] = ' checked="checked"'
      else:
        form_data['allow'] = ''
    except ValueError:
      form_data['allow'] = ''

    return self.origin.t_engine_modify_postman.substitute(form_data)

  def send_commands(self, modify_cmd=''):
    data = dict()
    data['navigation'] = self.__get_navigation('commands')
    data_list = list()
    modify_data = list()
    data_selector = dict()
    data_selector[1] = {0: 'local', 1: 'remote', -1: 'disable'}
    data_selector[2] = {0: 'local', 1: 'both',   -1: 'disable'}
    data_selector[3] = {0: 'No', 1: 'Yes'}
    for row in self.origin.sqlite_censor.execute('SELECT cmd_map.command, send, received, replayable FROM cmd_map, commands WHERE cmd_map.command = commands.command ORDER BY commands.id').fetchall():
      if modify_cmd == row[0]: modify_data = row
      data_row = dict()
      data_row['command'] = row[0]
      data_row['send'] = data_selector[1].get(row[1], 'error')
      data_row['received'] = data_selector[2].get(row[2], 'error')
      data_row['replayable'] = data_selector[3].get(row[3], 'ERR')
      data_list.append(self.origin.t_engine_commands_row.substitute(data_row))

    data['commands_list'] = '\n'.join(data_list)
    if len(modify_data) > 0:
      data['modify_command'] = self.commands_modify(modify_data, data_selector)
      help_target = 'send_modify_commands'
    else:
      data['modify_command'] = ''
      help_target = 'send_commands'

    self._substitute_and_send(self.origin.t_engine_commands, data, help_target)

  def commands_modify(self, modify_data, data_selector):
    command_data = dict()
    command_data['send_remote'] = self.__remote_sending_str('handle-srnd-cmd')
    command_data['command'] = modify_data[0]
    command_data['send'] = self.__selector_construct(data_selector[1], modify_data[1])
    command_data['received'] = self.__selector_construct(data_selector[2], modify_data[2])
    command_data['replayable'] = self.__selector_construct(data_selector[3], modify_data[3])
    return self.origin.t_engine_modify_commands.substitute(command_data)

  @staticmethod
  def __selector_construct(select_data, checked):
    if checked not in select_data:
      checked = 0
    table = list()
    for item in select_data:
      if checked == item:
        check_this = ' selected'
      else:
        check_this = ''
      table.append('<OPTION value="{0}"{1}>{2}</OPTION>'.format(item, check_this, select_data[item]))
    return ''.join(table)

  def _srnd_control(self, data):
    status = list()
    update_hooks_ = {'action': 'update', 'hook': 'hooks'}
    # reload outfeed
    if data['action'] == 'reload' and data.get('hook') == 'outfeed':
      # is None - all outfeed
      target = '-'.join((data['hook'], data['target'])) if 'target' in data else None
      if not self.origin.SRNd_ctl({'action': 'die', 'hook': 'outfeed', 'targets': target}):
        status.append('kill outfeed(s)')
      if not self.origin.SRNd_ctl({'action': 'update', 'hook': 'outfeed'}):
        status.append('update outfeeds')
      if not self.origin.SRNd_ctl(update_hooks_):
        status.append('update hooks')
      if not self.origin.SRNd_ctl({'action': 'sync', 'hook': 'outfeed', 'targets': target}):
        status.append('resync outfeed(s)')
    # kill outfeed or plugin
    elif data['action'] == 'die' and data.get('hook') in ('outfeed', 'plugin') and data.get('target') is not None:
      target = '-'.join((data['hook'], data['target']))
      if data['target'] != 'censor' and not self.origin.SRNd_ctl({'action': 'die', 'hook': data['hook'], 'targets': target}):
        status.append('kill {}'.format(data['hook']))
      # thread not killing self
      elif data['target'] == 'censor':
        status.append('What is dead may never die.')
      if not self.origin.SRNd_ctl(update_hooks_):
        status.append('update hooks')
    # reload hooks
    elif data['action'] == 'reload' and data.get('hook') == 'hooks':
      if not self.origin.SRNd_ctl(update_hooks_):
        status.append('update hooks')
    elif data['action'] == 'update' and data.get('hook') == 'plugin':
      # update and start plugins
      if not self.origin.SRNd_ctl({'action': 'update', 'hook': 'plugin'}):
        status.append('update plugin')
      if not self.origin.SRNd_ctl(update_hooks_):
        status.append('update hooks')
      if not self.origin.SRNd_ctl({'action': 'start', 'hook': 'plugin'}):
        status.append('start plugins')
    if not status:
      self.send_redirect(self.path.split('?', 1)[0], 'Success!', 2)
    else:
      self.send_redirect(self.path.split('?', 1)[0], 'WARNING! Requests not fulfilled: {}'.format(', '.join(status)), 8)

  def send_info(self, url_query):
    data = {
        'navigation': self.__get_navigation('info'),
        'status': '',
        'start_time_human': None,
        'start_time_raw': None,
        'uptime_human': None,
        'uptime_raw': None,
        'cpu_usage': None,
        'ram_human': None,
        'ram_raw': None,
        'disk_free_human': None,
        'disk_free': None,
        'disk_used_human': None,
        'disk_used': None,
        'plugins': '',
        'plugins_count': 0,
        'infeeds_count': None,
        'infeeds': '',
        'outfeeds_count': None,
        'outfeeds': '',
        'hooks_count': 0,
        'hooks': ''
    }
    if self.origin.SRNd_info is None:
      data['status'] = '<b>Add to censor config for enabling this:</b> #start_param SRNd_info=info<br /><br />'
    elif not self.__check_legal_access('srnd-acl-mod'):
      data['status'] = '<b>Not authorized, flag srnd-acl-mod missing</b><br /><br />'
    else:
      if 'action' in url_query and self.origin.SRNd_ctl is not None:
        self._srnd_control(url_query)
        return
      feed_data = self.origin.SRNd_info({'command': 'status', 'data': 'feeds'})
      for target in ('infeeds', 'outfeeds'):
        feeds = list()
        for feed in feed_data.get(target, {}):
          feed_data[target][feed]['name'] = feed
          feed_data[target][feed]['transfer_human'] = self.__sizeof_human_readable(feed_data[target][feed]['transfer'])
          feed_data[target][feed]['speed_human'] = self.__sizeof_human_readable(int(feed_data[target][feed]['transfer'] / feed_data[target][feed]['transfer_time']))
          feed_data[target][feed]['actions'] = self.origin.t_engine_info_feed_actions.substitute(name=feed) if target == 'outfeeds' else ''
          feeds.append(self.origin.t_engine_info_feed_row.substitute(feed_data[target][feed]))
        data[target] = '\n'.join(feeds)

      plugins = list()
      for plugin in [x[7:] if x.lower().startswith('plugin-') else x for x in self.origin.SRNd_info({'command': 'status', 'data': 'plugins'}).get('active', {})]:
        data['plugins_count'] += 1
        plugins.append(
            self.origin.t_engine_info_plugin_row.substitute(
                name=plugin,
                actions='<a href="?action=die&hook=plugin&target={}">bye</a>'.format(plugin)
            )
        )
      data['plugins'] = '\n'.join(plugins)
      hooks_data = self.origin.SRNd_info({'command': 'status', 'data': 'hooks'})
      hooks = list()
      if len(hooks_data['whitelist']) > 0:
        hooks.append('whitelist:')
        for target in hooks_data['whitelist']:
          hooks.append(' {}'.format(target))
          data['hooks_count'] += len(hooks_data['whitelist'][target])
          hooks.extend(['   {}'.format(xx) for xx in hooks_data['whitelist'][target]])
        hooks.append('')
      if len(hooks_data['blacklist']) > 0:
        hooks.append('blacklist:')
        for target in hooks_data['blacklist']:
          hooks.append(' {}'.format(target))
          data['hooks_count'] += len(hooks_data['blacklist'][target])
          hooks.extend(['   {}'.format(xx) for xx in hooks_data['blacklist'][target]])
        hooks.append('')
      data['hooks'] = '\n'.join(hooks)

      stats = self.origin.SRNd_info({'command': 'stats'})
      data['start_time_human'] = datetime.utcfromtimestamp(stats['start_up_timestamp']).strftime('%d.%m.%y %H:%M')
      data['start_time_raw'] = stats['start_up_timestamp']
      data['uptime_raw'] = int(time.time()) - stats['start_up_timestamp']
      data['uptime_human'] = timedelta(seconds=data['uptime_raw'])
      data['cpu_usage'] = stats['cpu']
      data['ram_human'] = self.__sizeof_human_readable(stats['ram'])
      data['ram_raw'] = stats['ram']
      data['disk_free_human'] = self.__sizeof_human_readable(stats['disk_free'])
      data['disk_free'] = stats['disk_free']
      data['disk_used_human'] = self.__sizeof_human_readable(stats['disk_used'])
      data['disk_used'] = stats['disk_used']
      data['infeeds_count'] = stats['infeeds']
      data['outfeeds_count'] = stats['outfeeds']

    self._substitute_and_send(self.origin.t_engine_info, data, 'send_info')

  def handle_delete(self, message_id):
    path = os.path.join('articles', 'censored', message_id)
    try:
      if os.stat(path).st_size > 0:
        f = open(path, 'w')
        f.close()
    except:
      pass
    self.send_redirect(self.root_path, "redirecting", 0)

  def handle_restore(self, message_id):
    censore_path = os.path.join('articles', 'censored', message_id)
    if os.path.isfile(censore_path):
      article_path = os.path.join('articles', message_id)
      if os.path.isfile(article_path) and os.path.getsize(censore_path) == os.path.getsize(article_path):
        # Attach restored? Remove article and processing now as deleted article
        os.unlink(article_path)
      f = open(os.path.join('articles', 'restored', message_id), 'w')
      f.close()
      os.rename(censore_path, os.path.join('incoming', message_id + '_'))
      self.send_redirect(self.root_path, "redirecting", 0)
    else:
      self.send_redirect(self.root_path, 'message_id does not exist in articles/censored', 5)

  def _send_error(self, errormessage):
    self.send_response(200)
    self.send_header('Content-type', 'text/plain')
    self.end_headers()
    self.wfile.write(errormessage)

  def send_error(self, code, message=None):
    """Overrides method in BaseHTTPRequestHandler
    Don't send errors to the user, only logs
    """
    if message is None:
      message = self.responses.get(code, ('???', '???'))[0]
    self.origin.log(self.origin.logger.ERROR, "Internal server error: code {}, message {}".format(code, message))

  def _substitute_and_send(self, t_engine, data, target=None):
    if target is None or len(self.origin.help_data.get(target, '')) == 0:
      data['help'] = ''
    else:
      data['help'] = self.origin.t_engine_help.substitute(help=self.origin.help_data[target])
    self.send_response(200)
    self.send_header('Content-type', 'text/html')
    self.end_headers()
    self.wfile.write(t_engine.substitute(data).encode('UTF-8'))

  def __write_nntp_article(self, f):
    attachment = re.compile('^[cC]ontent-[tT]ype: ([a-zA-Z0-9/]+).*name="([^"]+)')
    attachment_details = None
    title_ = u'" title="{}" />\n'
    img_ = u'\n<img src="data:{};base64,\n'
    base64_ = False
    writing_base64 = False
    for line in f:
      if line.lower().startswith('content-type:'):
        attachment_details = attachment.match(line)
      elif line.lower().startswith('content-transfer-encoding: base64'):
        base64_ = True
      elif len(line) == 1 and base64_ and attachment_details is not None:
        self.wfile.write(img_.format(basicHTMLencode(attachment_details.group(1))).encode('UTF-8'))
        writing_base64 = True
      elif writing_base64 and line.startswith('--'):
        self.wfile.write(title_.format(basicHTMLencode(attachment_details.group(2))).encode('UTF-8'))
        writing_base64 = False
        base64_ = False
      else:
        self.wfile.write(basicHTMLencodeNoStrip(line).encode('UTF-8'))
    f.close()
    if writing_base64:
      self.wfile.write(title_.format(basicHTMLencode(attachment_details.group(2))).encode('UTF-8'))

  def __stats_frontends(self):
    hosts = list()
    try:
      for row in self.origin.sqlite_overchan.execute('SELECT count(1) as counter, rtrim(substr(article_uid, instr(article_uid, "@") + 1), ">") as hosts FROM articles GROUP by hosts ORDER BY counter DESC').fetchall():
        hosts.append((row[0], row[1]))
    except:
      # work around old sqlite3 version without instr() support:
      #  - remove all printable ASCII chars but " @ and > from the left
      #  - remove all printable ASCII chars but ' @ and > from the left
      #  - remove @ from the left
      #  - remove > from the right
      #  - group by result
      for row in self.origin.sqlite_overchan.execute('SELECT count(1) as counter, rtrim(ltrim(ltrim(ltrim(article_uid, " !#$%&\'()*+,-./0123456789:;<=?ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~"), \' !"#$%&()*+,-./0123456789:;<=?ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~\'), "@"), ">") as hosts FROM articles GROUP by hosts ORDER BY counter DESC').fetchall():
        hosts.append((row[0], row[1]))
    return hosts

  @staticmethod
  def __sizeof_human_readable(num, suffix='B'):
    for unit in ('', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi'):
      if abs(num) < 1024.0:
        return "%3.1f%s%s" % (num, unit, suffix)
      num /= 1024.0
    return "%.1f%s%s" % (num, 'Yi', suffix)

  def __stats_groups(self):
    find_path = 'groups'
    articles_path = 'articles'
    groups = list()
    summary = [0, 0]
    for group in os.listdir(find_path):
      target = os.path.join(find_path, group)
      if os.path.isdir(target):
        all_size, counts = 0, 0
        for article in os.listdir(target):
          try:
            all_size += os.path.getsize(os.path.join(articles_path, os.path.basename(os.readlink(os.path.join(target, article)))))
          except: pass
          else: counts += 1
        if counts > 0:
          summary[0] += counts
          summary[1] += all_size
          groups.append((counts, group, self.__sizeof_human_readable(all_size)))
    groups.append((summary[0], 'all', self.__sizeof_human_readable(summary[1])))
    return sorted(groups, key=lambda x: x[0], reverse=True)

  def __stats_usage_by_frontend(self, days=7, bar_length=29):
    stats = list()
    totals = int(self.origin.sqlite_overchan.execute('SELECT count(1) FROM articles WHERE sent > strftime("%s", "now", "-' + str(days) + ' days")').fetchone()[0])
    stats.append(('all posts', totals, '&nbsp;', 'in previous %s days' % days))
    max_ = 0
    for row in self.origin.sqlite_overchan.execute('SELECT count(1) as counter, strftime("%Y-%m-%d",  sent, "unixepoch") as day, strftime("%w", sent, "unixepoch") as weekday, rtrim(substr(article_uid, instr(article_uid, "@") + 1), ">") as host FROM articles WHERE sent > strftime("%s", "now", "-' + str(days) + ' days") GROUP BY day, host ORDER BY day DESC').fetchall():
      if row[0] > max_: max_ = row[0]
      stats.append((row[0], row[1], self.origin.weekdays[int(row[2])], row[3]))
    for index in range(1, len(stats)):
      graph = ''
      for x in range(0, int(float(stats[index][0])/max_*bar_length)):
        graph += '='
      if len(graph) == 0:
        graph = '&nbsp;'
      stats[index] = ('<span title="%s">%s</span>' % (stats[index][2], stats[index][1]), stats[index][0], stats[index][3], graph)
    return stats

  def __stats_usage(self, days=30, bar_length=29):
    stats = list()
    totals = int(self.origin.sqlite_overchan.execute('SELECT count(1) FROM articles WHERE sent > strftime("%s", "now", "-31 days")').fetchone()[0])
    stats.append(('all posts', totals, 'in previous %s days' % 31))
    max_ = 0
    for row in self.origin.sqlite_overchan.execute('SELECT count(1) as counter, strftime("%Y-%m-%d",  sent, "unixepoch") as day, strftime("%w", sent, "unixepoch") as weekday FROM articles WHERE sent > strftime("%s", "now", "-31 days") GROUP BY day ORDER BY day DESC').fetchall():
      if row[0] > max_: max_ = row[0]
      stats.append((row[0], row[1], self.origin.weekdays[int(row[2])]))
    for index in range(1, len(stats)):
      graph = ''
      for x in range(0, int(float(stats[index][0])/max_*bar_length)):
        graph += '='
      if len(graph) == 0:
        graph = '&nbsp;'
      stats[index] = ('<span title="%s">%s</span>' % (stats[index][2], stats[index][1]), stats[index][0], graph)
    return stats

  def __stats_usage_month(self, bar_length=29):
    stats = list()
    totals = int(self.origin.sqlite_overchan.execute('SELECT count(1) FROM articles').fetchone()[0])
    stats.append(('all posts', totals, 'since beginning'))
    max_ = 0
    for row in self.origin.sqlite_overchan.execute('SELECT count(1) as counter, strftime("%Y-%m",  sent, "unixepoch") as month FROM articles GROUP BY month ORDER BY month DESC').fetchall():
      if row[0] > max_: max_ = row[0]
      stats.append((row[0], row[1]))
    for index in range(1, len(stats)):
      graph = ''
      for x in range(0, int(float(stats[index][0])/max_*bar_length)):
        graph += '='
      if len(graph) == 0:
        graph = '&nbsp;'
      stats[index] = (stats[index][1], stats[index][0], graph)
    return stats

  def __stats_usage_weekday(self, days=None, bar_length=29):
    if days:
      if days % 7 != 0:
        raise Exception("days has to be a multiple of 7 or None")
      result = self.origin.sqlite_overchan.execute('SELECT count(1) as counter, strftime("%w",  sent, "unixepoch") as weekday FROM articles WHERE sent > strftime("%s", "now", "-' + str(days) + ' days") GROUP BY weekday ORDER BY weekday ASC').fetchall()
    else:
      result = self.origin.sqlite_overchan.execute('SELECT count(1) as counter, strftime("%w",  sent, "unixepoch") as weekday FROM articles GROUP BY weekday ORDER BY weekday ASC').fetchall()
    if len(result) == 0:
      return ((None, None, None),)
    stats = list()
    max_ = 0
    for row in result:
      if days:
        avg = float(row[0]) / (days / 7)
        if avg > max_: max_ = avg
        stats.append((avg, self.origin.weekdays[int(row[1])]))
      else:
        if row[0] > max_: max_ = row[0]
        stats.append((row[0], self.origin.weekdays[int(row[1])]))
    for index in range(0, len(stats)):
      graph = ''
      for x in range(0, int(float(stats[index][0])/max_*bar_length + 0.5)):
        graph += '='
      if len(graph) == 0:
        graph = '&nbsp;'
      if days:
        stats[index] = (stats[index][1], "%.2f" % stats[index][0], graph)
      else:
        stats[index] = (stats[index][1], stats[index][0], graph)
    stats.append(stats[0])
    return stats[1:]

  @staticmethod
  def __get_navigation(current, add_after=None):
    out = list()
    for item in (('key_stats', 'key stats'), ('commands', 'c&c'), ('moderation_log', 'moderation log'), ('pic_log', 'pic log'),
                 ('message_log', 'message log'), ('stats', 'stats'), ('settings', 'settings'), ('postman', 'postman'), ('info', 'info')):
      if item[0] == current:
        out.append(item[1])
      else:
        out.append('<a href="%s">%s</a>' % item)
    out = '[&nbsp;%s&nbsp;]' % '&nbsp;|&nbsp;'.join(out)
    if add_after is not None:
      out += add_after
    out += '<br /><br />'
    return out

  def die(self, message=''):
    self.console_headers_dump("%s:%i wants to fuck around, %s" % (self.client_address[0], self.client_address[1], message))
    if self.origin.reject_debug:
      self._send_error('don\'t fuck around here mkay\n%s' % message)
    else:
      self._send_error('don\'t fuck around here mkay')

  def __get_message_id_by_hash(self, hash_):
    return self.origin.sqlite_hasher.execute("SELECT message_id FROM article_hashes WHERE message_id_hash = ?", (hash_,)).fetchone()[0]

  def __get_dest_hash_by_hash(self, hash_):
    return self.origin.sqlite_hasher.execute("SELECT sender_desthash FROM article_hashes WHERE message_id_hash = ?", (hash_,)).fetchone()[0]

  def __get_messages_id_by_dest_hash(self, dest_hash):
    return self.origin.sqlite_hasher.execute("SELECT message_id FROM article_hashes WHERE sender_desthash = ?", (dest_hash,)).fetchall()

  def handle_moderation_request(self):
    post_vars = self.post_vars_init()

    if 'target' in post_vars:
      target = post_vars['target'].value
    else:
      target = '/'
    if 'secret' not in post_vars:
      self.die('local moderation request: secret not in post_vars')
      return
    secret = post_vars['secret'].value
    if len(secret) != 64:
      self.die('local moderation request: invalid secret key received')
      return
    try:
      keypair = nacl.signing.SigningKey(unhexlify(secret))
      pubkey = hexlify(keypair.verify_key.encode())
      flags_available = int(self.origin.sqlite_censor.execute("SELECT flags FROM keys WHERE key=?", (pubkey,)).fetchone()[0])
    except Exception as e:
      self.die('local moderation request: invalid secret key received: %s' % e)
      return
    else:
      del keypair
    if flags_available == 0:
      self.die('local moderation request: public key rejected, no flags required')
      return

    commands = dict()
    for evil, srnd, comment in self.origin.sqlite_censor.execute('SELECT evil, srnd, comment FROM evil_to_srnd WHERE evil != "" AND srnd != ""').fetchall():
      if evil in post_vars:
        if srnd not in commands: commands[srnd] = set()
        add_comment = '#' + comment if comment else ''
        for item in post_vars.getlist(evil):
          if evil == 'purge_desthash':
            try:
              i2p_dest_hash = self.__get_dest_hash_by_hash(item)
            except Exception as e:
              self.console_headers_dump("local moderation request: could not find X-I2P-DestHash for hash %s: %s" % (item, e))
            else:
              if len(i2p_dest_hash) == 44:
                commands[srnd].update(['{0}{1}'.format(message_id[0], add_comment) for message_id in self.__get_messages_id_by_dest_hash(i2p_dest_hash)])
          else:
            try:
              commands[srnd].add('{0}{1}'.format(self.__get_message_id_by_hash(item), add_comment))
            except Exception as e:
              self.console_headers_dump("local moderation request: could not find message_id for hash %s: %s" % (item, e))
        if len(commands[srnd]) == 0: del commands[srnd]
    if len(commands) > 0 and self.handle_commands(commands, pubkey, secret):
      self.send_redirect(target, 'moderation request received. will redirect you in a moment.', 2)
    else:
      self.die('local moderation request: nothing to do')

  def handle_commands(self, commands, pubkey, secret=None):
    local_cmd = set()
    remote_cmd = set()
    for command, send in self.origin.sqlite_censor.execute('SELECT command, send FROM cmd_map WHERE send != -1').fetchall():
      if command in commands:
        if type(commands[command]) not in (list, tuple, set):
          self.origin.log(self.origin.logger.ERROR, 'INTERNAL ERROR: command %s is not "array". FIXME!' % command)
          return False
        cmd_list = ['{0} {1}'.format(command, self.__remove_cmd__escape(cmd)) for cmd in commands[command]]
        if send == 1 and secret is not None:
          remote_cmd.update(cmd_list)
        elif send in (0, 1):
          local_cmd.update(cmd_list)

    status = False
    if len(local_cmd) > 0:
      self.send_local_cmd(pubkey, local_cmd)
      status = True
    if len(remote_cmd) > 0:
      self.send_remote_cmd(secret, pubkey, remote_cmd)
      status = True
    return status

  def send_local_cmd(self, pubkey, lines):
    self.origin.censor.add_article((pubkey, '\n'.join(lines)), "httpd")

  @staticmethod
  def __remove_cmd__escape(line):
    return line.replace('\n', '').replace('\t', '').replace('\r', '')

  def send_remote_cmd(self, secret, pubkey, lines):
    author = 'Anonymous'
    email = 'an@onymo.us'
    sender = '%s <%s>' % (author, email)
    now = int(time.time())
    subject = 'no subject'
    newsgroups = 'ctl'
    uid_rnd = ''.join(random.choice(string.ascii_lowercase) for x in range(10))
    uid_message_id = '<%s%i@%s>' % (uid_rnd, now, self.origin.uid_host)
    now = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S +0000')

    article = self.origin.template_message_control_inner.format(sender, now, newsgroups, subject, uid_message_id, self.origin.uid_host, "\n".join(lines))
    #print "'%s'" % article
    hasher = sha512()
    old_line = None
    for line in article.split("\n")[:-1]:
      if old_line:
        hasher.update(old_line)
      old_line = '%s\r\n' % line
    hasher.update(old_line.replace("\r\n", ""))
    keypair = nacl.signing.SigningKey(unhexlify(secret))
    signature = hexlify(keypair.sign(hasher.digest()).signature)
    signed = self.origin.template_message_control_outer.format(sender, now, newsgroups, subject, uid_message_id, self.origin.uid_host, pubkey, signature, article)
    del keypair
    del signature
    del hasher
    f = open(os.path.join('incoming', 'tmp', uid_message_id), 'w')
    f.write(signed)
    f.close()
    del lines
    del article
    del signed
    os.rename(os.path.join('incoming', 'tmp', uid_message_id), os.path.join('incoming', uid_message_id))

  def log_request(self, *kwargs):
    return

  def log_message(self, format_, *args):
    return

  def send_something(self, something):
    try:
      self.send_response(200)
      self.send_header('Content-type', 'text/html')
      self.end_headers()
      self.wfile.write('<html><head><title>foobar</title></head><body style="font-family: arial,helvetica,sans-serif; font-size: 10pt;"><center><br />your message has been received.<br />%s</center></body></html>' % something)
    except socket.error as e:
      if e.errno == 32:
        self.origin.log(e, 2)
        # Broken pipe
      else:
        raise e

class censor_httpd(threading.Thread):

  def log(self, loglevel, message):
    if loglevel >= self.loglevel:
      self.logger.log(self.name, message, loglevel)

  def __init__(self, thread_name, logger, args):
    threading.Thread.__init__(self)
    self.name = thread_name
    self.logger = logger
    self._db_connector = args['db_connector']
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
    self.log(self.logger.DEBUG, 'initializing as plugin..')
    self.should_terminate = False
    for key in ('bind_ip', 'bind_port', 'template_directory', 'censor', 'uid_host'):
      if not key in args:
        self.log(self.logger.CRITICAL, '%s not in args' % key)
        self.should_terminate = True
    if self.should_terminate:
      self.log(self.logger.CRITICAL, 'terminating..')
      return
    self.uid_host = args['uid_host']
    self.ip = args['bind_ip']
    try:
      self.port = int(args['bind_port'])
    except ValueError as e:
      self.log(self.logger.CRITICAL, "'%s' is not a valid bind_port" % args['bind_port'])
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
        self.log(self.logger.CRITICAL, "'%s' is not a valid value for bind_use_ipv6. only true and false allowed." % args['bind_use_ipv6'])
        self.should_terminate = True
        self.log(self.logger.CRITICAL, 'terminating..')
        return
    #self.censor = args['censor']

    self.log(self.logger.INFO, 'using {}'.format(HTTPServer.__name__))
    self.httpd = HTTPServer((self.ip, self.port), censor)
    if 'reject_debug' in args:
      tmp = args['reject_debug']
      if tmp.lower() == 'true':
        self.httpd.reject_debug = True
      elif tmp.lower() == 'false':
        self.httpd.reject_debug = False
      else:
        self.log(self.logger.WARNING, "'%s' is not a valid value for reject_debug. only true and false allowed. setting value to false.")
    self.httpd.SRNd_info = args.get('srnd_info', None)
    self.httpd.SRNd_ctl = args['srnd'].internal_ctl if 'srnd' in args and self.httpd.SRNd_info is not None else None
    help_lang = args.get('help', 'en')
    self.httpd.log = self.log
    self.httpd.logger = self.logger
    self.httpd.rnd = open("/dev/urandom", "r")
    self.httpd.sessions = dict()
    self.httpd.uid_host = self.uid_host
    self.httpd.censor = args['censor']
    self.httpd.weekdays = ('Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday')
    self.httpd.runtime_salt = self.httpd.rnd.read(8)

    # read templates
    self.log(self.logger.DEBUG, 'reading templates..')
    template_directory = args['template_directory']
    f = open(os.path.join(template_directory, 'keys.tmpl'), 'r')
    self.httpd.template_keys = f.read()
    f.close()
    f = open(os.path.join(template_directory, 'send_remote.tmpl'), 'r')
    self.httpd.template_send_remote = f.read()
    f.close()
    f = open(os.path.join(template_directory, 'log_flagnames.tmpl'), 'r')
    self.httpd.template_log_flagnames = f.read()
    f.close()
    f = open(os.path.join(template_directory, 'log_flagset.tmpl'), 'r')
    self.httpd.template_log_flagset = f.read()
    f.close()
    f = open(os.path.join(template_directory, 'log_unknown.tmpl'), 'r')
    self.httpd.template_log_unknown = f.read()
    f.close()
    f = open(os.path.join(template_directory, 'log_whitelist.tmpl'), 'r')
    self.httpd.template_log_whitelist = f.read()
    f.close()
    f = open(os.path.join(template_directory, 'message_control_inner.tmpl'), 'r')
    self.httpd.template_message_control_inner = f.read()
    f.close()
    f = open(os.path.join(template_directory, 'message_control_outer.tmpl'), 'r')
    self.httpd.template_message_control_outer = f.read()
    f.close()
    f = open(os.path.join(template_directory, 'modify_key.tmpl'), 'r')
    self.httpd.template_modify_key = f.read()
    f.close()
    f = open(os.path.join(template_directory, 'modify_key_flagset.tmpl'), 'r')
    self.httpd.template_modify_key_flagset = f.read()
    f.close()
    f = open(os.path.join(template_directory, 'settings.tmpl'), 'r')
    self.httpd.t_engine_settings = string.Template(f.read())
    f.close()
    f = open(os.path.join(template_directory, 'settings_list.tmpl'), 'r')
    self.httpd.t_engine_settings_list = string.Template(f.read())
    f.close()
    f = open(os.path.join(template_directory, 'modify_board.tmpl'), 'r')
    self.httpd.t_engine_modify_board = string.Template(f.read())
    f.close()
    f = open(os.path.join(template_directory, 'stats.tmpl'), 'r')
    self.httpd.t_engine_stats = string.Template(f.read())
    f.close()
    f = open(os.path.join(template_directory, 'evil_mod.tmpl'), 'r')
    template_evil_mod = f.read()
    f.close()
    f = open(os.path.join(template_directory, 'log_row.tmpl'), 'r')
    template_log_row = f.read()
    f.close()
    f = open(os.path.join(template_directory, 'search_form.tmpl'), 'r')
    template_search_form = f.read()
    f.close()
    f = open(os.path.join(template_directory, 'message_log.tmpl'), 'r')
    self.httpd.t_engine_message_log = string.Template(
        string.Template(f.read()).safe_substitute(
            evil_mod=template_evil_mod,
            search_form=template_search_form
        )
    )
    f.close()
    f = open(os.path.join(template_directory, 'message_log_row.tmpl'), 'r')
    self.httpd.t_engine_message_log_row = string.Template(f.read())
    f.close()
    f = open(os.path.join(template_directory, 'postman.tmpl'), 'r')
    self.httpd.t_engine_postman = string.Template(f.read())
    f.close()
    f = open(os.path.join(template_directory, 'postman_row.tmpl'), 'r')
    self.httpd.t_engine_postman_row = string.Template(f.read())
    f.close()
    f = open(os.path.join(template_directory, 'modify_postman.tmpl'), 'r')
    self.httpd.t_engine_modify_postman = string.Template(f.read())
    f.close()
    f = open(os.path.join(template_directory, 'send_login.tmpl'), 'r')
    self.httpd.t_engine_send_login = string.Template(f.read())
    f.close()
    f = open(os.path.join(template_directory, 'log.tmpl'), 'r')
    self.httpd.t_engine_log = string.Template(f.read())
    f.close()
    f = open(os.path.join(template_directory, 'log_row_ignored.tmpl'), 'r')
    self.httpd.t_engine_log_ignored = string.Template(
        string.Template(template_log_row).safe_substitute(
            log_type=f.read().rstrip()
        )
    )
    f.close()
    f = open(os.path.join(template_directory, 'log_row_accepted.tmpl'), 'r')
    self.httpd.t_engine_log_accepted = string.Template(
        string.Template(template_log_row).safe_substitute(
            log_type=f.read().rstrip()
        )
    )
    f.close()
    f = open(os.path.join(template_directory, 'commands.tmpl'), 'r')
    self.httpd.t_engine_commands = string.Template(f.read())
    f.close()
    f = open(os.path.join(template_directory, 'commands_row.tmpl'), 'r')
    self.httpd.t_engine_commands_row = string.Template(f.read())
    f.close()
    f = open(os.path.join(template_directory, 'modify_commands.tmpl'), 'r')
    self.httpd.t_engine_modify_commands = string.Template(f.read())
    f.close()
    with open(os.path.join(template_directory, 'info.tmpl'), 'r') as f:
      self.httpd.t_engine_info = string.Template(f.read())
    with open(os.path.join(template_directory, 'info_feed_row.tmpl'), 'r') as f:
      self.httpd.t_engine_info_feed_row = string.Template(f.read())
    with open(os.path.join(template_directory, 'info_plugin_row.tmpl'), 'r') as f:
      self.httpd.t_engine_info_plugin_row = string.Template(f.read())
    with open(os.path.join(template_directory, 'info_feed_actions.tmpl'), 'r') as f:
      self.httpd.t_engine_info_feed_actions = string.Template(f.read())
    with open(os.path.join(template_directory, 'help.tmpl'), 'r') as f:
      self.httpd.t_engine_help = string.Template(f.read())

    self.httpd.help_data = self._load_help_data(os.path.join(template_directory, 'help'), help_lang)

  def _load_help_data(self, help_dir, lang):
    if lang.lower() in ('false', 'none', 'no', '0'):
      return {}
    if os.path.isfile(os.path.join(help_dir, lang)):
      pass
    elif os.path.isfile(os.path.join(help_dir, 'en')):
      self.log(self.logger.WARNING, 'Help file "{}" not found. Use default "{}"'.format(os.path.join(help_dir, lang), os.path.join(help_dir, 'en')))
      lang = 'en'
    else:
      self.log(self.logger.WARNING, 'help files not found. Help disabled')
      return {}
    with codecs.open(os.path.join(help_dir, lang), 'r', 'UTF-8') as f:
      try:
        help_data = json.load(f)
      except ValueError as e:
        self.log(self.logger.ERROR, 'Error loading "{}": {}. Help disabled'.format(os.path.join(help_dir, lang), e))
        return {}
    if not isinstance(help_data, dict):
      self.log(self.logger.ERROR, 'Strange "{}": loading data is not dict. Help disabled'.format(os.path.join(help_dir, lang)))
      return {}
    else:
      return self._formatting_help_data(help_data)

  @staticmethod
  def _formatting_help_data(data):
    # TODO: nesting, indentation?
    for data_row in [x for x in data]:
      if isinstance(data[data_row], list):
        data[data_row] = u'<br />'.join(data[data_row])
    return data

  def shutdown(self):
    self.httpd.shutdown()

  def add_article(self, message_id, source="article"):
    self.log(self.logger.WARNING, 'this plugin does not handle any article. remove hook parts from {0}'.format(os.path.join('config', 'plugins', self.name.split('-', 1)[1])))

  def run(self):
    if self.should_terminate:
      return
    self.httpd.sqlite_hasher = self._db_connector('hashes', timeout=60)
    self.httpd.sqlite_censor = self._db_connector('censor', timeout=60)
    self.httpd.sqlite_overchan = self._db_connector('overchan', timeout=60)
    self.httpd.postmandb = self._db_connector('postman', timeout=60)
    self.httpd.pastesdb = self._db_connector('pastes', timeout=60)

    self.log(self.logger.INFO, 'start listening at http://%s:%i' % (self.ip, self.port))
    self.httpd.serve_forever()
    self.httpd.sqlite_hasher.close()
    self.httpd.sqlite_censor.close()
    self.httpd.sqlite_overchan.close()
    self.httpd.postmandb.close()
    self.httpd.pastesdb.close()
    self.httpd.rnd.close()
    self.log(self.logger.INFO, 'bye')

if __name__ == '__main__':
  print "[%s] %s" % ("censor", "this plugin can't run as standalone version. yet.")
  exit(1)
