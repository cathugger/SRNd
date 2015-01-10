#!/usr/bin/python

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
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from binascii import hexlify, unhexlify
from cgi import FieldStorage
from datetime import datetime
from hashlib import sha1, sha512
from urllib import unquote

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
        flags_available = int(self.origin.sqlite_censor.execute("SELECT flags FROM keys WHERE key=?", (self.origin.sessions[self.session][1],)).fetchone()[0])
        flag_required = int(self.origin.sqlite_censor.execute('SELECT flag FROM commands WHERE command="srnd-acl-mod"').fetchone()[0])
        if (flags_available & flag_required) != flag_required:
          self.send_redirect(self.root_path, "not authorized, flag srnd-acl-mod flag missing.<br />redirecting you in a moment.", 7)
          return
        if key == 'create':
          self.send_modify_key(key, create_key=True)
          return
        try:
          self.handle_update_key(key)
          self.send_redirect(self.root_path, "update ok<br />redirecting you in a moment.", 4)
        except Exception as e:
          self.send_redirect(self.root_path, "update failed: %s<br />redirecting you in a moment." % e, 9)
      elif path.startswith('/settings?'):
        key = path[10:]
        flags_available = int(self.origin.sqlite_censor.execute("SELECT flags FROM keys WHERE key=?", (self.origin.sessions[self.session][1],)).fetchone()[0])
        flag_required = int(self.origin.sqlite_censor.execute('SELECT flag FROM commands WHERE command="overchan-board-mod"').fetchone()[0])
        if (flags_available & flag_required) != flag_required:
          self.send_redirect(self.root_path + 'settings', "not authorized, flag overchan-board-mod missing.<br />redirecting you in a moment.", 7)
          return
        try:
          self.handle_update_board(key)
          self.send_redirect(self.root_path + 'settings', "update ok<br />redirecting you in a moment.", 4)
        except Exception as e:
          self.send_redirect(self.root_path + 'settings', "update board failed: %s<br />redirecting you in a moment." % e, 9)
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
      self.send_error("secret: %s\npublic: %s" % (hexlify(secret), hexlify(public)))
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
        self.send_modify_key(key)
      elif path.startswith('/pic_log'):
        page = 1
        if '?' in path:
          try: page = int(path.split('?')[-1])
          except: pass
          if page < 1: page = 1 
        self.send_piclog(page)
      elif path.startswith('/moderation_log'):
        page = 1
        if '?' in path:
          try: page = int(path.split('?')[-1])
          except: pass
          if page < 1: page = 1 
        self.send_log(page)
      elif path.startswith('/message_log'):
        self.send_messagelog()
      elif path.startswith('/stats'):
        self.send_stats()
      elif path.startswith('/settings'):
        if path.startswith('/settings?'):
          key = path[10:]
          self.send_settings(key)
        else:
          self.send_settings()
      elif path.startswith('/showmessage?'):
        self.send_message(path[13:])
      elif path.startswith('/delete?'):
        self.handle_delete(path[8:])
      elif path.startswith('/restore?'):
        self.handle_restore(path[9:])
      elif path.startswith('/notimplementedyet'):
        self.send_error('not implemented yet')
      else:
        self.send_keys()
      return
    self.origin.log(self.origin.logger.WARNING, "illegal access: %s" % self.path)
    self.send_response(200)
    self.send_header('Content-type', 'text/plain')
    self.end_headers()
    self.wfile.write('nope')

  def handle_update_key(self, key):
    post_vars = FieldStorage(
      fp=self.rfile,
      headers=self.headers,
      environ={
        'REQUEST_METHOD':'POST',
        'CONTENT_TYPE':self.headers['Content-Type'],
      }
    )
    flags = post_vars.getlist("flags")
    if 'local_nick' in post_vars:
      local_nick = post_vars['local_nick'].value.replace("<", "&lt;").replace(">", "&gt;").replace("#", "").strip()
    else:
      local_nick = ''
    result = sum([int(flag) for flag in flags])
    comment = '#'
    if int(self.origin.sqlite_censor.execute('SELECT count(id) FROM keys WHERE key = ?', (key,)).fetchone()[0]):
      old_nick, old_flags = self.origin.sqlite_censor.execute('SELECT local_name, flags FROM keys WHERE key = ?', (key,)).fetchone()
      if local_nick != old_nick:
        comment += '%s rename to %s' % (old_nick, local_nick)
      if int(old_flags) != result:
        comment += ' change flag %s->%s ' % (old_flags, result)
    else:
      comment += 'add new key %s, flags %s' % (local_nick, result)
    if comment == '#': comment = ''
    self.origin.censor.add_article((self.origin.sessions[self.session][1], "srnd-acl-mod %s %i %s%s" % (key, result, local_nick, comment)), "httpd")

  def handle_update_board(self, board_id):
    post_vars = FieldStorage(
      fp=self.rfile,
      headers=self.headers,
      environ={
        'REQUEST_METHOD':'POST',
        'CONTENT_TYPE':self.headers['Content-Type'],
      }
    )
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
      self.origin.censor.add_article((self.origin.sessions[self.session][1], "overchan-board-add {0} {1} {2}#request for create {0}, flags {1}".format(new_board, result, aliases_blob)), "httpd")
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
    self.origin.censor.add_article((self.origin.sessions[self.session][1], "overchan-board-mod {0} {1} {2}#{3}".format(board_name, result, aliases_blob, comment)), "httpd")

  def get_senderhash(self):
    if 'X-I2P-DestHash' in self.headers:
      return sha512(self.headers['X-I2P-DestHash'] + self.origin.runtime_salt).hexdigest()[:32]
    elif False:
      return sha512('TODO: add tor desthash or remove this' + self.origin.runtime_salt).hexdigest()[:32]
    return sha512(self.client_address[0] + self.origin.runtime_salt).hexdigest()[:32]

  def legal_session (self, session_id):
    if session_id in self.origin.sessions:
      if self.origin.sessions[session_id][2] != self.get_senderhash():
        self.origin.log(self.origin.logger.WARNING, 'Destanation change! Maybe sessionkey leak. ')
        self.origin.log(self.origin.logger.WARNING, self.headers)
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
    post_vars = FieldStorage(
      fp=self.rfile,
      headers=self.headers,
      environ={
        'REQUEST_METHOD':'POST',
        'CONTENT_TYPE':self.headers['Content-Type'],
      }
    )
    if not 'secret' in post_vars:
      self.origin.log(self.origin.logger.WARNING, 'admin panel login: no secret key received')
      self.origin.log(self.origin.logger.WARNING, self.headers)
      return False
    if len(post_vars['secret'].value) != 64:
      self.origin.log(self.origin.logger.WARNING, 'admin panel login: invalid secret key received, length != 64')
      self.origin.log(self.origin.logger.WARNING, self.headers)
      return False
    try:
      public = hexlify(nacl.signing.SigningKey(unhexlify(post_vars['secret'].value)).verify_key.encode())
      flags_available = int(self.origin.sqlite_censor.execute("SELECT flags FROM keys WHERE key=?", (public,)).fetchone()[0])
      flag_required = int(self.origin.sqlite_censor.execute('SELECT flag FROM commands WHERE command="srnd-acl-view"').fetchone()[0])
      if (flags_available & flag_required) == flag_required:
        return public
      else:
        return False
    except Exception as e:
      self.origin.log(self.origin.logger.WARNING, 'admin panel login: invalid secret key received: %s' % e)
      self.origin.log(self.origin.logger.WARNING, self.headers)
      return False

  def send_redirect(self, target, message, wait=0):
    self.send_response(200)
    self.send_header('Content-type', 'text/html')
    self.end_headers()
    self.wfile.write('<html><head><link type="text/css" href="/styles.css" rel="stylesheet"><META HTTP-EQUIV="Refresh" CONTENT="%i; URL=%s"></head><body class="mod"><center><br /><b>%s</b></center></body></html>' % (wait, target, message))
    return

  def send_login(self, message=""):
    self.send_response(200)
    self.send_header('Content-type', 'text/html')
    self.end_headers()
    self.wfile.write('<html><head><link type="text/css" href="/styles.css" rel="stylesheet"></head><body class="mod"><center>%s<br /><form action="/moderate?auth" enctype="multipart/form-data" method="POST"><label>your secret</label>&nbsp;<input type="text" name="secret" style="width: 400px;"/><input type="submit" /></form></html></html>' % message)

  def send_modify_key(self, key, create_key=False):    
    if create_key:
      post_vars = FieldStorage(
        fp=self.rfile,
        headers=self.headers,
        environ={
          'REQUEST_METHOD':'POST',
          'CONTENT_TYPE':self.headers['Content-Type'],
        }
      )
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
    flagset_template = self.origin.template_modify_key_flagset
    out = self.origin.template_modify_key.replace("%%key%%", row[0]).replace("%%nick%%", row[1])
    flaglist = list()
    counter = 0
    for flag in flags:
      counter += 1
      if (int(row[2]) & int(flag[1])) == int(flag[1]):
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
    out = out.replace("%%modify_key_flagset%%", "".join(flaglist))
    del flaglist[:]
    self.send_response(200)
    self.send_header('Content-type', 'text/html')
    self.end_headers()
    self.wfile.write(out)

  def send_modify_board(self, board_id):
    if board_id.startswith('id='):
      row = self.origin.sqlite_overchan.execute("SELECT group_id, group_name, flags, ph_name, ph_shortname, link, tag, description \
          FROM groups WHERE group_id = ?", (board_id[3:],)).fetchone()
    elif board_id.startswith('name='):
      row = self.origin.sqlite_overchan.execute("SELECT group_id, group_name, flags, ph_name, ph_shortname, link, tag, description \
        FROM groups WHERE group_name = ?", (board_id[5:],)).fetchone()
    elif board_id.startswith('new'):
      row = ('new', 'overchan.<input type="text" name="board_name" value="" class="posttext"/>', '0', '', '', '', '', '')
    else:
      return ''
    if not row:
      return 'Board not found'

    flags = self.origin.sqlite_overchan.execute("SELECT flag_name, flag FROM flags").fetchall()
    flagset_template = self.origin.template_modify_key_flagset
    form_data = dict()
    flaglist = list()
    counter = 0
    for flag in flags:
      counter += 1
      if (int(row[2]) & int(flag[1])) == int(flag[1]):
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
    form_data['board_id'] = str(row[0])
    form_data['board'] = row[1]
    form_data['modify_key_flagset'] = ''.join(flaglist)
    form_data['ph_name'] = row[3]
    form_data['ph_shortname'] = row[4]
    form_data['link'] = row[5]
    form_data['tag'] = row[6]
    form_data['description'] = row[7]
    del flaglist[:]
    return self.origin.t_engine_modify_board.substitute(form_data)

  def send_keys(self):
    out = self.origin.template_keys
    create_key = '<div style="float:right;"><form action="modify?create" enctype="multipart/form-data" method="POST"><input name="new_key" type="text" class="posttext"><input type="submit" class="postbutton" value="add key"></form></div>'
    out = out.replace("%%navigation%%", ''.join(self.__get_navigation('key_stats', add_after=create_key)))
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
    flagset_template = self.origin.template_log_flagset
    flaglist = list()
    #for row in self.origin.sqlite_censor.execute('SELECT key, local_name, flags, count(key_id) as counter FROM keys, log WHERE (flags != 0 OR local_name != "") AND keys.id = log.key_id GROUP BY key_id ORDER by counter DESC').fetchall():
    for row in self.origin.sqlite_censor.execute('SELECT key, local_name, flags FROM keys WHERE flags != 0 OR local_name != "" ORDER BY abs(flags) DESC, local_name ASC').fetchall():
      cur_template = self.origin.template_log_whitelist
      cur_template = cur_template.replace("%%key%%", row[0])
      cur_template = cur_template.replace("%%nick%%", self.hidden_line(row[1], 30))
      #table.append(self.origin.template_log_flagset)
      for flag in flags:
        if (int(row[2]) & int(flag[1])) == int(flag[1]):
          flaglist.append(flagset_template.replace("%%flag%%", '<b style="color: #00E000;">y</b>'))
        else:
          flaglist.append(flagset_template.replace("%%flag%%", "n"))
      cur_template = cur_template.replace("%%flagset%%", "\n".join(flaglist))
      del flaglist[:]
      #cur_template = cur_template.replace("%%count%%", str(row[3]))
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
    self.wfile.write(out)

  def hidden_line(self, line, max_len = 60):
    line = line.replace("<", "&lt;").replace(">", "&gt;").strip()
    if 16 < max_len < len(line):
      return '%s[..]%s' % (line[:6], line[-6:])
    else:
      return line

  def send_log(self, page=1, pagecount=100):
    out = self.origin.template_log
    pagination = '<div style="float:right;">'
    if page > 1:
      pagination += '<a href="moderation_log?%i">previous</a>' % (page-1)
    else:
      pagination += 'previous'
    pagination += '&nbsp;<a href="moderation_log?%i">next</a></div>' % (page+1)
    out = out.replace("%%navigation%%", ''.join(self.__get_navigation('moderation_log', add_after=pagination)))
    out = out.replace('%%pagination%%', pagination)
    table = list()    
    for row in self.origin.sqlite_censor.execute("SELECT key, local_name, command, data, reason, comment, timestamp FROM log, commands, keys, reasons WHERE log.accepted = 1 AND keys.id = log.key_id AND commands.id = log.command_id AND reasons.id = log.reason_id ORDER BY log.id DESC LIMIT ?, ?", ((page-1)*pagecount, pagecount)).fetchall():
      cur_template = self.origin.template_log_accepted
      if row[1] != '':
        cur_template = cur_template.replace("%%key_or_nick%%", self.hidden_line(row[1], 30))
      else:
        cur_template = cur_template.replace("%%key_or_nick%%", self.hidden_line(row[0]))
      cur_template = cur_template.replace("%%key%%", row[0])
      cur_template = cur_template.replace("%%action%%", row[2])
      cur_template = cur_template.replace("%%reason%%", row[4])
      cur_template = cur_template.replace("%%date%%", datetime.utcfromtimestamp(row[6]).strftime('%Y/%m/%d %H:%M'))
      comment_zip  = [self.hidden_line(x, 30)  for x in row[5].split(' ')]
      cur_template = cur_template.replace("%%comment%%", " ".join(comment_zip))
      del comment_zip[:]
      data = self.hidden_line(row[3], 64)
      if row[2] == 'srnd-acl-mod':
        cur_template = cur_template.replace("%%postid%%", data)
        cur_template = cur_template.replace("%%restore_link%%", '<a href="modify?%s">modify key</a>' % (row[3]))
        cur_template = cur_template.replace("%%delete_link%%", '')
      elif row[2] in ('overchan-board-mod', 'overchan-board-add', 'overchan-board-del'):
        cur_template = cur_template.replace("%%postid%%", data)
        cur_template = cur_template.replace("%%restore_link%%", '<a href="settings?name=%s">modify board</a>' % (row[3]))
        cur_template = cur_template.replace("%%delete_link%%", '')
      elif row[2] not in ('delete', 'overchan-delete-attachment', 'overchan-sticky', 'overchan-close'):
        cur_template = cur_template.replace("%%postid%%", data)
        cur_template = cur_template.replace("%%restore_link%%", '').replace("%%delete_link%%", '')
      else:
        message_id = row[3].replace("<", "&lt;").replace(">", "&gt;")
        try:
          if os.stat(os.path.join('articles', 'censored', row[3])).st_size > 0:
            cur_template = cur_template.replace("%%postid%%", '<a href="showmessage?%s" target="_blank">%s</a>' % (message_id, data))
            if row[2] in ('delete', 'overchan-delete-attachment'):
              cur_template = cur_template.replace("%%restore_link%%", '<a href="restore?%s">restore</a>&nbsp;' % message_id)
            else:
              cur_template = cur_template.replace("%%restore_link%%", '')
            cur_template = cur_template.replace("%%delete_link%%", '<a href="delete?%s">delete</a>&nbsp;' % message_id)
          else:
            cur_template = cur_template.replace("%%postid%%", data)
            cur_template = cur_template.replace("%%restore_link%%", '').replace("%%delete_link%%", '')
        except:
          cur_template = cur_template.replace("%%postid%%", data)
          cur_template = cur_template.replace("%%delete_link%%", '')
          if os.path.isfile(os.path.join('articles', row[3])):
            item_row = self.origin.sqlite_overchan.execute('SELECT parent FROM articles WHERE article_uid = ?', (row[3],)).fetchone()
            if item_row:
              if item_row[0] == '':
                cur_template = cur_template.replace("%%restore_link%%", '<a href="/thread-%s.html" target="_blank">view thread</a>&nbsp;' % sha1(row[3]).hexdigest()[:10])
              else:
                cur_template = cur_template.replace("%%restore_link%%", '<a href="/thread-%s.html#%s" target="_blank">view post</a>&nbsp;' % (sha1(item_row[0]).hexdigest()[:10], sha1(row[3]).hexdigest()[:10]))
            else:
              cur_template = cur_template.replace("%%restore_link%%", 'restored&nbsp;')
          else:
            cur_template = cur_template.replace("%%restore_link%%", '')
      table.append(cur_template)
    out = out.replace("%%mod_accepted%%", "\n".join(table))
    del table[:]
    for row in self.origin.sqlite_censor.execute("SELECT key, local_name, command, data, reason, comment, timestamp FROM log, commands, keys, reasons WHERE log.accepted = 0 AND keys.id = log.key_id AND commands.id = log.command_id AND reasons.id = log.reason_id ORDER BY log.id DESC LIMIT ?, ?", ((page-1)*pagecount, pagecount)).fetchall():
      cur_template = self.origin.template_log_ignored
      if row[1] != '':
        cur_template = cur_template.replace("%%key_or_nick%%", self.hidden_line(row[1], 30))
      else:
        cur_template = cur_template.replace("%%key_or_nick%%", self.hidden_line(row[0]))
      cur_template = cur_template.replace("%%key%%", row[0])
      cur_template = cur_template.replace("%%action%%", row[2])
      comment_zip  = [self.hidden_line(x, 30)  for x in row[5].split(' ')]
      cur_template = cur_template.replace("%%comment%%", " ".join(comment_zip))
      message_id = row[3].replace("<", "&lt;").replace(">", "&gt;")
      data = self.hidden_line(row[3], 64)
      try:
        if os.stat(os.path.join('articles', row[3])).st_size > 0:
          cur_template = cur_template.replace("%%postid%%", '<a href="showmessage?%s" target="_blank">%s</a>' % (message_id, data))
        else:
          cur_template = cur_template.replace("%%postid%%", data)
      except:
        cur_template = cur_template.replace("%%postid%%", message_id)
      cur_template = cur_template.replace("%%reason%%", row[4])
      cur_template = cur_template.replace("%%date%%", datetime.utcfromtimestamp(row[6]).strftime('%Y/%m/%d %H:%M'))
      table.append(cur_template)
    out = out.replace("%%mod_ignored%%", "\n".join(table))
    del table[:]

    self.send_response(200)
    self.send_header('Content-type', 'text/html')
    self.end_headers()
    self.wfile.write(out)
    
  def send_piclog(self, page=1, pagecount=30):
    #out = '<html><head><link type="text/css" href="/styles.css" rel="stylesheet"><style type="text/css">body { margin: 10px; margin-top: 20px; font-family: monospace; font-size: 9pt; } .navigation { background: #101010; padding-top: 19px; position: fixed; top: 0; width: 100%; }</style></head><body>%%navigation%%'
    out = '<html><head><title>piclog</title><link type="text/css" href="/styles.css" rel="stylesheet"></head>\n<body class="mod">\n%%navigation%%\n'
    pagination = '<div style="float:right;">'
    if page > 1:
      pagination += '<a href="pic_log?%i">previous</a>' % (page-1)
    else:
      pagination += 'previous'
    pagination += '&nbsp;<a href="pic_log?%i">next</a></div>' % (page+1)
    out = out.replace("%%navigation%%", ''.join(self.__get_navigation('pic_log', add_after=pagination)))
    table = list()
    table.append(out.replace("%%pagination%%", pagination))
    #self.wfile.write(out)
    for row in self.origin.sqlite_overchan.execute('SELECT * FROM (SELECT thumblink, parent, article_uid, last_update, sent FROM articles WHERE thumblink != "" AND thumblink != "invalid" AND thumblink != "document" ORDER BY last_update DESC) ORDER by sent DESC LIMIT ?, ?', ((page-1)*pagecount, pagecount)).fetchall():
      cur_template = '<a href="/%%target%%" target="_blank"><img src="%%thumblink%%" class="image" style="height: 200px;" /></a>'
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
    
  def send_messagelog(self, page=0):
    table = list()
    #out = u'<html><head><meta http-equiv="content-type" content="text/html; charset=utf-8"><link type="text/css" href="/styles.css" rel="stylesheet"><style type="text/css">table { font-size: 9pt;} td { vertical-align: top; } .dontwrap { white-space: nowrap; } body { margin: 10px; margin-top: 20px; font-family: monospace; font-size: 9pt; } .navigation { background: #101010; padding-top: 19px; position: fixed; top: 0; width: 100%; }</style></head><body>%%navigation%%%%content%%</body></html>'
    out = u'<html><head><meta http-equiv="content-type" content="text/html; charset=utf-8"><title>messagelog</title><link type="text/css" href="/styles.css" rel="stylesheet"></head><body class="mod">%%navigation%%%%content%%</body></html>'
    out = out.replace("%%navigation%%", ''.join(self.__get_navigation('message_log'))) 
    #for row in self.origin.sqlite_overchan.execute('SELECT article_uid, parent, sender, subject, message, parent, public_key, sent, group_name FROM articles, groups WHERE groups.group_id = articles.group_id ORDER BY articles.sent DESC LIMIT ?,50', (50*page,)).fetchall():
    for row in self.origin.sqlite_overchan.execute('SELECT article_uid, parent, sender, subject, message, parent, public_key, sent, group_name FROM articles, groups WHERE groups.group_id = articles.group_id ORDER BY articles.sent DESC LIMIT ?,100', (0,)).fetchall():
      if row[1] == '' or row[1] == row[0]:
        # parent
        link = "thread-%s.html" % sha1(row[0]).hexdigest()[:10]
      else:
        link = "thread-%s.html#%s" % (sha1(row[1]).hexdigest()[:10], sha1(row[0]).hexdigest()[:10])
      sender = row[2]
      subject = row[3]
      message = row[4]
      if len(sender) > 15:
        sender = sender[:15]+ ' [..]'
      if len(subject) > 45:
        subject = subject[:45] + ' [..]'
      if len(message) > 200:
        message = message[:200] + "\n[..]"
      subject = self.origin.breaker.sub(self.__breakit, subject)
      message = self.origin.breaker.sub(self.__breakit, message)
      table.append(u'<tr><td class="dontwrap">%s</td><td class="dontwrap">%s</td><td>%s</td><td><a href="/%s" target="_blank">%s</a></td><td class="message_span">%s</td></tr>' % (datetime.utcfromtimestamp(row[7]).strftime('%Y/%m/%d %H:%M'), row[8], sender, link, subject, message))
    out = out.replace("%%content%%", '<table class="datatable"><tr><th>sent</th><th>board</th><th>sender</th><th>subject</th><th>message</th></tr>\n' + '\n'.join(table))
    self.send_response(200)
    self.send_header('Content-type', 'text/html')
    self.end_headers()
    self.wfile.write(out.encode('UTF-8'))

  def send_stats(self, page=0):
    stats_data = dict()
    t_2_rows = '<tr><td class="right">%s</td><td>%s</td></tr>'
    t_3_rows = '<tr><td>%s</td><td class="right">%s</td><td>%s</td></tr>'
    t_4_rows = '<tr><td>%s</td><td class="right">%s</td><td>%s</td><td>%s</td></tr>'

    stats_data['navigation']             = ''.join(self.__get_navigation('stats'))
    stats_data['stats_usage']            = ''.join( t_3_rows % x for x in self.__stats_usage(31, 30)    )
    stats_data['stats_fronteds']         = ''.join( t_2_rows % x for x in self.__stats_frontends()      )
    stats_data['stats_groups']           = ''.join( t_2_rows % x for x in self.__stats_groups()         )
    stats_data['stats_usage_month']      = ''.join( t_3_rows % x for x in self.__stats_usage_month(30)  )
    stats_data['stats_usage_weekday_28'] = ''.join( t_3_rows % x for x in self.__stats_usage_weekday(28))
    stats_data['stats_usage_weekday']    = ''.join( t_3_rows % x for x in self.__stats_usage_weekday()  )

    self.send_response(200)
    self.send_header('Content-type', 'text/html')
    self.end_headers()
    self.wfile.write(self.origin.t_engine_stats.substitute(stats_data))

  def send_message(self, message_id):
    self.send_response(200)
    self.send_header('Content-type', 'text/html')
    self.end_headers()
    #out = '<html><head><link type="text/css" href="/styles.css" rel="stylesheet"><style type="text/css">body { margin: 10px; margin-top: 20px; font-family: monospace; font-size: 9pt; } .navigation { background: #101010; padding-top: 19px; position: fixed; top: 0; width: 100%; }</style></head><body>%%navigation%%<pre>'
    out = '<html><head><title>view message</title><link type="text/css" href="/styles.css" rel="stylesheet"></head><body class="mod">%%navigation%%<pre>'
    out = out.replace("%%navigation%%", ''.join(self.__get_navigation('')))
    self.wfile.write(out.encode('UTF-8'))

    if os.path.isfile(os.path.join('articles', 'censored', message_id)):
      f = codecs.open(os.path.join('articles', 'censored', message_id), 'r', 'UTF-8')
      self.__write_nntp_article(f)
    elif os.path.isfile(os.path.join('articles', message_id)):
      f = codecs.open(os.path.join('articles', message_id), 'r', 'UTF-8')
      self.__write_nntp_article(f)
    else:
      self.wfile.write('message_id \'%s\' not found' % message_id.replace('<', '&lt;').replace('>', '&gt;'))
    self.wfile.write('</pre></body></html>')

  def send_settings(self, board_id =''):
    out = self.origin.template_settings
    out = out.replace("%%navigation%%", ''.join(self.__get_navigation('settings')))
    table = list()
    flags = self.origin.sqlite_overchan.execute("SELECT flag_name, flag FROM flags").fetchall()
    cur_template = self.origin.template_log_flagnames
    for flag in flags:
      table.append(cur_template.replace("%%flag%%", flag[0]))
    out = out.replace("%%flag_names%%", "\n".join(table))
    del table[:]
    flagset_template = self.origin.template_log_flagset
    flaglist = list()
    for row in self.origin.sqlite_overchan.execute('SELECT group_name, article_count, group_id, flags FROM groups WHERE group_name != "" ORDER BY abs(article_count) DESC, group_name ASC').fetchall():
      cur_template = self.origin.template_settings_lst
      cur_template = cur_template.replace("%%board%%",    str(row[0]))
      cur_template = cur_template.replace("%%posts%%",    str(row[1]))
      cur_template = cur_template.replace("%%board_id%%", str(row[2]))
      for flag in flags:
        if (int(row[3]) & int(flag[1])) == int(flag[1]):
          flaglist.append(flagset_template.replace("%%flag%%", '<b style="color: #00E000;">y</b>'))
        else:
          flaglist.append(flagset_template.replace("%%flag%%", "n"))
      cur_template = cur_template.replace("%%flagset%%", "\n".join(flaglist))
      del flaglist[:]
      table.append(cur_template)
    out = out.replace("%%board_list%%", "\n".join(table))
    del table[:]
    if board_id:
      out = out.replace("%%post_form%%", self.send_modify_board(board_id))
    else:
      out = out.replace("%%post_form%%", "")
    self.send_response(200)
    self.send_header('Content-type', 'text/html')
    self.end_headers()
    self.wfile.write(out.encode('UTF-8'))
    
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

  def send_error(self, errormessage):
    self.send_response(200)
    self.send_header('Content-type', 'text/plain')
    self.end_headers()
    self.wfile.write(errormessage)

  def __write_nntp_article(self, f):
    attachment = re.compile('^[cC]ontent-[tT]ype: ([a-zA-Z0-9/]+).*name="([^"]+)')
    attachment_details = None
    base64 = False
    writing_base64 = False
    for line in f:
      if line.lower().startswith('content-type:'):
        attachment_details = attachment.match(line)
      elif line.lower().startswith('content-transfer-encoding: base64'):
        base64 = True
      if len(line) == 1:
        if base64 == True and attachment_details != None:
          self.wfile.write('\n<img src="data:%s;base64,' % attachment_details.group(1))
          writing_base64 = True
        else:
          self.wfile.write(line)
      elif writing_base64 and line.startswith('--'):
        self.wfile.write('" title="%s" width="100%%" />\n' % attachment_details.group(2).replace('<', '&lt;').replace('>', '&gt;').encode('UTF-8'))
        writing_base64 = False
        base64 = False
      elif writing_base64:
        self.wfile.write(line.encode('UTF-8'))
      else:
        self.wfile.write(line.replace('<', '&lt;').replace('>', '&gt;').encode('UTF-8'))
    f.close()
    if writing_base64:
      self.wfile.write('" title="%s" />\n' % attachment_details.group(2).replace('<', '&lt;').replace('>', '&gt;'))

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

  def __stats_groups(self, ids=False, status=False):
    groups = list()
    for row in self.origin.sqlite_overchan.execute('SELECT count(1) as counter, group_name, groups.group_id, flags FROM articles, groups WHERE articles.group_id = groups.group_id GROUP BY articles.group_id ORDER BY counter DESC').fetchall():
      if ids and status:
        groups.append((row[0], row[1], row[2], row[3]))
      elif ids:
        groups.append((row[0], row[1], row[2]))
      elif status:
        groups.append((row[0], row[1], row[3]))
      else:
        groups.append((row[0], row[1].replace(',', ',<br />')))
    return groups

  def __stats_usage_by_frontend(self, days=7, bar_length=29):    
    stats = list()
    totals = int(self.origin.sqlite_overchan.execute('SELECT count(1) FROM articles WHERE sent > strftime("%s", "now", "-' + str(days) + ' days")').fetchone()[0])
    stats.append(('all posts', totals, '&nbsp;', 'in previous %s days' % days))
    max = 0
    for row in self.origin.sqlite_overchan.execute('SELECT count(1) as counter, strftime("%Y-%m-%d",  sent, "unixepoch") as day, strftime("%w", sent, "unixepoch") as weekday, rtrim(substr(article_uid, instr(article_uid, "@") + 1), ">") as host FROM articles WHERE sent > strftime("%s", "now", "-' + str(days) + ' days") GROUP BY day, host ORDER BY day DESC').fetchall():
      if row[0] > max: max = row[0]
      stats.append((row[0], row[1], self.origin.weekdays[int(row[2])], row[3]))
    for index in range(1, len(stats)):
      graph = ''
      for x in range(0, int(float(stats[index][0])/max*bar_length)):
        graph += '='
      if len(graph) == 0:
        graph = '&nbsp;'
      stats[index] = ('<span title="%s">%s</span>' % (stats[index][2], stats[index][1]), stats[index][0], stats[index][3], graph)
    return stats

  def __stats_usage(self, days=30, bar_length=29):
    stats = list()
    totals = int(self.origin.sqlite_overchan.execute('SELECT count(1) FROM articles WHERE sent > strftime("%s", "now", "-31 days")').fetchone()[0])
    stats.append(('all posts', totals, 'in previous %s days' % 31))
    max = 0
    for row in self.origin.sqlite_overchan.execute('SELECT count(1) as counter, strftime("%Y-%m-%d",  sent, "unixepoch") as day, strftime("%w", sent, "unixepoch") as weekday FROM articles WHERE sent > strftime("%s", "now", "-31 days") GROUP BY day ORDER BY day DESC').fetchall():
      if row[0] > max: max = row[0]
      stats.append((row[0], row[1], self.origin.weekdays[int(row[2])]))
    for index in range(1, len(stats)):
      graph = ''
      for x in range(0, int(float(stats[index][0])/max*bar_length)):
        graph += '='
      if len(graph) == 0:
        graph = '&nbsp;'
      stats[index] = ('<span title="%s">%s</span>' % (stats[index][2], stats[index][1]), stats[index][0], graph)
    return stats

  def __stats_usage_month(self, bar_length=29):
    stats = list()
    totals = int(self.origin.sqlite_overchan.execute('SELECT count(1) FROM articles').fetchone()[0])
    stats.append(('all posts', totals, 'since beginning'))
    max = 0
    for row in self.origin.sqlite_overchan.execute('SELECT count(1) as counter, strftime("%Y-%m",  sent, "unixepoch") as month FROM articles GROUP BY month ORDER BY month DESC').fetchall():
      if row[0] > max: max = row[0]
      stats.append((row[0], row[1]))
    for index in range(1, len(stats)):
      graph = ''
      for x in range(0, int(float(stats[index][0])/max*bar_length)):
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
    stats = list()
    max = 0 
    for row in result:
      if days:
        avg = float(row[0]) / (days / 7)
        if avg > max: max = avg
        stats.append((avg, self.origin.weekdays[int(row[1])]))
      else:
        if row[0] > max: max = row[0]
        stats.append((row[0], self.origin.weekdays[int(row[1])]))
    for index in range(0, len(stats)):
      graph = ''
      for x in range(0, int(float(stats[index][0])/max*bar_length + 0.5)):
        graph += '='
      if len(graph) == 0:
        graph = '&nbsp;'
      if days:
        stats[index] = (stats[index][1], "%.2f" % stats[index][0], graph)
      else:
        stats[index] = (stats[index][1], stats[index][0], graph)
    stats.append(stats[0])
    return stats[1:]

  def __get_navigation(self, current, add_after=None):
    out = list()
    #out.append('<div class="navigation">')
    for item in (('key_stats', 'key stats'), ('moderation_log', 'moderation log'), ('pic_log', 'pic log'), ('message_log', 'message log'),('stats', 'stats'), ('settings', 'settings')):
      if item[0] == current:
        out.append(item[1] + '&nbsp;')
      else:
        out.append('<a href="%s">%s</a>&nbsp;' % item)
    if add_after != None:
      out.append(add_after)
    #out.append('<br /><br /></div><br /><br />')
    out.append('<br /><br />')
    return out

  def die(self, message=''):
    self.origin.log(self.origin.logger.WARNING, "%s:%i wants to fuck around, %s" % (self.client_address[0], self.client_address[1], message))
    self.origin.log(self.origin.logger.WARNING, self.headers)
    if self.origin.reject_debug:
      self.send_error('don\'t fuck around here mkay\n%s' % message)
    else:
      self.send_error('don\'t fuck around here mkay')

  def __get_message_id_by_hash(self, hash):
    return self.origin.sqlite_hasher.execute("SELECT message_id FROM article_hashes WHERE message_id_hash = ?", (hash,)).fetchone()[0]

  def __get_dest_hash_by_hash(self, hash):
    return self.origin.sqlite_hasher.execute("SELECT sender_desthash FROM article_hashes WHERE message_id_hash = ?", (hash,)).fetchone()[0]

  def __get_messages_id_by_dest_hash(self, dest_hash):
    return self.origin.sqlite_hasher.execute("SELECT message_id FROM article_hashes WHERE sender_desthash = ?", (dest_hash,)).fetchall()

  def __breakit(self, rematch):
    return '%s ' % rematch.group(0)

  def handle_moderation_request(self):
    author = 'Anonymous'
    email = 'an@onymo.us'
    sender = '%s <%s>' % (author, email)
    now = int(time.time())
    subject = 'no subject'
    newsgroups = 'ctl'
    uid_rnd = ''.join(random.choice(string.ascii_lowercase) for x in range(10))
    uid_message_id = '<%s%i@%s>' % (uid_rnd, now, self.origin.uid_host)
    now = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S +0000')
    lines = list()
    
    post_vars = FieldStorage(
      fp=self.rfile,
      headers=self.headers,
      environ={
        'REQUEST_METHOD':'POST',
        'CONTENT_TYPE':self.headers['Content-Type'],
      }
    )

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
    if flags_available == 0:
      self.die('local moderation request: public key rejected, no flags required')
      return
    local_cmd = False
    for key in ('purge', 'purge_root'):
      if key in post_vars:
        purges = post_vars.getlist(key)
        for item in purges:
          try:
            lines.append("delete %s" % self.__get_message_id_by_hash(item))
          except Exception as e:
            self.origin.log(self.origin.logger.WARNING, "local moderation request: could not find message_id for hash %s: %s" % (item, e))
            self.origin.log(self.origin.logger.WARNING, self.headers)
    if 'purge_desthash' in post_vars:
      delete_by_desthash = post_vars.getlist('purge_desthash')
      for item in delete_by_desthash:
        try:
          i2p_dest_hash = self.__get_dest_hash_by_hash(item)
        except Exception as e:
          self.origin.log(self.origin.logger.WARNING, "local moderation request: could not find X-I2P-DestHash for hash %s: %s" % (item, e))
          self.origin.log(self.origin.logger.WARNING, self.headers)
        else:
          if len(i2p_dest_hash) == 44:
            lines.extend("delete %s" % message_id for message_id in self.__get_messages_id_by_dest_hash(i2p_dest_hash))
    if 'delete_a' in post_vars:
      delete_attachments = post_vars.getlist('delete_a')
      for item in delete_attachments:
        try:
          lines.append("overchan-delete-attachment %s" % self.__get_message_id_by_hash(item))
        except Exception as e:
          self.origin.log(self.origin.logger.WARNING, "local moderation request: could not find message_id for hash %s: %s" % (item, e))
          self.origin.log(self.origin.logger.WARNING, self.headers)
    if 'sticky' in post_vars:
      sticky_thread = post_vars.getlist('sticky')
      for item in sticky_thread:
        try:
          #lines.append("overchan-sticky %s" % self.__get_message_id_by_hash(item)) #only local
          self.origin.censor.add_article((pubkey, "overchan-sticky {0}#sticky\unsticky thread request".format(self.__get_message_id_by_hash(item))), "httpd")
          local_cmd = True
        except Exception as e:
          self.origin.log(self.origin.logger.WARNING, "local moderation request: could not find message_id for hash %s: %s" % (item, e))
          self.origin.log(self.origin.logger.WARNING, self.headers)
    if 'close' in post_vars:
      close_thread = post_vars.getlist('close')
      for item in close_thread:
        try:
          self.origin.censor.add_article((pubkey, "overchan-close {0}#closing\opening thread request".format(self.__get_message_id_by_hash(item))), "httpd")
          local_cmd = True
        except Exception as e:
          self.origin.log(self.origin.logger.WARNING, "local moderation request: could not find message_id for hash %s: %s" % (item, e))
          self.origin.log(self.origin.logger.WARNING, self.headers)
    if len(lines) == 0:
      if local_cmd:
        self.send_redirect(target, 'moderation request received. will redirect you in a moment.', 2)
      else:
        self.die('local moderation request: nothing to do')
      return
    #remove duplicates
    lines = list(set(lines))
    #lines.append("")
    article = self.origin.template_message_control_inner.format(sender, now, newsgroups, subject, uid_message_id, self.origin.uid_host, "\n".join(lines))
    #print "'%s'" % article
    hasher = sha512()
    old_line = None
    for line in article.split("\n")[:-1]:
      if old_line:
        hasher.update(old_line)
      old_line = '%s\r\n' % line
    hasher.update(old_line.replace("\r\n", ""))
    #keypair = nacl.signing.SigningKey(unhexlify(secret))
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
    self.send_redirect(target, 'moderation request received. will redirect you in a moment.', 2)

  def log_request(self, code):
    return

  def log_message(self, format):
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
        pass
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

    self.log(self.logger.DEBUG, 'initializing httpserver..')
    self.httpd = HTTPServer((self.ip, self.port), censor)
    if 'reject_debug' in args:
      tmp = args['reject_debug']
      if tmp.lower() == 'true':
        self.httpd.reject_debug = True
      elif tmp.lower() == 'false':
        self.httpd.reject_debug = False
      else:
        self.log(self.logger.WARNING, "'%s' is not a valid value for reject_debug. only true and false allowed. setting value to false.")
    self.httpd.log = self.log
    self.httpd.logger = self.logger
    self.httpd.rnd = open("/dev/urandom", "r")
    self.httpd.sessions = dict()
    self.httpd.uid_host = self.uid_host
    self.httpd.censor = args['censor']
    self.httpd.weekdays =  ('Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday')
    self.httpd.breaker = re.compile('([^ ]{16})')
    self.httpd.runtime_salt = self.httpd.rnd.read(8)

    # read templates
    self.log(self.logger.DEBUG, 'reading templates..')
    template_directory = args['template_directory']
    f = open(os.path.join(template_directory, 'keys.tmpl'), 'r')
    self.httpd.template_keys = f.read()
    f.close()
    f = open(os.path.join(template_directory, 'log.tmpl'), 'r')
    self.httpd.template_log = f.read()
    f.close()
    f = open(os.path.join(template_directory, 'log_accepted.tmpl'), 'r')
    self.httpd.template_log_accepted = f.read()
    f.close()
    f = open(os.path.join(template_directory, 'log_flagnames.tmpl'), 'r')
    self.httpd.template_log_flagnames = f.read()
    f.close()
    f = open(os.path.join(template_directory, 'log_flagset.tmpl'), 'r')
    self.httpd.template_log_flagset = f.read()
    f.close()
    f = open(os.path.join(template_directory, 'log_ignored.tmpl'), 'r')
    self.httpd.template_log_ignored = f.read()
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
    self.httpd.template_settings = f.read()
    f.close()
    f = open(os.path.join(template_directory, 'settings_list.tmpl'), 'r')
    self.httpd.template_settings_lst = f.read()
    f.close()
    f = open(os.path.join(template_directory, 'modify_board.tmpl'), 'r')
    self.httpd.t_engine_modify_board  = string.Template(f.read())
    f.close()
    f = open(os.path.join(template_directory, 'stats.tmpl'), 'r')
    self.httpd.t_engine_stats = string.Template(f.read())
    f.close()
    #f = open(os.path.join(template_directory, 'message_pic.template'), 'r')
    #self.httpd.template_message_pic = f.read()
    #f.close()
    #f = open(os.path.join(template_directory, 'message_signed.template'), 'r')
    #self.httpd.template_message_signed = f.read()
    #f.close()

  def shutdown(self):
    self.httpd.shutdown()

  def add_article(self, message_id, source="article"):
    self.log(self.logger.WARNING, 'this plugin does not handle any article. remove hook parts from {0}'.format(os.path.join('config', 'plugins', self.name.split('-', 1)[1])))

  def run(self):
    if self.should_terminate:
      return
    # connect to hasher database
    # FIXME: add database_directory to postman?
    self.database_directory = ''
    self.httpd.sqlite_hasher_conn = sqlite3.connect('hashes.db3', timeout=15)
    self.httpd.sqlite_hasher = self.httpd.sqlite_hasher_conn.cursor()
    self.httpd.sqlite_censor_conn = sqlite3.connect('censor.db3', timeout=15)
    self.httpd.sqlite_censor = self.httpd.sqlite_censor_conn.cursor()
    # FIXME get overchan db path via arg
    self.httpd.sqlite_overchan_conn = sqlite3.connect('plugins/overchan/overchan.db3', timeout=15)
    self.httpd.sqlite_overchan = self.httpd.sqlite_overchan_conn.cursor()
    self.log(self.logger.INFO, 'start listening at http://%s:%i' % (self.ip, self.port))
    self.httpd.serve_forever()
    self.httpd.sqlite_hasher_conn.close()
    self.httpd.sqlite_censor_conn.close()
    self.httpd.sqlite_overchan_conn.close()
    self.httpd.rnd.close()
    self.log(self.logger.INFO, 'bye')

if __name__ == '__main__':
  print "[%s] %s" % ("censor", "this plugin can't run as standalone version. yet.")
  exit(1)
