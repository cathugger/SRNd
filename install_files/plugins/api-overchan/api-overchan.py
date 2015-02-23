#!/usr/bin/python

import os
import sqlite3
import threading
import time
import json
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from urllib import unquote
from urlparse import urlparse, parse_qs

class OverchanAPI(BaseHTTPRequestHandler):
  def __init__(self, request, client_address, origin):
    self.origin = origin
    BaseHTTPRequestHandler.__init__(self, request, client_address, origin)

  def log_request(self, *code):
    return

  def log_message(self, formats):
    return

  def do_POST(self):
    return

  def do_GET(self):
    cmd, data = self.get_command()
    self.write_result(self.origin.api_worker(cmd, data))

  def get_command(self):
    path = unquote(self.path)
    data = parse_qs(urlparse(path).query)
    cmd = os.path.split(urlparse(path).path)[-1].encode('ascii', 'ignore')
    return cmd, {x: unicode(''.join(data[x]), 'utf-8') for x in data}

  def write_result(self, data):
    self.send_response(200)
    self.send_header('Content-type', 'application/json; charset=utf-8')
    self.end_headers()
    self.wfile.write(data.encode('UTF-8'))

class main(threading.Thread):

  def log(self, loglevel, message):
    if loglevel >= self.config.get('debug', 2):
      self.logger.log(self.name, message, loglevel)

  def __init__(self, thread_name, logger, args):
    threading.Thread.__init__(self)
    self.name = thread_name
    self.logger = logger
    self.serving = False
    self.sync_on_startup = False
    self.config = dict()
    self.config = self._init_config(args)
    if 'database_directory' not in self.config:
      self.log(self.logger.CRITICAL, 'database_directory not present in config, bye.')
      exit(1)
    self.httpd = HTTPServer((self.config['bind_ip'], self.config['bind_port']), OverchanAPI)
    self.httpd.log = self.log
    self.httpd.logger = self.logger
    self.httpd.api_worker = self.api_worker
    self.last_request = int(time.time())
    self.request_count = 0
    self.errors = {\
        1: 'request {cmd} not found. Use /info',
        2: 'too many requests. Stop It!',
        3: 'not implemented yet',
        4: 'required key {misskey} missing'}

  def run(self):
    if not self.config['running']:
      return
    self.overchandb_conn = sqlite3.connect(os.path.join(self.config['database_directory'], 'overchan.db3'), timeout=5)
    self.overchandb = self.overchandb_conn.cursor()
    self.cache = dict()
    self._cache_init()
    self.log(self.logger.INFO, 'start listening at http://{}:{}'.format(self.config['bind_ip'], self.config['bind_port']))
    self.log(self.logger.INFO, 'allowed API command: {}.'.format(', '.join([x for x in self.config['requests']])))
    self.serving = True
    self.httpd.serve_forever()
    self.overchandb_conn.close()
    self.log(self.logger.INFO, 'bye')

  def shutdown(self):
    if self.serving:
      self.httpd.shutdown()
      self.serving = False
    else:
      self.log(self.logger.INFO, 'bye')

  def _init_config(self, args, add_default=True):
    cfg_new = dict()
    cfg_def = {\
        'debug': self.logger.INFO,
        'allow_request': '*',
        'disallow_request': '',
        'request_limit': 15,
        'bind_ip': '127.0.0.1',
        'bind_port': 66666,
        'bind_use_ipv6': False,
        'ensure_ascii': True,
        'pretty': False,
        'running': True}
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

    cfg_new['requests'] = self._get_all_handles(cfg_new['allow_request'].split(';'), cfg_new['disallow_request'].split(';'))
    del cfg_new['allow_request'], cfg_new['disallow_request']
    return cfg_new

  def _get_all_handles(self, allows, disallows):
    request_handles = dict()
    for method in [xxx for xxx in dir(self) if xxx.startswith('_handle_')]:
      handle_name = method[8:]
      add_this = False
      # add allowed requests
      for allow in allows:
        if handle_name == allow or allow == '*' or (allow.endswith('*') and handle_name.startswith(allow[:-1])):
          add_this = True
          break
      # remove sisallowe requests
      for disallow in disallows:
        if handle_name == disallow or disallow == '*' or (disallow.endswith('*') and handle_name.startswith(disallow[:-1])):
          add_this = False
          break
      if add_this:
        request_handles[handle_name] = getattr(self, method)
    return request_handles

  def _cache_init(self):
    self.cache['flags'] = {row[0]: row[1] for row in self.overchandb.execute('SELECT flag_name, cast(flag as integer) FROM flags WHERE flag_name != ""').fetchall()}

  def api_worker(self, cmd, request_data):
    self.log(self.logger.DEBUG, 'got request: {}, data: {}'.format(cmd, str(request_data)))
    current_time = int(time.time())
    if current_time - 10 > self.last_request:
      self.last_request = current_time
      self.request_count = 0
    else:
      self.request_count += 1
    if self.request_count > self.config['request_limit']:
      return self.send_as_json(self.send_error(2))
    elif cmd in self.config['requests']:
      return self.send_as_json(self.config['requests'][cmd](request_data))
    else:
      return self.send_as_json(self.send_error(1, cmd=cmd))

  def send_as_json(self, data):
    if self.config['pretty']:
      return json.dumps(data, ensure_ascii=self.config['ensure_ascii'], indent=4, separators=(',', ': '))
    else:
      return json.dumps(data, ensure_ascii=self.config['ensure_ascii'])

  def send_error(self, code, **kwargs):
    if len(kwargs) > 0:
      return {'err': {'code': code, 'msg': self.errors.get(code, 'unknown error').format(**kwargs)}}
    else:
      return {'err': {'code': code, 'msg': self.errors.get(code, 'unknown error')}}

  def missing_request_data(self, request_data, *reqs):
    for req in reqs:
      if req not in request_data or request_data[req] == '':
        return self.send_error(4, misskey=req)
    return False

  def _handle_lastposts(self, request_data):
    """[WIP]return lastposts list. time - int unuxtime, send after this. limit - post limit, max 100 min 1. group - groupname, defaul not use exemple: get /lastpost?limit=10&group=ru.drugs"""
    return self.send_error(3)

  def _handle_boardlist(self, request_data):
    """return board list. No argument"""
    exclude_flags = self.cache['flags']['hidden'] | self.cache['flags']['blocked']
    data = [row[0] for row in self.overchandb.execute('SELECT group_name FROM groups WHERE (cast(flags as integer) & ?) = 0 ORDER by group_name ASC', (exclude_flags,)).fetchall()]
    return data

  def _handle_boardinfo(self, request_data):
    """group info. group - groupname"""
    miss = self.missing_request_data(request_data, 'group')
    if miss:
      return miss
    params = ('ph_name', 'ph_shortname', 'link', 'tag', 'description', 'flags', 'article_count', 'last_update')
    row = self.overchandb.execute('SELECT {} FROM groups WHERE group_name = ? LIMIT 1'.format(', '.join(params)), (request_data['group'],)).fetchone()
    return dict(zip(params, row)) if row else {}

  def _handle_post(self, request_data):
    """send post data. id - post id"""
    miss = self.missing_request_data(request_data, 'uid')
    if miss:
      return miss
    params = ('parent', 'sender', 'subject', 'sent', 'message', 'imagename', 'imagelink', 'thumblink', 'public_key', 'last_update', 'closed', 'sticky')
    row = self.overchandb.execute('SELECT {} FROM articles WHERE article_uid = ? LIMIT 1'.format(', '.join(params)), (request_data['uid'],)).fetchone()
    return dict(zip(params, row)) if row else {}

  def _handle_thread(self, request_data):
    """send root post and all child post. limit - child post limit, time - after time (only for child), uid - root post"""
    return self.__handle_thread(request_data, False)

  def _handle_childsthread(self, request_data):
    """see thread, return thread without root post"""
    return self.__handle_thread(request_data, True)

  def _handle_lastpostsroot(self, request_data):
    """[WIP]see lastposts, return only new or updated root post"""
    return self.send_error(3)

  def _handle_info(self, request_data):
    """this"""
    return {'requests': {x: self.config['requests'][x].__doc__ for x in self.config['requests']},
            'request_limit': self.config['request_limit']}

  def __handle_thread(self, request_data, only_childs):
    """ for childsthread and thread"""
    miss = self.missing_request_data(request_data, 'uid')
    if miss:
      return miss
    uid = request_data['uid']
    try:
      limits = int(request_data.get('limit', -1))
    except ValueError:
      limits = -1
    try:
      after_time = int(request_data.get('time', 0))
    except ValueError:
      after_time = 0
    params = ('article_uid', 'sender', 'subject', 'sent', 'message', 'imagename', 'imagelink', 'thumblink', 'public_key')
    childs = list()
    for row in self.overchandb.execute('SELECT * FROM (SELECT {} FROM articles WHERE parent = ? AND article_uid != parent AND sent > ? ORDER BY sent DESC LIMIT ?) ORDER BY sent ASC'.format(', '.join(params)), \
                                       (uid, after_time, limits)).fetchall():
      childs.append(dict(zip(params, row)))
    if only_childs:
      return childs
    else:
      return {'root': self._handle_post({'uid': uid}), 'childs': childs}
