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
    cmd, ver, data = self.get_command()
    self.write_result(self.origin.api_worker(cmd, ver, data))

  def get_command(self):
    path = unquote(self.path)
    data = parse_qs(urlparse(path).query)
    ver, cmd = os.path.split(urlparse(path).path)
    return cmd.encode('ascii', 'ignore'), os.path.split(ver)[-1].encode('ascii', 'ignore'), {x: unicode(''.join(data[x]), 'utf-8') for x in data}

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
    self.apis = dict()
    self.cache = dict()

  def run(self):
    if not self.config['running']:
      return
    self.overchandb_conn = sqlite3.connect(os.path.join(self.config['database_directory'], 'overchan.db3'), timeout=5)
    self.overchandb = self.overchandb_conn.cursor()
    self._cache_init()
    self.log(self.logger.INFO, 'start listening at http://{}:{}'.format(self.config['bind_ip'], self.config['bind_port']))
    self._api_init()
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

    return cfg_new

  def _cache_init(self):
    self.cache['flags'] = {row[0]: row[1] for row in self.overchandb.execute('SELECT flag_name, cast(flag as integer) FROM flags WHERE flag_name != ""').fetchall()}

  def _api_init(self):
    for api in [xxx for xxx in globals() if xxx.startswith('API_') and str(type(globals()[xxx])) == "<type 'type'>"]:
      api_ver = api[4:]
      self.apis[api_ver] = globals()[api]({'db_connector': self.overchandb, 'config': self.config, 'cache': self.cache, 'version': api_ver})
      self.log(self.logger.INFO, self.apis[api_ver].info())

  def api_worker(self, cmd, version, request_data):
    start_time = time.time()
    current_time = int(start_time)
    if current_time - 10 > self.last_request:
      self.last_request = current_time
      self.request_count = 0
    else:
      self.request_count += 1
    if version not in self.apis:
      version = '1'
    if self.request_count > self.config['request_limit']:
      data = self.apis[version].go()
    else:
      data = self.apis[version].go(cmd, request_data)
    self.log(self.logger.DEBUG, 'API {}: got request: {}, data: {}, exec time: {}'.format(version, cmd, str(request_data), (time.time() - start_time)))
    return data

class MainAPIHandler(object):
  def __init__(self, args):
    self.overchandb = args['db_connector']
    self.config = args['config']
    self.version = args['version']
    self.cache = args['cache']
    self.requests = self._get_all_handles(self.config['allow_request'].split(';'), self.config['disallow_request'].split(';'))
    self.errors = {\
        1: 'request {cmd} not found. Use /info',
        2: 'too many requests. Stop It!',
        3: 'not implemented yet',
        4: 'required key {misskey} missing',
        5: 'incorrect data in {key}'}
    for up_error in args.get('errors', {}):
      self.errors[up_error] = args['errors'][up_error]

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

  def go(self, cmd=None, request_data=None):
    if cmd is None:
      data = self.send_as_json(self.send_error(2))
    elif cmd in self.requests:
      data = self.send_as_json(self.requests[cmd](request_data))
    else:
      data = self.send_as_json(self.send_error(1, cmd=cmd))
    return data

  def info(self):
    return 'API {}: allowed API command: {}.'.format(self.version, ', '.join([x for x in self.requests]))

class API_1(MainAPIHandler):
  def __init__(self, args):
    MainAPIHandler.__init__(self, args)

  def _handle_lasts(self, request_data):
    """return last posts list. time - int unuxtime, sent after this. limit - post limit, max 100 min 1. group - groupname.exemple: get /lastpost?limit=10&group=ru.drugs"""
    limits, after_time, group = self._prepare_lasts(request_data)
    params = ['article_hash', 'sent']
    if group == 'all':
      params += ['group_name',]
      rows = self.overchandb.execute('SELECT {} FROM groups, articles WHERE sent > ? AND groups.group_id = articles.group_id ORDER BY sent DESC LIMIT ?'.format(', '.join(params)), (after_time, limits)).fetchall()
    else:
      rows = self.overchandb.execute('SELECT {} FROM groups, articles WHERE sent > ? AND group_name = ? AND groups.group_id = articles.group_id \
           ORDER BY sent DESC LIMIT ?'.format(', '.join(params)), (after_time, group, limits)).fetchall()
    return [dict(zip(params, row)) for row in rows]

  def _handle_lastsroot(self, request_data):
    """see lasts, return updated root posts"""
    limits, after_time, group = self._prepare_lasts(request_data)
    params = ['article_hash', 'articles.last_update']
    if group == 'all':
      params += ['group_name',]
    req = ', '.join(params)
    params[1] = 'last_update'
    if group == 'all':
      rows = self.overchandb.execute('SELECT {} FROM groups, articles WHERE articles.last_update > ? AND groups.group_id = articles.group_id \
           AND (articles.parent = "" OR articles.parent = articles.article_uid) ORDER BY articles.last_update DESC LIMIT ?'.format(req), (after_time, limits)).fetchall()
    else:
      rows = self.overchandb.execute('SELECT {} FROM groups, articles WHERE articles.last_update > ? AND group_name = ? AND groups.group_id = articles.group_id \
           AND (articles.parent = "" OR articles.parent = articles.article_uid) ORDER BY articles.last_update DESC LIMIT ?'.format(req), (after_time, group, limits)).fetchall()
    return [dict(zip(params, row)) for row in rows]

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
    """send post data. id - full post hash"""
    miss = self.missing_request_data(request_data, 'id')
    if miss:
      return miss
    params = ('article_uid', 'parent', 'sender', 'subject', 'sent', 'message', 'imagename', 'imagelink', 'thumblink', 'public_key', 'last_update', 'closed', 'sticky')
    row = self.overchandb.execute('SELECT {} FROM articles WHERE article_hash = ? LIMIT 1'.format(', '.join(params)), (request_data['id'],)).fetchone()
    return dict(zip(params, row)) if row else {}

  def _handle_thread(self, request_data):
    """send root post and all child post. limit - child post limit, time - after time (only for child), id - root post full hash"""
    return self._prepare_thread(request_data, False)

  def _handle_childs(self, request_data):
    """see thread, return thread without root post"""
    return self._prepare_thread(request_data, True)

  def _handle_fullhash(self, request_data):
    """ return full post hash from 10 chars short hash. id - short hash """
    miss = self.missing_request_data(request_data, 'id')
    if miss:
      return miss
    if len(request_data['id']) != 10:
      return self.send_error(5, key='id')
    fullhash = self.overchandb.execute('SELECT article_hash FROM articles WHERE article_hash >= ? and article_hash < ? LIMIT 1', (request_data['id'], request_data['id']+'h')).fetchone()
    return fullhash[0] if fullhash else ''

  def _handle_error(self, request_data):
    """ send error. code = error code"""
    try:
      code = int(request_data.get('code', -1))
    except ValueError:
      code = -1
    return self.send_error(code)

  def _handle_info(self, request_data):
    """this"""
    return {'requests': {x: self.requests[x].__doc__ for x in self.requests},
            'request_limit': self.config['request_limit'],
            'version': self.version}

  def _prepare_lasts(self, request_data):
    """ extractor for lasts and lastsroot """
    try:
      limits = int(request_data.get('limit', 100))
    except ValueError:
      limits = 100
    if limits < 1 or limits > 100:
      limits = 100
    try:
      after_time = int(request_data.get('time', 0))
    except ValueError:
      after_time = 0
    group = request_data.get('group', 'all')
    return limits, after_time, group

  def _prepare_thread(self, request_data, only_childs):
    """ for childs and thread """
    miss = self.missing_request_data(request_data, 'id')
    if miss:
      return miss
    hashid = request_data['id']
    try:
      limits = int(request_data.get('limit', -1))
    except ValueError:
      limits = -1
    try:
      after_time = int(request_data.get('time', 0))
    except ValueError:
      after_time = 0
    root_post = self._handle_post({'id': hashid})
    params = ('article_uid', 'sender', 'subject', 'sent', 'message', 'imagename', 'imagelink', 'thumblink', 'public_key')
    childs = list()
    if 'article_uid' in root_post:
      for row in self.overchandb.execute('SELECT * FROM (SELECT {} FROM articles WHERE parent = ? AND article_uid != parent AND sent > ? ORDER BY sent DESC LIMIT ?) ORDER BY sent ASC'.format(', '.join(params)), \
                                         (root_post['article_uid'], after_time, limits)).fetchall():
        childs.append(dict(zip(params, row)))
    if only_childs:
      return childs
    else:
      return {'root': root_post, 'childs': childs}
