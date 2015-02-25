#!/usr/bin/python

import os
import sqlite3
import threading
import time
import json
import random
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
    self.config = self._init_config(args)
    if 'database_directory' not in self.config:
      self.log(self.logger.CRITICAL, 'database_directory not present in config.')
      self.config['running'] = False

  def run(self):
    if not self.config['running']:
      self.log(self.logger.INFO, 'running is False.')
      return
    self.overchandb_conn = sqlite3.connect(os.path.join(self.config['database_directory'], 'overchan.db3'), timeout=5)
    self.overchandb = self.overchandb_conn.cursor()
    self._cache_init()
    self._api_init()
    self._start_serving()
    self.overchandb_conn.close()
    self.log(self.logger.INFO, 'bye')

  def _start_serving(self):
    self.httpd = HTTPServer((self.config['bind_ip'], self.config['bind_port']), OverchanAPI)
    self.httpd.log = self.log
    self.httpd.logger = self.logger
    self.httpd.api_worker = self.api_worker
    self.serving = True
    self.log(self.logger.INFO, 'start listening at http://{}:{}'.format(self.config['bind_ip'], self.config['bind_port']))
    self.httpd.serve_forever()
    self.serving = False

  def shutdown(self):
    if self.serving:
      self.httpd.shutdown()
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
        'running': True,
        'cache_reply': False,
        'cache_life': 5,
        'cache_max': 10,
        'cache_allow': '*'}
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
    self.cache = dict()
    self.cache['flags'] = {row[0]: row[1] for row in self.overchandb.execute('SELECT flag_name, cast(flag as integer) FROM flags WHERE flag_name != ""').fetchall()}

  def _api_init(self):
    self.apis = dict()
    for api in [xxx for xxx in globals() if xxx.startswith('API_') and str(type(globals()[xxx])) == "<type 'type'>"]:
      api_ver = api[4:]
      self.apis[api_ver] = globals()[api]({'db_connector': self.overchandb, 'config': self.config, 'cache': self.cache, 'version': api_ver})
      self.log(self.logger.INFO, self.apis[api_ver].info())

  def api_worker(self, cmd, version, request_data):
    start_time = time.time()
    if version not in self.apis:
      version = '1'
    data = self.apis[version].go(cmd, request_data)
    self.log(self.logger.DEBUG, 'API {}: got request: {}, data: {}, exec time: {}, cached: {}'.format(version, cmd, str(request_data), (time.time() - start_time), data[0]))
    return data[1]

class MainAPIHandler(object):
  def __init__(self, args):
    self.last_request = int(time.time())
    self.request_count = 0
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
    self.cmd_cache = self._init_cmd_cache(self.config['cache_allow'].split(';'))

  def _init_cmd_cache(self, cmd_list):
    cmd_cache = dict()
    if self.config['cache_reply']:
      for cmd in self.requests:
        for allow in cmd_list:
          if cmd == allow or allow == '*' or (allow.endswith('*') and cmd.startswith(allow[:-1])):
            cmd_cache[cmd] = dict()
            break
    return cmd_cache

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
        # add missing attr
        for add_attr in ('keys', 'requ'):
          if add_attr not in request_handles[handle_name].__dict__:
            request_handles[handle_name].__dict__[add_attr] = None
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

  def _missing_request_key(self, cmd, requ):
    if self.requests[cmd].requ is None:
      return False
    for req in self.requests[cmd].requ:
      if req not in requ:
        return self.send_error(4, misskey=req)
    return False

  def _request_counter(self, curent_time):
    if curent_time - 10 > self.last_request:
      self.last_request = curent_time
      self.request_count = 0
    else:
      self.request_count += 1

  def _cleaned_keys(self, cmd, request_data):
    if self.requests[cmd].keys is None:
      return request_data
    requ = dict()
    for c_key in self.requests[cmd].keys:
      if c_key in request_data:
        if self.requests[cmd].keys[c_key] is None:
          requ[c_key] = request_data[c_key]
        elif type(self.requests[cmd].keys[c_key]) is bool:
          requ[c_key] = False if request_data[c_key].lower() in ('false', 'no', '0', 'disable') else True
        else:
          try:
            requ[c_key] = type(self.requests[cmd].keys[c_key])(request_data[c_key])
          except ValueError:
            requ[c_key] = self.requests[cmd].keys[c_key]
    return requ

  def go(self, cmd, request_data):
    if cmd not in self.requests:
      return False, self.send_as_json(self.send_error(1, cmd=cmd))

    curent_time = int(time.time())
    requ = self._cleaned_keys(cmd, request_data)
    misskey = self._missing_request_key(cmd, requ)
    if misskey:
      return False, self.send_as_json(misskey)
    if self.request_count > self.config['request_limit']:
      data = (False, self.send_as_json(self.send_error(2)))
    elif cmd in self.cmd_cache:
      data = self._get_from_cache(cmd, requ, curent_time)
    else:
      self._request_counter(curent_time)
      data = (False, self.send_as_json(self.requests[cmd](requ)))
    return data

  def _get_from_cache(self, cmd, request_data, curent_time):
    hashkey = hash(str(request_data))
    if hashkey in self.cmd_cache[cmd] and self.cmd_cache[cmd][hashkey][0] + self.config['cache_life'] > curent_time:
      return True, self.cmd_cache[cmd][hashkey][1]
    if len(self.cmd_cache[cmd]) >= self.config['cache_max']:
      self._clearnup_cache(cmd, curent_time)
    self._request_counter(curent_time)
    self.cmd_cache[cmd][hashkey] = (curent_time, self.send_as_json(self.requests[cmd](request_data)))
    return False, self.cmd_cache[cmd][hashkey][1]

  def _clearnup_cache(self, cmd, curent_time):
    for hashkey in self.cmd_cache[cmd]:
      if self.cmd_cache[cmd][hashkey][0] + self.config['cache_life'] < curent_time:
        self.cmd_cache[cmd].pop(hashkey)
    while len(self.cmd_cache[cmd]) >= self.config['cache_max']:
      self.cmd_cache[cmd].pop(random.choice(self.cmd_cache[cmd].keys()))

  def info(self):
    return 'API {}: allowed API command: {}. Cached reply: {}.'.format(self.version, ', '.join([x for x in self.requests]), ', '.join([x for x in self.cmd_cache]))

class API_1(MainAPIHandler):
  def __init__(self, args):
    MainAPIHandler.__init__(self, args)

  def _handle_lasts(self, requ):
    """return last posts list. time - int unuxtime, sent after this. limit - post limit, max 100 min 1. group - groupname.exemple: get /lasts?limit=10&group=overchan.ru.drugs"""
    limits, after_time, group = self._prepare_lasts(requ)
    params = ['article_hash', 'sent']
    if group == 'all':
      params += ['group_name',]
      rows = self.overchandb.execute('SELECT {} FROM groups, articles WHERE sent > ? AND groups.group_id = articles.group_id ORDER BY sent DESC LIMIT ?'.format(', '.join(params)), (after_time, limits)).fetchall()
    else:
      rows = self.overchandb.execute('SELECT {} FROM groups, articles WHERE sent > ? AND group_name = ? AND groups.group_id = articles.group_id \
           ORDER BY sent DESC LIMIT ?'.format(', '.join(params)), (after_time, group, limits)).fetchall()
    return [dict(zip(params, row)) for row in rows]
  _handle_lasts.keys = {'time': 0, 'limit': 100, 'group': None}

  def _handle_lastsroot(self, requ):
    """see lasts, return updated root posts"""
    limits, after_time, group = self._prepare_lasts(requ)
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
  _handle_lastsroot.keys = _handle_lasts.keys

  def _handle_boardlist(self, requ):
    """return board list. No argument"""
    exclude_flags = self.cache['flags']['hidden'] | self.cache['flags']['blocked']
    data = [row[0] for row in self.overchandb.execute('SELECT group_name FROM groups WHERE (cast(flags as integer) & ?) = 0 ORDER by group_name ASC', (exclude_flags,)).fetchall()]
    return data
  _handle_boardlist.keys = {}

  def _handle_boardinfo(self, requ):
    """group info. group - groupname"""
    params = ('ph_name', 'ph_shortname', 'link', 'tag', 'description', 'flags', 'article_count', 'last_update')
    row = self.overchandb.execute('SELECT {} FROM groups WHERE group_name = ? LIMIT 1'.format(', '.join(params)), (requ['group'],)).fetchone()
    return dict(zip(params, row)) if row else {}
  _handle_boardinfo.keys = {'group': None}
  _handle_boardinfo.requ = ('group',)

  def _handle_post(self, requ):
    """send post data. id - full post hash"""
    params = ('article_uid', 'parent', 'sender', 'subject', 'sent', 'message', 'imagename', 'imagelink', 'thumblink', 'public_key', 'last_update', 'closed', 'sticky')
    row = self.overchandb.execute('SELECT {} FROM articles WHERE article_hash = ? LIMIT 1'.format(', '.join(params)), (requ['id'],)).fetchone()
    return dict(zip(params, row)) if row else {}
  _handle_post.keys = {'id': None}
  _handle_post.requ = ('id',)

  def _handle_thread(self, requ):
    """send root post and all child post. limit - child post limit, time - after time (only for child), id - root post full hash"""
    return self._prepare_thread(requ, False)
  _handle_thread.keys = {'id': None, 'limit': -1, 'time': 0}
  _handle_thread.requ = ('id',)

  def _handle_childs(self, requ):
    """see thread, return thread without root post"""
    return self._prepare_thread(requ, True)
  _handle_childs.keys = _handle_thread.keys
  _handle_childs.requ = _handle_thread.requ

  def _handle_fullhash(self, requ):
    """ return full post hash from 10 chars short hash. id - short hash """
    if len(requ['id']) != 10:
      return self.send_error(5, key='id')
    fullhash = self.overchandb.execute('SELECT article_hash FROM articles WHERE article_hash >= ? and article_hash < ? LIMIT 1', (requ['id'], requ['id']+'h')).fetchone()
    return fullhash[0] if fullhash else ''
  _handle_fullhash.keys = {'id': None}
  _handle_fullhash.requ = ('id',)

  def _handle_error(self, requ):
    """ send error. code = error code"""
    return self.send_error(requ['code'])
  _handle_error.keys = {'code': -1}
  _handle_error.requ = ('code',)

  def _handle_info(self, requ):
    """this. cmd - more info from command"""
    if 'cmd' in requ and requ['cmd'] in self.requests:
      return {'info': self.requests[requ['cmd']].__doc__,
              'allow keys': self.requests[requ['cmd']].keys,
              'required keys': self.requests[requ['cmd']].requ}
    return {'requests': {x: self.requests[x].__doc__ for x in self.requests},
            'request_limit': self.config['request_limit'],
            'version': self.version}
  #  keys = {'key': def, 'key2': some def}
  #  Only key present this dict extract of request_data. If key present, value cast in type(def) and set def if ValueError.
  #  if key is None - no cast
  #  If keys not present or None - all values send is as.
  #  if keys empty - requ = {}, all keys ignoring
  _handle_info.keys = {'cmd': None}
  #  requ = ('key', 'somekey')
  #  if key missing handler not call and return error. Of course, all key in requ must be in keys if keys is not None
  #  if requ not present or None - no check.
  _handle_info.requ = None

  @staticmethod
  def _prepare_lasts(request_data):
    """ extractor for lasts and lastsroot """
    limits = request_data.get('limit', 100)
    if limits < 1 or limits > 100:
      limits = 100
    after_time = request_data.get('time', 0)
    group = request_data.get('group', 'all')
    return limits, after_time, group

  def _prepare_thread(self, request_data, only_childs):
    """ for childs and thread """
    hashid = request_data['id']
    limits = request_data.get('limit', -1)
    after_time = request_data.get('time', 0)
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
