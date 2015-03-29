#!/usr/bin/python

import os
import sqlite3
import threading
import time
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
from urllib import unquote
from urlparse import urlparse, parse_qs

import api

class OverchanAPI(BaseHTTPRequestHandler):
  def __init__(self, request, client_address, origin):
    self.origin = origin
    BaseHTTPRequestHandler.__init__(self, request, client_address, origin)

  def log_request(self, *code):
    return

  def log_message(self, _format, *args):
    return

  @staticmethod
  def do_POST():
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
    self.overchandb_conn = sqlite3.connect(os.path.join(self.config['database_directory'], 'overchan.db3'), timeout=60)
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
    self.config['running'] = False
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
        'cache_allow': '*',
        'cache_disallow': 'error;info'}
    for target in args:
      if target in cfg_def:
        try:
          if isinstance(cfg_def[target], bool) and args[target].lower() in ('false', 'no', '0', 'disable'):
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
    while len(self.cache) < 1 and self.config['running']:
      try:
        self.cache['flags'] = {row[0]: row[1] for row in self.overchandb.execute('SELECT flag_name, cast(flag as integer) FROM flags WHERE flag_name != ""').fetchall()}
      except sqlite3.Error:
        # db not created. wait...
        time.sleep(5)

  def _api_init(self):
    self.apis = dict()
    for target in [xxx for xxx in dir(api) if xxx.startswith('API_')]:
      api_ver = target[4:]
      self.apis[api_ver] = getattr(api, target)({'db_connector': self.overchandb, 'config': self.config, 'cache': self.cache, 'version': api_ver})
      self.log(self.logger.INFO, self.apis[api_ver].info())

  def api_worker(self, cmd, version, request_data):
    start_time = time.time()
    if version not in self.apis:
      version = api.DEFAULT_VERSION
    data = self.apis[version].go(cmd, request_data)
    self.log(self.logger.DEBUG, 'API {}: got request: {}, data: {}, exec time: {}, cached: {}'.format(version, cmd, str(request_data), (time.time() - start_time), data[0]))
    return data[1]

