#!/usr/bin/python

import time
import json
import random

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
    self.cmd_cache = self._init_cmd_cache(self.config['cache_allow'].split(';'), self.config['cache_disallow'].split(';'))

  def _init_cmd_cache(self, allows, disallows):
    cmd_cache = dict()
    if self.config['cache_reply'] and self.config['cache_max'] > 0:
      for cmd in self.requests:
        if self._check_for_in(cmd, allows) and not self._check_for_in(cmd, disallows):
          cmd_cache[cmd] = dict()
    return cmd_cache

  def _get_all_handles(self, allows, disallows):
    request_handles = dict()
    for method in [xxx for xxx in dir(self) if xxx.startswith('_handle_')]:
      handle_name = method[8:]
      if self._check_for_in(handle_name, allows) and not self._check_for_in(handle_name, disallows):
        request_handles[handle_name] = getattr(self, method)
        # add missing attr
        for add_attr in ('keys', 'requ'):
          if add_attr not in request_handles[handle_name].__dict__:
            request_handles[handle_name].__dict__[add_attr] = None
    return request_handles

  @staticmethod
  def _check_for_in(target, regex_list):
    for regex in regex_list:
      if target == regex or regex == '*' or (regex.endswith('*') and target.startswith(regex[:-1])):
        return True
    return False

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
    return self.request_count <= self.config['request_limit']

  def _cleaned_keys(self, cmd, request_data):
    if self.requests[cmd].keys is None:
      return request_data
    requ = dict()
    for c_key in self.requests[cmd].keys:
      if c_key in request_data:
        if self.requests[cmd].keys[c_key] is None:
          requ[c_key] = request_data[c_key]
        elif isinstance(self.requests[cmd].keys[c_key], bool):
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
    requ = self._cleaned_keys(cmd, request_data)
    misskey = self._missing_request_key(cmd, requ)
    if misskey is not False:
      return False, self.send_as_json(misskey)

    curent_time = int(time.time())
    if cmd in self.cmd_cache:
      data = self._get_from_cache(cmd, requ, curent_time)
    elif not self._request_counter(curent_time):
      data = (False, self.send_as_json(self.send_error(2)))
    else:
      data = (False, self.send_as_json(self.requests[cmd](requ)))
    return data

  def _get_from_cache(self, cmd, request_data, curent_time):
    hashkey = hash(str(request_data))
    if hashkey in self.cmd_cache[cmd] and self.cmd_cache[cmd][hashkey][0] + self.config['cache_life'] > curent_time:
      return True, self.cmd_cache[cmd][hashkey][1]
    if not self._request_counter(curent_time):
      return False, self.send_as_json(self.send_error(2))
    if len(self.cmd_cache[cmd]) >= self.config['cache_max']:
      self._clearnup_cache(cmd, curent_time)
    self.cmd_cache[cmd][hashkey] = (curent_time, self.send_as_json(self.requests[cmd](request_data)))
    return False, self.cmd_cache[cmd][hashkey][1]

  def _clearnup_cache(self, cmd, curent_time):
    for hashkey in self.cmd_cache[cmd]:
      if self.cmd_cache[cmd][hashkey][0] + self.config['cache_life'] < curent_time:
        self.cmd_cache[cmd].pop(hashkey)
    while len(self.cmd_cache[cmd]) >= self.config['cache_max']:
      self.cmd_cache[cmd].pop(random.choice(self.cmd_cache[cmd].keys()))

  def info(self):
    return 'API {0} allows request: {1}.\nAPI {0} cached replies: {2}.'.format(self.version, ', '.join([x for x in self.requests]), ', '.join([x for x in self.cmd_cache]))

