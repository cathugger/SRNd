#!/usr/bin/python

import os
import random
import string
import time
from hashlib import sha512
from binascii import unhexlify

import nacl.signing

import feeds.feed as feed

class InFeed(feed.BaseFeed):

  def __init__(self, master, logger, config, connection, debug, db_connector):
    feed.BaseFeed.__init__(self, master, logger, debug, 'infeed-{}-{}'.format(*connection[1]))
    self.infeed_hooks = config.get('rules', None)
    self.config = config['config']
    self.socket = connection[0]
    self.polltimeout = -1
    self._db_connector = db_connector
    self._auth_data = dict()
    self.caps = [
        '101 i support to the following:',
        'VERSION 2',
        'IMPLEMENTATION artificial NNTP processing unit SRNd v0.1',
        'POST',
        'IHAVE',
        'STREAMING',
        'SUPPORT'
    ]
    # append caps
    if self.config['srndauth_required'] > 0:
      self.caps.append('SRNDAUTH')
    self.welcome = '200 welcome much to artificial NNTP processing unit some random NNTPd v0.1, posting allowed'
    self.current_group_id = -1
    self.current_article_id = -1
    self.message_id_takethis = ''
    # get flag srnd-infeed-access from db
    self._srnd_infeed_access = self._db_connector('censor', timeout=60).fetchone('SELECT flag FROM commands WHERE command="srnd-infeed-access"')
    self._srnd_infeed_access = 0 if self._srnd_infeed_access is None else int(self._srnd_infeed_access[0])

  def bump_qsize(self):
    self.qsize = len(self.articles_queue)

  def main_loop(self):
    self.log(self.logger.INFO, 'connection established')
    self.send(self.welcome)
    self.state = 'idle'
    poll = self._create_poll()
    self.sqlite_dropper = self._db_connector('dropper', timeout=60)
    while self.running and not self.con_broken:
      if poll(self.polltimeout):
        self._handle_received()
        self.bump_qsize()
      if not self.qsize:
        time.sleep(0.5)
    self.sqlite_dropper.close()
    if self.running:
      self.log(self.logger.INFO, 'client disconnected, terminating')
    else:
      self.log(self.logger.INFO, 'bye')

  def _get_infeed_name_by_key(self, key):
    _censordb = self._db_connector('censor', timeout=60)
    try:
      # return new name if srnd-infeed-access present, else None
      result = _censordb.fetchone('SELECT local_name FROM keys WHERE key = ? and (cast(flags as integer) & ?) = ?', (key, self._srnd_infeed_access, self._srnd_infeed_access))
      if result is None:
        return None
      # remove bad chars
      new_name = result[0].encode('ascii', 'ignore').replace(' ', '')
      if len(new_name) < 3 or new_name.startswith('1'):
        return key
      # name must have unique
      if int(_censordb.fetchone('SELECT count(local_name) FROM keys WHERE local_name = ?', (result[0],))[0]) == 1:
        return new_name
      else:
        return key
    finally:
      _censordb.close()

  def _infeed_SRNDAUTH(self, cmd_list):
    # empty, bad, replay or first request
    if len(cmd_list) != 2 or 'secret' not in self._auth_data or cmd_list[0] not in self._srndauth_requ or cmd_list[0] in self._auth_data:
      #reinit and send
      self._auth_data = dict()
      self._auth_data['secret'] = ''.join(random.choice(string.ascii_uppercase+string.digits) for x in range(333))
      # stop flood
      time.sleep(random.uniform(5, 15))
      self.send('SRNDAUTH {}'.format(self._auth_data['secret']), 'SRNDAUTH')
    else:
      self._auth_data[cmd_list[0]] = cmd_list[1].lower()
    # recive all data - check key
    if len(self._auth_data) == 3:
      self._infeed_SRNDAUTH_check()

  def _infeed_SRNDAUTH_check(self):
    new_name = None
    if self._check_sign(self._auth_data):
      new_name = self._get_infeed_name_by_key(self._auth_data[self._srndauth_requ[0]])
      if new_name is not None:
        self._srnd_auth = True
        self.send('281 {} access granted'.format(self._auth_data[self._srndauth_requ[0]]), 'SRNDAUTH_ok')
      else:
        self.send('481 {} key not allowed at this server'.format(self._auth_data[self._srndauth_requ[0]]), 'SRNDAUTH_reject')
        self.log(self.logger.WARNING, '{} not allowed at this server'.format(self._auth_data[self._srndauth_requ[0]]))
    else:
      self.send('482 bad key or signature', 'SRNDAUTH_error')
      self.log(self.logger.WARNING, 'bad key or signature, key="{}" signature="{}"'.format(self._auth_data[self._srndauth_requ[0]], self._auth_data[[1]]))
    del self._auth_data['secret'], self._auth_data[self._srndauth_requ[1]]
    if self._srnd_auth:
      if self.config['pretty_name']:
        # rename infeed using pubkey or local_name
        self._set_infeed_pretty_name(new_name)
      self.log(self.logger.INFO, 'access granted for {}'.format(new_name))
    else:
      del self._auth_data[self._srndauth_requ[0]]

  def _set_infeed_pretty_name(self, to_name):
    new_name = 'infeed-' + to_name
    new_name_ = self.SRNd.rename_infeed(self.name, new_name)
    if new_name_ is not None:
      self.name = new_name_
    else:
      self.log(self.logger.WARNING, 'Error rename to {}'.format(new_name))

  def _check_sign(self, data):
    try:
      nacl.signing.VerifyKey(unhexlify(data[self._srndauth_requ[0]])).verify(sha512(data['secret']).digest(), unhexlify(data[self._srndauth_requ[1]]))
    except Exception as e:
      self.log(self.logger.DEBUG, 'could not verify signature: {}'.format(e))
      return False
    else:
      return True

  def _allow_groups(self, newsgroups):
    if newsgroups == '' or self.infeed_hooks is None:
      return True
    groups = newsgroups.split(';') if ';' in newsgroups else newsgroups.split(',')
    for group in groups:
      if not self._isgroup_in_rules(group, self.infeed_hooks['whitelist']) or self._isgroup_in_rules(group, self.infeed_hooks['blacklist']):
        return False
    return True

  @staticmethod
  def _isgroup_in_rules(group, regexp_list):
    for regexp in regexp_list:
      if regexp == group or regexp == '*' or regexp[-1] == '*' and group.startswith(regexp[:-1]):
        return True
    return False

  def handle_multiline(self, handle_incoming):
    # TODO if variant != POST think about using message_id in handle_singleline for self.outfile = open(tmp/$message_id, 'w')
    # TODO also in handle_singleline: if os.path.exists(tmp/$message_id): retry later
    if self.waitfor == 'article':
      self.byte_transfer += handle_incoming.read_byte
      self.time_transfer += handle_incoming.transfer_time
      self._handle_article(handle_incoming)
    else:
      self.log(self.logger.INFO, 'should handle multi line while waiting for %s:' % self.waitfor)
      self.log(self.logger.INFO, ''.join(handle_incoming.header))
      self.log(self.logger.INFO, 'should handle multi line end')
    self.waitfor = ''
    self.variant = ''

  def _handle_article(self, handle_incoming):
    error = ''
    add_headers = list()
    self.articles_queue.discard(handle_incoming.message_id)

    # check for errors
    if not handle_incoming.body_found:
      error += 'no body found, '
    if handle_incoming.newsgroups == '':
      error += 'no newsgroups found, '
    if handle_incoming.message_id == '':
      if self.variant != 'POST':
        error += 'no message-id in article, '
      else:
        rnd = ''.join(random.choice(string.ascii_lowercase) for x in range(10))
        handle_incoming.message_id = '<{0}{1}@POSTED.SRNd>'.format(rnd, int(time.time()))
        add_headers.append('Message-ID: {0}'.format(handle_incoming.message_id))
    elif '/' in handle_incoming.message_id:
      error += '/ in message-id, '
    if error != '':
      if self.variant == 'IHAVE':
        self.send('437 invalid article: {0}'.format(error[:-2]))
      elif self.variant == 'TAKETHIS':
        self.send('439 {0} invalid article: {1}'.format(self.message_id_takethis, error[:-2]))
        self.message_id_takethis = ''
      elif self.variant == 'POST':
        self.send('441 invalid article: {0}'.format(error[:-2]))
      # save in articles/invalid for manual debug
      add_headers.append('X-SRNd-invalid: {0}'.format(error[:-2]))
      add_headers.append('X-SRNd-source: {0}'.format(self.name))
      add_headers.append('X-SRNd-variant: {0}'.format(self.variant))
      handle_incoming.move_to(os.path.join('articles', 'invalid', '{0}-{1}'.format(self.name, int(time.time()))), add_headers)
      self.log(self.logger.INFO, 'article invalid %s: %s' % (handle_incoming.message_id, error[:-2]))
      return
    self.log(self.logger.DEBUG, 'article received {}. Large: {}'.format(handle_incoming.message_id, handle_incoming.file_large))
    # save article in tmp and mv to incoming
    if self.variant == 'POST':
      self.send('240 article received')
    elif self.variant == 'IHAVE':
      self.send('235 article received')
      #TODO: failed but try again later ==> 436
    elif self.variant == 'TAKETHIS':
      if os.path.exists(os.path.join('articles', handle_incoming.message_id)) or os.path.exists(os.path.join('incoming', handle_incoming.message_id)):
        self.send('439 {0} i know this article already'.format(handle_incoming.message_id))
        self.log(self.logger.DEBUG, 'rejecting already known article %s' % handle_incoming.message_id)
        return
      if os.path.exists(os.path.join('articles', 'censored', handle_incoming.message_id)):
        self.send('439 {0} article is blacklisted'.format(handle_incoming.message_id))
        self.log(self.logger.DEBUG, 'rejecting blacklisted article %s' % handle_incoming.message_id)
        return
      if not self._allow_groups(handle_incoming.newsgroups):
        self.send('439 {} article reject. group {} is blacklisted'.format(handle_incoming.message_id, handle_incoming.newsgroups))
        self.log(self.logger.DEBUG, 'rejecting article {}: group {} is blacklisted'.format(handle_incoming.message_id, handle_incoming.newsgroups))
        return
      self.send('239 {0} article received'.format(self.message_id_takethis))
      self.message_id_takethis = ''
    self.log(self.logger.INFO, 'article received and accepted %s' % handle_incoming.message_id)

    target = os.path.join('incoming', handle_incoming.message_id)
    if not os.path.exists(target):
      handle_incoming.move_to(target, add_headers)
    else:
      self.log(self.logger.INFO, 'got duplicate article: %s does already exist. removing temporary file' % target)

  def handle_line(self, line):
    self.log(self.logger.VERBOSE, 'in: %s' % line)
    commands = line.upper().split(' ')
    if len(commands) == 0:
      self.log(self.logger.VERBOSE, 'should handle empty line')
      return
    if commands[0] == 'CAPABILITIES':
      # send CAPABILITIES. Work before authentication
      self.send(self.caps)
      self.send('.')
    elif commands[0] == 'QUIT':
      self.send('205 bye bye')
      self.state = 'closing down'
      self.running = False
    elif not self._srnd_auth and (self.config['srndauth_required'] == 2 or (commands[0] == 'SRNDAUTH' and self.config['srndauth_required'] == 1)):
      # not authenticated and (authentication required or (cliens send SRNDAUTH and authentication allow))
      if commands[0] == 'SRNDAUTH':
        self._infeed_SRNDAUTH(commands[1:])
      else:
        self._infeed_SRNDAUTH([])
    elif commands[0] == 'SRNDAUTH':
      # already authenticated or authentication disallow. WTF?
      if self._srnd_auth:
        if self._srndauth_requ[0] in self._auth_data:
          self.send('281 {} already authenticated'.format(self._auth_data[self._srndauth_requ[0]]), 'SRNDAUTH_double')
        else:
          self.log(self.logger.ERROR, 'Internal error: self._srnd_auth=True and {} not in self._auth_data'.format(self._srndauth_requ[0]))
      else:
        self.send('501 {} not support. I much recommend in speak to the proper NNTP based on CAPABILITIES'.format(commands[0]), 'SRNDAUTH_501')
    elif commands[0] == 'SUPPORT':
      # 191 - initial SUPPORT reply
      self.send('191 i support:', 'SUPPORT')
      # send support options. Format '<KEY> <value>'
      # read direct option from infeeds config and send is as
      to_send = ['{} {}'.format(key.upper()[8:], value) for key, value in self.config.iteritems() if key.startswith('support_')]
      if to_send:
        self.send(to_send, 'SUPPORT')
      self.send('.', 'SUPPORT')
    elif commands[0] == 'MODE' and len(commands) == 2 and commands[1] == 'STREAM':
      self._handshake_state = True
      self.send('203 stream as you like')
    #elif commands[0] == 'MODE' and commands[1] == 'READER':
    #  self.send('502 i recommend in check to the CAPABILITIES')
    elif commands[0] == 'CHECK' and len(commands) == 2:
      #TODO 431 message-id   Transfer not possible; try again later
      message_id = line.split(' ', 1)[1]
      if '/' in message_id:
        self.send('438 {0} illegal message-id'.format(message_id))
      elif os.path.exists(os.path.join('articles', message_id)) or os.path.exists(os.path.join('incoming', message_id)):
        self.send('438 {0} i know this article already'.format(message_id))
      elif os.path.exists(os.path.join('articles', 'censored', message_id)):
        self.send('438 {0} article is blacklisted'.format(message_id))
      else:
        self.articles_queue.add(message_id)
        self.qsize = len(self.articles_queue)
        self.send('238 {0} go ahead, send to the article'.format(message_id))
    elif commands[0] == 'TAKETHIS' and len(commands) == 2:
      self.waitfor = 'article'
      self.variant = 'TAKETHIS'
      self.message_id_takethis = line.split(' ', 1)[1]
      self.in_buffer.set_multiline()
    elif commands[0] == 'POST':
      self._handshake_state = True
      self.send('340 go ahead, send to the article')
      self.waitfor = 'article'
      self.variant = 'POST'
      self.in_buffer.set_multiline()
    elif commands[0] == 'IHAVE':
      self._handshake_state = True
      arg = line.split(' ', 1)[1]
      if '/' in arg:
        self.send('435 illegal message-id')
      elif os.path.exists(os.path.join('articles', arg)) or os.path.exists(os.path.join('incoming', arg)):
        self.send('435 already have this article')
      elif os.path.exists(os.path.join('articles', 'censored', arg)):
        self.send('435 article is blacklisted')
      else:
        #TODO: add currently receiving same message_id from another feed == 436, try again later
        self.send('335 go ahead, send to the article'.format(arg))
        self.waitfor = 'article'
        self.variant = 'IHAVE'
        self.in_buffer.set_multiline()
    elif commands[0] == 'STAT':
      self._handshake_state = True
      if len(commands) == 1:
        # STAT without arguments
        if self.current_group_id == -1:
          self.send('412 i much recommend in select to the newsgroup first')
        elif self.current_article_id == -1:
          self.send('420 i claim in current group is empty')
        else:
          message_id = self.sqlite_dropper.execute('SELECT message_id FROM articles WHERE group_id = ? AND article_id = ?', (self.current_group_id, self.current_article_id)).fetchone()
          if message_id:
            message_id = message_id[0]
            self.send('223 {0} {1}'.format(self.current_article_id, message_id))
          else:
            self.log(self.logger.CRITICAL, 'internal state messed up. current_article_id does not have connected message_id')
            self.log(self.logger.CRITICAL, 'current_group_id: %s, current_article_id: %s' % (self.current_group_id, self.current_article_id))
        return
      if len(commands) != 2:
        self.send('501 i much recommend in speak to the proper NNTP')
        return
      try:
        arg = int(commands[1])
      except ValueError:
        arg = line.split(' ')[1]
        # STAT argument is message_id
        #if self.sqlite_dropper.execute('SELECT message_id FROM articles WHERE message_id = ?', (arg,)).fetchone():
        if os.path.exists(os.path.join('articles', arg)):
          self.send('223 0 {0}'.format(arg))
        else:
          self.send('430 i do not know much in {0}'.format(arg))
      else:
        # STAT argument is article_id
        if self.current_group_id == -1:
          self.send('412 i much recommend in select to the newsgroup first')
        else:
          message_id = self.sqlite_dropper.execute('SELECT message_id FROM articles WHERE group_id = ? AND article_id = ?', (self.current_group_id, arg)).fetchone()
          if message_id:
            message_id = message_id[0]
            self.current_article_id = arg
            self.send('223 {0} {1}'.format(self.current_article_id, message_id))
          else:
            self.send('423 i claim such == invalid number')
    else:
      self.send('501 {} unknown. I much recommend in speak to the proper NNTP based on CAPABILITIES'.format(commands[0]))

