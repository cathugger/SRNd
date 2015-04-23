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
    self._auth_data = None
    self.caps = [
        '101 i support to the following:',
        'VERSION 2',
        'IMPLEMENTATION artificial NNTP processing unit SRNd v0.1',
        'READER',
        'POST',
        'IHAVE',
        'LIST ACTIVE NEWSGROUPS OVERVIEW.FMT',
        'STREAMING'
    ]
    # append caps
    if self.config['support']:
      self.caps.append('SUPPORT')
    if self.config['auth_required'] > 0:
      if 'nntp' in self.config['auth_support']:
        self.caps.append('AUTHINFO USER PASS')
      if 'srnd' in self.config['auth_support']:
        self.caps.append('SRNDAUTH')
    self.welcome = '200 welcome much to artificial NNTP processing unit some random NNTPd v0.1, posting allowed'
    self.current_group_id = -1
    self.current_group_name = None
    self.current_article_id = -1
    self.message_id_wait = ''
    # get flag srnd-infeed-access from db
    self._srnd_infeed_access = self._db_connector('censor', timeout=60).fetchone('SELECT flag FROM commands WHERE command="srnd-infeed-access"')
    self._srnd_infeed_access = 0 if self._srnd_infeed_access is None else int(self._srnd_infeed_access[0])
    # list not sending headers in READER MODE.
    self._remove_headers = ('X-I2P-DESTHASH',)
    # switcher for reader mode
    self.READER_SEND = {
        'HEAD': ('221', True, False, 'send_head'),
        'BODY': ('222', False, True, 'send_body'),
        'ARTICLE': ('220', True, True, 'send_article')
    }
    # OVERVIEW.FMT reply
    self._OVERVIEW_FMT = ['subject:', 'from:', 'date:', 'message-id:', 'references:', ':bytes', ':lines']

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
    if len(cmd_list) < 2 or cmd_list[0] not in self._SRNDAUTH_REQU:
      # empty, bad or issued request
      self.send('482 Authentication commands issued. Allow only {}'.format(' or '.join(self._SRNDAUTH_REQU)), 'SRNDAUTH')
    elif cmd_list[0] == self._SRNDAUTH_REQU[0]:
      # SRNDAUTH PUBKEY KEY - first clien request. Generate and send secret, save pubkey and secret
      if self._auth_data is not None:
        # stop flood
        time.sleep(random.uniform(5, 15))
      # reset data and send new secret
      self._auth_data = dict()
      self._auth_data[self._SRNDAUTH_REQU[0]] = cmd_list[1].lower()
      self._auth_data['secret'] = ''.join(random.choice(string.ascii_uppercase+string.digits) for x in range(333))
      self.send('SRNDAUTH {}'.format(self._auth_data['secret']), 'SRNDAUTH')
    elif cmd_list[0] == self._SRNDAUTH_REQU[1]:
      # SRNDAUTH SIGNATURE signature - client send signature
      if self._auth_data is not None and self._SRNDAUTH_REQU[0] in self._auth_data:
        # save signature and check user data
        self._auth_data[self._SRNDAUTH_REQU[1]] = cmd_list[1].lower()
        self._infeed_SRNDAUTH_check()
      else:
        # user send signature and not send pubkey. WTF?
        self.send('482 send your pubkey before signature', 'SRNDAUTH')

  def _infeed_AUTHINFO(self, cmd_list):
    if len(cmd_list) < 2 or cmd_list[0] not in ('USER', 'PASS'):
      self.send('482 Authentication commands issued out of sequence')
    elif cmd_list[0] == 'USER':
      # ignore username, get private key
      self.send('381 send me your private key, kekeke')
    elif cmd_list[0] == 'PASS':
      pubkey = self._key_from_private(cmd_list[1])
      if pubkey is None:
        self.log(self.logger.WARNING, 'bad private key')
        # stop flood
        time.sleep(random.uniform(5, 15))
        self.send('481 Authentication failed/rejected')
      else:
        new_name = self._get_infeed_name_by_key(pubkey)
        if new_name is not None:
          self._srnd_auth = True
          self.send('281 {} access granted'.format(pubkey), 'AUTHINFO_ok')
          if self.config['pretty_name']:
            # rename infeed using pubkey or local_name
            self._set_infeed_pretty_name(new_name)
          self.log(self.logger.INFO, 'access granted for {}'.format(new_name))
          self._auth_data = {self._SRNDAUTH_REQU[0]: pubkey}
        else:
          self.log(self.logger.WARNING, '{} not allowed at this server'.format(pubkey))
          # stop flood
          time.sleep(random.uniform(5, 15))
          self.send('481 {} key not allowed at this server'.format(pubkey), 'AUTHINFO_reject')

  def _infeed_SRNDAUTH_check(self):
    new_name = None
    if self._check_sign(self._auth_data):
      new_name = self._get_infeed_name_by_key(self._auth_data[self._SRNDAUTH_REQU[0]])
      if new_name is not None:
        self._srnd_auth = True
        self.send('281 {} access granted'.format(self._auth_data[self._SRNDAUTH_REQU[0]]), 'SRNDAUTH_ok')
      else:
        self.send('481 {} key not allowed at this server'.format(self._auth_data[self._SRNDAUTH_REQU[0]]), 'SRNDAUTH_reject')
        self.log(self.logger.WARNING, '{} not allowed at this server'.format(self._auth_data[self._SRNDAUTH_REQU[0]]))
    else:
      self.send('482 bad key or signature', 'SRNDAUTH_error')
      self.log(self.logger.WARNING, 'bad key or signature, key="{}" signature="{}"'.format(self._auth_data[self._SRNDAUTH_REQU[0]], self._auth_data[[1]]))
    del self._auth_data['secret'], self._auth_data[self._SRNDAUTH_REQU[1]]
    if self._srnd_auth:
      if self.config['pretty_name']:
        # rename infeed using pubkey or local_name
        self._set_infeed_pretty_name(new_name)
      self.log(self.logger.INFO, 'access granted for {}'.format(new_name))
    else:
      del self._auth_data[self._SRNDAUTH_REQU[0]]

  def _set_infeed_pretty_name(self, to_name):
    new_name = 'infeed-' + to_name
    new_name_ = self.SRNd.rename_infeed(self.name, new_name)
    if new_name_ is not None:
      self.name = new_name_
    else:
      self.log(self.logger.WARNING, 'Error rename to {}'.format(new_name))

  def _check_sign(self, data):
    try:
      nacl.signing.VerifyKey(unhexlify(data[self._SRNDAUTH_REQU[0]])).verify(sha512(data['secret']).digest(), unhexlify(data[self._SRNDAUTH_REQU[1]]))
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
    self.message_id_wait = ''

  def _handle_article(self, handle_incoming):
    # variant: (error, ok)
    variants = {
        'IHAVE': ('437', '235'),
        'TAKETHIS': ('439', '239'),
        'POST': ('240', '240')
    }
    if self.variant not in variants:
      self.log(self.logger.ERROR, 'Unknown variant "{}". Interrupt processing article'.format(self.variant))
      return
    error = ''
    add_headers = list()
    self.articles_queue.discard(handle_incoming.message_id)

    # check for errors
    if not handle_incoming.body_found:
      error += 'no body found, '
    if handle_incoming.newsgroups == '':
      error += 'no newsgroups found, '
    if handle_incoming.message_id == '':
      if self.variant == 'POST':
        rnd = ''.join(random.choice(string.ascii_lowercase) for x in range(10))
        handle_incoming.message_id = '<{}{}@POSTED.{}>'.format(rnd, int(time.time()), self.config.get('instance_name', 'SRNd'))
        add_headers.append('Message-ID: {0}'.format(handle_incoming.message_id))
      elif self.valid_message_id(self.message_id_wait):
        handle_incoming.message_id = self.message_id_wait
        add_headers.append('Message-ID: {0}'.format(handle_incoming.message_id))
      else:
        error += 'no message-id in article, '
    elif not self.valid_message_id(handle_incoming.message_id):
      error += 'message-id invalid, '
    if error != '':
      self.send('{} {} invalid article: {}'.format(variants[self.variant][0], self.message_id_wait, error[:-2]))
      # save in articles/invalid for manual debug
      add_headers.append('X-SRNd-invalid: {0}'.format(error[:-2]))
      add_headers.append('X-SRNd-source: {0}'.format(self.name))
      add_headers.append('X-SRNd-variant: {0}'.format(self.variant))
      handle_incoming.move_to(os.path.join('articles', 'invalid', '{0}-{1}'.format(self.name, int(time.time()))), add_headers)
      self.log(self.logger.INFO, 'article invalid %s: %s' % (handle_incoming.message_id, error[:-2]))
      return
    self.log(self.logger.DEBUG, 'article received {}. Large: {}'.format(handle_incoming.message_id, handle_incoming.file_large))
    # save article in tmp and mv to incoming
    if os.path.exists(os.path.join('articles', handle_incoming.message_id)) or os.path.exists(os.path.join('incoming', handle_incoming.message_id)):
      self.send('{} {} i know this article already'.format(variants[self.variant][0], handle_incoming.message_id))
      self.log(self.logger.DEBUG, 'rejecting already known article %s' % handle_incoming.message_id)
    elif os.path.exists(os.path.join('articles', 'censored', handle_incoming.message_id)):
      self.send('{} {} article is blacklisted'.format(variants[self.variant][0], handle_incoming.message_id))
      self.log(self.logger.DEBUG, 'rejecting blacklisted article %s' % handle_incoming.message_id)
    elif not self._allow_groups(handle_incoming.newsgroups):
      self.send('{} {} article reject. group {} is blacklisted'.format(variants[self.variant][0], handle_incoming.message_id, handle_incoming.newsgroups))
      self.log(self.logger.DEBUG, 'rejecting article {}: group {} is blacklisted'.format(handle_incoming.message_id, handle_incoming.newsgroups))
    else:
      self.send('{} {} article received'.format(variants[self.variant][1], handle_incoming.message_id))
      handle_incoming.move_to(os.path.join('incoming', handle_incoming.message_id), add_headers)
      self.log(self.logger.INFO, 'article received and accepted %s' % handle_incoming.message_id)

  def handle_line(self, line):
    self.log(self.logger.VERBOSE, 'in: %s' % line)
    commands = line.upper().split(' ')
    if len(commands) == 0:
      self.log(self.logger.VERBOSE, 'should handle empty line')
    elif commands[0] == 'CAPABILITIES':
      # send CAPABILITIES. Work before authentication
      self.send(self.caps)
      self.send('.')
    elif commands[0] == 'QUIT':
      self.send('205 bye bye')
      self.state = 'closing down'
      self.running = False
    elif commands[0] == 'SRNDAUTH' and self.config['auth_required'] > 0 and not self._srnd_auth and 'srnd' in self.config['auth_support']:
      # allow SRNDAUTH
      self._infeed_SRNDAUTH(commands[1:])
    elif commands[0] == 'AUTHINFO' and self.config['auth_required'] > 0 and not self._srnd_auth and 'nntp' in self.config['auth_support']:
      # allow AUTHINFO
      self._infeed_AUTHINFO(commands[1:])
    elif not self._srnd_auth and self.config['auth_required'] == 2:
      # not authenticated and authentication required
      self.send('480 Authentication required')
    elif commands[0] == 'SUPPORT':
      # 191 - initial SUPPORT reply
      self.send('191 i support:', 'SUPPORT')
      # send support options. Format '<KEY> <value>'
      if self.config['support']:
        self.send(self.config['support'], 'SUPPORT')
      self.send('.', 'SUPPORT')
    elif commands[0] == 'MODE' and len(commands) == 2 and commands[1] == 'STREAM':
      self._handshake_state = True
      self.send('203 stream as you like')
      self._current_mode = self._MODE['stream']
    elif commands[0] == 'MODE' and commands[1] == 'READER':
      #200    Posting allowed
      #201    Posting prohibited
      #502    Reading service permanently unavailable
      #TODO: add self.reader_mode true/false and reader_mode switcher to config
      self.send('200 Posting allowed')
      self._current_mode = self._MODE['reader']
      self.log(self.logger.DEBUG, 'switch to MODE READER')
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
      self.message_id_wait = line.split(' ', 1)[1]
      self.in_buffer.set_multiline()
    elif commands[0] == 'POST':
      self._handshake_state = True
      self.send('340 go ahead, send to the article')
      self.waitfor = 'article'
      self.variant = 'POST'
      self.in_buffer.set_multiline()
      # remove UA from POST
      self.incoming_file.remove_headers(headers=['user-agent',])
      self._current_mode = self._MODE['post']
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
        self.send('335 go ahead, send to the {}'.format(arg))
        self.waitfor = 'article'
        self.variant = 'IHAVE'
        self.message_id_wait = arg
        self.in_buffer.set_multiline()
        self._current_mode = self._MODE['ihave']
    elif commands[0] == 'STAT':
      message_uid, message_id = self._article_check(line.split(' ')[1:])
      if message_uid:
        self.send('223 {} {}'.format(message_id, message_uid))
    elif commands[0] == 'LIST':
      self._response_LIST(commands[1:])
    elif commands[0] == 'XOVER':
      min_id, max_id = self._check_id_range(commands[1:])
      if min_id:
        all_articles = self._get_article_range(min_id, max_id)
        if all_articles:
          self._send_header_XOVER(all_articles)
        else:
          self.send('423 No articles in that range')
    elif commands[0] == 'NEWGROUPS':
      # not implemented yet, return all groups
      self._response_LIST_ACTIVE([])
    elif commands[0] == 'GROUP':
      if len(commands) != 2:
        self.send('501 Syntax Error')
      else:
        group_data = self.sqlite_dropper.fetchone('SELECT article_count, lowest_id, highest_id, group_name, group_id FROM groups WHERE group_name = ?', (line.split(' ')[1],))
        if not group_data:
          self.send('411 {} is unknown'.format(line.split(' ')[1]))
        else:
          self.send('211 {}'.format(' '.join(str(xx) for xx in group_data[:-1])))
          self.current_article_id = group_data[1]
          self.current_group_id = group_data[4]
          self.current_group_name = line.split(' ')[1]
    elif commands[0] in self.READER_SEND:
      # BODY, HEAD or ARTICLE
      message_uid, message_id = self._article_check(line.split(' ')[1:])
      if message_uid:
        self._send_article_READER(message_uid, message_id, commands[0])
    else:
      self.send('500 {} unknown, I much recommend in speak to the proper NNTP based on CAPABILITIES'.format(commands[0]))

  def _article_check(self, cmd):
    """ Check BODY, HEAD or ARTICLE command. return 2 strings contains name and id. If name is None - do nothing"""
    message_id = None
    message_uid = None
    if self.current_group_id == -1:
      self.send('412 No newsgroup selected')
    elif not cmd and self.current_article_id == -1:
      self.send('420 Current article number is invalid')
    elif not cmd or cmd[0].isdigit():
      # current article number used else article number specified
      message_id = self.current_article_id if not cmd else cmd[0]
      message_uid = self.sqlite_dropper.execute('SELECT message_id FROM articles WHERE group_id = ? AND article_id = ?', (self.current_group_id, message_id)).fetchone()
      if message_uid is None:
        self.send('423 No article with that {}'.format(message_id))
      else:
        message_uid = message_uid[0]
    else:
      # message-id specified
      message_uid = os.path.basename(cmd[0])
      message_id = 0
    if message_uid is not None and not os.path.isfile(os.path.join('articles', message_uid)):
      if message_id == 0:
        self.send('430 No article with that {}'.format(message_uid))
      else:
        self.send('423 No article with that {}'.format(message_id))
      message_uid = None
    return message_uid, message_id

  def _check_id_range(self, cmd):
    """Return min, max id from XOVER. If min_id is None - do nothing"""
    min_id, max_id = None, None
    if self.current_group_id == -1:
      self.send('412 No newsgroup selected')
    elif not cmd and self.current_article_id == -1:
      self.send('420 No article(s) selected')
    elif not cmd:
      # current article number used
      min_id, max_id = self.current_article_id, self.current_article_id
    elif cmd[0].isdigit():
      # article number
      min_id, max_id = cmd[0], cmd[0]
    else:
      # article number range
      min_id, _, max_id = cmd[0].partition('-')
      if not min_id.isdigit() or (max_id and not max_id.isdigit()):
        self.send('423 invalid id')
        min_id = None
    if min_id is None:
      pass
    elif not max_id:
      # XOVER X-. Set +1000
      max_id = int(min_id) + 1000
    elif int(max_id) - int(min_id) > 1000:
      # very large range
      self.send('502 very large article_id range')
      min_id = None
    return min_id, max_id

  def _get_article_range(self, min_id, max_id):
    """return list *(article_id, message_id)"""
    all_data = list()
    for data in self.sqlite_dropper.fetchall('SELECT article_id, message_id FROM articles WHERE group_id = ? AND article_id >= ? AND article_id <= ?', (self.current_group_id, min_id, max_id)):
      if os.path.isfile(os.path.join('articles', data[1])):
        all_data.append(data)
    return all_data

  def _send_header_XOVER(self, all_data):
    self.send('224 Overview information follows')
    start_time = time.time()
    sending = 0
    for article_id, message_uid in all_data:
      article_path = os.path.join('articles', message_uid)
      data = [''] * (len(self._OVERVIEW_FMT) + 1)
      data[0] = str(article_id)
      data[6] = str(os.path.getsize(article_path))
      with open(article_path, 'rb') as fd:
        for line in self._read_article(fd, True, False):
          head, _, value = line.partition(' ')
          head = head.lower()
          if head in self._OVERVIEW_FMT:
            data[self._OVERVIEW_FMT.index(head) + 1] = value
      sending += self.send('\t'.join(data), 'XOVER')
      if self.con_broken:
        break
    if not self.con_broken:
      self.send('.', 'XOVER')
      self.byte_transfer += sending
      self.time_transfer += time.time() - start_time

  def _send_article_READER(self, message_uid, message_id, mode):
    """Send body, head or full article in MODE READER. mode in ('HEAD', 'BODY', 'ARTICLE')"""
    # don't check header if send body
    head_complit = True if mode == 'BODY' else False
    mode = self.READER_SEND[mode]

    self.log(self.logger.DEBUG, '{} {}'.format(mode[3], message_uid))
    start_time = time.time()
    sending = 0
    self.send('{} {} {}'.format(mode[0], message_id, message_uid))
    with open(os.path.join('articles', message_uid), 'rb') as fd:
      for to_send in self._read_article(fd, mode[1], mode[2]):
        if not head_complit:
          if to_send == '':
            head_complit = True
          elif to_send.split(': ')[0].upper() in self._remove_headers:
            continue
        sending += self.send(to_send, mode[3])
        if self.con_broken:
          break
    if not self.con_broken:
      self.send('.', mode[3])
      self.byte_transfer += sending
      self.time_transfer += time.time() - start_time

  def _response_LIST(self, commands):
    if not commands or commands[0] == 'ACTIVE':
      self._response_LIST_ACTIVE(commands[1:])
    elif commands[0] == 'NEWSGROUPS':
      self.send('215 information follows')
      for line in self.sqlite_dropper.fetchall('SELECT group_name FROM groups'):
        self.send(line[0])
      self.send('.')
    elif commands[0] == 'OVERVIEW.FMT':
      self.send('215 Order of fields in overview database:')
      self.send(self._OVERVIEW_FMT)
      self.send('.')
    else:
      self.send('503 program error, {} not performed'.format(commands[0]))

  def _response_LIST_ACTIVE(self, commands):
    if commands:
      self.send('501 Syntax Error')
    else:
      self.send('215 list of newsgroups follows')
      for line in self.sqlite_dropper.fetchall('SELECT group_name, highest_id, lowest_id, flag FROM groups'):
        self.send(' '.join(str(xx) for xx in line))
      self.send('.')
