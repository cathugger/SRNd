#!/usr/bin/python

import os
import Queue
import socket
import time
import traceback
from hashlib import sha512
from binascii import hexlify, unhexlify

import nacl.signing

import feeds.sockssocket as sockssocket
import feeds.feed as feed

class OutFeed(feed.BaseFeed):

  def __init__(self, master, logger, config, server, sync_on_startup, proxy, debug):
    # tuple(host, port)
    self.server = server
    feed.BaseFeed.__init__(self, master, logger, debug, 'outfeed-{}-{}'.format(*self.server))
    # only config
    self.config = config
    self.sync_on_startup = sync_on_startup
    self.proxy = proxy
    self.queue = Queue.LifoQueue()
    self.outstream_flags_reset()
    self.polltimeout = 500 # 1 * 1000
    self.cooldown_period = 60
    self.cooldown_counter = 0
    self.rechecking = dict()
    self.rechecking_step = 0
    self.message_id = ''
    self.outstream_flags_reset()

  def _init_outcoming_socket(self):
    proxy_types = {'socks5': sockssocket.PROXY_TYPE_SOCKS5, 'socks4': sockssocket.PROXY_TYPE_SOCKS4, 'http': sockssocket.PROXY_TYPE_HTTP}
    socket_ = None
    if ':' in self.server[0]:
      if self.proxy is not None:
        # FIXME: this should be loglevel.ERROR and then terminating itself
        self.log(self.logger.ERROR, "can't use proxy server for ipv6 connections")
        self.running = False
      else:
        socket_ = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    elif self.proxy is None:
      socket_ = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    elif self.proxy[0] in proxy_types:
      socket_ = sockssocket.socksocket(socket.AF_INET, socket.SOCK_STREAM)
      socket_.setproxy(proxy_types[self.proxy[0]], self.proxy[1], self.proxy[2], rdns=True)
    else:
      self.log(self.logger.ERROR, "unknown proxy type {}, must be one of {}.".format(self.proxy[0], ', '.join(proxy_types.keys())))
      self.running = False
    return socket_

  def add_article(self, message_id):
    self.queue.put(message_id)

  def bump_qsize(self):
    self.qsize = self.queue.qsize() + len(self.articles_queue) + len(self.rechecking)

  def outstream_flags_reset(self):
    self._support_vars = dict()
    self._try_srndauth_bypass = False
    self._handshake_state = False
    self._srnd_auth = False
    self._caps_cache = None
    self.outstream_stream = False
    self.outstream_ihave = False
    self.outstream_post = False
    self.outstream_ready = False
    self.outstream_currently_testing = ''

  def _cooldown(self, additional_message=''):
    if self.cooldown_counter != 0:
      loglevel = self.logger.DEBUG if self.cooldown_counter == 10 else self.logger.INFO
      self.log(loglevel, '{} sleeping {} seconds'.format(additional_message, self.cooldown_period * self.cooldown_counter))
      end_time = int(time.time()) + self.cooldown_period * self.cooldown_counter
      self.state = 'cooldown'
      while self.running and int(time.time()) < end_time:
        time.sleep(2)
    if self.cooldown_counter < 10:
      self.cooldown_counter += 1

  def _connect_to_server(self):
    """Connect to server. Return empty line if connected or error message"""
    message = ''
    try:
      self.socket.connect(self.server)
    except socket.error as e:
      if e.errno == 9:
        # Bad file descriptor
        self.socket = self._init_outcoming_socket()
        message = e
      elif e.errno == 106:
        # tunnelendpoint already connected. wtf? only happened via proxy
        # FIXME debug this
        self.log(self.logger.ERROR, '%s: setting connected = True' % e)
      elif e.errno in (111, 113):
        # 111 Connection refused
        # 113 no route to host
        message = e
      else:
        self.log(self.logger.ERROR, 'unhandled initial connect socket.error: %s' % e)
        self.log(self.logger.ERROR, traceback.format_exc())
        message = e
    except sockssocket.ProxyError as e:
      message = '[Errno {}] {}'.format(*e.message)
      if e.message[0] in (0, 4):
        # 0 - connection closed unexpectedly
        # 4 - Host unreachable
        pass
      else:
        self.log(self.logger.ERROR, 'unhandled initial connect ProxyError: %s' % message)
        self.log(self.logger.ERROR, traceback.format_exc())
    return message

  def _handle_connect(self, reconnect=False):
    """Work while not connected and outfeed running. Return poll and set self.con_broken = False if connect else None"""
    self._socket_shutdown()
    self._socket_close()
    self.socket = self._init_outcoming_socket()
    self.in_buffer.reset()
    self.outstream_flags_reset()
    not_connected = ' '
    poll = None
    while self.running and not_connected:
      self.bump_qsize()
      if reconnect and self.qsize == 0:
        self.log(self.logger.INFO, 'connection broken. no article to send, sleeping: {}'.format(not_connected))
        self.state = 'nothing_to_send'
        while self.running and self.queue.qsize() == 0:
          time.sleep(2)
        continue
      self._cooldown(not_connected)
      self.state = 'connecting'
      if reconnect:
        self.log(self.logger.INFO, 'connection broken. reconnecting..')
      not_connected = self._connect_to_server()
      if not_connected:
        reconnect = True
      else:
        self.cooldown_counter = 0
        proxy_info = ' via proxy {} {}:{}'.format(*self.proxy) if self.proxy is not None else ''
        self.log(self.logger.INFO, 'connection established{}'.format(proxy_info))
        poll = self._create_poll()
        self.con_broken = False
    return poll

  def main_loop(self):
    self.con_broken = True
    poll = None
    while self.running:
      self.bump_qsize()
      if self.con_broken:
        # self.socket is None - firs connect. reconnect = False
        poll = self._handle_connect(self.socket is not None)
        if not self.con_broken:
          self.state = 'wait_welcome'
      if self.con_broken:
        pass
      elif poll(self.polltimeout):
        # read and parse incoming data
        self._handle_received()
      elif self.outstream_ready and self.state == 'idle':
        self._recheck_sending()
        if self.outstream_stream:
          if len(self.articles_queue) > 0:
            self._worker_send_article_stream()
          else:
            self._send_new_check('CHECK', 50)
          self.state = 'idle'
        elif self.queue.qsize() > 0 and not self.con_broken:
          if self.outstream_ihave:
            self._send_new_check('IHAVE')
          elif self.outstream_post:
            self.message_id = self.queue.get()
            self.send('POST')
      if not self.qsize:
        time.sleep(0.5)
    self.log(self.logger.INFO, 'bye')

  def _recheck_sending(self, message_id=None, act=None, step=120):
    """ Add or remove article in dict. If no act and step 's after adding article - re-adding article in queue.
        self.rechecking_step - empty cycle for increase performance if list very large"""
    curent_time = int(time.time())
    if act == 'add':
      self.rechecking[message_id] = curent_time + step
    elif act == 'remove':
      self.rechecking.pop(message_id, None)
    elif self.rechecking_step < curent_time:
      self.rechecking_step = curent_time + 20
      for add_article in [x for x in self.rechecking if self.rechecking[x] < curent_time]:
        self.rechecking.pop(add_article, None)
        self.log(self.logger.DEBUG, 'no response for {} - re-adding in queue'.format(add_article))
        self.add_article(add_article)

  def _worker_send_article_stream(self, send_time=120):
    start_time = int(time.time())
    while len(self.articles_queue) > 0 and start_time + send_time > int(time.time()) and not self.con_broken:
      message_id = self.articles_queue.pop()
      if os.path.exists(os.path.join('articles', message_id)):
        self.send('TAKETHIS {0}'.format(message_id))
        self.send_article(message_id, 'outfeed_send_article_stream')

  def _send_new_check(self, cmd, max_count=1):
    """ Collect IHAVE and CHECK article id and re-add in queue if don't response or connect broken when send this """
    to_send = list()
    count = 0
    while self.queue.qsize() > 0 and count < max_count:
      self.message_id = self.queue.get()
      if os.path.isfile(os.path.join('articles', self.message_id)):
        to_send.append(self.message_id)
        count += 1
    if to_send:
      self.send([' '.join((cmd, xx)) for xx in to_send], 'outfeed_send_{}_stream'.format(cmd))
      if self.con_broken:
        self.log(self.logger.DEBUG, 'con_broken while sending {} {} messages. Re-adding in queue'.format(cmd, len(to_send)))
        for message_id in to_send:
          self.add_article(message_id)
      else:
        self.log(self.logger.DEBUG, 'send {} {}'.format(cmd, ', '.join(to_send)))
        for message_id in to_send:
          self._recheck_sending(message_id, 'add')

  def _disallow_to_send(self, message_id):
    if self._support_vars.get('MAX_SEND_SIZE') is not None and self._support_vars['MAX_SEND_SIZE'] < os.path.getsize(os.path.join('articles', message_id)):
      self.log(self.logger.INFO, 'not sending article {}. Server allow max file size {} bytes'.format(message_id, self._support_vars['MAX_SEND_SIZE']))
      return True
    return False

  def send_article(self, message_id, state='sending_article'):
    if self._disallow_to_send(message_id):
      self.update_trackdb('000 {} disallow to send'.format(message_id))
      return
    self.log(self.logger.INFO, 'sending article %s' % message_id)
    start_time = time.time()
    sending = 0
    with open(os.path.join('articles', message_id), 'rb') as fd:
      for to_send in self._read_article(fd):
        sending += self.send(to_send, state)
        if self.con_broken:
          break
    if not self.con_broken:
      self.send('.', state)
      self.byte_transfer += sending
      self.time_transfer += time.time() - start_time
    # ~ + 4 minute in 1 mb. May be need correct for other network
    # rechecking small articles first
    multiplier = (sending) / (1024 * 64)
    multiplier = multiplier * 120 if multiplier > 0 else 120
    if multiplier > 3600:
      multiplier = 3600
    self.log(self.logger.VERBOSE, 'add {}s waiting after sending {}'.format(multiplier, message_id))
    self._recheck_sending(message_id, 'add', multiplier)

  def update_trackdb(self, line):
    self.log(self.logger.DEBUG, 'updating trackdb: %s' % line)
    message_id = line.split(' ')[1]
    # remove existing\sending\etc article
    self._recheck_sending(message_id, 'remove')
    try:
      f = open('{0}.trackdb'.format(self.name), 'a')
    except IOError as e:
      self.log(self.logger.ERROR, 'cannot open: %s: %s' % ('{0}.trackdb'.format(self.name), e.strerror))
    else:
      f.write('{0}\n'.format(message_id))
      f.close()

  def _send_MODESTREAM(self):
    self.send('MODE STREAM')
    self.send('MODE STREAM')

  def _get_CAPABILITIES(self):
    if self._caps_cache is None:
      self.send('CAPABILITIES')
    else:
      # CAPABILITIES already reading. Use cache
      self._check_CAPABILITIES(self._caps_cache)

  def _check_CAPABILITIES(self, caps):
    # WTF? Stop serving
    if 'STREAMING' not in caps:
      # hack for old servers
      if 'STREAMING' not in caps[-1]:
        self.log(self.logger.CRITICAL, "Server doesn't support STREAMING! EXTERMINATED!")
        self.shutdown()
        return
    # server support SRNDAUTH and key present and not authenticate. authentication
    if 'SRNDAUTH' in caps and self.config['srndauth_key'] is not None and not self._srnd_auth and not self._try_srndauth_bypass:
      self.send('SRNDAUTH')
    # server support SUPPORT, send it and wait response 191
    elif 'SUPPORT' in caps:
      self.send('SUPPORT')
    else:
      # old server, go stream
      self._send_MODESTREAM()

  def _check_SUPPORT(self, varlist):
    for line in varlist:
      key, val = line.split(' ', 1)
      self.log(self.logger.DEBUG, 'Server support key="{}", value="{}"'.format(key, val))
      self._support_vars[key] = val
      if key == 'MAX_SEND_SIZE':
        try:
          self._support_vars[key] = int(self._support_vars[key])
        except ValueError:
          self._support_vars[key] = None
        else:
          if self._support_vars[key] < 20:
            self._support_vars[key] = None
        if self._support_vars[key] is None:
          self.log(self.logger.WARNING, 'Error parsing MAX_SEND_SIZE: abnormal value "{}"'.format(val))
        else:
          self.log(self.logger.INFO, 'Server support maximum filesize: {} bytes'.format(self._support_vars[key]))
    # initial start streaming
    self._send_MODESTREAM()

  def handle_multiline(self, handle_incoming):
    if self.waitfor == 'SUPPORT':
      self._check_SUPPORT(handle_incoming.header)
    elif self.waitfor == 'CAPABILITIES':
      # save caps in cache
      self._caps_cache = list(handle_incoming.header)
      self.log(self.logger.DEBUG, 'Server caps: {}'.format(self._caps_cache))
      self._check_CAPABILITIES(self._caps_cache)
    else:
      self.log(self.logger.INFO, 'should handle multi line while waiting for %s:' % self.waitfor)
      self.log(self.logger.INFO, ''.join(handle_incoming.header))
      self.log(self.logger.INFO, 'should handle multi line end')
    self.waitfor = ''

  def _outfeed_SRNDAUTH(self, secret):
    if self._try_srndauth_bypass:
      self.log(self.logger.WARNING, 'Server require authentication. Work is not possible.')
      self.send('QUIT')
      self.cooldown_counter = 5
      self.con_broken = True
      return
    if self.config['srndauth_key'] is None:
      self.log(self.logger.ERROR, 'Server required SRDNAUTH and srndauth_key not in outfeed config or invalid.')
      if not self._srndauth_bypass():
        self.shutdown()
      return
    pubkey = self._key_from_private(self.config['srndauth_key'])
    if pubkey is None:
      self.log(self.logger.ERROR, 'Private key invalid. Check srndauth_key in outfeed config')
      if not self._srndauth_bypass():
        self.shutdown()
      return
    if len(secret) != 333:
      self.log(self.logger.WARNING, 'Response secret {} != 333. Authentication is not possible.'.format(len(secret)))
      if not self._srndauth_bypass():
        self.cooldown_counter = 3
        self.con_broken = True
      return
    sign = self._create_sign(self.config['srndauth_key'], secret)
    if sign is not None:
      self.send('SRNDAUTH {} {}'.format(self._srndauth_requ[0], pubkey), 'SRNDAUTH')
      self.send('SRNDAUTH {} {}'.format(self._srndauth_requ[1], sign), 'SRNDAUTH')

  @staticmethod
  def _create_sign(priv_key, secret):
    keypair = nacl.signing.SigningKey(unhexlify(priv_key))
    return hexlify(keypair.sign(sha512(secret).digest()).signature)

  @staticmethod
  def _key_from_private(priv_key):
    try:
      return hexlify(nacl.signing.SigningKey(unhexlify(priv_key)).verify_key.encode())
    except:
      return None

  def _srndauth_bypass(self):
    # if SRNDAUTH fail, send MODE STREAM once - if server set 1 its work
    if self._try_srndauth_bypass:
      return False
    self.log(self.logger.WARNING, 'SRNDAUTH error - try handshake without authentication')
    self._try_srndauth_bypass = True
    self._get_CAPABILITIES()
    return True

  def handle_line(self, line):
    self.log(self.logger.VERBOSE, 'in: %s' % line)
    commands = line.upper().split(' ')
    if len(commands) == 0:
      self.log(self.logger.VERBOSE, 'should handle empty line')
      return
    if not self.outstream_ready:
      if commands[0] == 'SRNDAUTH':
        # server allowed or required SRDNAUTH
        if len(commands) == 2:
          self._outfeed_SRNDAUTH(commands[1])
        else:
          self.log(self.logger.ERROR, 'Recived incorrect SRNDAUTH. Authentication is not possible: {}'.format(line))
          if not self._srndauth_bypass():
            self.cooldown_counter = 3
            self.con_broken = True
      elif commands[0] == '101':
        # check CAPABILITES
        self.waitfor = 'CAPABILITIES'
        self.in_buffer.set_multiline()
      elif commands[0] == '200':
        self.cooldown_counter = 0
        # check server CAPABILITES
        self._get_CAPABILITIES()
      elif commands[0] == '203':
        # MODE STREAM test successfull
        self.outstream_stream = True
        self.outstream_ready = True
        self._handshake_state = True
        if self._try_srndauth_bypass:
          self.log(self.logger.WARNING, 'successful login, SRNDAUTH breaking. FIX IT!')
      elif commands[0] == '191':
        # SUPPORT 191 = receive varlist
        self.waitfor = 'SUPPORT'
        self.in_buffer.set_multiline()
      elif commands[0] == '281':
        # SRNDAUTH 281 - access granted. check server CAPABILITES
        if len(commands) > 1 and len(commands[1]) == 64:
          rec_key = commands[1].lower()
        else:
          rec_key = 'you key'
        self.log(self.logger.INFO, 'successful login using {}'.format(rec_key))
        self._srnd_auth = True
        self._get_CAPABILITIES()
      elif commands[0] == '501' or commands[0] == '500':
        if self.outstream_currently_testing == '':
          # MODE STREAM test failed
          self.outstream_currently_testing = 'IHAVE'
          self.send('IHAVE <thisarticledoesnotexist>')
        elif self.outstream_currently_testing == 'IHAVE':
          # IHAVE test failed
          self.outstream_post = True
          self.outstream_ready = True
          self._handshake_state = True
          if self.queue.qsize() > 0:
            self.message_id = self.queue.get()
            self.send('POST')
      elif commands[0] == '435':
        # IHAVE test successfull
        self.outstream_ihave = True
        self.outstream_ready = True
        self._handshake_state = True
      elif commands[0] == '335':
        # IHAVE test successfull
        self.send('.')
        self.outstream_ihave = True
        self.outstream_ready = True
        self._handshake_state = True
      elif commands[0] == '481':
        # SRNDAUTH 481 - key not allowed at this server
        if len(commands) > 1 and len(commands[1]) == 64:
          rec_key = commands[1].lower()
        else:
          rec_key = 'You key'
        self.log(self.logger.WARNING, '{} not allowed at this server'.format(rec_key))
        self.state = 'SRNDAUTH_reject'
        self._srndauth_bypass()
      elif commands[0] == '482':
        # SRNDAUTH 482 - bad key or signature
        self.log(self.logger.WARNING, 'bad key or signature')
        self.state = 'SRNDAUTH_error'
        self._srndauth_bypass()
      else:
        self.log(self.logger.WARNING, 'got unknown command: {}'.format(line))
      # FIXME how to treat try later for IHAVE and CHECK?
    elif self.outstream_ready and commands[0] == '200':
      # TODO check specs for reply 200 again, only valid as first welcome line?
      self.cooldown_counter = 0
    elif self.outstream_stream:
      if commands[0] == '238':
        # CHECK 238 == article wanted
        article_wanted = line.split(' ')[1]
        self.articles_queue.add(article_wanted)
        self._recheck_sending(article_wanted, 'remove')
      if commands[0] == '239' or commands[0] == '438' or commands[0] == '439':
        # TAKETHIS 239 == Article transferred OK, record successfully sent message-id to database
        # CHECK 438 == Article not wanted
        # TAKETHIS 439 == Transfer rejected; do not retry
        self.update_trackdb(line)
      elif commands[0] == '431':
        # CHECK 431 == try again later
        self.add_article(line.split(' ')[1])
        self._recheck_sending(line.split(' ')[1], 'remove')
    elif self.outstream_ihave:
      if commands[0] == '235' or commands[0] == '435' or commands[0] == '437':
        # IHAVE 235 == last article received
        # IHAVE 435 == article not wanted
        # IHAVE 437 == article rejected
        self.update_trackdb(line)
        if self.queue.qsize() > 0:
          self._send_new_check('IHAVE')
      elif commands[0] == '436':
        # IHAVE 436 == try again later
        self._recheck_sending(self.message_id, 'add', 600)
      elif commands[0] == '335':
        # IHAVE 335 == waiting for article
        self.send_article(self.message_id)
      else:
        self.log(self.logger.INFO, 'unknown response to IHAVE: %s' % line)
    elif self.outstream_post:
      if commands[0] == '340':
        # POST 340 == waiting for article
        self.send_article(self.message_id)
      elif commands[0] == '240' or commands[0] == '441':
        # POST 240 == last article received
        # POST 441 == posting failed
        if commands[0] == '240':
          # Got 240 after POST: record successfully sent message-id to database
          self.update_trackdb(line)
        if self.queue.qsize() > 0:
          self.message_id = self.queue.get()
          self.send('POST')
      elif commands[0] == '440':
        # POST 440 == posting not allowed
        self.log(self.logger.ERROR, 'remote host does not allow MODE STREAM, IHAVE or POST. shutting down')
        self.running = False
      else:
        self.log(self.logger.ERROR, 'unknown response to POST: %s' % line)

