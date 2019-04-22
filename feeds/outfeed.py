#!/usr/bin/env python2

import os
import Queue
import socket
import time
from hashlib import sha512
from binascii import hexlify, unhexlify

import nacl.signing

import feeds.sockssocket as sockssocket
import feeds.feed as feed

class OutFeed(feed.BaseFeed):

  def __init__(self, kill_me, logger, config):
    self.config = config
    feed.BaseFeed.__init__(self, kill_me, logger, self.config['debug'], 'outfeed-{}-{}'.format(*self.config['server']))
    self.sync_on_startup = self.config['sync_on_startup']
    self.queue = Queue.LifoQueue()
    self.ctl_queue = Queue.Queue()
    self.polltimeout = 500 # 1 * 1000
    self.cooldown_period = 60
    self.cooldown_counter = 0
    self.rechecking = dict()
    self.rechecking_step = 0
    self.message_id = ''
    self._RESPONSES = (
        self._handle_response_NONE,
        self._handle_response_STREAM,
        self._handle_response_IHAVE,
        self._handle_response_POST
    )
    self.outstream_flags_reset()

  def _init_outcoming_socket(self):
    proxy_types = {'socks5': sockssocket.PROXY_TYPE_SOCKS5, 'socks4': sockssocket.PROXY_TYPE_SOCKS4, 'http': sockssocket.PROXY_TYPE_HTTP}
    socket_ = None
    if self.config['ipv6']:
      if self.config['proxy'] is not None:
        self.log(self.logger.ERROR, "can't use proxy server for ipv6 connections")
        self.running = False
      else:
        socket_ = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    elif self.config['proxy'] is None:
      socket_ = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    elif self.config['proxy']['proxy_type'] in proxy_types:
      socket_ = sockssocket.socksocket(socket.AF_INET, socket.SOCK_STREAM)
      socket_.setproxy(proxy_types[self.config['proxy']['proxy_type']], self.config['proxy']['proxy_ip'], self.config['proxy']['proxy_port'], rdns=True)
    else:
      self.log(self.logger.ERROR, "unknown proxy type {}, must be one of {}.".format(self.config['proxy']['proxy_type'], ', '.join(proxy_types.keys())))
      self.running = False
    return socket_

  def add_article(self, message_id, ctl=False):
    if ctl:
      self.ctl_queue.put(message_id)
    else:
      self.queue.put(message_id)

  def bump_qsize(self):
    self.qsize = self.queue.qsize() + len(self.articles_queue) + len(self.rechecking) + self.ctl_queue.qsize()

  def outstream_flags_reset(self):
    self._support_vars = dict()
    self._try_srndauth_bypass = False
    self._srnd_auth = False
    self._caps_cache = None
    self._handshake_state = False
    self._current_mode = self._MODE['none']
    self.outstream_currently_testing = ''
    # gzip
    self._srndgzip = None
    self._srndgzip_error = False
    # for POST and IHAVE mode
    self._wait_response = False
    self._wait_response_time = 0

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
    """Connect to server. Set self.con_broken empty line if connected or error message"""
    self.con_broken = ''
    try:
      self.socket.connect(self.config['server'])
    except socket.error as e:
      if e.errno == 9:
        # Bad file descriptor
        self.socket = self._init_outcoming_socket()
        self.con_broken = e
      elif e.errno == 106:
        # tunnelendpoint already connected. wtf? only happened via proxy
        # FIXME debug this
        self.log(self.logger.ERROR, '%s: setting connected = True' % e)
      else:
        self._socket_exception(e)
    except sockssocket.ProxyError as e:
      self._proxy_exception(e)

  def _queue_allow(self):
    if self.queue.qsize():
      return True
    if self.ctl_queue.qsize():
      self.queue.put(self.ctl_queue.get())
      return True
    return False

  def _handle_connect(self, reconnect=False):
    """Work while not connected and outfeed running. Return poll if connect else None"""
    self._socket_shutdown()
    self._socket_close()
    self.socket = self._init_outcoming_socket()
    # clear all data from socket
    self.in_buffer.reset()
    self.incoming_file.reset()

    self.outstream_flags_reset()
    poll = None
    while self.running and self.con_broken:
      self.bump_qsize()
      if reconnect and self.qsize == 0:
        self.log(self.logger.INFO, 'connection broken. no article to send, sleeping: {}'.format(self.con_broken))
        self.state = 'nothing_to_send'
        while self.running and not self._queue_allow():
          time.sleep(2)
        continue
      self._cooldown(self.con_broken)
      self.state = 'connecting'
      if reconnect:
        self.log(self.logger.INFO, 'connection broken. reconnecting..')
      self._connect_to_server()
      if self.con_broken:
        reconnect = True
      else:
        proxy_info = ' via proxy {proxy_type} {proxy_ip}:{proxy_port}'.format(**self.config['proxy']) if self.config['proxy'] is not None else ''
        self.log(self.logger.INFO, 'connection established{}'.format(proxy_info))
        poll = self._create_poll()
    return poll

  def main_loop(self):
    self.con_broken = 'connection broken'
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
      elif self.state == 'idle':
        self._recheck_sending()
        self._handle_send()
        self.state = 'idle'
      if not self.qsize:
        time.sleep(0.5)
    self.log(self.logger.INFO, 'bye')

  def _handle_send(self):
    if self._current_mode == self._MODE['stream']:
      if len(self.articles_queue) > 0:
        self._worker_send_article_stream()
      else:
        self._send_new_check('CHECK', 50)
    elif self._queue_allow():
      if not self._wait_response:
        if self._current_mode == self._MODE['ihave']:
          self._send_new_check('IHAVE')
        elif self._current_mode == self._MODE['post']:
          self.message_id = self.queue.get()
          self.send('POST')
      elif int(time.time()) - self._wait_response_time > 1200:
        # deblock sending if server not send reply after 20 min
        self._wait_response = False

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
    if self.config['infinity_stream']:
      self._infinity_stream_on()
    while len(self.articles_queue) > 0 and start_time + send_time > int(time.time()) and not self.con_broken:
      message_id = self.articles_queue.pop()
      if os.path.exists(os.path.join('articles', message_id)) and not self._disallow_to_send(message_id):
        self.sendM('TAKETHIS {}'.format(message_id))
        self.send_article(message_id, 'outfeed_send_article_stream')
    self._infinity_stream_off()

  def _send_new_check(self, cmd, max_count=1):
    """Collect IHAVE and CHECK article id and re-add in queue if don't response or connect broken when send this """
    to_send = list()
    count = 0
    while self._queue_allow() and count < max_count:
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
      self.update_trackdb('000 {} disallow to send'.format(message_id))
      return True
    return False

  def send_article(self, message_id, state='sending_article'):
    self.log(self.logger.INFO, 'sending article %s' % message_id)
    with open(os.path.join('articles', message_id), 'rb') as fd:
      sending, real_len, send_time = self._send_article(fd, state)
    if not self.con_broken:
      self.byte_transfer += sending
      self.time_transfer += send_time
      if real_len > 0:
        diff = -int(float(sending - real_len)/sending * 100) if sending > 0 else 0
        self.log(self.logger.DEBUG, '{} send: size: {}, compressed: {}, diff: {}%'.format(message_id, sending, real_len, diff))
    # ~ + 4 minute in 1 mb. May be need correct for other network
    # rechecking small articles first
    multiplier = sending / (1024 * 64)
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

  def _get_CAPABILITIES(self):
    if self._caps_cache is None:
      self.send('CAPABILITIES')
    else:
      # CAPABILITIES already reading. Use cache
      self._check_CAPABILITIES(self._caps_cache)

  def _check_CAPABILITIES(self, caps):
    if not self._srndgzip_error and self._srndgzip is None and 'SRNDGZIP' in caps:
      # server support gzip - handshake
      self.send('SRNDGZIP')
    elif 'SRNDAUTH' in caps and not (self.config['srndauth_key'] is None or self._srnd_auth or self._try_srndauth_bypass):
      # server support SRNDAUTH and key present and not authenticate.
      pubkey = self._key_from_private(self.config['srndauth_key'])
      if pubkey is None:
        self.log(self.logger.ERROR, 'Private key invalid. Check srndauth_key in outfeed config')
        if not self._srndauth_bypass():
          self.shutdown()
      else:
        # authentication - send pubkey
        self.send('SRNDAUTH {} {}'.format(self._SRNDAUTH_REQU[0], pubkey), 'SRNDAUTH')
    elif 'SUPPORT' in caps:
      # server support SUPPORT, send it and wait response 191
      self.send('SUPPORT')
    else:
      # old server, go stream
      self.outstream_currently_testing = 'STREAM'
      self.send('MODE STREAM')

  def _check_SUPPORT(self, varlist):
    for line in varlist:
      key, val = line.upper().split(' ', 1)
      self.log(self.logger.DEBUG, 'Server support key="{}", value="{}"'.format(key, val))
      if key == 'MAX_SEND_SIZE':
        try:
          self._support_vars[key] = int(val)
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
    self.outstream_currently_testing = 'STREAM'
    self.send('MODE STREAM')

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
      self.con_broken = 'Work is not possible.'
    elif self.config['srndauth_key'] is None:
      self.log(self.logger.ERROR, 'Server required SRDNAUTH and srndauth_key not in outfeed config or invalid.')
      if not self._srndauth_bypass():
        self.shutdown()
    elif len(secret) != 333:
      self.log(self.logger.WARNING, 'Response secret {} != 333. Authentication is not possible.'.format(len(secret)))
      if not self._srndauth_bypass():
        self.cooldown_counter = 5
        self.con_broken = 'Authentication is not possible.'
    else:
      # send signature
      sign = self._create_sign(self.config['srndauth_key'], secret)
      if sign is None:
        self.log(self.logger.ERROR, 'Private key invalid. Check srndauth_key in outfeed config')
        if not self._srndauth_bypass():
          self.shutdown()
      else:
        self.send('SRNDAUTH {} {}'.format(self._SRNDAUTH_REQU[1], sign), 'SRNDAUTH')

  @staticmethod
  def _create_sign(priv_key, secret):
    try:
      keypair = nacl.signing.SigningKey(unhexlify(priv_key))
    except:
      return None
    else:
      return hexlify(keypair.sign(sha512(secret).digest()).signature)

  def _srndauth_bypass(self):
    # if SRNDAUTH fail, send MODE STREAM once - if server set 1 its work
    if self._try_srndauth_bypass:
      return False
    self.log(self.logger.WARNING, 'SRNDAUTH error - try handshake without authentication')
    self._try_srndauth_bypass = True
    self._get_CAPABILITIES()
    return True

  def _handle_response_NONE(self, commands, _):
    """Mode selector"""
    if commands[0] == '203':
      # MODE STREAM test successfull
      self._current_mode = self._MODE['stream']
      if self._try_srndauth_bypass:
        self.log(self.logger.WARNING, 'successful login, SRNDAUTH breaking. FIX IT!')
    elif commands[0] == '435':
      # IHAVE test successfull
      self._current_mode = self._MODE['ihave']
    elif commands[0] == '335':
      # IHAVE test successfull
      self.send('.')
      self._current_mode = self._MODE['ihave']
    elif commands[0] == '340':
      # POST test successfull
      self.send('.')
      self._current_mode = self._MODE['post']
    elif commands[0] in ('500', '501', '502'):
      if self.outstream_currently_testing == '':
        # WTF? Test MODE STREAM
        self.send('MODE STREAM')
        self.outstream_currently_testing = 'STREAM'
      elif self.outstream_currently_testing == 'STREAM':
        # MODE STREAM test failed
        self.outstream_currently_testing = 'IHAVE'
        self.send('IHAVE <thisarticle@doesnotexist>')
      elif self.outstream_currently_testing == 'IHAVE':
        # IHAVE test failed
        self.outstream_currently_testing = 'POST'
        self.send('POST')
      elif self.outstream_currently_testing == 'POST':
        self.log(self.logger.ERROR, 'remote host does not allow MODE STREAM, IHAVE or POST. shutting down')
        self.running = False
    elif commands[0] == '440':
      self.log(self.logger.ERROR, 'remote host does not allow MODE STREAM, IHAVE or POST. shutting down')
      self.running = False
    else:
      return True
    self._handshake_state = self._current_mode != self._MODE['none']

  def _handle_response_STREAM(self, commands, line):
    """MODE STREAM. If command unknown return True"""
    if commands[0] == '238':
      # CHECK 238 == article wanted
      article_wanted = line.split(' ')[1]
      self.articles_queue.add(article_wanted)
      self._recheck_sending(article_wanted, 'remove')
    elif commands[0] in ('239', '438'):
      # TAKETHIS 239 == Article transferred OK, record successfully sent message-id to database
      # CHECK 438 == Article not wanted
      self.update_trackdb(line)
    elif commands[0] == '439':
      # TAKETHIS 439 == Transfer rejected; do not retry
      self.log(self.logger.WARNING, repr(line))
      self.update_trackdb(line)
    elif commands[0] == '431':
      # CHECK 431 == try again later
      self._recheck_sending(line.split(' ')[1], 'add', 300)
    else:
      return True

  def _handle_response_IHAVE(self, commands, line):
    if commands[0] in ('235', '435', '437'):
      # IHAVE 235 == last article received
      # IHAVE 435 == article not wanted
      # IHAVE 437 == article rejected
      if self.message_id:
        self.update_trackdb('{} {} {}'.format(commands[0], self.message_id, line.split(' ', 2)[2:][0]))
      self._wait_response = False
    elif commands[0] == '436':
      # IHAVE 436 == try again later
      self._recheck_sending(self.message_id, 'add', 300)
      self._wait_response = False
    elif commands[0] == '335':
      # IHAVE 335 == waiting for article
      self.send_article(self.message_id)
      self._wait_response = True
      self._wait_response_time = int(time.time())
    else:
      return True

  def _handle_response_POST(self, commands, line):
    if commands[0] == '340':
      # POST 340 == waiting for article
      self.send_article(self.message_id)
      self._wait_response = True
      self._wait_response_time = int(time.time())
    elif commands[0] in ('240', '441'):
      # POST 240 == last article received
      # POST 441 == posting failed
      if commands[0] == '240' and self.message_id:
        # Got 240 after POST: record successfully sent message-id to database
        self.update_trackdb('{} {} {}'.format(commands[0], self.message_id, line.split(' ', 2)[2:][0]))
      self._wait_response = False
    else:
      return True

  def _handle_handshake(self, commands, line):
    if commands[0] == '480':
      # Authentication required.
      if not self._srndauth_bypass():
        self.cooldown_counter = 5
        self.con_broken = 'Authentication required'
    elif commands[0] == 'SRNDAUTH':
      # server allowed or required SRDNAUTH
      if len(commands) == 2:
        self._outfeed_SRNDAUTH(commands[1])
      else:
        self.log(self.logger.ERROR, 'Recived incorrect SRNDAUTH response. Authentication is not possible: {}'.format(line))
        if not self._srndauth_bypass():
          self.cooldown_counter = 5
          self.con_broken = 'Recived incorrect SRNDAUTH response.'
    elif commands[0] == '101':
      # receive CAPABILITES
      self.waitfor = 'CAPABILITIES'
      self.in_buffer.set_multiline()
    elif commands[0] == '191':
      # SUPPORT 191 = receive varlist
      self.waitfor = 'SUPPORT'
      self.in_buffer.set_multiline()
    elif commands[0] == '200':
      self.cooldown_counter = 0
      # check server CAPABILITES
      self._get_CAPABILITIES()
    elif commands[0] == '281':
      # SRNDAUTH 281 - access granted. check server CAPABILITES
      if len(commands) > 1 and len(commands[1]) == 64:
        rec_key = commands[1].lower()
      else:
        rec_key = 'you key'
      self.log(self.logger.INFO, 'successful login using {}'.format(rec_key))
      self._srnd_auth = True
      self._get_CAPABILITIES()
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
    elif commands[0] == '952':
      # SRNDGZIP 952 - ok enable gzip
      self._enable_gzip()
      self.log(self.logger.INFO, 'Enable compression')
      self._get_CAPABILITIES()
    elif commands[0] == '954':
      # SRNDGZIP 954 - server not support gzip
      self._srndgzip_error = True
      self.log(self.logger.WARNING, 'error handshake for compression. WTF?')
      self._get_CAPABILITIES()
    else:
      return True

  def handle_line(self, line):
    self.log(self.logger.VERBOSE, 'in: %s' % line)
    commands = line.upper().split(' ')
    if len(commands) == 0:
      self.log(self.logger.VERBOSE, 'should handle empty line')
    elif self._current_mode == self._MODE['none'] and not self._handle_handshake(commands, line):
      pass
    elif self._RESPONSES[self._current_mode](commands, line):
      self.log(self.logger.ERROR, 'unknown response in mode {}: {}'.format(self._MODE_REVERS[self._current_mode], repr(line)))

