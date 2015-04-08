#!/usr/bin/python
import os
import Queue
import random
import select
import socket
import sqlite3
import string
import threading
import time
import traceback
from hashlib import sha512
from binascii import hexlify, unhexlify

import nacl.signing

import sockssocket


class feed(threading.Thread):

  def log(self, loglevel, message):
    if loglevel >= self.loglevel:
      self.logger.log(self.name, message, loglevel)

  def __init__(self, master, logger, config, db_connector, connection=None, outstream=False, host=None, port=None, sync_on_startup=False, proxy=None, debug=2):
    threading.Thread.__init__(self)
    self.infeed_hooks = config.get('rules', None)
    self.config = config.get('config', {})
    self.outstream = outstream
    self.loglevel = debug
    self.logger = logger
    self.state = 'init'
    self.SRNd = master
    self.proxy = proxy
    self._srnd_auth = self._srnd_auth_init()
    if outstream:
      self.host = host
      self.port = port
      self.queue = Queue.LifoQueue()
      self._outstream_flags_init()
      self.polltimeout = 500 # 1 * 1000
      self.name = 'outfeed-{0}-{1}'.format(self.host, self.port)
      self.init_socket()
      self.rechecking = dict()
      self.rechecking_step = 0
    else:
      self._auth_data = dict()
      self.socket = connection[0]
      self.fileno = self.socket.fileno()
      self.host = connection[1][0]
      self.port = connection[1][1]
      self.polltimeout = -1
      self.name = 'infeed-{0}-{1}'.format(self.host, self.port)
    #self.socket.setblocking(0)
    self.buffersize = 2**16
    self.caps = [
        '101 i support to the following:',
        'VERSION 2',
        'IMPLEMENTATION artificial NNTP processing unit SRNd v0.1',
        'POST',
        'IHAVE',
        'STREAMING',
        'SUPPORT',
        'SRNDAUTH'
        ]
    self.welcome = '200 welcome much to artificial NNTP processing unit some random NNTPd v0.1, posting allowed'
    self._srndauth_requ = ('X-PUBKEY-ED25519', 'X-SIGNATURE-ED25519-SHA512')
    self.current_group_id = -1
    self.current_article_id = -1
    self.sync_on_startup = sync_on_startup
    self.qsize = 0
    self.articles_to_receive = set()
    self.byte_transfer = 1
    self.time_transfer = 0.1
    self._max_send_size = None
    self._db_connector = db_connector

  def _srnd_auth_init(self):
    return self.outstream or self.config.get('srndauth_required', 'false').lower() in ('false', 'no')

  def _outstream_flags_init(self):
    self.outstream_stream = False
    self.outstream_ihave = False
    self.outstream_post = False
    self.outstream_ready = False
    self.outstream_currently_testing = ''

  def init_socket(self):
    if ':' in self.host:
      if self.proxy != None:
        # FIXME: this should be loglevel.ERROR and then terminating itself
        raise Exception("can't use proxy server for ipv6 connections")
      self.socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
      return
    if self.proxy == None:
      self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    elif self.proxy[0] == 'socks5':
      self.socket = sockssocket.socksocket(socket.AF_INET, socket.SOCK_STREAM)
      self.socket.setproxy(sockssocket.PROXY_TYPE_SOCKS5, self.proxy[1], self.proxy[2], rdns=True)
    elif self.proxy[0] == 'socks4':
      self.socket = sockssocket.socksocket(socket.AF_INET, socket.SOCK_STREAM)
      self.socket.setproxy(sockssocket.PROXY_TYPE_SOCKS4, self.proxy[1], self.proxy[2], rdns=True)
    elif self.proxy[0] == 'http':
      self.socket = sockssocket.socksocket(socket.AF_INET, socket.SOCK_STREAM)
      self.socket.setproxy(sockssocket.PROXY_TYPE_HTTP, self.proxy[1], self.proxy[2], rdns=True)
    else:
      # FIXME: this should be loglevel.ERROR and then terminating itself
      raise Exception("unknown proxy type %s, must be one of socks5, socks4, http." % self.proxy[0])

  def add_article(self, message_id):
    self.queue.put(message_id)

  def send(self, message, state='sending'):
    #FIXME: readd message_id if conn_broken
    #FIXME: ^ add message_id as additional argument
    #TODO: do the actual reading and sending here as well, including converting
    #TODO: ^ provide file FD as argument so reply to remote can be checked first
    self.state = state
    sent = 0
    length = len(message)
    while sent != length:
      if sent > 0:
        self.log(self.logger.DEBUG, 'resending part of line, starting at %i to %i' % (sent, length))
      try:
        sent += self.socket.send(message[sent:])
      except socket.error as e:
        if e.errno == 11:
          # 11 Resource temporarily unavailable
          time.sleep(0.1)
        elif e.errno in (32, 104, 110):
          # 32 Broken pipe
          # 104 Connection reset by peer
          # 110 Connection timed out
          self.con_broken = True
          break
        else:
          self.log(self.logger.ERROR, 'got an unknown socket error at line 124 with error number %i: %s' % (e.errno, e))
          self.con_broken = True
          break
      except sockssocket.ProxyError as e:
        self.log(self.logger.ERROR, 'got an unknown proxy error at socket.send(), line 402 with error number %i: %s' % (e.errno, e))
        self.con_broken = True
        break
    self.log(self.logger.VERBOSE, 'out: %s' % message[:-2])
    return sent

  def shutdown(self):
    # FIXME socket.shutdown() needed if running == False?
    self.running = False
    try:
      self.socket.shutdown(socket.SHUT_RDWR)
    except socket.error as e:
      if e.errno not in (9, 107):   # 9 == bad filedescriptor, 107 == not connected
        raise e

  def cooldown(self, additional_message=''):
    # FIXME write that fuckin self.log() def already!
    if self.cooldown_counter == 0:
      self.cooldown_counter += 1
      return
    if self.cooldown_counter == 10:
      self.log(self.logger.DEBUG, '%ssleeping %s seconds' % (additional_message, self.cooldown_period * self.cooldown_counter))
    else:
      self.log(self.logger.INFO, '%ssleeping %s seconds' % (additional_message, self.cooldown_period * self.cooldown_counter))
    end_time = int(time.time()) + self.cooldown_period * self.cooldown_counter
    while self.running and int(time.time()) < end_time:
      time.sleep(2)
    if self.cooldown_counter != 10:
      self.cooldown_counter += 1

  def _bump_outstream_qsize(self):
    self.qsize = self.queue.qsize() + len(self.articles_to_send) + len(self.rechecking)

  def run(self):
    self.sqlite_dropper = self._db_connector('dropper', timeout=60)
    self.running = True
    connected = False
    self.multiline = False
    self.multiline_out = False
    self.cooldown_period = 60
    self.cooldown_counter = 0
    if not self.outstream:
      self.log(self.logger.INFO, 'connection established')
      self.send(self.welcome + '\r\n')
    else:
      self.articles_to_send = set()
      cooldown_msg = ''
      while self.running and not connected:
        self._bump_outstream_qsize()
        self.state = 'cooldown'
        self.cooldown(cooldown_msg)
        if not self.running:
          break
        self.state = 'connecting'
        try:
          self.socket.connect((self.host, self.port))
          connected = True
          if self.cooldown_counter == 10:
            self.log(self.logger.DEBUG, 'connection established via proxy %s' % str(self.proxy))
          else:
            self.log(self.logger.INFO, 'connection established via proxy %s' % str(self.proxy))
        except socket.error as e:
          if e.errno == 9:
            # Bad file descriptor
            self.init_socket()
            cooldown_msg = "can't connect: %s. " % e
          elif e.errno == 106:
            # tunnelendpoint already connected. wtf? only happened via proxy
            # FIXME debug this
            self.log(self.logger.ERROR, '%s: setting connected = True' % e)
            connected = True
          elif e.errno in (111, 113):
            # 111 Connection refused
            # 113 no route to host
            cooldown_msg = "can't connect: %s. " % e
          else:
            self.log(self.logger.ERROR, 'unhandled initial connect socket.error: %s' % e)
            self.log(self.logger.ERROR, traceback.format_exc())
            cooldown_msg = "can't connect: %s. " % e
        except sockssocket.ProxyError as e:
          uni_msg = '[Errno {}] {}'.format(*e.message)
          cooldown_msg = "can't connect: %s. " % uni_msg
          if e.message[0] == 4:
            # Host unreachable
            pass
          else:
            self.log(self.logger.ERROR, 'unhandled initial connect ProxyError: %s' % uni_msg)
            self.log(self.logger.ERROR, traceback.format_exc())
    self.state = 'idle'
    poll = select.poll()
    poll.register(self.socket.fileno(), select.POLLIN | select.POLLPRI)
    poll = poll.poll
    incoming_file = HandleIncoming(infeed_name=self.name)
    self.con_broken = False
    in_buffer = ''
    while self.running:
      if self.con_broken:
        if not self.outstream:
          self.log(self.logger.INFO, 'not an outstream, terminating')
          break
        else:
          connected = False
          self._outstream_flags_init()
          try:
            self.socket.shutdown(socket.SHUT_RDWR)
          except socket.error as e:
            #if self.debug > 4: print "[{0}] {1}".format(self.name, e)
            pass
          self.socket.close()
          self.init_socket()
          while self.running and not connected:
            self._bump_outstream_qsize()
            # TODO create def connect(), use self.vars for buffer, connected and poll
            if self.qsize == 0:
              self.log(self.logger.INFO, 'connection broken. no article to send, sleeping')
              self.state = 'nothing_to_send'
              while self.running and self.queue.qsize() == 0:
                time.sleep(2)
            else:
              self.state = 'cooldown'
              self.cooldown('connection broken. ')
            if not self.running:
              break
            self.state = 'connecting'
            self.log(self.logger.INFO, 'reconnecting..')
            try:
              self.socket.connect((self.host, self.port))
              if self.cooldown_counter == 10:
                self.log(self.logger.DEBUG, 'connection established via proxy %s' % str(self.proxy))
              else:
                self.log(self.logger.INFO, 'connection established via proxy %s' % str(self.proxy))
              connected = True
              self.con_broken = False
              poll = select.poll()
              poll.register(self.socket.fileno(), select.POLLIN | select.POLLPRI)
              poll = poll.poll
              in_buffer = ''
              self.multiline = False
              self.reconnect = False
              self.state = 'idle'
            except socket.error as e:
              # FIXME: check sockssocket sources again, might be required to recreate the proxy with break as well
              self.log(self.logger.ERROR, 'unhandled reconnect socks.error: %s' % e)
            except sockssocket.ProxyError as e:
              self.log(self.logger.ERROR, 'unhandled reconnect ProxyError: %s' % e)
              #if self.debug > 1: print "[%s] recreating proxy socket" % self.name
              break
          if not self.running: break
          if not connected: continue
      if poll(self.polltimeout):
        self.state = 'receiving_article' if self.multiline else 'receiving'
        cur_len = len(in_buffer)
        try:
          in_buffer += self.socket.recv(self.buffersize)
        except socket.error as e:
          self.log(self.logger.DEBUG, 'exception at socket.recv(): socket.error.errno: %s, socket.error: %s' % (e.errno, e))
          if e.errno == 11:
            # 11 Resource temporarily unavailable
            time.sleep(0.1)
            continue
          elif e.errno == 32 or e.errno == 104 or e.errno == 110:
            # 32 Broken pipe
            # 104 Connection reset by peer
            # 110 Connection timed out
            self.con_broken = True
            continue
          else:
            # FIXME: different OS might produce different error numbers. make this portable.
            self.log(self.logger.ERROR, 'got an unknown socket error at socket.recv() at line 272 with error number %i: %s' % (e.errno, e))
            self.log(self.logger.ERROR, traceback.format_exc())
            self.con_broken = True
            continue
        except sockssocket.ProxyError as e:
          self.log(self.logger.ERROR, 'exception at socket.recv(); sockssocket.proxy error.errno: %i, sockssocket.proxy error: %s' % (e.errno, e))
          self.con_broken = True
          continue
            #if self.debug > 1: print "[{0}] connection problem: {1}".format(self.name, e)
            #self.con_broken = True
            #break
        received = len(in_buffer) - cur_len
        #print "[{0}] received: {1}".format(self.name, received)
        if received == 0:
          self.con_broken = True
          continue
        if not '\r\n' in in_buffer:
          continue
        parts = in_buffer.split('\r\n')
        if in_buffer[-2:] == '\r\n':
          in_buffer = ''
          #print "[{0}] received full message with {1} parts".format(self.name, len(parts) - 1)
        else:
          in_buffer = parts[-1]
          #print "[{0}] received incomplete message with {1} valid parts".format(self.name, len(parts) - 1)
        del parts[-1]
        for part in parts:
          if not self.multiline:
            self.handle_line(part)
          elif len(part) != 1:
            incoming_file.add(part)
            self.log(self.logger.VERBOSE, 'multiline in: %s' % part)
          else:
            if part[0] == '.':
              incoming_file.complit()
              self.handle_multiline(incoming_file)
              incoming_file.bye()
              self.multiline = False
              incoming_file = HandleIncoming(infeed_name=self.name)
            else:
              incoming_file.add(part)
              self.log(self.logger.VERBOSE, 'multiline in: %s' % part)
          if not self.multiline:
            self.state = 'idle'
        continue
      else:
        #print "[{0}] timeout hit, state = {1}".format(self.name, self.state)
        if self.outstream_ready and self.state == 'idle':
          #print "[{0}] queue size: {1}".format(self.name, self.queue.qsize())
          self._recheck_sending()
          if self.outstream_stream:
            if len(self.articles_to_send) > 0:
              self._worker_send_article_stream()
            else:
              self._worker_send_check_stream()
            self.state = 'idle'
          elif self.queue.qsize() > 0 and not self.con_broken:
            #print "[{0}] got message-id {1}".format(self.name, self.message_id)
            if self.outstream_ihave:
              self._send_new_check('IHAVE')
            elif self.outstream_post:
              self.message_id = self.queue.get()
              self.send('POST\r\n')
          self._bump_outstream_qsize()
    self.log(self.logger.INFO, 'client disconnected')
    incoming_file.bye()
    self.socket.close()
    self.sqlite_dropper.close()
    self.SRNd.terminate_feed(self.name)

  def _worker_send_check_stream(self, max_check=50):
    self._bump_outstream_qsize()
    count = 0
    while self.queue.qsize() > 0 and count <= max_check and not self.con_broken:
      # FIXME why self.message_id here? IHAVE and POST makes sense, but streaming?
      # FIXME: add CHECK statements to list and send the whole bunch after the loop
      self._send_new_check('CHECK')
      count += 1

  def _worker_send_article_stream(self, send_time=120):
    self._bump_outstream_qsize()
    start_time = int(time.time())
    while len(self.articles_to_send) > 0 and start_time + send_time > int(time.time()) and not self.con_broken:
      message_id = self.articles_to_send.pop()
      if os.path.exists(os.path.join('articles', message_id)):
        self.send('TAKETHIS {0}\r\n'.format(message_id))
        self.send_article(message_id, 'outfeed_send_article_stream')
        self.qsize -= 1

  def _send_new_check(self, cmd):
    """ Collect IHAVE and CHECK article id and re-add in queue if don't response or connect broken when send this """
    self.message_id = self.queue.get()
    if os.path.exists(os.path.join('articles', self.message_id)):
      self.log(self.logger.DEBUG, 'send {} {}'.format(cmd, self.message_id))
      self.send('{} {}\r\n'.format(cmd, self.message_id), 'outfeed_send_{}_stream'.format(cmd))
      if self.con_broken:
        self.log(self.logger.DEBUG, 'conn_broken while sending {} {}. Re-adding in queue'.format(cmd, self.message_id))
        self.add_article(self.message_id)
      else:
        self._recheck_sending(self.message_id, 'add')

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

  @staticmethod
  def _read_and_prepare(fd, buffsize):
    data = ''
    while True:
      data_in = fd.read(buffsize)
      if not data_in: break
      data += data_in
      prepare = data.split('\n')
      data = prepare.pop(-1)
      for index in range(len(prepare)):
        if prepare[index].startswith('.'):
          prepare[index] = '.' + prepare[index]
      if len(prepare) > 0:
        yield '\r\n'.join(prepare) + '\r\n'
    # fix broken article
    if len(data) > 0:
      if data[-1] != '\n':
        data += '\r\n'
      yield data

  def _disallow_to_send(self, message_id):
    if self._max_send_size is not None and self._max_send_size < os.path.getsize(os.path.join('articles', message_id)):
      self.log(self.logger.INFO, 'not sending article {}. Server allow max file size {} bytes'.format(message_id, self._max_send_size))
      return True
    return False

  def send_article(self, message_id, state='sending_article'):
    if self._disallow_to_send(message_id):
      self.update_trackdb('000 {} disallow to send'.format(message_id))
      return
    self.log(self.logger.INFO, 'sending article %s' % message_id)
    start_time = time.time()
    buff = 16384
    self.multiline_out = True
    sending = 0
    with open(os.path.join('articles', message_id), 'rb') as fd:
      for to_send in self._read_and_prepare(fd, buff):
        sending += self.send(to_send, state)
        if self.con_broken:
          break
    if not self.con_broken:
      self.send('.\r\n', state)
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
    self.multiline_out = False

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
    self.send('MODE STREAM\r\n')
    self.send('MODE STREAM\r\n')

  def handle_line(self, line):
    self.log(self.logger.VERBOSE, 'in: %s' % line)
    commands = line.upper().split(' ')
    if len(commands) == 0:
      self.log(self.logger.VERBOSE, 'should handle empty line')
      return
    if self.outstream:
      if not self.outstream_ready:
        if commands[0] == 'SRNDAUTH':
          self.cooldown_counter = 0
          # server required SRDNAUTH
          if len(commands) == 2:
            self._outfeed_SRNDAUTH(commands[1])
          else:
            self.log(self.logger.ERROR, 'Recived incorrect SRNDAUTH. Authentication is not possible: {}'.format(line))
            self.cooldown_counter = 3
            self.con_broken = True
        elif commands[0] == '101':
          # check CAPABILITES
          self.waitfor = 'CAPABILITIES'
          self.multiline = True
        elif commands[0] == '200':
          self.cooldown_counter = 0
          # send CAPABILITES
          self.send('CAPABILITIES\r\n')
        elif commands[0] == '203':
          # MODE STREAM test successfull
          self.outstream_stream = True
          self.outstream_ready = True
        elif commands[0] == '191':
          # SUPPORT 191 = receive varlist
          self.waitfor = 'SUPPORT'
          self.multiline = True
        elif commands[0] == '281':
          # SRNDAUTH 281 - access granted. send CAPABILITES, again
          if len(commands) > 1:
            self.log(self.logger.INFO, 'successful login using key {}'.format(commands[1].lower()))
          self.send('CAPABILITIES\r\n')
        elif commands[0] == '501' or commands[0] == '500':
          if self.outstream_currently_testing == '':
            # MODE STREAM test failed
            self.outstream_currently_testing = 'IHAVE'
            self.send('IHAVE <thisarticledoesnotexist>\r\n')
          elif self.outstream_currently_testing == 'IHAVE':
            # IHAVE test failed
            self.outstream_post = True
            self.outstream_ready = True
            if self.queue.qsize() > 0:
              self.message_id = self.queue.get()
              self.send('POST\r\n')
        elif commands[0] == '435':
          # IHAVE test successfull
          self.outstream_ihave = True
          self.outstream_ready = True
        elif commands[0] == '335':
          # IHAVE test successfull
          self.send('.\r\n')
          self.outstream_ihave = True
          self.outstream_ready = True
        elif commands[0] in ('481', '482'):
          # SRNDAUTH 481 - key not allowed at this server
          self.log(self.logger.WARNING, 'You key not allowed at this server')
        elif commands[0] == '482':
          # SRNDAUTH 482 - bad key or signature
          self.log(self.logger.WARNING, 'bad key or signature')
        else:
          self.log(self.logger.WARNING, 'got unknown command: {}'.format(line))
        # FIXME how to treat try later for IHAVE and CHECK?
        return
      if commands[0] == '200':
        # TODO check specs for reply 200 again, only valid as first welcome line?
        self.cooldown_counter = 0
        return
      if self.outstream_stream:
        if commands[0] == '238':
          # CHECK 238 == article wanted
          article_wanted = line.split(' ')[1]
          self.articles_to_send.add(article_wanted)
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
            self.send('POST\r\n')
        elif commands[0] == '440':
          # POST 440 == posting not allowed
          self.log(self.logger.ERROR, 'remote host does not allow MODE STREAM, IHAVE or POST. shutting down')
          self.running = False
          try:
            self.socket.shutdown(socket.SHUT_RDWR)
          except:
            pass
        else:
          self.log(self.logger.ERROR, 'unknown response to POST: %s' % line)
      return
    elif not self._srnd_auth:
      # authentication required
      if commands[0] == 'SRNDAUTH':
        self._infeed_SRNDAUTH(commands[1:])
      else:
        self._infeed_SRNDAUTH([])
    elif commands[0] == 'CAPABILITIES':
      for cap in self.caps:
        self.send(cap + '\r\n')
      self.send('.\r\n')
    elif commands[0] == 'SUPPORT':
      # 191 - initial SUPPORT reply
      self.send('191 i support:\r\n')
      # send support options. Format '<KEY> <value>\r\n'
      # read direct option from infeeds config and send is as
      for conf_key in self.config:
        if conf_key.upper().startswith('SUPPORT_'):
          self.send('{} {}\r\n'.format(conf_key.upper()[8:], self.config[conf_key]))
      self.send('.\r\n')
    elif commands[0] == 'MODE' and len(commands) == 2 and commands[1] == 'STREAM':
      self.send('203 stream as you like\r\n')
    #elif commands[0] == 'MODE' and commands[1] == 'READER':
    #  self.send('502 i recommend in check to the CAPABILITIES\r\n')
    elif commands[0] == 'QUIT':
      self.send('205 bye bye\r\n')
      self.state = 'closing down'
      self.running = False
      self.socket.shutdown(socket.SHUT_RDWR)
    elif commands[0] == 'CHECK' and len(commands) == 2:
      #TODO 431 message-id   Transfer not possible; try again later
      message_id = line.split(' ', 1)[1]
      if '/' in message_id:
        self.send('438 {0} illegal message-id\r\n'.format(message_id))
        return
      if os.path.exists(os.path.join('articles', message_id)) or os.path.exists(os.path.join('incoming', message_id)):
        self.send('438 {0} i know this article already\r\n'.format(message_id))
        return
      if os.path.exists(os.path.join('articles', 'censored', message_id)):
        self.send('438 {0} article is blacklisted\r\n'.format(message_id))
        #print "[%s] CHECK article blacklisted: %s" % (self.name, message_id)
        return
      self.articles_to_receive.add(message_id)
      self.qsize = len(self.articles_to_receive)
      self.send('238 {0} go ahead, send to the article\r\n'.format(message_id))
    elif commands[0] == 'TAKETHIS' and len(commands) == 2:
      self.waitfor = 'article'
      self.variant = 'TAKETHIS'
      self.message_id_takethis = line.split(' ', 1)[1]
      self.multiline = True
    elif commands[0] == 'POST':
      self.send('340 go ahead, send to the article\r\n')
      self.waitfor = 'article'
      self.variant = 'POST'
      self.multiline = True
    elif commands[0] == 'IHAVE':
      arg = line.split(' ', 1)[1]
      if '/' in arg:
        self.send('435 illegal message-id\r\n')
        return
      #if self.sqlite_dropper.execute('SELECT message_id FROM articles WHERE message_id = ?', (arg,)).fetchone():
      if os.path.exists(os.path.join('articles', arg)) or os.path.exists(os.path.join('incoming', arg)):
        self.send('435 already have this article\r\n')
        return
      if os.path.exists(os.path.join('articles', 'censored', arg)):
        self.send('435 article is blacklisted\r\n')
        #print "[%s] IHAVE article blacklisted: %s" % (self.name, arg)
        return
      #TODO: add currently receiving same message_id from another feed == 436, try again later
      self.send('335 go ahead, send to the article\r\n'.format(arg))
      self.waitfor = 'article'
      self.variant = 'IHAVE'
      self.multiline = True
    elif commands[0] == 'STAT':
      if len(commands) == 1:
        # STAT without arguments
        if self.current_group_id == -1:
          self.send('412 i much recommend in select to the newsgroup first\r\n')
        elif self.current_article_id == -1:
          self.send('420 i claim in current group is empty\r\n')
        else:
          message_id = self.sqlite_dropper.execute('SELECT message_id FROM articles WHERE group_id = ? AND article_id = ?', (self.current_group_id, self.current_article_id)).fetchone()
          if message_id:
            message_id = message_id[0]
            self.send('223 {0} {1}\r\n'.format(self.current_article_id, message_id))
          else:
            self.log(self.logger.CRITICAL, 'internal state messed up. current_article_id does not have connected message_id')
            self.log(self.logger.CRITICAL, 'current_group_id: %s, current_article_id: %s' % (self.current_group_id, self.current_article_id))
        return
      if len(commands) != 2:
        self.send('501 i much recommend in speak to the proper NNTP\r\n')
        return
      try:
        arg = int(commands[1])
        # STAT argument is article_id
        if self.current_group_id == -1:
          self.send('412 i much recommend in select to the newsgroup first\r\n')
        else:
          message_id = self.sqlite_dropper.execute('SELECT message_id FROM articles WHERE group_id = ? AND article_id = ?', (self.current_group_id, arg)).fetchone()
          if message_id:
            message_id = message_id[0]
            self.current_article_id = arg
            self.send('223 {0} {1}\r\n'.format(self.current_article_id, message_id))
          else:
            self.send('423 i claim such == invalid number\r\n')
      except ValueError:
        arg = line.split(' ')[1]
        # STAT argument is message_id
        #if self.sqlite_dropper.execute('SELECT message_id FROM articles WHERE message_id = ?', (arg,)).fetchone():
        if os.path.exists(os.path.join('articles', arg)):
          self.send('223 0 {0}\r\n'.format(arg))
        else:
          self.send('430 i do not know much in {0}\r\n'.format(arg))
    else:
      self.send('501 {} unknown. I much recommend in speak to the proper NNTP based on CAPABILITIES\r\n'.format(commands[0]))

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

  def _check_SUPPORT(self, varlist):
    for line in varlist:
      key, val = line.split(' ', 1)
      self.log(self.logger.DEBUG, 'Server support key="{}", value="{}"'.format(key, val))
      if key == 'MAX_SEND_SIZE':
        try:
          self._max_send_size = int(val)
        except ValueError:
          pass
        else:
          if self._max_send_size < 20:
            self._max_send_size = None
        if self._max_send_size is None:
          self.log(self.logger.WARNING, 'Error parsing MAX_SEND_SIZE: abnormal value "{}"'.format(val))
        else:
          self.log(self.logger.INFO, 'Server support maximum filesize: {} bytes'.format(self._max_send_size))
    # initial start streaming
    self._send_MODESTREAM()

  def _check_CAPABILITIES(self, caps):
    self.log(self.logger.DEBUG, 'Server caps: {}'.format(caps))
    # WTF? Stop serving
    if 'STREAMING' not in caps:
      # hack for old servers
      if 'STREAMING' not in caps[-1]:
        self.log(self.logger.CRITICAL, "Server doesn't support STREAMING! EXTERMINATED!")
        self.shutdown()
        return
    # server support SUPPORT, send it and wait response 191
    if 'SUPPORT' in caps:
      self.send('SUPPORT\r\n')
    else:
      # server don't support SUPPORT, go stream
      self._send_MODESTREAM()

  def handle_multiline(self, handle_incoming):
    # TODO if variant != POST think about using message_id in handle_singleline for self.outfile = open(tmp/$message_id, 'w')
    # TODO also in handle_singleline: if os.path.exists(tmp/$message_id): retry later
    if  self.waitfor == 'SUPPORT':
      self.waitfor = ''
      self._check_SUPPORT(handle_incoming.header)
      return
    elif self.waitfor == 'CAPABILITIES':
      self.waitfor = ''
      self._check_CAPABILITIES(handle_incoming.header)
      return
    elif self.waitfor == 'article':
      self.byte_transfer += handle_incoming.read_byte
      self.time_transfer += handle_incoming.transfer_time
    else:
      self.log(self.logger.INFO, 'should handle multi line while waiting for %s:' % self.waitfor)
      self.log(self.logger.INFO, ''.join(handle_incoming.header))
      self.log(self.logger.INFO, 'should handle multi line end')
      self.waitfor = ''
      self.variant = ''
      return
    error = ''
    add_headers = list()
    self.articles_to_receive.discard(handle_incoming.message_id)
    self.qsize = len(self.articles_to_receive)

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
        handle_incoming.message_id = '{0}{1}@POSTED.SRNd'.format(rnd, int(time.time()))
        add_headers.append('Message-ID: {0}'.format(handle_incoming.message_id))
    elif '/' in handle_incoming.message_id:
      error += '/ in message-id, '
    if error != '':
      if self.variant == 'IHAVE':
        self.send('437 invalid article: {0}\r\n'.format(error[:-2]))
      elif self.variant == 'TAKETHIS':
        self.send('439 {0} invalid article: {1}\r\n'.format(self.message_id_takethis, error[:-2]))
        self.message_id_takethis = ''
      elif self.variant == 'POST':
        self.send('441 invalid article: {0}\r\n'.format(error[:-2]))
      # save in articles/invalid for manual debug
      add_headers.append('X-SRNd-invalid: {0}'.format(error[:-2]))
      add_headers.append('X-SRNd-source: {0}'.format(self.name))
      add_headers.append('X-SRNd-variant: {0}'.format(self.variant))
      handle_incoming.move_to(os.path.join('articles', 'invalid', '{0}-{1}'.format(self.name, int(time.time()))), add_headers)
      self.waitfor = ''
      self.variant = ''
      self.log(self.logger.INFO, 'article invalid %s: %s' % (handle_incoming.message_id, error[:-2]))
      return
    self.log(self.logger.DEBUG, 'article received {}. Large: {}'.format(handle_incoming.message_id, handle_incoming.file_large))
    # save article in tmp and mv to incoming
    if self.variant == 'POST':
      self.send('240 article received\r\n')
    elif self.variant == 'IHAVE':
      self.send('235 article received\r\n')
      #TODO: failed but try again later ==> 436
    elif self.variant == 'TAKETHIS':
      if os.path.exists(os.path.join('articles', handle_incoming.message_id)) or os.path.exists(os.path.join('incoming', handle_incoming.message_id)):
        self.send('439 {0} i know this article already\r\n'.format(handle_incoming.message_id))
        self.log(self.logger.DEBUG, 'rejecting already known article %s' % handle_incoming.message_id)
        return
      if os.path.exists(os.path.join('articles', 'censored', handle_incoming.message_id)):
        self.send('439 {0} article is blacklisted\r\n'.format(handle_incoming.message_id))
        self.log(self.logger.DEBUG, 'rejecting blacklisted article %s' % handle_incoming.message_id)
        return
      if not self._allow_groups(handle_incoming.newsgroups):
        self.send('439 {} article reject. group {} is blacklisted\r\n'.format(handle_incoming.message_id, handle_incoming.newsgroups))
        self.log(self.logger.DEBUG, 'rejecting article {}: group {} is blacklisted'.format(handle_incoming.message_id, handle_incoming.newsgroups))
        return
      self.send('239 {0} article received\r\n'.format(self.message_id_takethis))
      self.message_id_takethis = ''
    self.log(self.logger.INFO, 'article received and accepted %s' % handle_incoming.message_id)

    target = os.path.join('incoming', handle_incoming.message_id)
    if not os.path.exists(target):
      handle_incoming.move_to(target, add_headers)
    else:
      self.log(self.logger.INFO, 'got duplicate article: %s does already exist. removing temporary file' % target)
    self.waitfor = ''
    self.variant = ''

  def _check_sign(self, data):
    try:
      nacl.signing.VerifyKey(unhexlify(data[self._srndauth_requ[0]])).verify(sha512(data['secret']).digest(), unhexlify(data[self._srndauth_requ[1]]))
    except Exception as e:
      self.log(self.logger.DEBUG, 'could not verify signature: {}'.format(e))
      return False
    else:
      return True

  def _check_access_by_key(self, key):
    #TODO: Implement This
    return len(key) == 64

  def _infeed_SRNDAUTH(self, cmd_list):
    # empty, bad or first request
    if len(cmd_list) != 2 or 'secret' not in self._auth_data or cmd_list[0] not in self._srndauth_requ:
      #reinit and send
      self._auth_data = dict()
      self._auth_data['secret'] = ''.join(random.choice(string.ascii_uppercase+string.digits) for x in range(333))
      self.send('SRNDAUTH {}\r\n'.format(self._auth_data['secret']))
    else:
      self._auth_data[cmd_list[0]] = cmd_list[1].lower()
    # sleep 4-10s
    time.sleep(random.uniform(4, 10))
    # recive all data - check key
    if len(self._auth_data) == 3:
      if self._check_sign(self._auth_data):
        if self._check_access_by_key(self._auth_data[self._srndauth_requ[0]]):
          self._srnd_auth = True
          self.send('281 {} access granted\r\n'.format(self._auth_data[self._srndauth_requ[0]]))
        else:
          self.send('481 {} key not allowed at this server\r\n'.format(self._auth_data[self._srndauth_requ[0]]))
          self.log(self.logger.WARNING, '{} not allowed at this server'.format(self._auth_data[self._srndauth_requ[0]]))
      else:
        self.send('482 bad key or signature\r\n')
        self.log(self.logger.WARNING, 'bad key or signature, key="{}" signature="{}"'.format(self._auth_data[self._srndauth_requ[0]], self._auth_data[[1]]))
      del self._auth_data['secret']
      del self._auth_data[self._srndauth_requ[1]]
      if self._srnd_auth:
        self._set_infeed_pretty_name()
        self.log(self.logger.INFO, 'access granted for {}'.format(self._auth_data[self._srndauth_requ[0]]))
      else:
        del self._auth_data[self._srndauth_requ[0]]

  def _set_infeed_pretty_name(self):
    # rename infeed using pubkey
    if self.config.get('pretty_name', 'false').lower() in ('true', 'yes'):
      new_name = 'infeed-' + self._auth_data[self._srndauth_requ[0]]
      if self.SRNd.rename_infeed(self.name, new_name):
        self.name = new_name
      else:
        self.log(self.logger.WARNING, 'Error rename to {}'.format(new_name))

  def _outfeed_SRNDAUTH(self, secret):
    if 'srndauth_key' not in self.config:
      self.log(self.logger.ERROR, 'Server required SRDNAUTH and srndauth_key not in outfeed config.')
      self.shutdown()
      return
    pubkey = self._key_from_private(self.config['srndauth_key'])
    if pubkey is None:
      self.log(self.logger.ERROR, 'Private key invalid. Check srndauth_key in outfeed config')
      self.shutdown()
      return
    if len(secret) != 333:
      self.log(self.logger.WARNING, 'Response secret {} != 333. Authentication is not possible.'.format(len(secret)))
      self.cooldown_counter = 3
      self.con_broken = True
      return
    sign = self._create_sign(self.config['srndauth_key'], secret)
    if sign is not None:
      self.send('SRNDAUTH {} {}\r\n'.format(self._srndauth_requ[0], pubkey))
      self.send('SRNDAUTH {} {}\r\n'.format(self._srndauth_requ[1], sign))

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

class HandleIncoming(object):
  def __init__(self, infeed_name='_unnamed_', tmp_path=os.path.join('incoming', 'tmp')):
    self._tmp_path = tmp_path
    self._infeed_name = infeed_name
    self._article_path = os.path.join(tmp_path, self._get_random_id())

    self.body_found = False
    self.read_byte = 0
    self.file_large = False
    self.message_id = ''
    self.newsgroups = ''
    self.header = list()
    self.transfer_time = 0.0
    # if file size > _max_file_to_ram - save data in file.
    self._max_file_to_ram = 3 * 10 ** 6 # 3MB
    self._article_data = list()
    self._open_article = None
    self._no_data = False
    self._complit = False
    self._start_transfer = 0

  def _get_random_id(self):
    return '{}-{}-{}'.format(self._infeed_name, ''.join(random.choice(string.ascii_lowercase) for x in range(10)), int(time.time()))

  def _write(self, line):
    if not self.file_large and self.read_byte > self._max_file_to_ram:
      self._full_flush()
      self.file_large = True
    if self.file_large:
      self._open_article.write('{}\n'.format(line))
    else:
      self._article_data.append(line)

  def _add_headers(self, headers):
    if not self.file_large:
      self._article_data[0:0] = headers
    else:
      new_path = os.path.join(self._tmp_path, self._get_random_id())
      headers.append('')
      with open(new_path, 'w') as o, open(self._article_path, 'r') as i:
        o.write('\n'.join(headers))
        o.write(i.read())
      os.remove(self._article_path)
      self._article_path = new_path

  def _full_flush(self):
    if self.file_large:
      pass
    else:
      self._open_article = open(self._article_path, 'w')
      self._open_article.write('\n'.join(self._article_data))
      self._open_article.write('\n')
      del self._article_data[:]

  def add(self, line):
    if self._no_data or self._complit:
      raise Exception("article object already complit. Don't use add()")
    if not self.body_found and line == '':
      self.body_found = True
    if line.startswith('.'):
      line = line[1:]
    self._write(line)
    if not self.body_found:
      if line.lower().startswith('message-id:'):
        self.message_id = line.split(' ', 1)[1]
      elif line.lower().startswith('newsgroups:'):
        self.newsgroups = line.split(' ', 1)[1]
      self.header.append(line)
    self.read_byte += len(line) + 2
    if self._start_transfer == 0:
      self._start_transfer = time.time()

  def move_to(self, path, add_headers=None):
    if not self._complit:
      raise Exception("call complit before using move_to()")
    if self._no_data:
      raise Exception("article object already moved. Don't use move_to()")
    if add_headers is not None and len(add_headers) > 0:
      self._add_headers(add_headers)
    self._full_flush()
    self.complit()
    self._no_data = True
    os.rename(self._article_path, path)

  def complit(self):
    if not self._complit:
      self.transfer_time = time.time() - self._start_transfer
      self._complit = True
    if self._open_article is not None:
      self._open_article.close()

  def bye(self):
    self._complit = True
    self._no_data = True
    if os.path.isfile(self._article_path):
      os.remove(self._article_path)
