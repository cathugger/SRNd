#!/usr/bin/python

import select
import socket
import threading
import time
import traceback
import os
from binascii import hexlify, unhexlify

import nacl.signing

import feeds.sockssocket as sockssocket
from feeds.feed_utils import InBuffer, HandleIncoming

class BaseFeed(threading.Thread):

  def log(self, loglevel, message):
    if loglevel >= self.loglevel:
      self.logger.log(self.name, message, loglevel)

  def __init__(self, master, logger, debug, name):
    threading.Thread.__init__(self)
    self._MODE_REVERS = (
        'none',
        'stream',
        'ihave',
        'post',
        'reader'
    )
    self._MODE = {x: self._MODE_REVERS.index(x) for x in self._MODE_REVERS}
    self.state = 'init'
    self.loglevel = debug
    self.logger = logger
    self.SRNd = master
    self.name = name
    self.socket = None
    self.buffersize = 2**16
    self.qsize = 0
    # outfeed - to sending, infeed - to waiting
    self.articles_queue = set()
    self.byte_transfer = 0
    self.time_transfer = 0.1
    self._srnd_auth = False
    self._handshake_state = False
    self.running = False
    self.terminated = False
    self.waitfor = ''
    self.variant = ''
    self.con_broken = ''
    self._SRNDAUTH_REQU = ('PUBKEY', 'SIGNATURE')
    self._current_mode = self._MODE['none']

  def run(self):
    self.running = True
    self.incoming_file = HandleIncoming(self.name)
    self.in_buffer = InBuffer()
    self.state = 'idle'
    if not self.terminated:
      self.main_loop()
    self.state = 'die'
    self.incoming_file.bye()
    self._socket_shutdown()
    self._socket_close()
    self.SRNd.terminate_feed(self.name)

  def shutdown(self):
    self.running = False
    # breaking all process
    self.con_broken = 'shutdown'
    self.terminated = True
    self._socket_shutdown()

  def main_loop(self):
    """will be rewrite in subclasses"""
    while self.running:
      time.sleep(2)

  def get_status(self, target=None):
    if target == 'state':
      return self.state
    elif target == 'qsize':
      return self.qsize
    elif target == 'byte_transfer':
      return self.byte_transfer
    elif target == 'time_transfer':
      return self.time_transfer
    elif target == 'mode':
      return self._MODE_REVERS[self._current_mode]
    else:
      return None

  def handle_multiline(self, handle_incoming):
    """will be rewrite in subclasses"""
    self.log(self.logger.INFO, 'should handle multi line while waiting for %s:' % self.waitfor)
    self.log(self.logger.INFO, ''.join(handle_incoming.header))
    self.log(self.logger.INFO, 'should handle multi line end')
    self.waitfor = ''
    self.variant = ''

  @staticmethod
  def _key_from_private(priv_key):
    try:
      return hexlify(nacl.signing.SigningKey(unhexlify(priv_key)).verify_key.encode())
    except:
      return None

  @staticmethod
  def valid_message_id(message_id):
    return message_id == os.path.basename(message_id) and message_id.startswith('<') and message_id.endswith('>') and '@' in message_id

  def handle_line(self, line):
    """will be rewrite in subclasses"""
    self.log(self.logger.VERBOSE, 'in: %s' % line)
    commands = line.upper().split(' ')
    if len(commands) == 0:
      self.log(self.logger.VERBOSE, 'should handle empty line')

  def send(self, message, state='sending'):
    r"""Send line or list, tuple adding \r\n, return sending count"""
    if not isinstance(message, str):
      to_send = ''.join(('\r\n'.join(message), '\r\n'))
    else:
      to_send = ''.join((message, '\r\n'))
    self.state = state
    sent = 0
    length = len(to_send)
    while sent != length and not self.con_broken:
      if sent > 0:
        self.log(self.logger.DEBUG, 'resending part of line, starting at %i to %i' % (sent, length))
      sent += self._socket_worker('send', to_send[sent:])
    self.log(self.logger.VERBOSE, 'out: %s' % to_send[:-2])
    return sent

  def _handle_received(self):
    """Read and parsing data receive by socket"""
    self.state = 'receiving_article' if self.in_buffer.multiline else 'receiving'
    self._socket_worker('recv')
    if not self.con_broken:
      for line in self.in_buffer.read():
        # multiline data complit if return False, '' != False. Processing..
        if line is False:
          self.incoming_file.complit()
          self.handle_multiline(self.incoming_file)
          self.incoming_file.bye()
          self.incoming_file = HandleIncoming(self.name)
        elif self.in_buffer.multiline:
          self.log(self.logger.VERBOSE, 'multiline in: %s' % line)
          self.incoming_file.add(line)
        else:
          self.handle_line(line)
      if not self.in_buffer.multiline and self._handshake_state:
        self.state = 'idle'

  @staticmethod
  def _read_article(fd, header=True, body=True):
    """Read full or head/body article from open file"""
    header_complit = False
    for line in fd:
      line = line[:-1]
      if not header_complit and not line:
        header_complit = True
        # send empty line
        if header and body:
          yield line
      # don't send body
      elif not body and header_complit:
        break
      # don't send header if header == False
      elif header or header_complit:
        yield line

  def _socket_worker(self, mode, data=None):
    """handle exceptions for self.socket.send and self.socket.recv. Return length data send or zero"""
    try:
      if mode == 'send':
        return self.socket.send(data)
      elif mode == 'recv' and not self.in_buffer.add(self.socket.recv(self.buffersize)):
        self.con_broken = 'socket connection closed'
    except socket.error as e:
      self.log(self.logger.DEBUG, 'exception at socket.recv(): socket.error.errno: %s, socket.error: %s' % (e.errno, e))
      if e.errno == 11:
        # 11 Resource temporarily unavailable
        time.sleep(0.1)
      else:
        self._socket_exception(e)
    except sockssocket.ProxyError as e:
      self._proxy_exception(e)
    return 0

  def _socket_exception(self, except_):
    """Base socket exception"""
    self.con_broken = except_
    if except_.errno in (32, 104, 110, 111, 113):
      # 32 Broken pipe
      # 104 Connection reset by peer
      # 110 Connection time out
      # 111 Connection refused
      # 113 no route to host
      pass
    else:
      # FIXME: different OS might produce different error numbers. make this portable.
      self.log(self.logger.ERROR, 'got an unknown socket error. {}: {}'.format(except_.errno, except_))
      self.log(self.logger.ERROR, traceback.format_exc())

  def _proxy_exception(self, except_):
    """Base proxy exception"""
    self.con_broken = '[Errno {}] {}'.format(*except_.message)
    if except_.message[0] in (0, 4):
      # 0 - connection closed unexpectedly
      # 4 - Host unreachable
      pass
    else:
      self.log(self.logger.ERROR, 'got an unknown sockssocket.proxy error. {}: {}'.format(except_.message[0], except_.message[1]))
      self.log(self.logger.ERROR, traceback.format_exc())

  def _socket_close(self):
    self._socket_release('close')

  def _socket_shutdown(self,):
    self._socket_release('shutdown')

  def _socket_release(self, act):
    if isinstance(self.socket, socket.socket):
      try:
        if act == 'shutdown':
          self.socket.shutdown(socket.SHUT_RDWR)
        elif act == 'close':
          self.socket.close()
      except socket.error as e:
        if e.errno not in (9, 107):   # 9 == bad filedescriptor, 107 == not connected
          raise e

  def _create_poll(self):
    poll = select.poll()
    poll.register(self.socket.fileno(), select.POLLIN | select.POLLPRI)
    return poll.poll
