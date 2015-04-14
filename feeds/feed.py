#!/usr/bin/python

import select
import socket
import threading
import time
import traceback

import feeds.sockssocket as sockssocket
from feeds.feed_utils import InBuffer, HandleIncoming

class BaseFeed(threading.Thread):

  def log(self, loglevel, message):
    if loglevel >= self.loglevel:
      self.logger.log(self.name, message, loglevel)

  def __init__(self, master, logger, debug, name):
    threading.Thread.__init__(self)
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
    self.con_broken = False
    self._srndauth_requ = ('X-PUBKEY-ED25519', 'X-SIGNATURE-ED25519-SHA512')

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
    self.con_broken = True
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
    else:
      return None

  def handle_multiline(self, handle_incoming):
    """will be rewrite in subclasses"""
    self.log(self.logger.INFO, 'should handle multi line while waiting for %s:' % self.waitfor)
    self.log(self.logger.INFO, ''.join(handle_incoming.header))
    self.log(self.logger.INFO, 'should handle multi line end')
    self.waitfor = ''
    self.variant = ''

  def handle_line(self, line):
    """will be rewrite in subclasses"""
    self.log(self.logger.VERBOSE, 'in: %s' % line)
    commands = line.upper().split(' ')
    if len(commands) == 0:
      self.log(self.logger.VERBOSE, 'should handle empty line')

  def _send(self, message, state='sending'):
    """Send raw data, return sending count"""
    self.state = state
    sent = 0
    length = len(message)
    while sent != length and not self.con_broken:
      if sent > 0:
        self.log(self.logger.DEBUG, 'resending part of line, starting at %i to %i' % (sent, length))
      sent += self._socket_worker('send', message[sent:])
    self.log(self.logger.VERBOSE, 'out: %s' % message[:-2])
    return sent

  def send(self, commands, state='sending'):
    r"""Send line or list, tuple adding \r\n """
    if not isinstance(commands, str):
      self._send(''.join(('\r\n'.join(commands), '\r\n')), state)
    else:
      self._send(''.join((commands, '\r\n')), state)

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

  def _socket_worker(self, mode, data=None):
    """handle exceptions for self.socket.send and self.socket.recv. Return length data send or zero"""
    try:
      if mode == 'send':
        return self.socket.send(data)
      elif mode == 'recv' and not self.in_buffer.add(self.socket.recv(self.buffersize)):
        self.con_broken = True
    except socket.error as e:
      self.log(self.logger.DEBUG, 'exception at socket.recv(): socket.error.errno: %s, socket.error: %s' % (e.errno, e))
      if e.errno == 11:
        # 11 Resource temporarily unavailable
        time.sleep(0.1)
      elif e.errno in (32, 104, 110):
        # 32 Broken pipe
        # 104 Connection reset by peer
        # 110 Connection timei out
        self.con_broken = True
      else:
        # FIXME: different OS might produce different error numbers. make this portable.
        self.log(self.logger.ERROR, 'got an unknown socket error at mode "{}". {}: {}'.format(mode, e.errno, e))
        self.log(self.logger.ERROR, traceback.format_exc())
        self.con_broken = True
    except sockssocket.ProxyError as e:
      self.log(self.logger.ERROR, 'got an unknown sockssocket.proxy error at mode "{}". {}: {}'.format(mode, e.errno, e))
      self.log(self.logger.ERROR, traceback.format_exc())
      self.con_broken = True
    return 0

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
