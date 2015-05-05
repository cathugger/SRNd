#!/usr/bin/python

import random
import string
import os
import time
import zlib

class GzipError(Exception):
  pass

class InBuffer(object):
  def __init__(self):
    self.reset()

  def set_multiline(self):
    self.multiline = True

  def enable_gzip(self):
    if self._buffer:
      raise GzipError('enable gzip - buffer is not empty. WTF?')
    self._zip = zlib.decompressobj(zlib.MAX_WBITS | 16)

  def add(self, data):
    # no data. Need reconnection
    if not data:
      return False
    self._buffer += data if self._zip is None else self._decompress(data)
    if '\r\n' not in self._buffer:
      return True
    split_data = self._buffer.split('\r\n')
    self._buffer = split_data.pop(-1)
    self._data.extend(split_data)
    return True

  def _decompress(self, data):
    data = self._zip.decompress(data)
    if self._zip.unused_data:
      raise GzipError('decompress - received not compressed data. WTF?')
    return data

  def read(self):
    if self._data:
      for line in self._data:
        if line == '.':
          self.multiline = False
          # multiline is complit
          yield False
        else:
          yield line
      del self._data[:]

  def reset(self):
    self._zip = None
    self._buffer = ''
    self.multiline = False
    self._data = []

class Compressor(object):
  def __init__(self):
    self._zip = zlib.compressobj(9, zlib.DEFLATED, zlib.MAX_WBITS | 16)

  def compress(self, data):
    return self._zip.compress(data)

  def sync(self, data):
    return self._zip.compress(data) + self._zip.flush(zlib.Z_SYNC_FLUSH)

  def sync_force(self):
    return self._zip.flush(zlib.Z_SYNC_FLUSH)

class HandleIncoming(object):
  def __init__(self, infeed_name='_unnamed_', tmp_path=os.path.join('incoming', 'tmp')):
    self._tmp_path = tmp_path
    self._infeed_name = infeed_name
    self._reset()

  def _reset(self):
    self._article_path = os.path.join(self._tmp_path, self._get_random_id())
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
    self._remove_headers = None

  def remove_headers(self, headers):
    """Add header list, headers to be removed. Use this before adding lines"""
    self._remove_headers = [header.lower() for header in headers]

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
    if self._remove_headers and not self.body_found and line.split(':', 1)[0].lower() in self._remove_headers:
      return
    self._write(line)
    if not self.body_found:
      lower_line = line.lower()
      if lower_line.startswith('message-id: '):
        self.message_id = line.split(' ', 1)[1]
      elif lower_line.startswith('newsgroups: '):
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

  def reset(self):
    """Clear all data and set default state"""
    self.complit()
    self.bye()
    self._reset()

  def complit(self):
    if not self._complit:
      self.transfer_time = time.time() - self._start_transfer
      self._complit = True
    if self._open_article is not None:
      self._open_article.close()
      self._open_article = None

  def bye(self):
    self._complit = True
    self._no_data = True
    if os.path.isfile(self._article_path):
      os.remove(self._article_path)

