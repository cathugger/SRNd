#!/usr/bin/env python2

import time
import os
import mimetypes
mimetypes.init()
from binascii import unhexlify
from calendar import timegm
from datetime import datetime, timedelta
from email.feedparser import FeedParser
from email.utils import parsedate_tz
from hashlib import sha1, sha512

import nacl.signing

from srnd.utils import basicHTMLencode

class MessageParser(object):

  def __init__(self, fd):
    self.message = ''
    self.attachments = list()
    self.headers = {
        'subject': 'None',
        'sent': int(time.time()),
        'sender': 'Anonymous',
        'email': 'nobody@no.where',
        'group_name': '',
        'parent': '',
        'sage': False,
        'public_key': ''
    }
    self._signature = None
    self.signature_valid = None
    self._fd = fd
    self._parser = FeedParser()
    self._parse_headers()
    if self.headers and self.headers['public_key']:
      self._check_signature()

  def _parse_headers(self):
    headers_found = False
    line = self._fd.readline()
    while line:
      self._parser.feed(line)
      head, _, data = line.partition(': ')
      head = head.lower()
      data = data[:-1]
      if head == 'subject':
        self.headers['subject'] = basicHTMLencode(data[4:]) if data.lower().startswith('re: ') else basicHTMLencode(data)
      elif head == 'date':
        sent_tz = parsedate_tz(data)
        if sent_tz:
          offset = 0
          if sent_tz[-1]:
            offset = sent_tz[-1]
          self.headers['sent'] = timegm((datetime(*sent_tz[:6]) - timedelta(seconds=offset)).timetuple())
      elif head == 'from':
        sender, _, email = data.rpartition(' <')
        email = email.replace('>', '')
        if sender:
          self.headers['sender'] = sender
        if email:
          self.headers['email'] = email
      elif head == 'references':
        self.headers['parent'] = data.split(' ')[0]
      elif head == 'newsgroups':
        self.headers['group_name'] = data.split(';')[0].split(',')[0]
      elif head == 'x-sage':
        self.headers['sage'] = True
      elif head == 'x-pubkey-ed25519':
        self.headers['public_key'] = data
      elif head == 'x-signature-ed25519-sha512':
        self._signature = data
      elif line == '\n':
        headers_found = True
        break
      line = self._fd.readline()
    if not headers_found:
      self.headers = None

  def _check_signature(self):
    bodyoffset = self._fd.tell()
    hasher = sha512()
    oldline = None
    for line in self._fd:
      if oldline:
        hasher.update(oldline)
      oldline = line.replace("\n", "\r\n")
    hasher.update(oldline.replace("\r\n", ""))
    self._fd.seek(bodyoffset)
    try:
      nacl.signing.VerifyKey(unhexlify(self.headers['public_key'])).verify(hasher.digest(), unhexlify(self._signature))
    except:
      self.headers['public_key'] = ''
      self.signature_valid = False
    else:
      self.signature_valid = True
    del hasher

  @staticmethod
  def _read_filedata(part):
    data = dict()
    data['obj'] = part.get_payload(decode=True)
    if data['obj'] == None:
        data['obj'] = ''
    data['hash'] = sha1(data['obj']).hexdigest()
    data['name'] = 'empty_file_name' if part.get_filename() is None or part.get_filename().strip() == '' else basicHTMLencode(part.get_filename())
    data['ext'] = os.path.splitext(data['name'])[1].lower()
    data['type'] = mimetypes.types_map.get(data['ext'], '/')
    if data['type'] == '/':
      # mime not detected from file ext. Use remote mimetype for detection file ext. Ignore unknown mimetype.
      test_ext = mimetypes.guess_extension(part.get_content_type())
      if test_ext:
        data['ext'] = test_ext
        data['type'] = mimetypes.types_map.get(data['ext'], '/')
        data['name'] += data['ext']
    if len(data['name']) > 512:
      data['name'] = data['name'][:512] + '...'
    data['maintype'], data['subtype'] = data['type'].split('/', 2)
    return data

  def parse_body(self):
    self._parser.feed(self._fd.read())
    result = self._parser.close()
    self._parser = None
    if result.is_multipart():
      if len(result.get_payload()) == 1 and result.get_payload()[0].get_content_type() == "multipart/mixed":
        result = result.get_payload()[0]
      for part in result.get_payload():
        if part.get_content_type().lower() == 'text/plain':
          self.message += part.get_payload(decode=True)
        else:
          self.attachments.append(self._read_filedata(part))
    else:
      if result.get_content_type().lower() == 'text/plain':
        self.message += result.get_payload(decode=True)
      else:
        self.attachments.append(self._read_filedata(result))
    del result
    self.message = basicHTMLencode(self.message)
