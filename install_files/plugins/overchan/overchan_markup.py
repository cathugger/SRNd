#!/usr/bin/python

import re
from hashlib import sha1

class OverchanMarkup(object):
  def __init__(self, overchandb=None, dropperdb=None, fake_id=False, disable_regexes=None, get_board_data=None):
    # disallow fake_id if dropperdb not connected
    self.fake_id = fake_id if dropperdb is not None else False
    self._overchandb = overchandb
    self._dropperdb = dropperdb
    self._group_id = None
    self._get_board_data = get_board_data
    if disable_regexes is None:
      disable_regexes = list()
    # disable quote if overchandb not connected
    if overchandb is None and 'linkit' not in disable_regexes:
      disable_regexes.append('linkit')
    self._regexes = self._compite_regexes(disable_regexes)

    self.upper_table = {
        '0': '1',
        '1': '2',
        '2': '3',
        '3': '4',
        '4': '5',
        '5': '6',
        '6': '7',
        '7': '8',
        '8': '9',
        '9': 'a',
        'a': 'b',
        'b': 'c',
        'c': 'd',
        'd': 'e',
        'e': 'f',
        'f': 'g'
    }

  def upp_it(self, data):
    if data[-1] not in self.upper_table:
      return data
    return data[:-1] + self.upper_table[data[-1]]

  def message_uid_to_fake_id(self, message_uid):
    fake_id = self._dropperdb.fetchone('SELECT article_id FROM articles WHERE message_id = ?', (message_uid,))
    return fake_id[0] if fake_id is not None else sha1(message_uid).hexdigest()[:10]


  def _compite_regexes(self, disable_regexes):
    regexes = dict()
    # AHTUNG: consistency is important!
    regexes['unbreakable_markup'] = [
        # make code blocks
        (re.compile(r'\[code](?!\[/code])(.+?)\[/code]', re.DOTALL), self._regex_codeit),
        # make [aa][/aa]
        (re.compile(r'\[aa](?!\[/aa])(.+?)\[/aa]', re.DOTALL), self._regex_sjisit)
    ]
    regexes['regular_markup'] = [
        # make >>post_id links
        (re.compile(r"(&gt;&gt;)([0-9a-f]{10})"), self._regex_linkit),
        # make >quotes
        (re.compile(r"^&gt;(?!&gt;[0-9a-f]{10}).*", re.MULTILINE), self._regex_quoteit),
        # make spoilers
        (re.compile(r"%% (?!\s) (.+?) (?!\s) %%", re.VERBOSE), self._regex_spoilit),
        # make <details> for [spoiler]
        (re.compile(r'\[spoiler](?!\[/spoiler])(.+?)\[/spoiler]', re.DOTALL), self._regex_largespoilit),
        # make <b>
        (re.compile(r"(?<![0-9a-zA-Z\x80-\x9f\xe0-\xfc*_/()]) \*\* (?![\s*_]) (.+?) (?<![\s*_]) \*\* (?![0-9a-zA-Z\x80-\x9f\xe0-\xfc*_/()])", re.VERBOSE), self._regex_boldit),
        (re.compile(r"(?<![0-9a-zA-Z\x80-\x9f\xe0-\xfc*_/()]) __ (?![\s*_]) (.+?) (?<![\s*_]) __ (?![0-9a-zA-Z\x80-\x9f\xe0-\xfc*_/()])", re.VERBOSE), self._regex_boldit),
        # make <i>
        (re.compile(r"(?<![0-9a-zA-Z\x80-\x9f\xe0-\xfc*_/()]) \* (?![\s*_]) (.+?) (?<![\s*_]) \* (?![0-9a-zA-Z\x80-\x9f\xe0-\xfc*_/()])", re.VERBOSE), self._regex_italit),
        # make <strike>
        (re.compile(r"(?<![0-9a-zA-Z\x80-\x9f\xe0-\xfc*_/()\-]) -- (?![\s*_-]) (.+?) (?<![\s*_-]) -- (?![0-9a-zA-Z\x80-\x9f\xe0-\xfc*_/()\-])", re.VERBOSE), self._regex_strikeit),
        # make underlined text
        (re.compile(r"(?<![0-9a-zA-Z\x80-\x9f\xe0-\xfc*_/()]) _ (?![\s*_]) (.+?) (?<![\s*_]) _ (?![0-9a-zA-Z\x80-\x9f\xe0-\xfc*_/()])", re.VERBOSE), self._regex_underlineit),
        # Make http:// urls in posts clickable
        (re.compile(r"(http://|https://|ftp://|mailto:|news:|irc:|magnet:\?|maggot://)([^\s\[\]<>'\"]*)"), self._regex_clickit)
    ]
    return self._regexes_remover(regexes, disable_regexes)

  @staticmethod
  def _regexes_remover(regexes, disable_regexes):
    new_regexes = {'unbreakable_markup': [], 'regular_markup': []}
    for reg_type in regexes:
      for target in regexes[reg_type]:
        if target[1].__name__[7:] not in disable_regexes:
          new_regexes[reg_type].append(target)
    return new_regexes

  def parse(self, message, group_id=None):
    self._group_id = group_id
    # perform parsing
    for regex, handler in self._regexes['unbreakable_markup']:
      if re.search(regex, message):
        # list indices: 0 - before [code], 1 - inside [code]...[/code], 2 - after [/code]
        message_parts = re.split(regex, message, maxsplit=1)
        # % fastet in python2.7. 3+ use join
        message = '%s%s%s' % (self.parse(message_parts[0], group_id), handler(message_parts[1]), self.parse(message_parts[2], group_id))
        return message
    for regex, handler in self._regexes['regular_markup']:
      message = regex.sub(handler, message)
    return message


  def _regex_linkit(self, rematch):
    row = self._overchandb.fetchall("SELECT article_uid, parent, group_id FROM articles WHERE article_hash >= ? and article_hash < ? LIMIT 2", (rematch.group(2), self.upp_it(rematch.group(2))))
    if not row or len(row) > 1:
      # hash not found or multiple matches for that 10 char hash
      return rematch.group(0)
    message_id, parent_id, group_id = row[0]
    if self._group_id is not None and group_id != self._group_id and self._get_board_data is not None:
      another_board = u' [%s]' % self._get_board_data(int(group_id), 'board')[:20]
    else:
      another_board = ''
    if self.fake_id:
      article_name = self.message_uid_to_fake_id(message_id)
    else:
      article_name = rematch.group(2)
    if parent_id == "":
      # article is root post
      return u'<a onclick="return highlight(\'{0}\');" href="thread-{0}.html">{1}{2}{3}</a>'.format(rematch.group(2), rematch.group(1), article_name, another_board)
    # article has a parent
    # FIXME: cache results somehow?
    parent = sha1(parent_id).hexdigest()[:10]
    return u'<a onclick="return highlight(\'{0}\');" href="thread-{1}.html#{0}">{2}{3}{4}</a>'.format(rematch.group(2), parent, rematch.group(1), article_name, another_board)

  @staticmethod
  def _regex_quoteit(rematch):
    return u'<span class="quote">%s</span>' % rematch.group(0).rstrip("\r")

  @staticmethod
  def _regex_clickit(rematch):
    return u'<a href="%s%s">%s%s</a>' % (rematch.group(1), rematch.group(2), rematch.group(1), rematch.group(2))

  @staticmethod
  def _regex_codeit(text):
    return u'<pre class="code">%s</pre>' % text

  @staticmethod
  def _regex_sjisit(text):
    return u'<pre class="aa">%s</pre>' % text

  @staticmethod
  def _regex_spoilit(rematch):
    return u'<span class="spoiler">%s</span>' % rematch.group(1)

  @staticmethod
  def _regex_largespoilit(rematch):
    return u'<details class="details">%s</details>' %rematch.group(1)

  @staticmethod
  def _regex_boldit(rematch):
    return u'<b>%s</b>' % rematch.group(1)

  @staticmethod
  def _regex_italit(rematch):
    return u'<i>%s</i>' % rematch.group(1)

  @staticmethod
  def _regex_strikeit(rematch):
    return u'<strike>%s</strike>' % rematch.group(1)

  @staticmethod
  def _regex_underlineit(rematch):
    return u'<span style="border-bottom: 1px solid">%s</span>' % rematch.group(1)

