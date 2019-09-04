#!/usr/bin/env python2

import re
import string
import random
import os

def basicHTMLencode(inputString):
  return basicHTMLencodeNoStrip(inputString).strip(' \t\n\r')

def basicHTMLencodeNoStrip(inputString):
  html_escape_table = (("&", "&amp;"), ('"', "&quot;"), ("'", "&apos;"), (">", "&gt;"), ("<", "&lt;"),)
  for x in html_escape_table:
    inputString = inputString.replace(x[0], x[1])
  return inputString

def chrootRandom(n):
  """/dev/random emulator. Slow"""
  return ''.join([chr(random.randrange(0, 255)) for _ in xrange(n)])

def trydecode(msg):
  """Guess the encoding roulette"""
  for char_type in ('UTF-8', 'KOI8-R', 'cp1252', 'cp1251'):
    try:
      return msg.decode(char_type)
    except:
      pass
  return unicode(msg, errors='replace')

def str_reaper(msg, max_len=78):
  """accurately truncate the string"""
  return trydecode(msg)[:max_len].encode('UTF-8')

def valid_group_name(name):
  bad_char = ("&", '"', "'", '/', '\\', '<', '>')
  name2 = name.encode('ascii', 'ignore')
  if name2 != name:
    return False
  for char_ in bad_char:
    if char_ in name2:
      return False
  return True

def generate_pubkey_short_utf_8(full_pubkey_hex, length=6):
  pub_short = ''
  for x in range(0, length / 2):
    pub_short += '&#%i;' % (0x2590 + int(full_pubkey_hex[x*2:x*2+2], 16))
  length -= length / 2
  for x in range(0, length):
    pub_short += '&#%i;' % (0x2590 + int(full_pubkey_hex[-(length*2):][x*2:x*2+2], 16))
  return pub_short

def html_minifer(templates, ignored=None):
  old_size, new_size, count = 0, 0, 0
  for target in templates:
    if ignored is None or target not in ignored:
      count += 1
      html = templates[target].safe_substitute()
      old_size += len(html)
      html = __html_minifer(html)
      new_size += len(html)
      templates[target] = string.Template(html)
  diff = -int(float(old_size-new_size)/old_size * 100) if old_size > 0 else 0
  info = 'Minify {} html templates: old size={}, new size={}, difference={}%'.format(count, old_size, new_size, diff)
  return templates, info

def __html_minifer(html):
  # TODO: Improve this
  html = re.sub(r'\s+', ' ', html)
  return html

def css_minifer(css):
  """
  Thanks for Borgar
  https://stackoverflow.com/questions/222581/python-script-for-minifying-css
  """
  minifed_css = list()
  # remove comments - this will break a lot of hacks :-P
  css = re.sub(r'\s*/\*\s*\*/', "$$HACK1$$", css) # preserve IE<6 comment hack
  css = re.sub(r'/\*[\s\S]*?\*/', "", css)
  css = css.replace("$$HACK1$$", '/**/') # preserve IE<6 comment hack
  # url() doesn't need quotes
  css = re.sub(r'url\((["\'])([^)]*)\1\)', r'url(\2)', css)
  # spaces may be safely collapsed as generated content will collapse them anyway
  css = re.sub(r'\s+', ' ', css)
  # shorten collapsable colors: #aabbcc to #abc
  css = re.sub(r'#([0-9a-f])\1([0-9a-f])\2([0-9a-f])\3(\s|;)', r'#\1\2\3\4', css)
  # fragment values can loose zeros
  css = re.sub(r':\s*0(\.\d+([cm]m|e[mx]|in|p[ctx]))\s*;', r':\1;', css)
  for rule in re.findall(r'([^{]+){([^}]*)}', css):
    # we don't need spaces around operators
    selectors = [re.sub(r'(?<=[\[\(>+=])\s+|\s+(?=[=~^$*|>+\]\)])', r'', selector.strip()) for selector in rule[0].split(',')]
    # order is important, but we still want to discard repetitions
    properties = {}
    porder = []
    for prop in re.findall('(.*?):(.*?)(;|$)', rule[1]):
      css_key = prop[0].strip().lower()
      if css_key not in porder:
        porder.append(css_key)
      properties[css_key] = prop[1].strip()
    # output rule if it contains any declarations
    if properties:
      minifed_css.append("%s{%s}" % (','.join(selectors), ''.join(['%s:%s;' % (x, properties[x]) for x in porder])[:-1]))
  return '\n'.join(minifed_css)

def overchan_thread_unlink(path, name, ext='.html'):
  postfix = ''
  step = 50
  while True:
    target = os.path.join(path, name + postfix + ext)
    if os.path.isfile(target):
      try:
        os.unlink(target)
      except OSError as e:
        yield '{}: {}'.format(target, e)
    else:
      break
    postfix = '-%s' % step
    step += 100
