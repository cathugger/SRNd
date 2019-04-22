#!/usr/bin/env python2

import time
import string
import random
import os
import cStringIO
from hashlib import sha256

import Image
import ImageFilter
import ImageDraw
import ImageFont

from srnd.utils import chrootRandom

class Captcha(object):
  def __init__(self, **kwargs):
    self.log = kwargs['log']
    self.logger = kwargs['logger']

    # +- captcha_len
    self._captcha_randomize = kwargs.get('captcha_randomize', 0)
    self._captcha_len = kwargs.get('captcha_len', 6)
    self._captcha_expires = kwargs.get('captcha_expires', 300)
    self._sercret = chrootRandom(32)
    self._whitelist = set()
    self._whitelist_maxlen = 300

    self._captcha = NewCaptcha(**kwargs) if kwargs.get('diff_mode') is not None else OriginCaptcha(**kwargs)
    cache_init = self._captcha.init_cache()
    if cache_init:
      self.log(self.logger.INFO, cache_init)
    self.cache_bump = self._captcha.cache_bump

  def _get_solution_hash(self, guess, expires, cookie):
    return sha256(sha256(self._sercret + cookie).digest() + sha256(guess).digest() + sha256(str(expires)).digest()).hexdigest()

  def _get_guess(self, str_set):
    return ''.join(random.choice(str_set) for x in range(self._captcha_len + random.randint(-self._captcha_randomize, self._captcha_randomize)))

  def _check_whitelist(self, solution_hash, expires):
    if (solution_hash, expires) in self._whitelist:
      self._whitelist.remove((solution_hash, expires))
      return True
    self.log(self.logger.WARNING, "captcha fake or replay detected: %s" % solution_hash)
    return False

  def _bump_whitelist(self, solution_hash, expires):
    if len(self._whitelist) >= self._whitelist_maxlen:
      is_remove = False
      current_time = int(time.time())
      # remove expired
      for item in [xx for xx in self._whitelist if xx[1] < current_time]:
        self._whitelist.remove(item)
        is_remove = True
      if not is_remove:
        self._whitelist.clear()
    self._whitelist.add((solution_hash, expires))

  @staticmethod
  def _img_to_b64(img):
    img_to_str = cStringIO.StringIO()
    img.save(img_to_str, 'PNG')
    content = img_to_str.getvalue()
    img_to_str.close()
    return content.encode("base64").replace("\n", "")

  def get_captcha(self, cookie=''):
    """return captcha image as base64, captcha expire as int, solution_hash as str"""
    return self._get_captcha(cookie)[:-1]

  def _get_captcha(self, cookie):
    guess = self._get_guess(self._captcha.alphabet)
    b64 = self._img_to_b64(self._captcha.captcha(guess))
    expires = int(time.time()) + self._captcha_expires
    solution_hash = self._get_solution_hash(guess, expires, cookie)
    self._bump_whitelist(solution_hash, expires)
    return b64, expires, solution_hash, guess

  def captcha_verify(self, expires, solution_hash, guess, cookie=''):
    guess = self._captcha.prepare_check(guess)
    try:
      expires = int(expires)
    except ValueError:
      return False
    current_time = int(time.time())
    if current_time > expires or expires - current_time > 3600:
      return False
    return solution_hash == self._get_solution_hash(guess, expires, cookie) and self._check_whitelist(solution_hash, expires)

class OriginCaptcha(object):
  def __init__(self, **kwargs):
    self._filter = kwargs.get('filter', ImageFilter.EMBOSS)
    self.alphabet = string.ascii_letters + string.digits
    for char in ('I', 'l', 'O', '0', 'k', 'K'):
      self.alphabet = self.alphabet.replace(char, '')
    self._fontdir = kwargs.get('fontdir', os.path.join('plugins', 'postman', 'fonts'))
    tiles_path = kwargs.get('tiles_path', os.path.join('plugins', 'postman', 'tiles'))
    self._captcha_tiles = [Image.open(os.path.join(tiles_path, xx)) for xx in os.listdir(tiles_path) if os.path.isfile(os.path.join(tiles_path, xx))]

  def captcha(self, guess):
    """ generate captcha """
    font = self._get_captcha_font()
    #if self.captcha_size is None: size = self.defaultSize
    #img = Image.new("RGB", (256,96))
    w, h, x, y = 300, 100, 30, 25
    w += random.randint(4, 50)
    h += random.randint(4, 50)
    x += random.randint(4, 50)
    y += random.randint(4, 50)
    tile = random.choice(self._captcha_tiles)
    img = Image.new("RGB", (w, h))
    for _ in range(10):
      offset = (random.uniform(0, 1), random.uniform(0, 1))
      for j in xrange(-1, int(img.size[1] / tile.size[1]) + 1):
        for i in xrange(-1, int(img.size[0] / tile.size[0]) + 1):
          dest = (int((offset[0] + i) * tile.size[0]),
                  int((offset[1] + j) * tile.size[1]))
          img.paste(tile, dest)
    draw = ImageDraw.Draw(img)
    #draw.text((40,20), guess, font=font, fill='white')
    draw.text((x, y), guess, font=font, fill='black')
    if self._filter:
      img = img.filter(self._filter)
    return img

  @staticmethod
  def init_cache():
    return ''

  @staticmethod
  def cache_bump():
    return True

  @staticmethod
  def prepare_check(guess):
    return guess

  def _get_captcha_font(self):
    """ get random font """
    font = os.path.join(self._fontdir, random.choice(os.listdir(self._fontdir)))
    return ImageFont.truetype(font, random.randint(32, 48))

class NewCaptcha(object):
  def __init__(self, **kwargs):
    self._diff_mode = kwargs['diff_mode']
    self._filter = kwargs.get('filter', ImageFilter.GaussianBlur(4))
    self.alphabet = string.ascii_uppercase + string.digits
    for char in ('I', 'O', '0', '1'):
      self.alphabet = self.alphabet.replace(char, '')

    self._fontdir = kwargs.get('fontdir', os.path.join('plugins', 'postman', 'fonts'))
    self.plazma_cache = dict()
    self.plazma_cache_size = 15
    self.plazma_cache['reusage'] = 0
    self.plazma_cache['plazma'] = [None] * self.plazma_cache_size
    self.plazma_cache['size'] = list()

  @staticmethod
  def prepare_check(guess):
    return guess.upper()

  def init_cache(self):
    check_time = time.time()
    self._init_cache()
    return 'new_captcha: init %s plazma cache in %s seconds...' % (self.plazma_cache_size, int(time.time() - check_time))

  def _init_cache(self):
    self.plazma_cache['size'] = [
        300 + random.randint(4, 50),
        100 + random.randint(4, 50)
    ]
    for x in xrange(self.plazma_cache_size):
      self.plazma_cache['plazma'][x] = self.__plazma(self.plazma_cache['size'][0], self.plazma_cache['size'][1])
    self.plazma_cache['reusage'] = random.randint(2, 5) * self.plazma_cache_size

  def _get_captcha_font(self):
    font_list = ('FreeSansBold.ttf', 'FreeSerifBold.ttf', 'FreeMonoBold.ttf')
    font = os.path.join(self._fontdir, font_list[random.randint(0, 2)])
    return ImageFont.truetype(font, random.randint(43, 54))

  def cache_bump(self):
    if self.plazma_cache['reusage'] <= 0:
      self._init_cache()
    return True

  def captcha(self, guess):
    font = self._get_captcha_font()
    if self.plazma_cache['reusage'] <= -5:
      self._init_cache()
    self.plazma_cache['reusage'] -= 1
    mask = Image.new('RGBA', (self.plazma_cache['size'][0], self.plazma_cache['size'][1]))
    font_width, _ = font.getsize(guess)
    font_width /= len(guess)

    x_offset = random.randint(-1, 1) * 5

    draw = ImageDraw.Draw(mask)
    for i in guess:
      x_offset += font_width + random.randint(1, 5)
      y_offset = random.randint(1, 7) * 5
      draw.text((x_offset + random.randint(-(font_width / 10), (font_width / 10)) * 2, y_offset), i, font=font)

    angle = random.randint(-2, 3) * 5
    mask = mask.rotate(angle)

    pattern_1 = pattern_2 = None
    while pattern_1 is pattern_2:
      pattern_1 = self.plazma_cache['plazma'][random.randint(0, self.plazma_cache_size - 1)]
      pattern_2 = self.plazma_cache['plazma'][random.randint(0, self.plazma_cache_size - 1)]

    result = Image.composite(pattern_1, pattern_2, mask)

    if self._filter is not None:
      for _ in range(self._diff_mode):
        result = result.filter(self._filter)
    return result

  def __plazma(self, width, height):
    plazma = Image.new('RGB', (width, height))
    pix = plazma.load()

    for xy in [(0, 0), (width-1, 0), (0, height-1), (width-1, height-1)]:
      rgb = []
      for _ in xrange(3):
        rgb.append(int(random.random()*256))
      pix[xy[0], xy[1]] = (rgb[0], rgb[1], rgb[2])

    self.__plazmaRec(pix, 0, 0, width-1, height-1)
    return plazma

  def __plazmaRec(self, pix, x1, y1, x2, y2):
    if (abs(x1 - x2) <= 1) and (abs(y1 - y2) <= 1):
      return
    rgb = []
    for i in xrange(3):
      rgb.append((pix[x1, y1][i] + pix[x1, y2][i])/2)
      rgb.append((pix[x2, y1][i] + pix[x2, y2][i])/2)
      rgb.append((pix[x1, y1][i] + pix[x2, y1][i])/2)
      rgb.append((pix[x1, y2][i] + pix[x2, y2][i])/2)

      tmp = (pix[x1, y1][i] + pix[x1, y2][i] +
             pix[x2, y1][i] + pix[x2, y2][i])/4
      diagonal = ((x1-x2)**2 + (y1-y2)**2)**0.5
      while True:
        delta = int(((random.random() - 0.5) / 100 * min(100, diagonal)) * 255)
        if (tmp + delta >= 0) and (tmp + delta <= 255):
          tmp += delta
          break
      rgb.append(tmp)

    pix[x1, (y1 + y2)/2] = (rgb[0], rgb[5], rgb[10])
    pix[x2, (y1 + y2)/2] = (rgb[1], rgb[6], rgb[11])
    pix[(x1 + x2)/2, y1] = (rgb[2], rgb[7], rgb[12])
    pix[(x1 + x2)/2, y2] = (rgb[3], rgb[8], rgb[13])
    pix[(x1 + x2)/2, (y1 + y2)/2] = (rgb[4], rgb[9], rgb[14])

    self.__plazmaRec(pix, x1, y1, (x1+x2)/2, (y1+y2)/2)
    self.__plazmaRec(pix, (x1+x2)/2, y1, x2, (y1+y2)/2)
    self.__plazmaRec(pix, x1, (y1+y2)/2, (x1+x2)/2, y2)
    self.__plazmaRec(pix, (x1+x2)/2, (y1+y2)/2, x2, y2)

