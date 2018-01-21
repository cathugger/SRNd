#!/usr/bin/python

import time
import sys
# for importing srnd.utils
sys.path.append('../../')

from captcha import Captcha

if __name__ == '__main__':
  class DummyLogger(object):
    VERBOSE = 'VERBOSE'
    DEBUG = 'DEBUG'
    INFO = 'INFO'
    WARNING = 'WARNING'
    ERROR = 'ERROR'
    CRITICAL = 'CRITICAL'
  def _log(lvl, msg):
    if lvl != 'WARNING':
      print('[{}] {}'.format(lvl, msg))

  def get_info(target, cookie=''):
    result = list(target._get_captcha(cookie)[1:])
    result.append(cookie)
    return result

  config = {'log': _log, 'logger': DummyLogger, 'fontdir': 'fonts', 'tiles_path': 'tiles'}

  start_time = time.time()
  testme = Captcha(**config)
  for xxx in range(100):
    cookiex = '' if xxx % 2 else str(time.time())
    data = get_info(testme, cookiex)
    if xxx % 2:
      data[0] += time.time()
      assert not testme.captcha_verify(*data), 'Error captcha_verify 1'
    else:
      assert testme.captcha_verify(*data), 'Error captcha_verify 2'
    assert not testme.captcha_verify(*data), 'Error captcha_verify - check_whitelist 3'
  print('Origin captcha tests ok: ', time.time() - start_time)

  start_time = time.time()
  config['diff_mode'] = 2
  testme = Captcha(**config)
  for xxx in range(100):
    cookiex = '' if xxx % 2 else str(time.time())
    data = get_info(testme, cookiex)
    data[2] = data[2].lower()
    if xxx % 2:
      data[0] += time.time()
      assert not testme.captcha_verify(*data), 'Error captcha_verify 4'
    else:
      assert testme.captcha_verify(*data), 'Error captcha_verify 5'
    assert not testme.captcha_verify(*data), 'Error captcha_verify - check_whitelist 6'
  print('New captcha tests ok: ', time.time() - start_time)



