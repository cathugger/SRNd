#!/usr/bin/env python2

from main_api import MainAPIHandler

DEFAULT_VERSION = '1'

class API_1(MainAPIHandler):
  def __init__(self, args):
    MainAPIHandler.__init__(self, args)

  def _handle_lasts(self, requ):
    """return last posts list. time - int unixtime, sent after this. limit - post limit, max 100 min 1. group - groupname. By example: get /lasts?limit=10&group=overchan.ru.drugs"""
    limits, after_time, group = self._prepare_lasts(requ)
    params = ['article_hash', 'sent']
    if group == 'all':
      params += ['group_name',]
      rows = self.overchandb.execute('SELECT {} FROM groups, articles WHERE sent > ? AND groups.group_id = articles.group_id ORDER BY sent DESC LIMIT ?'.format(', '.join(params)), (after_time, limits)).fetchall()
    else:
      rows = self.overchandb.execute('SELECT {} FROM groups, articles WHERE sent > ? AND group_name = ? AND groups.group_id = articles.group_id \
           ORDER BY sent DESC LIMIT ?'.format(', '.join(params)), (after_time, group, limits)).fetchall()
    return [dict(zip(params, row)) for row in rows]
  _handle_lasts.keys = {'time': 0, 'limit': 100, 'group': None}

  def _handle_lastsroot(self, requ):
    """see lasts, return updated root posts"""
    limits, after_time, group = self._prepare_lasts(requ)
    params = ['article_hash', 'articles.last_update']
    if group == 'all':
      params += ['group_name',]
    req = ', '.join(params)
    params[1] = 'last_update'
    if group == 'all':
      rows = self.overchandb.execute('SELECT {} FROM groups, articles WHERE articles.last_update > ? AND groups.group_id = articles.group_id \
           AND (articles.parent = "" OR articles.parent = articles.article_uid) ORDER BY articles.last_update DESC LIMIT ?'.format(req), (after_time, limits)).fetchall()
    else:
      rows = self.overchandb.execute('SELECT {} FROM groups, articles WHERE articles.last_update > ? AND group_name = ? AND groups.group_id = articles.group_id \
           AND (articles.parent = "" OR articles.parent = articles.article_uid) ORDER BY articles.last_update DESC LIMIT ?'.format(req), (after_time, group, limits)).fetchall()
    return [dict(zip(params, row)) for row in rows]
  _handle_lastsroot.keys = _handle_lasts.keys

  def _handle_boardlist(self, _):
    """return board list. No argument"""
    exclude_flags = self.cache['flags']['hidden'] | self.cache['flags']['blocked']
    data = [row[0] for row in self.overchandb.execute('SELECT group_name FROM groups WHERE (cast(flags as integer) & ?) = 0 ORDER by group_name ASC', (exclude_flags,)).fetchall()]
    return data
  _handle_boardlist.keys = {}

  def _handle_boardinfo(self, requ):
    """group info. group - groupname"""
    params = ('ph_name', 'ph_shortname', 'link', 'tag', 'description', 'flags', 'article_count', 'last_update')
    row = self.overchandb.execute('SELECT {} FROM groups WHERE group_name = ? LIMIT 1'.format(', '.join(params)), (requ['group'],)).fetchone()
    return dict(zip(params, row)) if row else {}
  _handle_boardinfo.keys = {'group': None}
  _handle_boardinfo.requ = ('group',)

  def _handle_post(self, requ):
    """send post data. id - full post hash"""
    params = ('article_uid', 'parent', 'sender', 'subject', 'sent', 'message', 'imagename', 'imagelink', 'thumblink', 'public_key', 'last_update', 'closed', 'sticky')
    row = self.overchandb.execute('SELECT {} FROM articles WHERE article_hash = ? LIMIT 1'.format(', '.join(params)), (requ['id'],)).fetchone()
    return dict(zip(params, row)) if row else {}
  _handle_post.keys = {'id': None}
  _handle_post.requ = ('id',)

  def _handle_thread(self, requ):
    """send root post and all child post. limit - child post limit, time - after time (only for child), id - root post full hash"""
    return self._prepare_thread(requ, False)
  _handle_thread.keys = {'id': None, 'limit': -1, 'time': 0}
  _handle_thread.requ = ('id',)

  def _handle_childs(self, requ):
    """see thread, return thread without root post"""
    return self._prepare_thread(requ, True)
  _handle_childs.keys = _handle_thread.keys
  _handle_childs.requ = _handle_thread.requ

  def _handle_fullhash(self, requ):
    """return full post hash from 10 chars short hash. id - short hash"""
    if len(requ['id']) != 10:
      return self.send_error(5, key='id')
    fullhash = self.overchandb.execute('SELECT article_hash FROM articles WHERE article_hash >= ? and article_hash < ? LIMIT 1', (requ['id'], requ['id']+'h')).fetchone()
    return fullhash[0] if fullhash else ''
  _handle_fullhash.keys = {'id': None}
  _handle_fullhash.requ = ('id',)

  def _handle_error(self, requ):
    """send error. code - error code"""
    return self.send_error(requ['code'])
  _handle_error.keys = {'code': -1}
  _handle_error.requ = ('code',)

  def _handle_info(self, requ):
    """this. cmd - more info from command"""
    if 'cmd' in requ and requ['cmd'] in self.requests:
      return {'info': self.requests[requ['cmd']].__doc__,
              'allow_keys': self.requests[requ['cmd']].keys,
              'required_keys': self.requests[requ['cmd']].requ}
    return {'requests': {x: self.requests[x].__doc__ for x in self.requests},
            'request_limit': self.config['request_limit'],
            'version': self.version}
  _handle_info.keys = {'cmd': None}


  @staticmethod
  def _prepare_lasts(request_data):
    """ extractor for lasts and lastsroot """
    limits = request_data.get('limit', 100)
    if limits < 1 or limits > 100:
      limits = 100
    after_time = request_data.get('time', 0)
    group = request_data.get('group', 'all')
    return limits, after_time, group

  def _prepare_thread(self, request_data, only_childs):
    """ for childs and thread """
    hashid = request_data['id']
    limits = request_data.get('limit', -1)
    after_time = request_data.get('time', 0)
    root_post = self._handle_post({'id': hashid})
    params = ('article_uid', 'sender', 'subject', 'sent', 'message', 'imagename', 'imagelink', 'thumblink', 'public_key')
    childs = list()
    if 'article_uid' in root_post:
      for row in self.overchandb.execute('SELECT * FROM (SELECT {} FROM articles WHERE parent = ? AND article_uid != parent AND sent > ? ORDER BY sent DESC LIMIT ?) ORDER BY sent ASC'.format(', '.join(params)), \
                                         (root_post['article_uid'], after_time, limits)).fetchall():
        childs.append(dict(zip(params, row)))
    if only_childs:
      return childs
    else:
      return {'root': root_post, 'childs': childs}

