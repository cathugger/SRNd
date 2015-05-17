#!/usr/bin/python

import codecs
import os
import sqlite3
import string
import time
import json
from hashlib import sha1
from datetime import datetime

from srnd.utils import basicHTMLencode, generate_pubkey_short_utf_8, html_minifer, overchan_thread_unlink



class OverchanGeneratorInit(object):
  def __init__(self, db_conns, log, logger, config):
    self.overchandb = db_conns.get('overchandb', None)
    self.dropperdb = db_conns.get('dropperdb', None)
    self.censordb = db_conns.get('censordb', None)
    self._log = log
    self.logger = logger
    self.config = config
    self.silent_mode = False

    self.t_engine = self._load_templates()

  def log(self, loglevel, message):
    if not self.silent_mode or loglevel >= self.logger.INFO:
      self._log(loglevel, message)

  def _css_headers_construct(self):
    with codecs.open(os.path.join(self.config['template_directory'], 'base_css_head.tmpl'), "r", "utf-8") as f:
      css_header = string.Template(f.read().rstrip())
    return '\n'.join([css_header.substitute(stylesheet=css) for css in self.config['csss'] \
                      if os.path.isfile(os.path.join(self.config['output_directory'], css)) and os.stat(os.path.join(self.config['output_directory'], css)).st_size > 0])

  def _load_evil_commands(self, evil_conf='evil_cmd.json'):
    with codecs.open(os.path.join(self.config['template_directory'], evil_conf), 'r', 'UTF-8') as f:
      evil_cmd = json.load(f)
    # Load only enabled commands
    # FIXME: first start table maybe not created. What check it? Re-load templates if values changed?
    try:
      allow_cmd = [x[0] for x in self.censordb.fetchall('SELECT evil FROM evil_to_srnd, cmd_map WHERE srnd = command AND (send = 1 or send = 0)')]
    except sqlite3.Error as e:
      allow_cmd = ['purge', 'purge_root']
      self.log(self.logger.WARNING, 'Error loading evil config from censordb. Allow default: {}. Error: {}'.format(allow_cmd, e))
    injected_cmd = {'root': [], 'child_pic': [], 'child_nopic': []}
    for cmd in allow_cmd:
      for target in injected_cmd:
        if target in evil_cmd[cmd]['target']:
          formatting_cmd = '{0}{1}\n{0}{2}'.format(evil_cmd['_base']['html_sugar'], evil_cmd['_base']['input'], evil_cmd['_base']['label'])
          formatting_cmd = string.Template(formatting_cmd).safe_substitute(
              evil_cmd=cmd,
              input_title=evil_cmd[cmd]['input_title'],
              label_txt=evil_cmd[cmd]['label_txt']
          )
          injected_cmd[target].append((formatting_cmd, evil_cmd[cmd]['pos']))
   # sort and join
    for target in injected_cmd:
      injected_cmd[target] = '\n'.join(y[0] for y in sorted(injected_cmd[target], key=lambda x_: x_[1]))
    return injected_cmd

  def _load_templates(self):
    start_time = time.time()
    t_engine = dict()
    for x in ('stats_usage_row', 'latest_posts_row', 'stats_boards_row', 'news'):
      with codecs.open(os.path.join(self.config['template_directory'], '%s.tmpl' % x), "r", "utf-8") as f:
        t_engine[x] = string.Template(f.read())

    # temporary templates
    template_brick = dict()
    for x in ('help', 'base_pagelist', 'base_postform', 'base_footer', 'dummy_postform', 'message_child_quickreply', 'message_root_quickreply', 'stats_usage', \
      'latest_posts', 'stats_boards', 'base_help', 'base_js_head'):
      with codecs.open(os.path.join(self.config['template_directory'], '%s.tmpl' % x), "r", "utf-8") as f:
        template_brick[x] = f.read()

    evil_cmd = self._load_evil_commands()
    css_headers = self._css_headers_construct()
    for target, evil_inject in (('message_root', 'root'), ('message_child_pic', 'child_pic'), ('message_child_nopic', 'child_nopic')):
      with codecs.open(os.path.join(self.config['template_directory'], '{}.tmpl'.format(target)), "r", "utf-8") as f:
        template_brick[target] = string.Template(f.read()).safe_substitute(
            {'evil_{}'.format(evil_inject): evil_cmd.get(evil_inject, 'Internal error')}
        )
    with codecs.open(os.path.join(self.config['template_directory'], 'base_head.tmpl'), "r", "utf-8") as f:
      template_brick['base_head'] = string.Template(f.read()).safe_substitute(
          stylesheet=css_headers,
          title=self.config['title']
      )
    template_brick['base_head_prep'] = string.Template(template_brick['base_head']).safe_substitute(
        head_title=string.Template('${title} :: ${board}').safe_substitute(title=self.config['title']),
        javascript=template_brick['base_js_head']
    )
    f = codecs.open(os.path.join(self.config['template_directory'], 'thread_single.tmpl'), "r", "utf-8")
    template_brick['thread_single'] = string.Template(
        string.Template(f.read()).safe_substitute(
            head_single=string.Template(template_brick['base_head']).safe_substitute(
                head_title=string.Template('${title} :: ${board} :: ${subject}').safe_substitute(title=self.config['title']),
                javascript=template_brick['base_js_head']
            ),
            base_help=template_brick['base_help']
        )
    )
    f.close()
    # template_engines
    f = codecs.open(os.path.join(self.config['template_directory'], 'board.tmpl'), "r", "utf-8")
    t_engine['board'] = string.Template(
        string.Template(f.read()).safe_substitute(
            base_head=template_brick['base_head_prep'],
            base_pagelist=template_brick['base_pagelist'],
            base_help=template_brick['base_help'],
            base_footer=template_brick['base_footer'],
            base_postform=string.Template(template_brick['base_postform']).safe_substitute(
                postform_action='new thread',
                thread_id='',
                new_thread_id='id="newthread" '
            )
        )
    )
    f.close()
    t_engine['thread_single'] = string.Template(
        template_brick['thread_single'].safe_substitute(
            single_postform=string.Template(template_brick['base_postform']).safe_substitute(
                postform_action='reply',
                new_thread_id=''
            )
        )
    )
    t_engine['thread_single_closed'] = string.Template(
        template_brick['thread_single'].safe_substitute(
            single_postform=template_brick['dummy_postform']
        )
    )
    f = codecs.open(os.path.join(self.config['template_directory'], 'index.tmpl'), "r", "utf-8")
    t_engine['index'] = string.Template(
        string.Template(f.read()).safe_substitute(
            title=self.config['title']
        )
    )
    f.close()
    if self.config['i2paddresshelper']:
      with codecs.open(os.path.join(self.config['template_directory'], 'menu_i2paddresshelper.tmpl'), "r", "utf-8") as f:
        i2paddresshelper = string.Template(f.read()).substitute(
            site_url=self.config['site_url'],
            local_dest=self.config['local_dest']
        )
    else:
      i2paddresshelper = u''
    f = codecs.open(os.path.join(self.config['template_directory'], 'menu.tmpl'), "r", "utf-8")
    t_engine['menu'] = string.Template(
        string.Template(f.read()).safe_substitute(
            title=self.config['title'],
            stylesheet=css_headers,
            i2paddresshelper=i2paddresshelper
        )
    )
    f.close()
    recent_link = u'<a href="${group_name}-recent.html" target="main">(${postcount})</a>' if self.config['enable_recent'] else u''
    with codecs.open(os.path.join(self.config['template_directory'], 'menu_entry.tmpl'), "r", "utf-8") as f:
      t_engine['menu_entry'] = string.Template(
          string.Template(f.read()).safe_substitute(recent_link=recent_link)
      )
    f = codecs.open(os.path.join(self.config['template_directory'], 'overview.tmpl'), "r", "utf-8")
    t_engine['overview'] = string.Template(
        string.Template(f.read()).safe_substitute(
            stats_usage=template_brick['stats_usage'],
            latest_posts=template_brick['latest_posts'],
            stats_boards=template_brick['stats_boards'],
            head_overview=string.Template(template_brick['base_head']).safe_substitute(
                head_title='{} :: Overview'.format(self.config['title']),
                javascript=''
            )
        )
    )
    f.close()
    f = codecs.open(os.path.join(self.config['template_directory'], 'board_threads.tmpl'), "r", "utf-8")
    t_engine['board_threads'] = string.Template(f.read())
    f.close()
    f = codecs.open(os.path.join(self.config['template_directory'], 'archive_threads.tmpl'), "r", "utf-8")
    t_engine['archive_threads'] = string.Template(f.read())
    f.close()
    t_engine['message_root'] = string.Template(
        string.Template(template_brick['message_root']).safe_substitute(
            root_quickreply=template_brick['message_root_quickreply'],
            click_action='Reply'
        )
    )
    t_engine['message_root_closed'] = string.Template(
        string.Template(template_brick['message_root']).safe_substitute(
            root_quickreply='&#8470;  ${article_id}',
            click_action='View'
        )
    )
    t_engine['message_pic'] = string.Template(
        string.Template(template_brick['message_child_pic']).safe_substitute(
            child_quickreply=template_brick['message_child_quickreply']
        )
    )
    t_engine['message_pic_closed'] = string.Template(
        string.Template(template_brick['message_child_pic']).safe_substitute(
            child_quickreply='${article_id}'
        )
    )
    t_engine['message_nopic'] = string.Template(
        string.Template(template_brick['message_child_nopic']).safe_substitute(
            child_quickreply=template_brick['message_child_quickreply']
        )
    )
    t_engine['message_nopic_closed'] = string.Template(
        string.Template(template_brick['message_child_nopic']).safe_substitute(
            child_quickreply='${article_id}'
        )
    )
    f = codecs.open(os.path.join(self.config['template_directory'], 'signed.tmpl'), "r", "utf-8")
    t_engine['signed'] = string.Template(f.read())
    f.close()
    f = codecs.open(os.path.join(self.config['template_directory'], 'help_page.tmpl'), "r", "utf-8")
    t_engine['help_page'] = string.Template(
        string.Template(f.read()).safe_substitute(
            base_head=string.Template(template_brick['base_head_prep']).safe_substitute(board='help'),
            help=template_brick['help'],
            base_footer=template_brick['base_footer']
        )
    )
    f.close()
    if self.config['minify_html']:
      t_engine, msg = html_minifer(t_engine, ('help_page',))
      self.log(self.logger.INFO, msg)
    self.log(self.logger.INFO, 'Templates loaded at {} seconds'.format(int(time.time() - start_time)))
    return t_engine

class OverchanGeneratorTools(OverchanGeneratorInit):
  """ Collect different methods needed for pages generation """
  def __init__(self, db_conns, log, logger, config, cache, board_cache_conns, markup_parser):
    OverchanGeneratorInit.__init__(self, db_conns, log, logger, config)
    self.get_board_list = board_cache_conns['get_board_list']
    self.get_board_data = board_cache_conns['get_board_data']
    self.cache = cache
    self.thumb_cache = dict()

    self.markup_parser = markup_parser

    self._page_stamp = {'board': {}, 'archive': {}}
    self.regenerate_boards = set()
    self.regenerate_threads = set()

  def flush_pagestamp_cache(self, group_id=None):
    if group_id is not None:
      self._page_stamp['board'][group_id] = dict()
      self._page_stamp['archive'][group_id] = dict()
    else:
      self._page_stamp['board'] = dict()
      self._page_stamp['archive'] = dict()

  @staticmethod
  def _extract_frontend(uid):
    if '@' in uid:
      frontend = uid.split('@')[1][:-1]
    else:
      frontend = 'nntp'
    return frontend

  def _get_thumb_info(self, thumbname, isroot, standart=False):
    if standart and thumbname in self.thumb_cache:
      # standart thumb - use cache
      xy = self.thumb_cache[thumbname]
    else:
      xy = self.overchandb.fetchone('SELECT x, y FROM thumb_info WHERE name = ?', (thumbname,))
      if standart:
        self.thumb_cache[thumbname] = xy
    if xy is None:
      # legacy - use old value
      return 'width="180" max-height="360"' if isroot else 'width="150" max-height="300"'
    else:
      return 'width="%s" height="%s"' % (xy[0], xy[1])

  def _delete_thread_page(self, thread_name):
    self.log(self.logger.DEBUG, 'this page belongs to some blocked board. deleting %s.html' % thread_name)
    for error_ in overchan_thread_unlink(self.config['output_directory'], thread_name):
      self.log(self.logger.WARNING, 'could not delete %s' % error_)

  def _generate_news_data(self):
    t_engine_mappings_news = {'subject': '', 'sent': '', 'author': '', 'pubkey_short': '', 'pubkey': '', 'comment_count': ''}
    news_board = self.overchandb.execute('SELECT group_id, group_name FROM groups WHERE \
        (cast(flags as integer) & ?) != 0 AND (cast(flags as integer) & ?) = 0', (self.cache['flags']['news'], self.cache['flags']['blocked'])).fetchone()
    if news_board:
      t_engine_mappings_news['allnews_link'] = '{0}-1.html'.format(news_board[1].split('.', 1)[-1].replace('"', '').replace('/', ''))
      row = self.overchandb.execute('SELECT subject, message, sent, public_key, article_uid, sender FROM articles \
          WHERE (parent = "" OR parent = article_uid) AND group_id = ? ORDER BY sticky DESC, last_update DESC', (news_board[0],)).fetchone()
    else:
      t_engine_mappings_news['allnews_link'] = 'overview.html'
    if not (news_board and row):
      t_engine_mappings_news['parent'] = 'does_not_exist_yet'
      t_engine_mappings_news['message'] = 'once upon a time there was a news post'
    else:
      parent = sha1(row[4]).hexdigest()[:10]
      if len(row[1].split('\n')) > 5:
        message = '\n'.join(row[1].split('\n')[:5]) + '\n[..] <a href="thread-%s.html"><i>message too large</i></a>' % parent
      elif len(row[1]) > 1000:
        message = row[1][:1000] + '\n[..] <a href="thread-%s.html"><i>message too large</i></a>' % parent
      else:
        message = row[1]
      message = self.markup_parser.parse(message)
      t_engine_mappings_news['subject'] = 'Breaking news' if row[0] == 'None' or row[0] == '' else row[0]
      t_engine_mappings_news['sent'] = datetime.utcfromtimestamp(row[2] + self.config['utc_time_offset']).strftime(self.config['datetime_format'])
      if row[3] != '':
        t_engine_mappings_news['pubkey_short'] = generate_pubkey_short_utf_8(row[3])
        moder_name = self._pubkey_to_name(row[3])
      else:
        moder_name = ''
      t_engine_mappings_news['author'] = moder_name if moder_name else row[5]
      t_engine_mappings_news['pubkey'] = row[3]
      t_engine_mappings_news['parent'] = parent
      t_engine_mappings_news['message'] = message
      t_engine_mappings_news['comment_count'] = self.overchandb.execute('SELECT count(article_uid) FROM articles WHERE \
          parent = ? AND parent != article_uid AND group_id = ?', (row[4], news_board[0])).fetchone()[0]
    return self.t_engine['news'].substitute(t_engine_mappings_news)

  @staticmethod
  def _generate_pagelist(count, current, board_name_unquoted, archive_link=False):
    if count < 2:
      return ''
    pagelist = list()
    pagelist.append('Pages: ')
    for page in xrange(1, count + 1):
      if page != current:
        pagelist.append('<a href="{0}-{1}.html">[{1}]</a> '.format(board_name_unquoted, page))
      else:
        pagelist.append('[{0}] '.format(page))
    if archive_link:
      pagelist.append('<a href="{0}-archive-1.html">[Archive]</a> '.format(board_name_unquoted))
    return ''.join(pagelist)

  def _get_preparse_post(self, data, message_id_hash, group_id, max_row, max_chars, child_view, father='', father_pubkey='', single=False):
    #father initiate parsing child post and contain root_post_hash_id
        #data = 0 - article_uid 1- sender 2 - subject 3 - sent 4 - message 5 - imagename 6 - imagelink 7 - thumblink -8 public_key
    #message_id_hash = sha1(data[0]).hexdigest() #use globally for decrease sha1 root post uid iteration
    is_playable = False
    parsed_data = dict()
    if data[6] != '':
      imagelink = data[6]
      if data[7] in self.config['thumbs']:
        thumblink = self.config['thumbs'][data[7]]
        if data[6] in self.config['thumbs']:
          imagelink = self.config['thumbs'][data[6]]
        parsed_data['thumb_info'] = self._get_thumb_info(thumblink, father == '', True)
      else:
        thumblink = data[7]
        parsed_data['thumb_info'] = self._get_thumb_info(thumblink, father == '')
        if data[6] != data[7] and data[6].rsplit('.', 1)[-1] in ('gif', 'webm', 'mp4'):
          is_playable = True
    else:
      imagelink = thumblink = self.config['thumbs'].get('no_file', 'error')
      parsed_data['thumb_info'] = self._get_thumb_info(thumblink, father == '', True)
    if data[8] != '':
      parsed_data['signed'] = self.t_engine['signed'].substitute(
          articlehash=message_id_hash[:10],
          pubkey=data[8],
          pubkey_short=generate_pubkey_short_utf_8(data[8])
      )
      author = self._pubkey_to_name(data[8], father_pubkey, data[1])
      if author == '':
        author = data[1]
    else:
      parsed_data['signed'] = ''
      author = data[1]
    if not single and len(data[4].split('\n')) > max_row:
      if father != '':
        message = '\n'.join(data[4].split('\n')[:max_row]) + '\n[..] <a href="thread-%s.html#%s"><i>message too large</i></a>' % (father[:10], message_id_hash[:10])
      else:
        message = '\n'.join(data[4].split('\n')[:max_row]) + '\n[..] <a href="thread-%s.html"><i>message too large</i></a>' % message_id_hash[:10]
    elif not single and len(data[4]) > max_chars:
      if father != '':
        message = data[4][:max_chars] + '\n[..] <a href="thread-%s.html#%s"><i>message too large</i></a>' % (father[:10], message_id_hash[:10])
      else:
        message = data[4][:max_chars] + '\n[..] <a href="thread-%s.html"><i>message too large</i></a>' % message_id_hash[:10]
    else:
      message = data[4]
    message = self.markup_parser.parse(message, group_id)
    if father == '':
      child_count = int(self.overchandb.execute('SELECT count(article_uid) FROM articles WHERE parent = ? AND parent != article_uid', (data[0],)).fetchone()[0])
      if self.config['bump_limit'] > 0 and child_count >= self.config['bump_limit']:
        parsed_data['thread_status'] = '[fat]'
      else:
        parsed_data['thread_status'] = ''
      if child_count > child_view:
        missing = child_count - child_view
        if missing == 1:
          post = "post"
        else:
          post = "posts"
        message += '\n\n<a href="thread-{0}.html">{1} {2} omitted</a>'.format(message_id_hash[:10], missing, post)
        if child_view < 10000 and child_count > 80:
          start_link = child_view / 50 * 50 + 50
          if start_link % 100 == 0:
            start_link += 50
          if child_count - start_link > 0:
            message += ' [%s ]' % ''.join(' <a href="thread-{0}-{1}.html">{1}</a>'.format(message_id_hash[:10], x) for x in range(start_link, child_count, 100))
    parsed_data['frontend'] = self._extract_frontend(data[0])
    parsed_data['message'] = message
    parsed_data['articlehash'] = message_id_hash[:10]
    parsed_data['articlehash_full'] = message_id_hash
    parsed_data['author'] = author
    if father != '' and data[2] == 'None':
      parsed_data['subject'] = ''
    else:
      parsed_data['subject'] = data[2]
    parsed_data['sent'] = datetime.utcfromtimestamp(data[3] + self.config['utc_time_offset']).strftime(self.config['datetime_format'])
    parsed_data['imagelink'] = imagelink
    parsed_data['thumblink'] = thumblink
    parsed_data['imagename'] = data[5]
    if father != '':
      parsed_data['parenthash'] = father[:10]
      parsed_data['parenthash_full'] = father
    if self.config['fake_id']:
      parsed_data['article_id'] = self._message_uid_to_fake_id(data[0])
    else:
      parsed_data['article_id'] = message_id_hash[:10]
    if is_playable:
      parsed_data['play_button'] = '<span class="play_button"></span>'
    else:
      parsed_data['play_button'] = ''
    return parsed_data

  def _get_board_root_posts(self, group_id, post_count, offset=0):
    return self.overchandb.execute('SELECT article_uid, sender, subject, sent, message, imagename, imagelink, thumblink, public_key, last_update, closed, sticky FROM \
      articles WHERE group_id = ? AND (parent = "" OR parent = article_uid) ORDER BY sticky DESC, last_update DESC LIMIT ? OFFSET ?', (group_id, post_count, offset)).fetchall()

  def _board_root_post_iter(self, board_data, group_id, pages, threads_per_page, cache_target='board'):
    if group_id not in self._page_stamp[cache_target]:
      self._page_stamp[cache_target][group_id] = dict()
    for page in xrange(1, pages + 1):
      page_data = board_data[threads_per_page*(page-1):threads_per_page*(page-1)+threads_per_page]
      first_last_parent = sha1(page_data[0][0] + page_data[-1][0]).hexdigest()[:10] if len(page_data) > 0 else None
      if self._page_stamp[cache_target][group_id].get(page, '') != first_last_parent or len(self.regenerate_threads & set(x[0] for x in page_data)) > 0:
        self._page_stamp[cache_target][group_id][page] = first_last_parent
        yield page, page_data

  @staticmethod
  def _get_page_count(thread_count, threads_per_page):
    pages = int(thread_count / threads_per_page)
    if (thread_count % threads_per_page != 0) or pages == 0:
      pages += 1
    return pages

  def _get_base_thread(self, root_row, root_message_id_hash, group_id, child_count=4, single=False):
    if root_row[10] != 0:
      isclosed = True
    else:
      isclosed = False
    if root_message_id_hash == '':
      root_message_id_hash = sha1(root_row[0]).hexdigest()
    message_root = self._get_root_post(root_row, group_id, child_count, root_message_id_hash, single, isclosed)
    if child_count == 0:
      return {'message_root': message_root}
    message_childs = ''.join(self._get_childs_posts(root_row[0], group_id, root_message_id_hash, root_row[8], child_count, single, isclosed))
    return {'message_root': message_root, 'message_childs': message_childs}

  def _get_root_post(self, data, group_id, child_count, message_id_hash, single, isclosed):
    root_data = self._get_preparse_post(data[:9], message_id_hash, group_id, 25, 2000, child_count, '', '', single)
    if data[11] != 0:
      root_data['thread_status'] += '[&#177;]'
      root_data['sticky_prefix'] = 'un'
    else:
      root_data['sticky_prefix'] = ''
    if isclosed:
      root_data['close_action'] = 'open'
      root_data['thread_status'] += '[closed]'
      return self.t_engine['message_root_closed'].substitute(root_data)
    else:
      root_data['close_action'] = 'close'
      return self.t_engine['message_root'].substitute(root_data)

  def _get_childs_posts(self, parent, group_id, father, father_pubkey, child_count, single, isclosed):
    childs = list()
    childs.append('') # FIXME: the fuck is this for?
    for child_row in self.overchandb.execute('SELECT * FROM (SELECT article_uid, sender, subject, sent, message, imagename, imagelink, thumblink, public_key \
        FROM articles WHERE parent = ? AND parent != article_uid AND group_id = ? ORDER BY sent DESC LIMIT ?) ORDER BY sent ASC', (parent, group_id, child_count)).fetchall():
      childs_message = self._get_preparse_post(child_row, sha1(child_row[0]).hexdigest(), group_id, 20, 1500, 0, father, father_pubkey, single)
      nopic = '' if child_row[6] != '' else 'no'
      closed = '' if not isclosed else '_closed'
      childs.append(self.t_engine['message_'+ nopic +'pic'+ closed].substitute(childs_message))
    return childs

  def _message_uid_to_fake_id(self, message_uid):
    fake_id = self.dropperdb.execute('SELECT article_id FROM articles WHERE message_id = ?', (message_uid,)).fetchone()
    return fake_id[0] if fake_id is not None else sha1(message_uid).hexdigest()[:10]

  def _get_moder_name(self, full_pubkey_hex):
    try:
      result = self.censordb.execute('SELECT local_name from keys WHERE key=? and local_name != ""', (full_pubkey_hex,)).fetchone()
    except sqlite3.Error:
      return None
    else:
      return result[0] if result is not None else None

  def _pubkey_to_name(self, full_pubkey_hex, root_full_pubkey_hex='', sender=''):
    op_flag, nickname = '', ''
    local_name = self._get_moder_name(full_pubkey_hex)
    if full_pubkey_hex == root_full_pubkey_hex:
      op_flag = '<span class="op-kyn">OP</span> '
      nickname = sender
    if local_name is not None:
      nickname = '<span class="zoi">%s</span>' % local_name
    return '%s%s' % (op_flag, nickname)

class OverchanGeneratorStatic(OverchanGeneratorTools):
  def __init__(self, db_conns, log, logger, config, cache, board_cache_conns, markup_parser, silent_mode=False):
    OverchanGeneratorTools.__init__(self, db_conns, log, logger, config, cache, board_cache_conns, markup_parser)
    # don't print info\debug\verbose message
    self.silent_mode = silent_mode

  def generate_first_start(self):
    for data in self.generate_index():
      yield data
    for data in self.generate_menu():
      yield data
    for data in self.generate_overview():
      yield data
    for data in self.generate_top():
      yield data

  def generate_all(self):
    """ Generate all pages in self.regenerate_boards, self.regenerate_threads, overview, menu and top (if need). yield page name (without extension), page data"""
    regen_overview = False
    if len(self.regenerate_boards) > 0:
      regen_overview = True
      for board_data in self.generate_board_all():
        yield board_data
    if len(self.regenerate_threads) > 0:
      regen_overview = True
      for thread_data in self.generate_thread_all():
        yield thread_data
    if regen_overview:
      for data in self.generate_overview():
        yield data
      for data in self.generate_menu():
        yield data
    if regen_overview and self.config['enable_top']:
      if self.config['top_counter'] >= self.config['top_step']:
        self.config['top_counter'] = 0
        for data in self.generate_top():
          yield data
      else:
        self.config['top_counter'] += 1

  def generate_board_all(self):
    do_sleep = len(self.regenerate_boards) > self.config['sleep_threshold']
    if do_sleep:
      self.log(self.logger.DEBUG, 'boards: should sleep')
    for board in self.regenerate_boards:
      for board_data in self.generate_board(board):
        yield board_data
      if do_sleep:
        time.sleep(self.config['sleep_time'])
    self.regenerate_boards.clear()

  def generate_thread_all(self):
    thread_count = len(self.regenerate_threads)
    step_say = thread_count / 50
    silence = thread_count >= step_say and thread_count > 100
    do_sleep = thread_count > self.config['sleep_threshold']
    if do_sleep:
      self.log(self.logger.DEBUG, 'threads: should sleep')
    start_time = time.time()
    result_time = 0.0
    result_counter = 0
    counter = 0
    for thread in self.regenerate_threads:
      for thread_data in self.generate_thread(thread, silence):
        yield thread_data
      if do_sleep:
        time.sleep(self.config['sleep_time'])
      counter += 1
      result_counter += 1
      if silence and (counter >= step_say or (thread_count == result_counter and counter > 0)):
        all_time = time.time() - start_time
        result_time += all_time
        sleep_time = self.config['sleep_time'] * counter if do_sleep else 0
        percentage = (100 * result_counter) / thread_count
        self.log(self.logger.INFO, 'generating {} [{:3}%] threads at {:0.4f}s [work:{:0.4f}s, sleep:{:0.4f}s]'.format(counter, percentage, all_time, (all_time - sleep_time), sleep_time))
        start_time = time.time()
        counter = 0
    if silence and result_counter > 0:
      sleep_time = self.config['sleep_time'] * result_counter if do_sleep else 0
      work_time = result_time - sleep_time
      percentage = (100 * result_counter) / thread_count
      self.log(self.logger.INFO, 'result generating [{}/{}] [{}%] threads {:0.4f}s [work:{:0.4f}s, sleep:{:0.4f}s]'.format(result_counter, thread_count, percentage, result_time, work_time, sleep_time))
      self.log(self.logger.INFO, 'average generating 1 thread {:0.4f}s [work:{:0.4f}s, sleep:{:0.4f}s]'.format(result_time/result_counter, work_time/result_counter, sleep_time/result_counter))
    self.regenerate_threads.clear()

  def generate_board(self, group_id):
    start_time = time.time()
    threads_per_page = self.config['threads_per_page']
    pages_per_board = self.config['pages_per_board']
    board_data = self._get_board_root_posts(group_id, threads_per_page * pages_per_board)
    thread_count = len(board_data)
    pages = self._get_page_count(thread_count, threads_per_page)
    if self.config['enable_archive'] and (self.get_board_data(group_id, 'flags') & self.cache['flags']['no-archive'] == 0) and \
        int(self.overchandb.execute('SELECT count(group_id) FROM (SELECT group_id FROM articles WHERE group_id = ? AND (parent = "" OR parent = article_uid))', (group_id,)).fetchone()[0]) > thread_count:
      generate_archive = True
    else:
      generate_archive = False

    generation = list()
    basic_board = dict()
    basic_board['board_subtype'] = ''
    basic_board['boardlist'] = self.get_board_list(group_id)
    basic_board['full_board'], \
    board_name_unquoted, \
    basic_board['board'], \
    basic_board['board_description'] = self.get_board_data(group_id)
    prepared_template = string.Template(self.t_engine['board'].safe_substitute(basic_board))
    t_engine_mapper_board = dict()
    isgenerated = False
    for board, page_data in self._board_root_post_iter(board_data, group_id, pages, threads_per_page):
      isgenerated = True
      threads = list()
      generation.append(str(board))
      for root_row in page_data:
        root_message_id_hash = sha1(root_row[0]).hexdigest()
        threads.append(
            self.t_engine['board_threads'].substitute(
                self._get_base_thread(root_row, root_message_id_hash, group_id, 4)
            )
        )
      t_engine_mapper_board['threads'] = ''.join(threads)
      t_engine_mapper_board['pagelist'] = self._generate_pagelist(pages, board, board_name_unquoted, generate_archive)
      t_engine_mapper_board['target'] = "{0}-1.html".format(board_name_unquoted)
      yield '%s-%s' % (board_name_unquoted, board), prepared_template.substitute(t_engine_mapper_board)
    last_root_message = board_data[-1][0] if thread_count > 0 else None
    del board_data, t_engine_mapper_board, prepared_template
    if len(generation) > 0:
      self.log(self.logger.INFO, 'generating {}/{}-({}).html at {:0.4f}s'.format(self.config['output_directory'], board_name_unquoted, ','.join(generation), (time.time() - start_time)))
    if generate_archive and (self._page_stamp['board'][group_id].get(0, '') != last_root_message or (not isgenerated and len(self.regenerate_threads) > 0)):
      self._page_stamp['board'][group_id][0] = last_root_message
      for archive_data in self.generate_archive(group_id):
        yield archive_data
    if isgenerated and self.config['enable_recent']:
      for recent_data in self.generate_recent(group_id):
        yield recent_data

  def generate_archive(self, group_id):
    start_time = time.time()
    threads_per_page = self.config['archive_threads_per_page']
    pages_per_board = self.config['archive_pages_per_board']
    board_data = self._get_board_root_posts(group_id, threads_per_page * pages_per_board, self.config['threads_per_page'] * self.config['pages_per_board'])
    thread_count = len(board_data)
    if thread_count == 0:
      return
    pages = self._get_page_count(thread_count, threads_per_page)

    generation = list()
    basic_board = dict()
    basic_board['board_subtype'] = ' :: archive'
    basic_board['boardlist'] = self.get_board_list()
    basic_board['full_board'], \
    board_name_unquoted, \
    basic_board['board'], \
    basic_board['board_description'] = self.get_board_data(group_id)
    prepared_template = string.Template(self.t_engine['board'].safe_substitute(basic_board))
    t_engine_mapper_board = dict()
    for board, page_data in self._board_root_post_iter(board_data, group_id, pages, threads_per_page, 'archive'):
      threads = list()
      generation.append(str(board))
      for root_row in page_data:
        threads.append(
            self.t_engine['archive_threads'].substitute(
                self._get_base_thread(root_row, '', group_id, child_count=0)
            )
        )
      t_engine_mapper_board['threads'] = ''.join(threads)
      t_engine_mapper_board['pagelist'] = self._generate_pagelist(pages, board, board_name_unquoted+'-archive')
      t_engine_mapper_board['target'] = "{0}-archive-1.html".format(board_name_unquoted)

      yield '%s-archive-%s' % (board_name_unquoted, board), prepared_template.substitute(t_engine_mapper_board)
    if len(generation) > 0:
      self.log(self.logger.INFO, 'generating {}/{}-archive-({}).html at {:0.4f}s'.format(self.config['output_directory'], board_name_unquoted, ','.join(generation), (time.time() - start_time)))

  def generate_recent(self, group_id):
    # get only freshly updated threads
    timestamp = int(time.time()) - 3600*24
    threads = list()
    t_engine_mapper_board_recent = dict()
    t_engine_mapper_board_recent['board_subtype'] = ' :: recent'
    t_engine_mapper_board_recent['boardlist'] = self.get_board_list()
    t_engine_mapper_board_recent['full_board'], \
    board_name_unquoted, \
    t_engine_mapper_board_recent['board'], \
    t_engine_mapper_board_recent['board_description'] = self.get_board_data(group_id)
    self.log(self.logger.INFO, 'generating %s/%s-recent.html' % (self.config['output_directory'], board_name_unquoted))
    for root_row in self.overchandb.execute('SELECT article_uid, sender, subject, sent, message, imagename, imagelink, thumblink, public_key, last_update, closed, sticky \
        FROM articles WHERE group_id = ? AND (parent = "" OR parent = article_uid) AND last_update > ? ORDER BY sticky DESC, last_update DESC', (group_id, timestamp)).fetchall():
      root_message_id_hash = sha1(root_row[0]).hexdigest()
      threads.append(
          self.t_engine['board_threads'].substitute(
              self._get_base_thread(root_row, root_message_id_hash, group_id, 4)
          )
      )
    t_engine_mapper_board_recent['threads'] = ''.join(threads)
    t_engine_mapper_board_recent['target'] = "{0}-recent.html".format(board_name_unquoted)
    t_engine_mapper_board_recent['pagelist'] = ''

    yield '{0}-recent'.format(board_name_unquoted), self.t_engine['board'].substitute(t_engine_mapper_board_recent)

  def generate_thread(self, root_uid, silence):
    root_row = self.overchandb.execute('SELECT article_uid, sender, subject, sent, message, imagename, imagelink, thumblink, public_key, last_update, closed, sticky, group_id \
        FROM articles WHERE article_uid = ?', (root_uid,)).fetchone()
    if not root_row:
      # FIXME: create temporary root post here? this will never get called on startup because it checks for root posts only
      # FIXME: ^ alternatives: wasted threads in admin panel? red border around images in pic log? actually adding temporary root post while processing?
      #root_row = (root_uid, 'none', 'root post not yet available', 0, 'root post not yet available', '', '', 0, '')
      self.log(self.logger.INFO, 'root post not yet available: %s, should create temporary root post here' % root_uid)
      return
    group_id = root_row[-1]
    root_message_id_hash = sha1(root_uid).hexdigest()#self.overchandb_hashes.execute('SELECT message_id_hash from article_hashes WHERE message_id = ?', (root_row[0],)).fetchone()
    # FIXME: benchmark sha1() vs hasher_db_query
    child_count = int(self.overchandb.execute('SELECT count(article_uid) FROM articles WHERE parent = ? AND parent != article_uid AND group_id = ?', (root_row[0], group_id)).fetchone()[0])
    isblocked_board = self.get_board_data(group_id, 'flags') & self.cache['flags']['blocked'] != 0
    thread_name = 'thread-%s' % (root_message_id_hash[:10],)
    if isblocked_board:
      self._delete_thread_page(thread_name)
    else:
      yield thread_name, self._create_thread_page(root_row[:-1], thread_name, 10000, root_message_id_hash, group_id, silence)
      if child_count > 80:
        for max_child_view in range(50, child_count, 100):
          thread_name = 'thread-%s-%s' % (root_message_id_hash[:10], max_child_view)
          yield thread_name, self._create_thread_page(root_row[:-1], thread_name, max_child_view, root_message_id_hash, group_id, silence)

  def _create_thread_page(self, root_row, thread_name, max_child_view, root_message_id_hash, group_id, silence):
    if not silence:
      thread_path = os.path.join(self.config['output_directory'], '.'.join((thread_name, 'html')))
      self.log(self.logger.INFO, 'generating %s' % (thread_path,))
    t_engine_mappings_thread_single = dict()
    t_engine_mappings_thread_single['thread_single'] = self.t_engine['board_threads'].substitute(self._get_base_thread(root_row, root_message_id_hash, group_id, max_child_view, True))
    t_engine_mappings_thread_single['boardlist'] = self.get_board_list()
    t_engine_mappings_thread_single['full_board'], \
    board_name_unquoted, \
    t_engine_mappings_thread_single['board'], \
    t_engine_mappings_thread_single['board_description'] = self.get_board_data(group_id)
    t_engine_mappings_thread_single['thread_id'] = root_message_id_hash
    t_engine_mappings_thread_single['target'] = "{0}-1.html".format(board_name_unquoted)
    t_engine_mappings_thread_single['subject'] = root_row[2][:60]

    if root_row[10] == 0:
      return self.t_engine['thread_single'].substitute(t_engine_mappings_thread_single)
    else:
      return self.t_engine['thread_single_closed'].substitute(t_engine_mappings_thread_single)

  def generate_index(self):
    self.log(self.logger.INFO, 'generating %s/index.html' % self.config['output_directory'])
    yield 'index', self.t_engine['index'].substitute()

  def generate_menu(self):
    self.log(self.logger.INFO, 'generating %s/menu.html' % self.config['output_directory'])
    menu_entry = dict()
    menu_entries = list()
    exclude_flags = self.cache['flags']['hidden'] | self.cache['flags']['blocked']
    for group_row in self.overchandb.execute('SELECT group_name, group_id, ph_name, link FROM groups WHERE \
      (cast(groups.flags as integer) & ?) = 0 ORDER by group_name ASC', (exclude_flags,)).fetchall():
      menu_entry['group_name'] = group_row[0].split('.', 1)[-1].replace('"', '').replace('/', '')
      menu_entry['group_link'] = group_row[3] if self.config['use_unsecure_aliases'] and group_row[3] != '' else '%s-1.html' % menu_entry['group_name']
      menu_entry['group_name_encoded'] = group_row[2] if group_row[2] != '' else basicHTMLencode(menu_entry['group_name'])
      if self.config['enable_recent']:
        # get fresh posts count
        timestamp = int(time.time()) - 3600*24
        menu_entry['postcount'] = self.overchandb.execute('SELECT count(article_uid) FROM articles WHERE group_id = ? AND sent > ?', (group_row[1], timestamp)).fetchone()[0]
      menu_entries.append(self.t_engine['menu_entry'].substitute(menu_entry))

    yield 'menu', self.t_engine['menu'].substitute(menu_entries='\n'.join(menu_entries))

  def generate_overview(self):
    self.log(self.logger.INFO, 'generating %s/overview.html' % self.config['output_directory'])
    t_engine_mappings_overview = dict()
    t_engine_mappings_overview['boardlist'] = self.get_board_list()
    t_engine_mappings_overview['news'] = self._generate_news_data()

    weekdays = ('Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday')
    max_post = 0
    stats = list()
    bar_length = 20
    days = 30
    utc_offset = str(self.config['utc_time_offset']) + ' seconds'
    totals = int(self.overchandb.execute('SELECT count(1) FROM articles WHERE sent > strftime("%s", "now", "-' + str(days) + ' days")').fetchone()[0])
    stats.append(self.t_engine['stats_usage_row'].substitute({'postcount': totals, 'date': 'all posts', 'weekday': '', 'bar': 'since %s days' % days}))
    datarow = list()
    for row in self.overchandb.execute('SELECT count(1) as counter, strftime("%Y-%m-%d", sent, "unixepoch", "' + utc_offset + '") as day, strftime("%w", sent, "unixepoch", "' + utc_offset + '") as weekday FROM articles WHERE sent > strftime("%s", "now", "-' + str(days) + ' days") GROUP BY day ORDER BY day DESC').fetchall():
      if row[0] > max_post:
        max_post = row[0]
      datarow.append((row[0], row[1], weekdays[int(row[2])]))
    for row in datarow:
      graph = '=' * int(float(row[0])/max_post*bar_length)
      if len(graph) == 0:
        graph = '&nbsp;'
      stats.append(self.t_engine['stats_usage_row'].substitute({'postcount': row[0], 'date': row[1], 'weekday': row[2], 'bar': graph}))
    t_engine_mappings_overview['stats_usage_rows'] = '\n'.join(stats)

    postcount = 50
    stats = list()
    exclude_flags = self.cache['flags']['hidden'] | self.cache['flags']['no-overview'] | self.cache['flags']['blocked']
    for row in self.overchandb.execute('SELECT articles.last_update, group_name, subject, message, article_uid, ph_name FROM groups, articles WHERE \
      groups.group_id = articles.group_id AND (cast(groups.flags as integer) & ?) = 0 AND \
      (articles.parent = "" OR articles.parent = articles.article_uid) ORDER BY articles.last_update DESC LIMIT ?', (exclude_flags, str(postcount))).fetchall():
      latest_posts_row = dict()
      latest_posts_row['last_update'] = datetime.utcfromtimestamp(row[0] + self.config['utc_time_offset']).strftime(self.config['datetime_format'])
      latest_posts_row['board'] = row[5] if row[5] != '' else basicHTMLencode(row[1].split('.', 1)[-1].replace('"', ''))
      latest_posts_row['articlehash'] = sha1(row[4]).hexdigest()[:10]
      latest_posts_row['subject'] = row[2] if row[2] not in ('', 'None') else row[3]
      latest_posts_row['subject'] = latest_posts_row['articlehash'] if latest_posts_row['subject'] == '' else latest_posts_row['subject'].replace('\n', ' ')[:55]
      stats.append(self.t_engine['latest_posts_row'].substitute(latest_posts_row))
    t_engine_mappings_overview['latest_posts_rows'] = '\n'.join(stats)

    stats = list()
    exclude_flags = self.cache['flags']['hidden'] | self.cache['flags']['blocked']
    for row in self.overchandb.execute('SELECT count(1) as counter, group_name, ph_name FROM groups, articles WHERE \
      groups.group_id = articles.group_id AND (cast(groups.flags as integer) & ?) = 0 GROUP BY \
      groups.group_id ORDER BY counter DESC', (exclude_flags,)).fetchall():
      board = row[2] if row[2] != '' else basicHTMLencode(row[1].replace('"', ''))
      stats.append(self.t_engine['stats_boards_row'].substitute({'postcount': row[0], 'board': board}))
    t_engine_mappings_overview['stats_boards_rows'] = '\n'.join(stats)
    yield 'overview', self.t_engine['overview'].substitute(t_engine_mappings_overview)
    for help_data in self.generate_help(t_engine_mappings_overview['news']):
      yield help_data

  def generate_help(self, news_data=None):
    if news_data is None:
      news_data = self._generate_news_data()
    yield 'help', self.t_engine['help_page'].substitute({'boardlist': self.get_board_list(), 'news': news_data})

  def generate_top(self):
    start_time = time.time()
    top_list = list()
    exclude_flags = self.cache['flags']['hidden'] | self.cache['flags']['blocked']
    for row in self.overchandb.execute('SELECT article_uid, sender, subject, sent, message, imagename, imagelink, thumblink, public_key, parent, article_hash, articles.group_id \
        FROM groups, articles WHERE groups.group_id = articles.group_id AND (cast(groups.flags as integer) & ?) = 0 ORDER BY sent DESC LIMIT ?', (exclude_flags, self.config['top_count'])).fetchall():
      if row[9] in ('', row[0]):
        # root
        data = self._get_preparse_post(row[:9], row[10], -1, 15, 2000, 0)
        data['parenthash_full'] = row[10]
        data['parenthash'] = row[10][:10]
      else:
        data = self._get_preparse_post(row[:9], row[10], -1, 15, 2000, 0, sha1(row[9]).hexdigest())
      data['frontend'] = u'{} => {}'.format(data['frontend'], self.get_board_data(row[11], 'board')[:20])
      nopic = '' if row[7] != '' else 'no'
      top_list.append(self.t_engine['message_'+ nopic +'pic_closed'].substitute(data))

    t_engine_mapper_top = {
        'thread_single': ''.join(top_list),
        'subject': self.config['top_count'],
        'boardlist': self.get_board_list(),
        'board': 'top ',
        'board_description': '',
        'target': ''
    }
    yield 'top', self.t_engine['thread_single_closed'].substitute(t_engine_mapper_top)
    self.log(self.logger.INFO, 'generating {}/top.html at {:0.4f}s'.format(self.config['output_directory'], (time.time() - start_time)))

