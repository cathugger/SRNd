#!/usr/bin/env python
#
# -*- coding: utf-8 -*-
#

import psycopg2
import sqlite3
import sys
import os

#
# change these as needed
#
DB_HOST='database'
DB_USER='overchan'
DB_PASSWORD='overchan'
DB_PORT='5434'

def migrate(db, litedb):
    print ('migrate {}'.format(db))

    # connect to old database
    lite = sqlite3.connect(litedb)
    
    # connect to new database
    con = psycopg2.connect('user={} password={} host={} port={}'.format(DB_USER, DB_PASSWORD, DB_HOST, DB_PORT))
    cur = con.cursor()
    stuff = {
        'censor' : (
            (
                (
                    'cmd_map',
                    '(id INTEGER PRIMARY KEY, command text, received INTEGER DEFAULT -1, send INTEGER DEFAULT -1, replayable INTEGER DEFAULT -1)',
                    '(id, command, received, send, replayable) VALUES(%s, %s, %s, %s, %s)',
                ),
                (
                    'commands',
                    '(id INTEGER PRIMARY KEY, command TEXT, flag TEXT)',
                    '(id, command, flag) VALUES(%s, %s, %s)',
                ),
                (
                    'config',
                    '(key TEXT, value TEXT)',
                    '(key, value) VALUES(%s, %s)',
                ),
                (
                    'evil_to_srnd',
                    "(evil TEXT, srnd TEXT, comment TEXT DEFAULT '')",
                    '(evil, srnd, comment) VALUES(%s, %s, %s)',
                ),
                (
                    'keys',
                    '(id INTEGER PRIMARY KEY, key text UNIQUE, local_name text, flags text)',
                    '(id, key, local_name, flags) VALUES(%s, %s, %s, %s)',
                ),
                (
                    'log',
                    "(id INTEGER PRIMARY KEY, command_id INTEGER, accepted INTEGER, data TEXT, key_id INTEGER, reason_id INTEGER, comment TEXT, timestamp INTEGER, source TEXT DEFAULT 'local', UNIQUE(key_id, command_id, data, comment))",
                    '(id, command_id, accepted, data, key_id, reason_id, comment, timestamp, source) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)',
                ),
                (
                    'reasons',
                    '(id INTEGER PRIMARY KEY, reason text UNIQUE)',
                    '(id, reason) VALUES(%s, %s)',
                ),
                (
                    'signature_cache',
                    '(message_uid text PRIMARY KEY, valid INTEGER, received INTEGER DEFAULT 0)',
                    '(message_uid, valid, received) VALUES(%s, %s, %s)',
                )
            ),
            ('CREATE UNIQUE INDEX sig_cache_message_uid_idx ON censor.signature_cache(message_uid)',)
        ),
        'dropper': (
            (
                (
                    'article_path',
                    '(id INTEGER PRIMARY KEY, src TEXT, dst TEXT, count INTEGER DEFAULT 0, timestamp INTEGER DEFAULT 0, UNIQUE(src, dst))',
                    '(id, src, dst, count, timestamp) VALUES(%s, %s, %s, %s, %s)',
                ),
                (
                    'articles',
                    '(message_id text, group_id INTEGER, article_id INTEGER, received INTEGER, PRIMARY KEY (article_id, group_id))',
                    '(message_id, group_id, article_id, received) VALUES (%s, %s, %s, %s)',
                ),
                (
                    'config',
                    '(key text PRIMARY KEY, value text)',
                    '(key, value) VALUES(%s, %s)',
                ),
                (
                    'groups',
                    '(group_id SERIAL PRIMARY KEY ,group_name text UNIQUE, lowest_id INTEGER, highest_id INTEGER, article_count INTEGER, flag text, group_added_at INTEGER, last_update INTEGER)',
                    '(group_id, group_name, lowest_id, highest_id, article_count, flag, group_added_at, last_update) VALUES(%s, %s, %s, %s, %s, %s, %s, %s)',
                ),
            ),
            ('CREATE INDEX article_idx ON dropper.articles(message_id)', 'CREATE INDEX article_path_ab_idx ON dropper.article_path(src, dst)'),
        ),
        'hashes': (
            (
                (
                    'article_hashes',
                    '(message_id text PRIMARY KEY, message_id_hash text, sender_desthash text)',
                    '(message_id, message_id_hash, sender_desthash) VALUES(%s, %s, %s)',
                ),
            ),
            (
                'CREATE INDEX article_desthash_idx ON hashes.article_hashes(sender_desthash)',
                'CREATE INDEX article_hash_idx ON hashes.article_hashes(message_id_hash)',
            )
        ),
        'overchan': (
            (
                (
                    'articles',
                    '(article_uid text, group_id INTEGER, sender text, email text, subject text, sent INTEGER, parent text, message text, imagename text, imagelink text, thumblink text, last_update INTEGER, public_key text, received INTEGER DEFAULT 0, closed INTEGER DEFAULT 0, sticky INTEGER DEFAULT 0, article_hash text, PRIMARY KEY (article_uid, group_id))',
                    '(article_uid, group_id, sender, email, subject, sent, parent, message, imagename, imagelink, thumblink, last_update, public_key, received, closed, sticky, article_hash) VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)',
                ),
                (
                    'config',
                    '(key text PRIMARY KEY, value text)',
                    '(key, value) VALUES (%s, %s)',
                ),
                (
                    'flags',
                    '(flag_id SERIAL PRIMARY KEY, flag_name text UNIQUE, flag text)',
                    '(flag_id, flag_name, flag) VALUES(%s, %s, %s)',
                ),
                (
                    'groups',
                    "(group_id SERIAL PRIMARY KEY, group_name text UNIQUE, article_count INTEGER, last_update INTEGER, ph_name text DEFAULT '', ph_shortname text DEFAULT '', link text DEFAULT '', tag text DEFAULT '', description text DEFAULT '', flags text DEFAULT '0')",
                    '(group_id, group_name, article_count, last_update, ph_name, ph_shortname, link, tag, description, flags) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)',
                ),
                (
                    'thumb_info',
                    '(name TEXT PRIMARY KEY, x INTEGER, y INTEGER, size INTEGER)',
                    '(name, x, y, size) VALUES(%s, %s, %s, %s)',
                ),
            ),
            (
                'CREATE INDEX articles_article_hash_idx ON overchan.articles(article_hash)',
                'CREATE INDEX articles_article_idx ON overchan.articles(article_uid)',
                'CREATE INDEX articles_group_idx ON overchan.articles(group_id)',
                'CREATE INDEX articles_last_update_idx ON overchan.articles(group_id, parent, last_update)',
                'CREATE INDEX articles_parent_idx ON overchan.articles(parent)',
            ),
        ),
        'pastes': (
            (
                (
                    'pastes',
                    "(article_uid text, hash text PRIMARY KEY, sender text, email text, subject text, sent INTEGER, body text, root text, received INTEGER, lang text DEFAULT '', hidden INTEGER DEFAULT 0)",
                    '(article_uid, hash, sender, email, subject, sent, body, root, received, lang, hidden) VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)',
                ),
            ),[],
        ),
        'postman': (
            (
                (
                    'config',
                    '(key text PRIMARY KEY, value text)',
                    '(key, value) VALUES (%s, %s)',
                ),
                (
                    'i2p_desthash',
                    '(desthash text PRIMARY KEY, expires INTEGER)',
                    '(desthash, expires) VALUES(%s, %s)',
                ),
                (
                    'userkey',
                    '(userkey text PRIMARY KEY,         local_name text, expires INTEGER, allow INTEGER, cookie text, last_login INTEGER, postcount INTEGER DEFAULT 0, last_message INTEGER, last_message_id text)',
                    '(userkey, local_name, expires, allows, cookie, last_login, postcount, last_message, last_message_id) VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s)',
                ),
            ),
            ('CREATE INDEX userkey_cookie_idx ON postman.userkey(cookie, allow, expires)',)
        )
    }
    
    cur.execute('DROP SCHEMA IF EXISTS {} CASCADE'.format(db))
    cur.execute('CREATE SCHEMA IF NOT EXISTS {}'.format(db))
    
    for table, create, insert in stuff[db][0]:
        num = lite.execute('SELECT COUNT(*) FROM {}'.format(table)).fetchone()[0]
        print ('migrate {} to {}.{}'.format(num, db, table))
        cur.execute('CREATE TABLE IF NOT EXISTS {}.{}{}'.format(db, table, create))
        for tup in lite.execute('SELECT * FROM {}'.format(table)).fetchall():
            try:
                cur.execute('INSERT INTO {}.{}{}'.format(db, table, insert), tup)
            except:
                pass
    print ('create indexes for {}'.format(db))
    for query in stuff[db][1]:
        cur.execute(query)

    con.commit()
    lite.close()
    con.close()
    
def main():
    args = sys.argv[1:]
    if len(args) == 1:
        for db in ('censor', 'dropper', 'hashes', 'overchan', 'pastes', 'postman'):
            migrate(db, os.path.join(args[0], '{}.db3'.format(db)))
    else:
        print ('usage: {} /path/to/db_dir'.format(sys.argv[0]))

if __name__ == '__main__':
    main()
