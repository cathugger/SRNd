#!/usr/bin/python

import sqlite3
import os

_info = sqlite3.sqlite_version_info
if _info[0] <= 3 and _info[1] <= 8 and _info[2] <= 2:
  raise Exception("you need sqlite 3.8.3 or higher because expiration uses the WITH clause")

class SQLiteConnector(object):
  def __init__(self, database, **kwargs):
    self._conn = sqlite3.connect(database, **kwargs)
    self._sqlite = self._conn.cursor()

    self.execute = self._sqlite.execute
    self.commit = self._conn.commit
    self.close = self._conn.close

  def fetchone(self, sql, parameters=()):
    """Alternative method for execute(sql, parameters=()).fetchone()"""
    return self.execute(sql, parameters).fetchone()

  def fetchall(self, sql, parameters=()):
    """Alternative method for execute(sql, parameters=()).fetchall()"""
    return self.execute(sql, parameters).fetchall()

class DatabaseManager(object):
  def __init__(self, db_dir):
    self._db_dir = db_dir

  def connect(self, database, **kwargs):
    return SQLiteConnector(self._get_path(database), **kwargs)

  def _get_path(self, database):
    file_ext = '.db3'
    filename = os.path.splitext(os.path.basename(database))[0]
    if filename == '':
      raise sqlite3.Error('db name is empty')
    else:
      return os.path.join(self._db_dir, filename + file_ext)
