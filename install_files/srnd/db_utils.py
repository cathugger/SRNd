#!/usr/bin/python

import sqlite3
import sqlalchemy
from sqlalchemy.orm import sessionmaker
import os

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

class AlchemyConnector(object):

  def __init__(self, url, schema):
    self._engine = sqlalchemy.create_engine(url)
    self._conn = self._engine.connect()
    self._conn.execute('set search_path to {},public'.format(schema))
    
    self.close = self._conn.close

  def commit(self):
    pass
    
  def execute(self, sql, parameters=()):
    sql = sql.replace('""', "''")
    sql = sql.replace('?', '%s')
    return self._conn.execute(sql, parameters)
    
  def fetchone(self, sql, parameters=()):
    sql = sql.replace('""', "''")
    sql = sql.replace('?', '%s')
    return self.execute(sql, parameters).fetchone()

  def fetchall(self, sql, parameters=()):
    sql = sql.replace('""', "''")
    sql = sql.replace('?', '%s')
    return self.execute(sql, parameters).fetchall()
    
class SqliteManager(object):
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

class AlchemyManager(object):
  def __init__(self, url):
    self._url = url
    self._connector = AlchemyConnector

  def connect(self, database, **kwargs):
    return self._connector(self._url, database)


DatabaseManager = AlchemyManager
