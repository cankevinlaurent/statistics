# -*- coding: utf-8 -*-

import sqlite3

###############################################################################


class CommonDBProcessor(object):
    """数据库操作"""

    def __init__(self, database):
        self.conn = None
        try:
            self.conn = sqlite3.connect(database)
            self.cursor = self.conn.cursor()
        except:
            print 'Failed to connect to DB!'

    def __del__(self):
        try:
            self.conn.close()
        except:
            pass

##############################################################################
