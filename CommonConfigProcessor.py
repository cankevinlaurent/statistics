# -*- coding: utf-8 -*-

import codecs

###############################################################################


class CommonConfigProcessor(object):
    """从配置文件读取参数"""

    def __init__(self, filename):
        self._content = self._read_content(filename)
        self._location = self._set_location()
        self._port = self._set_port()
        self._username = self._set_username()
        self._password = self._set_password()

    def _read_content(self, filename):
        if not filename: return None
        content = []
        f = None
        try:
            f = codecs.open(filename, 'r', 'utf-8')
            lines = f.readlines()
        except:
            return None
        finally:
            f and f.close()
        if not lines: return None
        for line in lines:
            line = line.strip()
            if len(line) == 0: continue
            if line[0] == '#': continue
            content.append(line)
        if not content: return None
        else: return content

    def _set_location(self):
        if not self._content: return None
        for line in self._content:
            if 'location' in line and '=' in line:
                return line.split('=')[1].strip().lower()
        return None

    def _set_port(self):
        if not self._content: return None
        for line in self._content:
            if 'port' in line and '=' in line:
                return int(line.split('=')[1].strip())
        return None

    def _set_username(self):
        if not self._content: return None
        for line in self._content:
            if 'username' in line and '=' in line:
                return line.split('=')[1].strip()
        return None

    def _set_password(self):
        if not self._content: return None
        for line in self._content:
            if 'password' in line and '=' in line:
                return line.split('=')[1].strip()
        return None

    def get_location(self):
        return self._location

    def get_port(self):
        return self._port

    def get_username(self):
        return self._username

    def get_password(self):
        return self._password

###############################################################################
