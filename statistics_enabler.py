# -*- coding: utf-8 -*-

import CommonConfigProcessor
import CommonDBProcessor
import time
from flask import Flask
from flask import render_template
from flask import jsonify
from flask import make_response
from flask_httpauth import HTTPBasicAuth

###############################################################################


class DBHandler(CommonDBProcessor.CommonDBProcessor):
    """数据库操作"""

    def __init__(self, database):
        super(DBHandler, self).__init__(database)

##############################################################################


app = Flask(__name__)

auth = HTTPBasicAuth()

@auth.get_password
def get_password(username):
    if username == confprocessor.get_username():
        return confprocessor.get_password()
    else: return None

@auth.error_handler
def unauthorized():
    return make_response(jsonify({'results': 'Unauthorized access'}), 401)

@app.route('/', methods=['GET'])
def index():
    """Introduction of platform"""
    port = confprocessor.get_port()
    return u'''<html><head><title>欢迎使用报表查询平台</title></head>
               <body><h1>本平台开放以下报表</h1>
               <ul>
               <li>查询报表：[get] https://x.x.x.x:%d/query</li>
               </ul>
               </body></html>
            ''' %(port)

@app.route('/query', methods=['GET'])
def query():
    """Introduction of query function"""
    port = confprocessor.get_port()
    return u'''<html><head><title>查询报表</title></head>
               <body><h1>【查询】提供以下报表</h1>
               <ul>
               <li>全网资产清单：[get] https://x.x.x.x:%d/query/assets</li>
               <li>全网漏洞清单：[get] https://x.x.x.x:%d/query/security</li>
               <li>漏洞及整改建议：[get] https://x.x.x.x:%d/query/vuls</li>
               </ul>
               </body></html>
            ''' %(port, port, port)

@app.route('/query/assets', methods=['GET'])
def assets():
    return render_template("assets.html")

@app.route('/query/security', methods=['GET'])
def security():
    return render_template("security.html")

@app.route('/query/vuls', methods=['GET'])
def vuls():
    return render_template("vuls.html")

##############################################################################


if __name__ == '__main__':
    confprocessor = CommonConfigProcessor.CommonConfigProcessor(
        'config_statistics.txt')
    app.jinja_env.auto_reload = True
    app.run(
        host='0.0.0.0', port=confprocessor.get_port(), ssl_context='adhoc')

