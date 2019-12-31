##############################################################################
- @Code:    1016 Project
- @Purpose: 报表展示各项目、工程的数据信息。
- @Author:  Kévin
- @Update:  17 Oct. 2018
##############################################################################

##################
I. 项目文件
##################
- /statistics               项目文件夹。
- statistics.db             数据库，记录信息。
- CommonConfigProcessor.py  公共类，读取配置文件config.txt。
- CommonDBProcessor.py      公共类，数据库操作。
- statistics_retriever.py   读取各数据源API。
- statistics_enabler.py     使能程序，提供查询信息。
- config_statistics.txt     配置文件，包括端口、认证等。
- start_statistics.sh       启动脚本。
- readme_statistics.txt     本说明文档。

##################
II. 项目部署条件
##################
- 推荐CentOS 6.9或更高
- 推荐python 2.7.14或更高
- 不需要root账号
- #visudo，增加一句：wangwei ALL=(jtitsm)   ALL
- 正确设置文件和文件夹权限，如db文件及其全路径文件夹必须可写
- requests库：wangwei$pip install --user requests
- flask库：wangwei$pip install --user flask
- flask-httpauth库：wangwei$pip install --user flask-httpauth
- pyOpenSSL库：wangwei$pip install --user pyOpenSSL

##################
III. 项目运行
##################
- 应用账号：jtitsm，部署/运维账号：wangwei
- 启动脚本赋可执行权限：wangwei$chmod +x start_statistics.sh
- wangwei$sudo -u jtitsm ./start_statistics.sh

##################
IV. 数据库元信息
##################
- 数据库：SQLite3
- 数据库编码：utf-8
CREATE TABLE "asset" (
"ip"  TEXT NOT NULL,
"admin"  TEXT DEFAULT NULL,
"description"  TEXT DEFAULT NULL,
PRIMARY KEY ("ip" ASC)
);

CREATE TABLE "hosts" (
"id"  INTEGER NOT NULL,
"ip"  TEXT NOT NULL,
"hostname"  TEXT DEFAULT NULL,
"ostype"  TEXT DEFAULT NULL,
"portid"  TEXT DEFAULT NULL,
"proto"  TEXT DEFAULT NULL,
"service"  TEXT DEFAULT NULL,
"vulname"  TEXT DEFAULT NULL,
"timestamp"  INTEGER NOT NULL,
PRIMARY KEY ("id" ASC)
);

CREATE TABLE "ips" (
"ip"  TEXT NOT NULL,
"stat"  TEXT NOT NULL,
"timestamp"  INTEGER NOT NULL,
PRIMARY KEY ("ip")
);

CREATE TABLE "vulnerbilities" (
"vulname"  TEXT NOT NULL,
"level"  TEXT NOT NULL,
"desc"  TEXT NOT NULL,
"resolution"  TEXT DEFAULT NULL,
"cve"  TEXT DEFAULT NULL,
PRIMARY KEY ("vulname")
);

