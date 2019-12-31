# -*- coding: utf-8 -*-

import time
import os
import codecs
import requests
import CommonConfigProcessor
import CommonDBProcessor

##############################################################################


class ConfigHandler(CommonConfigProcessor.CommonConfigProcessor):

    def __init__(self, filename):
        super(ConfigHandler, self).__init__(filename)

##############################################################################


class DBHandler(CommonDBProcessor.CommonDBProcessor):

    def __init__(self, database):
        super(DBHandler, self).__init__(database)

    def clear_db_table(self, tablename):
        self.cursor.execute('DELETE FROM ' + tablename)
        self.conn.commit()

    def write_to_db_asset(self, result):
        self.cursor.executemany(
            'INSERT OR REPLACE INTO asset VALUES(?,?,?)', result)
        self.conn.commit()

    def write_to_db_hosts(self, result):
        self.cursor.executemany(
            'INSERT OR REPLACE INTO hosts VALUES(?,?,?,?,?,?,?,?,?)', result)
        self.conn.commit()

    def write_to_db_vuls(self, result):
        self.cursor.executemany(
            'INSERT OR REPLACE INTO vulnerbilities VALUES(?,?,?,?,?)', result)
        self.conn.commit()

    def write_to_db_ips(self, result):
        if not result: return
        self.cursor.executemany(
            'INSERT OR REPLACE INTO ips VALUES(?,?,?)', result)
        self.conn.commit()

    def fetch_active_ips(self):
        query = "SELECT ip, timestamp FROM ips WHERE stat='up'"
        self.cursor.execute(query)
        return self.cursor.fetchall()

    def get_asset(self):
        query = "SELECT * FROM asset"
        self.cursor.execute(query)
        return self.cursor.fetchall()

    def fetch_vuls(self):
        query = "SELECT * FROM vulnerbilities WHERE level='m' or level='h'"
        self.cursor.execute(query)
        return self.cursor.fetchall()

    def fetch_distinct_hosts(self):
        query = "SELECT DISTINCT(ip), hostname, ostype FROM hosts"
        self.cursor.execute(query)
        return self.cursor.fetchall()

    def fetch_hosts_n_asset(self):
        """port repr:
            7:echo, 13:daytime, 19:chargen, 22:ssh, 23:telnet, 25:smtp,
            37:time, 53:dns, 111:rpcbind/portmap, 113:ident, 123:ntp,
            139:netbios, 161:snmp, 177:xdmcp, 445:smb, 513:rlogin, 514:rsh,
            587:sendmail, 901:samba-swat, 993:imaps, 995:pop3, 2381:compaq,
            3389:rdp, 5151:ssh, 6112:dtspcd
        """
        query = "SELECT hosts.ip, timestamp, admin, description, ostype, \
            portid, service, hosts.vulname, level, cve \
            FROM hosts, asset, vulnerbilities \
            WHERE hosts.ip = asset.ip AND hosts.vulname = vulnerbilities.vulname \
            AND level != 'l' \
            AND portid NOT IN (7,13,19,22,23,25,37,53,111,113,123,139,161,177,445,513,514,587,901,993,995,2381,3389,5151,6112)"
        self.cursor.execute(query)
        return self.cursor.fetchall()

##############################################################################


class StatisticsRetriever(object):
    """obtain API data from outer sources"""

    def retrieve_asset_data(self, url, auth):
        try:
            resp = requests.get(url=url, auth=auth,
                headers={'Accept': 'application/json'}, verify=False)
            if resp.status_code != 200: return None
            if not resp.json().get('results'): return None
        except:
            print 'Error retrieving asset data'
            return None
        assets = []
        for asset in resp.json().get('results'):
            assets.append((asset.get('ip'), asset.get('admin'),
                asset.get('description')))
        return assets

    def retrieve_hosts_data(self, url, auth):
        try:
            resp = requests.get(url=url, auth=auth,
                headers={'Accept': 'application/json'}, verify=False)
            if resp.status_code != 200: return None
            if not resp.json().get('results'): return None
        except:
            print 'Error retrieving hosts data'
            return None
        hosts = []
        for host in resp.json().get('results'):
            hosts.append((host.get('id'), host.get('ip'),
                host.get('hostname'), host.get('ostype'), host.get('portid'),
                host.get('proto'),host.get('service'), host.get('vulname'),
                host.get('timestamp')))
        return hosts

    def retrieve_vuls_data(self, url, auth):
        try:
            resp = requests.get(url=url, auth=auth,
                headers={'Accept': 'application/json'}, verify=False)
            if resp.status_code != 200: return None
            if not resp.json().get('results'): return None
        except:
            print 'Error retrieving vuls data'
            return None
        vulnerbilities = []
        for vul in resp.json().get('results'):
            vulnerbilities.append((vul.get('vulname'), vul.get('level'),
                vul.get('desc'), vul.get('resolution'), vul.get('cve')))
        return vulnerbilities

    def retrieve_ips_data(self, url, auth):
        try:
            resp = requests.get(url=url, auth=auth,
                headers={'Accept': 'application/json'}, verify=False)
            if resp.status_code != 200: return None
            if not resp.json().get('results'): return None
        except:
            print 'Error retrieving ips data'
            return None
        ips = []
        for ip in resp.json().get('results'):
            ips.append((ip.get('ip'), ip.get('stat'), ip.get('timestamp')))
        return ips

##############################################################################


def main():
    confhandler = ConfigHandler('config_statistics.txt')
    dbhandler = DBHandler('statistics.db')

    st = StatisticsRetriever()

    #get asset from relation
    result_asset = st.retrieve_asset_data(
        'https://10.128.19.7:12580/query/relationship',
        (confhandler.get_username(), confhandler.get_password()))
    if result_asset:
        dbhandler.clear_db_table('asset')
        dbhandler.write_to_db_asset(result_asset)

    #get hosts from secsensor
    result_hosts = st.retrieve_hosts_data(
        'https://10.128.19.22:2018/query/hosts/table',
        (confhandler.get_username(), confhandler.get_password()))
    if result_hosts:
        dbhandler.clear_db_table('hosts')
        dbhandler.write_to_db_hosts(result_hosts)

    #get vulnerbilities from secsensor
    result_vuls = st.retrieve_vuls_data(
        'https://10.128.19.22:2018/query/vuls',
        (confhandler.get_username(), confhandler.get_password()))
    if result_vuls:
        dbhandler.clear_db_table('vulnerbilities')
        dbhandler.write_to_db_vuls(result_vuls)

    #update source data
    try:
        r = requests.post('https://10.128.19.8:20502/operation/renew', verify=False,
            auth=(confhandler.get_username(), confhandler.get_password()))
        r = requests.post('https://10.128.19.10:20502/operation/renew', verify=False,
            auth=(confhandler.get_username(), confhandler.get_password()))
        r = requests.post('https://10.128.19.11:20502/operation/renew', verify=False,
            auth=(confhandler.get_username(), confhandler.get_password()))
    except:
        print 'Error renewing sources'

    #get ips from hostsexplor
    result_ips_sh = st.retrieve_ips_data(
        'https://10.128.19.8:20502/query/hosts',
        (confhandler.get_username(), confhandler.get_password()))
    result_ips_nm = st.retrieve_ips_data(
        'https://10.128.19.10:20502/query/hosts',
        (confhandler.get_username(), confhandler.get_password()))
    result_ips_bj = st.retrieve_ips_data(
        'https://10.128.19.11:20502/query/hosts',
        (confhandler.get_username(), confhandler.get_password()))
    if result_ips_sh or result_ips_nm or result_ips_bj:
        dbhandler.clear_db_table('ips')
        dbhandler.write_to_db_ips(result_ips_sh)
        dbhandler.write_to_db_ips(result_ips_nm)
        dbhandler.write_to_db_ips(result_ips_bj)

    #preliminary processing for staticstics_enabler.py to fetch html directly
    #calculate asset.html
    ip_records = dbhandler.fetch_active_ips()
    asset_records = dbhandler.get_asset()
    host_records = dbhandler.fetch_distinct_hosts()
    if ip_records:
        htmlstring = u"<html><head><meta http-equiv='Content-Type' content='text/html; charset=utf-8'><title>全网资产清单</title></head><body><table><tr><td>IP</td><td>更新时间戳</td><td>责任人</td><td>IT系统描述</td><td>主机名</td><td>操作系统</td></tr>"
        for ip_record in ip_records:
            admin = None
            description = None
            if asset_records:
                for asset_record in asset_records:
                    if ip_record[0] == asset_record[0]:
                        admin = asset_record[1]
                        description = asset_record[2]
                        break
            hostname = None
            ostype = None
            if host_records:
                for host_record in host_records:
                    if ip_record[0] == host_record[0]:
                        hostname = host_record[1]
                        ostype = host_record[2]
                        break
            htmlstring = u"%s<tr><td>%s</td><td>%d</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" %(htmlstring, ip_record[0], ip_record[1], admin, description, hostname, ostype)
        htmlstring = htmlstring + u"</table></body></html>"

        print "writing to assets.html file"
        f = None
        try:
            f = codecs.open('./templates/temp_assets.html', 'w', 'utf-8')
            f.write(htmlstring)
        except:
            print traceback.format_exc()
        finally:
            f and f.close()
        if os.path.exists('./templates/assets.html'):
            os.remove('./templates/assets.html')
        if os.path.exists('./templates/temp_assets.html'):
            os.rename('./templates/temp_assets.html', './templates/assets.html')

    #calculate security.html
    hosts_records = dbhandler.fetch_hosts_n_asset()
    if hosts_records:
        htmlstring = u"<html><style>table {border-collapse: collapse; border:0px solid black; cellpadding='0'; cellspacing='0'; font-size='7pt'}</style><head><meta http-equiv='Content-Type' content='text/html; charset=utf-8'><title>全网漏洞清单</title></head><body><table><tr><td width='6%'>IP</td><td width='7%'>发现日期</td><td width='8%'>系统负责人</td><td width='16%'>IT系统描述</td><td width='5%'>操作系统</td><td width='4%'>端口号</td><td width='9%'>服务名</td><td width='35%'>漏洞名</td><td width='3%'>风险</td><td width='7%'>国际编号</td></tr>"
        for hosts_record in hosts_records:
            timestr = time.strftime('%Y-%m-%d %H:%M', time.localtime(hosts_record[1]))
            vul_level = u'高'
            if hosts_record[8] == u'm':
                vul_level = u'中'
            elif hosts_record[8] == u'l':
                vul_level = u'低'
            htmlstring = u"%s<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" %(htmlstring, hosts_record[0], timestr, hosts_record[2], hosts_record[3], hosts_record[4], hosts_record[5], hosts_record[6], hosts_record[7], vul_level, hosts_record[9])
        htmlstring = htmlstring + u"</table></body></html>"

        print "writing to security.html file"
        f = None
        try:
            f = codecs.open('./templates/temp_security.html', 'w', 'utf-8')
            f.write(htmlstring)
        except:
            print traceback.format_exc()
        finally:
            f and f.close()
        if os.path.exists('./templates/security.html'):
            os.remove('./templates/security.html')
        if os.path.exists('./templates/temp_security.html'):
            os.rename('./templates/temp_security.html', './templates/security.html')

    #calculate vuls.html
    vuls_records = dbhandler.fetch_vuls()
    if vuls_records:
        htmlstring = u"<html><style>table {border-collapse: collapse; border:1px solid black; cellpadding='0'; cellspacing='0'; font-size='7pt'} td {border:1px solid black;}</style><head><meta http-equiv='Content-Type' content='text/html; charset=utf-8'><title>漏洞名称及整改建议参考</title></head><body><table><tr><td>漏洞名称</td><td>威胁等级</td><td>详细描述</td><td>整改建议</td><td>国际编号</td></tr>"
        for vuls_record in vuls_records:
            vul_level = u'高'
            if hosts_record[1] == 'm': vul_level = u'中'
            vuls_record_2 = ""
            vuls_record_3 = ""
            if vuls_record[2]:
                vuls_record_2 = vuls_record[2].replace(u"<br/>", u"<br>")
                vuls_record_2 = vuls_record_2.replace(u'<tr class="odd">', u"")
                vuls_record_2 = vuls_record_2.replace(u'<td valign="top" width="20%">详细描述</td>', u"")
                vuls_record_2 = vuls_record_2.replace(u'<td valign="top">', u"")
                vuls_record_2 = vuls_record_2.replace(u'</td></tr>', u"")
                vuls_record_2 = vuls_record_2.replace(u'{{{', u"")
                vuls_record_2 = vuls_record_2.replace(u'<tr>', u"<span></span>")
                vuls_record_2 = vuls_record_2.replace(u'<td>', u"<span></span>")
                vuls_record_2 = vuls_record_2.replace(u'</tr>', u"<span></span>")
                vuls_record_2 = vuls_record_2.replace(u'</td>', u"<span></span>")
            if vuls_record[3]:
                vuls_record_3 = vuls_record[3].replace(u"<br/>", u"<br>")
                vuls_record_3 = vuls_record_3.replace(u'<tr class="even">', u"")
                vuls_record_3 = vuls_record_3.replace(u'<td valign="top">解决办法</td>', u"")
                vuls_record_3 = vuls_record_3.replace(u'<td valign="top">', u"")
                vuls_record_3 = vuls_record_3.replace(u'</td></tr>', u"")
                vuls_record_3 = vuls_record_3.replace(u'<tr>', u"<span></span>")
                vuls_record_3 = vuls_record_3.replace(u'<td>', u"<span></span>")
                vuls_record_3 = vuls_record_3.replace(u'</tr>', u"<span></span>")
                vuls_record_3 = vuls_record_3.replace(u'</td>', u"<span></span>")
            htmlstring = u"%s<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" %(htmlstring, vuls_record[0], vul_level, vuls_record_2, vuls_record_3, vuls_record[4])
        htmlstring = htmlstring + u"</table></body></html>"

        print "writing to vuls.html file"
        f = None
        try:
            f = codecs.open('./templates/temp_vuls.html', 'w', 'utf-8')
            f.write(htmlstring)
        except:
            print traceback.format_exc()
        finally:
            f and f.close()
        if os.path.exists('./templates/vuls.html'):
            os.remove('./templates/vuls.html')
        if os.path.exists('./templates/temp_vuls.html'):
            os.rename('./templates/temp_vuls.html', './templates/vuls.html')

##############################################################################


if __name__ == '__main__':
    while True:
        main()
        print 'All done!'
        time.sleep(3200)
