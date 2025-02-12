# -*- coding:utf-8 -*-
"""
从数据库中获取日志数据
"""
from Operation.Send_Payload.Connect_DB.access_pgsql import AccessPostgre
from Config.config import Config

class GetLog:
    def __init__(self):
        conf = Config()
        self.waf_ip = conf.waf_ip
        self.db_usr = conf.db_usr
        self.db_psw = conf.db_psw
        self.ap = AccessPostgre(ip=self.waf_ip, user=self.db_usr, password=self.db_psw)

    def get_log(self, table_name, fuzzy_fields=[], **kwargs):
        """
        根据自己的需求，自己设置条件字段
        :param table_name:
        :param query_fields:
        :param fuzzy_fields: 需要进行模糊查询的字段
        :param kwargs:
        :return:
        """
        try:
            result = self.ap.query_db_table(table_name, fuzzy_fields=fuzzy_fields, **kwargs)
            print(result)
            if len(result) != 0:
                return True  # 表示从数据库中查询到结果
            return False
        except Exception as e:
            print(e)
            return False

    def get_log_res(self, table_name, query_fields="*", fuzzy_fields=[], **kwargs):
        """
        函数功能:获取数据库查询后的结果
        :param table_name:
        :param query_fields: 需要查询的字段,默认*
        :param fuzzy_fields: 需要进行模糊查询的字段
        :param kwargs:
        :return:查询成功返回查询后的结果，数据类型是列表.查询失败返回的是False.
        """
        try:
            result = self.ap.query_db_table(table_name, query_fields=query_fields, fuzzy_fields=fuzzy_fields, **kwargs)
            if len(result) != 0:
                for i in range(len(result)):
                    value = result[i]
                    result[i] = value[0]
                return result  # 表示从数据库中查询到结果
            return False
        except Exception as e:
            print(e)
            return False

    def get_log_by_event_type(self, table_name, event_type):
        """
        根据事件类型查询数据库中是否存在对应的记录。
        :param ip: 管理ip
        :param table_name: 需要查询的数据库表名
        :return: True:表示存在对应查询条件的日志；False表示不存在对应查询条件的日志。
        """
        try:
            result = self.ap.query_db_table(table_name, event_type=event_type)
            print(result)
            if len(result) != 0:
                return True  # 表示从数据库中查询到结果
            return False
        except Exception as e:
            print(e)
            return False

    def get_log_by_uri_event_type(self, table_name, flag, event_type):
        try:
            sql = 'select * from %s where uri like \'%%%s%%\' and event_type=%s' % (table_name, str(flag), str(event_type))
            print("sql:", sql)
            result = self.ap.execute_sql(sql)
            if len(result) != 0:
                return True  # 表示从数据库中查询到结果
            return False
        except Exception as e:
            print(e)
            raise Exception(e)

    def get_log_by_uri(self, table_name, flag, field="uri"):
        """查询uri"""
        try:
            sql = 'select * from %s where %s like \'%%%s%%\'' % (table_name, field, str(flag))
            print("sql:", sql)
            result = self.ap.execute_sql(sql)
            if len(result) != 0:
                return True  # 表示从数据库中查询到结果
            return False
        except Exception as e:
            print(e)
            raise Exception(e)

    def delete_all_log(self, table_name):
        """
        清空数据库表防护日志.
        :param ip: waf管理ip
        :param table_name: 数据库表名
        :return: True表示清除成功,False表示删除失败
        """
        # 首先执行删除数据库表中的所有日志信息,如果删除失败,直接返回False
        try:
            self.ap.delete_table(table_name)
        except Exception as e:
            print(e)
            return False
        # 然后查询该数据库表,确定数据库表中的内容全部删除.
        sql = "select COUNT(*) as nums from %s;" % table_name
        try:
            result = self.ap.execute_sql(sql)
            print("result", result)  # [(0L,)]
            if int(result[0][0]) == 0:  # 表示该数据表已经被清空了。
                return True
            return False
        except Exception as e:
            print(e)
            return False

if __name__ == '__main__':
    pass
