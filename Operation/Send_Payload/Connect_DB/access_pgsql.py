# -*- coding:utf-8 -*-
"""
数据库访问类
"""
import psycopg2

class AccessPostgre():
    def __init__(self, ip, user, password):
        self.ip = ip
        self.user = user
        self.password = password
        self.cur = None
        self.conn = None
        self.connect_db()

    def connect_db(self):
        """连接数据库"""
        try:
            self.conn = psycopg2.connect(host=self.ip, user=self.user, password=self.password)
        except Exception as e:
            raise Exception("Database connection exception", e)

    def query_db_table(self, table_name, query_fields="*", fuzzy_fields=[], **kwargs):
        """
        从数据库中获取日志，根据传入的参数键值对进行查询。是一个通用的方法，主要目的是减少接口函数的数量，同时可以根据数据库中已经存在的参数灵活组合查询条件。
        :param ip: 管理IP
        :param table_name: 数据库表名
        :param query_fileds: 查询的字段,默认为空,可以为a,b,c...
        :param fuzzy_fields: kwargs的key中需要进行模糊查询的参数。
        :param kwargs: 查询的键值对信息，比如下面的例子中的event_type, action, dst_port都是对应t_ddoslog表中的列值。
        result = o.get_log(waf_ip, table_name="t_ddoslog", event_type=42, action=5, dst_port=888)
        :return: 返回查询结果

        例子：
        1: 当要查询的字段中包含需要模糊查询的字段，此时将需要模糊查询的字段放在fuzzy_fields中即可，如下：
        res = a.query_db_table(table_name="t_webseclog", event_type=21, uri="domain", policy_id=4980737, fuzzy_fields=["uri"])
        对应的sql为：select * from t_webseclog where policy_id=4980737 and event_type=21 and uri like '%domain%'
        2. 当要模糊查询的字段包含多个特征值，此时如下：
        res = a.query_db_table(table_name="t_webseclog", event_type=21, uri=["domain", "bbb"], policy_id=4980737, fuzzy_fields=["uri"])
        对应的sql为：select * from t_webseclog where policy_id=4980737 and event_type=21 and uri like '%domain%bbb%'

        """
        self.cur = self.conn.cursor()
        # print kwargs

        if kwargs:
            sql = "select %s from %s" % (query_fields, table_name)
            where_list = []
            # 获取kwargs中的键值对，然后构建sql语句
            for key, value in kwargs.items():
                # 模糊查询
                if key in fuzzy_fields:
                    # 针对多个特征取值的情况，比如uri=["domain", "bbb"]
                    if isinstance(value, list):
                        value = "%".join(value)
                    where_list.append("%s like '%%%s%%'"%(key, value))
                    continue
                where_list.append(key + "=" + str(value))
            where_st = " and ".join(where_list)
            sql = sql + " where " + where_st
        else:
            sql = "select %s from %s" % (query_fields, table_name)
        try:
            print("sql:", sql)
            self.cur.execute(sql)
            self.conn.commit()
            result = self.cur.fetchall()
            return result
        except Exception as e:
            raise Exception("Query sql:%s error. %s", (sql, e))

    def execute_sql(self, sql):
        """
        根据传入的sql查询结果。
        """
        self.cur = self.conn.cursor()
        try:
            self.cur.execute(sql)
            self.conn.commit()
            result = self.cur.fetchall()
            return result
        except Exception as e:
            raise Exception("Query sql:%s error. %s", (sql, e))

    def delete_table(self, table_name):
        """清空数据库表"""
        self.cur = self.conn.cursor()
        try:
            sql = 'delete from %s;' % table_name
            print(sql)
            self.cur.execute(sql)
            self.conn.commit()
        except Exception as e:
            raise Exception("sql语句(%s)执行错误. %s" % (sql, e))

    def close_db(self):
        self.cur.close()
        self.conn.close()