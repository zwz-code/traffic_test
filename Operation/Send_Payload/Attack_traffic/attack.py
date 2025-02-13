# -*- coding:utf-8 -*-
import time
import traceback
from Operation.Send_Payload.Send_Req.send_request import Send_Payload_Request
from Operation.Send_Payload.Connect_DB.get_waf_log import GetLog
from Operation.Send_Payload.Attack_traffic.loop import LoopFunc

class Attack():

    alert_number_map = {
        "http_protocol_validation": 1,  
        "web_server": 2,  
        "web_plugin": 3,  
        "spider_anti": 4,  
        "scan_anti": 5,  
        "csrf": 6,  
        "upload_limit": 7,  
        "xss": 8,  
        "sql": 9,  
        "ldap": 10,  
        "ssi": 11,  
        "xpath": 12,  
        "command_injection": 13,  
        "path_traversal": 14,  
        "remote_file_inclusion": 15, 
        "info_leak": 17,  
        "content_filter": 18,  
        "download_limit": 19,  
        "custom_policy": 21,  
        "http_flood": 25,  
        "http_acl": 27,  
        "anti_leech": 30,  
        "cookie_sec": 31,  
        "webshell": 35,  
        "sensitiveinfo_filter": 36,  
        "brute_force": 40,  
        "xml_firewall": 44,  
        "php_code_injection": 49,  
        "java_code_injection": 56  
    }

    def send_payload(self, ip, port, payload_type, rule_id, flag, protocol="http", index=1, count=1, domain=None):
        """
        发送payload
        :param ip:
        :param port:
        :param payload_type:
        :param rule_id:
        :param flag:
        :param protocol:
        :param index:
        :param count:
        :param domain:
        :return:
        """
        print("发送类型为：%s 的Payload"%payload_type)
        sendPR = Send_Payload_Request()
        try:
            result = sendPR.send_payload(ip, port, payload_type, rule_id, flag, protocol, index, count, domain)
            print("发送Payload的结果为%s"%result)
            return result
        except Exception as e:
            raise Exception("send payload failed, Detail:" %e)

    def get_alert_type_number(self, payload_type):
        """获取告警类型对应的数字"""
        if payload_type in self.alert_number_map.keys():
            return self.alert_number_map[payload_type]
        else:
            print ("%s中不包含payload类型:%s" % (self.alert_number_map.keys(), payload_type))
            return -1

    def payload_log_uri_event(self, server_ip, port, payload_type, rule_id, flag, table_name,
                              index, event_type, log_func, pay_exp_value, log_exp_value, protocol, domain, interval, count):
        """
        函数目的：将发送payload和根据uri和事件类型获取日志结合。
        1. ${flag}=None时，会调用get_log_by_event_type
        2. ${flag}!=None时，会调用get_log_by_uri_event_type
        3. 需要增加参数，用于指定调用的查询日志函数。loc_func参数:
            log_func= uri_event，会调用get_log_by_uri_event_type
            log_func=uri，此时调用 get_log_by_uri(field=uri)
            log_func=url，此时调用 get_log_by_uri(field=url)     t_webaccesslog中使用的是url
            log_func=event,此时调用 get_log_by_event_type

        :param server_ip:目标IP
        :param port:目标端口
        :param payload_type:payload类型
        :param rule_id:规则Id
        :param index:标识位
        :param ip:waf的IP
        :param table_name:数据库表名
        :param flag:标识符
        :param event_type:事件类型
        :param log_func:指定调用的查询日志函数
        :param pay_exp_value:payload执行的期望结果
        :param log_exp_value:日志查询的期望结果
        :param protocol:协议类型
        :param domain:域名
        :param interval:发送Payload和查数据库的间隔时间
        :param count:发送payload并发次数
        :return:
        """
        GREEN = '\033[32m'
        RED = '\033[31m'
        END_COLOR = '\033[0m'
        get_log = GetLog()
        # 首先, 根据log_func来判断是否需要event_type字段.
        # 接着, 如果需要event_type字段,且用户没有传递event_type字段时,此时程序会根据payload_type获取对应的event_type值
        # 然后, 如果没有获取到event_type值,则直接报错.
        if log_func in ["uri_event", "event"] and not event_type:
            event_type = self.get_alert_type_number(payload_type)
            if event_type == -1:
                # 2022.06.06当传入normal类型时，此时如果不传入event_type，则通过get_alert_type_number得到的event_type取值就是-1。这里不进行处理
                # 就让其为-1即可。
                print(RED+"payload_type=%s 不存在于%s中" % (payload_type, self.alert_number_map.keys())+END_COLOR)
        try:
            pay_res = self.send_payload(server_ip, port, payload_type, rule_id, flag, protocol=protocol, index=index, domain=domain, count=count)
            print("send_payload函数执行结果为:", pay_res)
            if str(pay_res) in pay_exp_value:  # 如果payload发送结果在期望结果中，则开始查询日志。
                print(GREEN+"send_payload执行结果(%s)在期望值(%s)中" % (pay_res, pay_exp_value)+END_COLOR)
                print("sleep: %s" % interval)
                time.sleep(int(interval))
                if log_func == "event":
                    log_res = get_log.get_log_by_event_type(table_name, event_type)
                elif log_func == "uri_event":
                    if flag:
                        log_res = get_log.get_log_by_uri_event_type(table_name, flag, event_type)
                    else:
                        log_res = get_log.get_log_by_event_type(table_name, event_type)
                elif log_func == "uri":
                    log_res = get_log.get_log_by_uri(table_name, flag, field="uri")
                elif log_func == "url":
                    log_res = get_log.get_log_by_uri(table_name, flag, field="url")
                else:
                    print(RED+"log_func参数(%s)错误" % log_func+END_COLOR)
                    raise Exception("log func(%s) is invalid or flag is invalid" % log_func)
                print("get_log结果为:", log_res)
                if log_res in log_exp_value:  # 表示日志查询结果与预期结果一致
                    print(GREEN+"get_log结果(%s)在期望结果(%s)中" % (log_res, log_exp_value)+END_COLOR)
                    return True
                else:
                    print(RED+"get_log结果(%s)不在期望结果(%s)中" % (log_res, log_exp_value)+END_COLOR)
                    return False
            else:
                print(RED+"send_payload执行结果(%s)不在期望值(%s)中" % (pay_res, pay_exp_value)+END_COLOR)
                return False
        except Exception as e:
            # 打印详细的错误信息
            traceback.print_exc()
            raise Exception("发送攻击和查询日志错误.%s" % e)

    def waf_payload_log_uri_event(self, server_ip, port, payload_type, rule_id, flag, index, table_name, event_type=None, log_func="uri_event", pay_exp_value=["1003"],
                                  log_exp_value=[True], protocol="http", domain=None, interval=4, count=1):
        """
        函数功能：循环远程发送攻击并查询告警日志信息。
        参数说明：
            - server_ip：发送payload的目标服务器IP
            - port：发送payload的目标服务器端口号
            - payload_type：payload类型
                支持的payload类型:可以查看payload.json文件中的key值
            - rule_id：payload规则id, 输入0即可
            - index：flag拼接的索引
                取值0 表示flag拼接在路径的最前.比如path为/py/index.php, 拼接flag=12345之后,此时的path为 /12345/py/index.php
                取值1 表示flag拼接在路径的参数部分. 比如path为/py/index.php, 拼接flag=12345之后,此时的path为 /py/index.php?12345
            - table_name：数据库表名
            - flag：uri中的flag标识
            - event_type：攻击触发的事件类型对应的数字编码。如果传入None，此时会自己根据payload_type获取对应的告警类型。
            - log_func: 查询日志的函数，默认使用uri_event，还可以取值为event、uri url
                uri_event: 同时根据uri和event_type来查询日志数据库;会查询日志数据库中的uri字段中是否包含flag,以及查询event_type字段取值是否等于event_type
                event: 只根据event_type来查询日志数据库.
                uri: 只根据uri来查询日志数据库
                url: 只根据url来查询日志数据库.有些数据库表中使用url,比如t_webaccesslog
            - pay_exp_value: list。期望的payload发送之后的响应结果，有1001 1002 1003 False这4个取值。
            - log_exp_value: list. True和False，[True]表示期望存在日志，[False]表示期望不存在日志, [True, False]则表示不在乎是否存在日志.
            - protocol: 协议类型，默认使用http
            - domain：域名,默认为None. 如果取值不为None,则发送payload时会使用域名.
            - interval: 发送payload和查询log之间的间隔。可以参考下面的说明来决定是否使用该参数
            - count: 并发发送payload的次数，默认只发送1次，如果设置count=3，则可以在1s内并发发送多次payload。目前不支持文件上传的并发。
        函数返回：
            - result：result：成功则返回True，失败则报错。
        """
        loop_func = LoopFunc()
        result = loop_func.loop_func(self.payload_log_uri_event, True, server_ip, port, payload_type, rule_id, flag, table_name, index, event_type, log_func,
                                          pay_exp_value, log_exp_value, protocol, domain, interval, count)
        # 这里的结果可能为乱码，因为打印的是一个元组，元组里面的中文会显示为unicode
        print(result)
        if result[0]:
            return True
        else:
            return False

att = Attack()
if __name__ == '__main__':
    pass
