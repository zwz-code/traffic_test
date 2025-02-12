# -*- coding:utf-8 -*-
import time
from Operation.Send_Payload.Attack_traffic.attack import att
import unittest
import json
from ddt import ddt,unpack,data
import os
from Base.base_methods import BaseMethods as bm
from Config.config import conf

def read_dict_json():
    path = os.path.abspath(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
    temp_path = r'\Sence\address_info.json'
    file_path = path+temp_path
    return json.load(open(file_path, 'r', encoding='utf-8'))  # 使用json包读取json文件，并作为返回值返回

@ddt
class TestPayload(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        pass

    @data(*read_dict_json())
    @unpack
    def test_spider_anti(self, server_ip, server_port, protocol):
        "爬虫防护"
        flag = int(time.time())
        result = att.waf_payload_log_uri_event(server_ip=server_ip, port=server_port, payload_type="spider_anti", rule_id="0", flag=flag, protocol=protocol,
                                  index=0, table_name="t_webseclog", log_func="uri_event")
        self.assertTrue(result)

    @data(*read_dict_json())
    @unpack
    def test_cookie_sec(self, server_ip, server_port, protocol):
        "cookie安全"
        flag = int(time.time())
        result = att.waf_payload_log_uri_event(server_ip=server_ip, port=server_port, payload_type="cookie_sec",
                                                rule_id="0", flag=flag, protocol=protocol,
                                                index=0, table_name="t_webseclog", log_func="uri_event")
        self.assertTrue(result)

    @data(*read_dict_json())
    @unpack
    def test_sql(self, server_ip, server_port, protocol):
        "web通用防护-sql注入"
        flag = int(time.time())
        result = att.waf_payload_log_uri_event(server_ip=server_ip, port=server_port, payload_type="sql",
                                                rule_id="1", flag=flag, protocol=protocol,
                                                index=0, table_name="t_webseclog", log_func="uri_event")
        self.assertTrue(result)

    @data(*read_dict_json())
    @unpack
    def test_http_acl(self, server_ip, server_port, protocol):
        "http访问控制策略-PUT请求"
        flag = int(time.time())
        result = att.waf_payload_log_uri_event(server_ip=server_ip, port=server_port, payload_type="http_acl",
                                                    rule_id="0", flag=flag, protocol=protocol,
                                                    index=0, table_name="t_webseclog", log_func="uri_event")
        self.assertTrue(result)

    @data(*read_dict_json())
    @unpack
    def test_anti_leech(self, server_ip, server_port, protocol):
        "盗链防护"
        flag = int(time.time())
        result = att.waf_payload_log_uri_event(server_ip=server_ip, port=server_port, payload_type="anti_leech",
                                                    rule_id="0", flag=flag, protocol=protocol,
                                                    index=0, table_name="t_webseclog", log_func="uri_event")
        self.assertTrue(result)

    @data(*read_dict_json())
    @unpack
    def test_scan_anti(self, server_ip, server_port, protocol):
        "扫描防护"
        flag = int(time.time())
        result = att.waf_payload_log_uri_event(server_ip=server_ip, port=server_port, payload_type="scan_anti",
                                                    rule_id="0", flag=flag, protocol=protocol, index=0, table_name="t_webseclog", log_func="event")
        self.assertTrue(result)

    @data(*read_dict_json())
    @unpack
    def test_upload_limit(self, server_ip, server_port, protocol):
        "非法上传"
        flag = int(time.time())
        result = att.waf_payload_log_uri_event(server_ip=server_ip, port=server_port, payload_type="upload_limit",
                                                    rule_id="0", flag=flag, protocol=protocol, index=0, table_name="t_webseclog", log_func="uri_event")
        self.assertTrue(result)

    @data(*read_dict_json())
    @unpack
    def test_download_limit(self, server_ip, server_port, protocol):
        "非法下载"
        flag = int(time.time())
        result = att.waf_payload_log_uri_event(server_ip=server_ip, port=server_port, payload_type="download_limit",
                                                    rule_id="1", flag=flag, protocol=protocol, index=1, table_name="t_webseclog", log_func="uri_event")
        self.assertTrue(result)

    @data(*read_dict_json())
    @unpack
    def test_content_filter(self, server_ip, server_port, protocol):
        "内容过滤"
        flag = int(time.time())
        result = att.waf_payload_log_uri_event(server_ip=server_ip, port=server_port, payload_type="content_filter",
                                                    rule_id="0", flag=flag, protocol=protocol, index=1, table_name="t_webseclog", log_func="uri_event")
        self.assertTrue(result)

    @data(*read_dict_json())
    @unpack
    def test_web_server(self, server_ip, server_port, protocol):
        "web服务器攻击"
        flag = int(time.time())
        result = att.waf_payload_log_uri_event(server_ip=server_ip, port=server_port, payload_type="web_server",
                                                    rule_id="0", flag=flag, protocol=protocol, index=1, table_name="t_webseclog", log_func="uri_event")
        self.assertTrue(result)

    @data(*read_dict_json())
    @unpack
    def test_xml_firewall(self, server_ip, server_port, protocol):
        "XML攻击防护"
        flag = int(time.time())
        result = att.waf_payload_log_uri_event(server_ip=server_ip, port=server_port, payload_type="xml_firewall", rule_id="0", flag=flag, protocol=protocol,
                                                    index=0, table_name="t_webseclog", log_func="uri_event")
        self.assertTrue(result)

    @data(*read_dict_json())
    @unpack
    def test_command_injection(self, server_ip, server_port, protocol):
        "web通用防护-命令注入攻击"
        flag = int(time.time())
        result = att.waf_payload_log_uri_event(server_ip=server_ip, port=server_port,
                                                    payload_type="command_injection", rule_id="0", flag=flag, protocol=protocol, index=0,
                                                    table_name="t_webseclog",
                                                    log_func="uri_event")
        self.assertTrue(result)

    @data(*read_dict_json())
    @unpack
    def test_ldap(self, server_ip, server_port, protocol):
        "web通用防护-LDAP注入攻击"
        flag = int(time.time())
        result = att.waf_payload_log_uri_event(server_ip=server_ip, port=server_port,
                                                    payload_type="ldap", rule_id="0", flag=flag, protocol=protocol, index=0,
                                                    table_name="t_webseclog",
                                                    log_func="uri_event")
        self.assertTrue(result)

    @data(*read_dict_json())
    @unpack
    def test_ssi(self, server_ip, server_port, protocol):
        "web通用防护-SSI指令攻击"
        flag = int(time.time())
        result = att.waf_payload_log_uri_event(server_ip=server_ip, port=server_port,
                                                    payload_type="ssi", rule_id="0", flag=flag, protocol=protocol, index=0,
                                                    table_name="t_webseclog",
                                                    log_func="uri_event")
        self.assertTrue(result)

    @data(*read_dict_json())
    @unpack
    def test_xpath(self, server_ip, server_port, protocol):
        "web通用防护-Xpath攻击"
        flag = int(time.time())
        result = att.waf_payload_log_uri_event(server_ip=server_ip, port=server_port,
                                                    payload_type="xpath", rule_id="0", flag=flag, protocol=protocol, index=0,
                                                    table_name="t_webseclog",
                                                    log_func="uri_event")
        self.assertTrue(result)

    @data(*read_dict_json())
    @unpack
    def test_xss(self, server_ip, server_port, protocol):
        "web通用防护-Xss攻击"
        flag = int(time.time())
        result = att.waf_payload_log_uri_event(server_ip=server_ip, port=server_port,
                                                    payload_type="xss", rule_id="1", flag=flag, protocol=protocol, index=0,
                                                    table_name="t_webseclog",
                                                    log_func="uri_event")
        self.assertTrue(result)

    @data(*read_dict_json())
    @unpack
    def test_path_traversal(self, server_ip, server_port, protocol):
        "web通用防护-路径穿越防护"
        flag = int(time.time())
        result = att.waf_payload_log_uri_event(server_ip=server_ip, port=server_port,
                                                    payload_type="path_traversal", rule_id="0", flag=flag, protocol=protocol, index=0,
                                                    table_name="t_webseclog",
                                                    log_func="uri_event")
        self.assertTrue(result)

    @data(*read_dict_json())
    @unpack
    def test_remote_file_inclusion(self, server_ip, server_port, protocol):
        "web通用防护-远程文件包含防护"
        flag = int(time.time())
        result = att.waf_payload_log_uri_event(server_ip=server_ip, port=server_port,
                                                    payload_type="remote_file_inclusion", rule_id="0", flag=flag, protocol=protocol, index=0,
                                                    table_name="t_webseclog",
                                                    log_func="uri_event")
        self.assertTrue(result)

    @data(*read_dict_json())
    @unpack
    def test_webshell(self, server_ip, server_port, protocol):
        "web通用防护-WebShell防护"
        flag = int(time.time())
        result = att.waf_payload_log_uri_event(server_ip=server_ip, port=server_port,
                                                    payload_type="webshell", rule_id="0", flag=flag, protocol=protocol,
                                                    index=0,
                                                    table_name="t_webseclog",
                                                    log_func="uri_event")
        self.assertTrue(result)

    @data(*read_dict_json())
    @unpack
    def test_web_plugin(self, server_ip, server_port, protocol):
        "web插件攻击"
        flag = int(time.time())
        result = att.waf_payload_log_uri_event(server_ip=server_ip, port=server_port,
                                                    payload_type="web_plugin", rule_id="1", flag=flag, protocol=protocol,
                                                    index=1,
                                                    table_name="t_webseclog",
                                                    log_func="uri_event")
        self.assertTrue(result)

    @data(*read_dict_json())
    @unpack
    def test_http_protocol_validation(self, server_ip, server_port, protocol):
        "http协议校验"
        flag = int(time.time())
        result = att.waf_payload_log_uri_event(server_ip=server_ip, port=server_port,
                                                    payload_type="http_protocol_validation", rule_id="0", flag=flag, protocol=protocol,
                                                    index=0,
                                                    table_name="t_webseclog",
                                                    log_func="uri_event")
        self.assertTrue(result)

    @data(*read_dict_json())
    @unpack
    def test_custom_policy(self, server_ip, server_port, protocol):
        "自定义策略"
        flag = int(time.time())
        result = att.waf_payload_log_uri_event(server_ip=server_ip, port=server_port,
                                                    payload_type="custom_policy", rule_id="0", flag=flag, protocol=protocol,
                                                    index=0,
                                                    table_name="t_webseclog",
                                                    log_func="uri_event")
        self.assertTrue(result)

    @data(*read_dict_json())
    @unpack
    def test_sensitiveinfo_filter(self, server_ip, server_port, protocol):
        "敏感信息过滤"
        flag = int(time.time())
        result = att.waf_payload_log_uri_event(server_ip=server_ip, port=server_port,
                                                    payload_type="sensitiveinfo_filter", rule_id="1", flag=flag, protocol=protocol,
                                                    index=1,pay_exp_value=["1002"],
                                                    table_name="t_webseclog",
                                                    log_func="uri_event")
        self.assertTrue(result)

    @data(*read_dict_json())
    @unpack
    def test_info_leak(self, server_ip, server_port, protocol):
        "信息泄露"
        flag = int(time.time())
        result = att.waf_payload_log_uri_event(server_ip=server_ip, port=server_port,
                                                    payload_type="info_leak", rule_id="0", flag=flag, protocol=protocol,
                                                    index=1,
                                                    table_name="t_webseclog",
                                                    log_func="uri_event")
        self.assertTrue(result)

    @data(*read_dict_json())
    @unpack
    def test_php_code_injection(self, server_ip, server_port, protocol):
        "PHP代码注入"
        flag = int(time.time())
        result = att.waf_payload_log_uri_event(server_ip=server_ip, port=server_port,
                                                    payload_type="php_code_injection", rule_id="0", flag=flag, protocol=protocol,
                                                    index=1,
                                                    table_name="t_webseclog",
                                                    log_func="uri_event")
        self.assertTrue(result)

    @data(*read_dict_json())
    @unpack
    def test_java_code_injection(self, server_ip, server_port, protocol):
        "Java代码注入"
        flag = int(time.time())
        result = att.waf_payload_log_uri_event(server_ip=server_ip, port=server_port, payload_type="java_code_injection",
                                                    rule_id="0", flag=flag, index=1, protocol=protocol,
                                                    table_name="t_webseclog",
                                                    log_func="uri_event")
        self.assertTrue(result)

