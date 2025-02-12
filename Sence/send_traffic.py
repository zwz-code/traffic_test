from Base.base_methods import BaseMethods as bm
from Config.config import conf
import time
from Operation.Send_Payload.Connect_DB.get_waf_log import GetLog
from Operation.Send_Payload.send_payload_req import TestPayload
import unittest
import os
from unittestreport import TestRunner
class SendTraffic:
    @classmethod
    def send_traffic_req(cls, TestClass=TestPayload, payload_type="all"):
        payload_dir = {
            "1": "http_protocol_validation",  
            "2": "web_server",  
            "3": "web_plugin",  
            "4": "spider_anti", 
            "5": "sql",  
            "6": "command_injection",  
            "7": "ldap",  
            "8": "ssi",  
            "9": "xpath",
            "10": "xss", 
            "11": "path_traversal", 
            "12": "remote_file_inclusion",  
            "13": "webshell", 
            "14": "upload_limit", 
            "15": "download_limit",  
            "16": "info_leak",  
            "17": "anti_leech", 
            "18": "scan_anti",  
            "19": "cookie_sec",  
            "20": "content_filter",
            "21": "sensitiveinfo_filter", 
            "22": "xml_firewall",
            "23": "php_code_injection",  
            "24": "java_code_injection",  
        }
        suite = unittest.TestSuite()
        #runner = unittest.TextTestRunner()
        if payload_type == "all":
            # 按类加载全部testxxx测试用例
            suite.addTest(unittest.makeSuite(TestPayload))
        else:
            # 按函数加载testxxx测试用例
            Test = []
            testdict = TestClass.__dict__
            for type in payload_type:
                type = "test_"+payload_dir[type]
                tmp_cases = filter(lambda cs: cs.startswith(type) and callable(getattr(TestClass, cs)), testdict)
                for tmp_case in tmp_cases:
                    Test.append(TestClass(tmp_case))
            suite.addTests(Test)
        report_dir = os.path.abspath(os.path.join(os.path.abspath(__file__), '..', '..', 'reports'))
        TestRunner(suite, tester=os.environ.get('USERNAME'), desc="自动化报告",  report_dir=report_dir, filename="%s报告.html"%(str(int(time.time())))).run()
        # result = runner.run(suite)

if __name__ == '__main__':
    pass

