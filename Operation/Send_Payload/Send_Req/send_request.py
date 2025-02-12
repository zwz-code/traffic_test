# -*- coding:utf-8 -*-
import os
import json
import requests
import IPy
import socket
from threading import Thread
import codecs

class Send_Payload_Request():
    def send_payload(self, ip, port, payload_type, rule_id, flag, protocol="http", index=1, count=1, domain=None):
        """
        发送特定请求的payload
        :param ip: 目的IP
        :param port: 目的端口
        :param payload_type: payload类型
        :param rule_id: payload文件中每种请求的规则ID
        :param flag: 标识符，拼接在请求的URI中
        :param protocol: 协议类型，默认http
        :param index: 位置符，和flag配合使用。默认为1 flag拼接在uri的参数部分，例：/py/flag.若为0则拼接在uri前面。flag/py
        :param count: 并发发送次数
        :param domain: 域名
        :return:
        """
        GREEN = '\033[31m'
        RED = '\033[32m'
        END_COLOR = '\033[0m'
        #对IP进行处理
        print(ip)
        if ip.startswith('['):  # 如果是传递的ipv6地址，手动增加了[]，此时就删除该值，然后判断合法性。
            ip = ip.strip('[[]]')  # 去除ip首尾的符号
        try:
            version = self.__checkip(address=ip)
        except Exception as e:
            print(RED+"Ip is illegal(1004).[error: %s]" % e+END_COLOR)
            return 1004, "IP不合法"
        if version == 6:
            ip = "[" + ip + "]"
            # 如果ip合法,此时就使用ip构建host
        host = "%s:%s" % (ip, str(port))
        # 判断ip是否能ping通.
        status = self.__test_connect_ip(ip, port)
        print("status:", status)
        if not status:
            print(RED+"Unable to connect to %s. Possible reason: 1)Wrong Ip; 2) Wrong Port; 3)Apache service is not started 4)Switch between client and server is faulty 5)Connection timed out. (1008)" % host+END_COLOR)
            return 1008, "error"

        # 根据payload类型和规则id,获取payload的json数据
        cur_path = os.path.abspath(os.path.dirname(__file__))  # 获取当前目录路径
        payload_json_path = os.path.join(cur_path, "payload.json")
        # 如果payload_type不存在，则直接返回False，就不再发送请求
        try:
            payload = self.__get_payload(payload_json_path, payload_type=payload_type, rule_id=rule_id)
        except Exception as e:
            print(e)
            return False
        # 获取请求方法
        method = payload["method"]
        # 获取url
        url_path = payload["urlpath"]
        url_path_flag = self.__url_with_flag(url_path, flag, index)  # 拼接路径部分
        url = self.__get_url(protocol, host, url_path_flag)
        # headers,修改host值(当使用域名匹配的时候,这个很重要,否则Host会被固定为127.0.0.1)
        headers = payload["headers"]
        headers["Host"] = domain if domain else str(ip)
        #data数据
        data = payload["body"]
        # 当存在files字段时，此时表示对应的payload需要上传文件。
        if "files" in payload.keys():
            cur_path = os.path.abspath(os.path.dirname(__file__))  # 获取当前目录路径
            filename = payload["files"]["filename"]
            content_type = payload["files"]["Content-Type"]
            filename = os.path.join(os.path.join(cur_path, "Payload_Files"), filename)
            files = {
                    "file": (filename, open(filename, "rb"), content_type)
                }
        else:
            files = None
        results = self.__con_http_requests(count, requests.request, method=method, url=url, headers=headers, data=data, files=files, timeout=30, verify=False)
        print("Send_payload results", results)
        # 获取所有执行结果的result值，这里假设可能出现不同的result结果。
        res = [result["result"] for result in results]
        max_res = max(res, key=res.count)  # 获取res中出现次数最多的元素
        if max_res == False or (max_res != False and int(max_res.status_code) == 403):
            print("1003-Send payload success and the request was blocked. (1003)")
            return 1003
        else:
            print("1002-Send payload success, but the request was not blocked. (1002)")
            return 1002

    def __con_http_requests(self, count, func, *args, **kwargs):
        """
        并发请求.
        :param count: 并发请求的次数
        :param method: 请求方法
        :param url: 完整url路径
        :param headers: 请求头
        :param files: 发送文件
        :return:
        """
        tasks = []  # 存储线程
        results = []  # 存储线程的get_results()函数结果

        for i in range(int(count)):
            t = TThread(func, args, kwargs)
            tasks.append(t)
            t.start()

        for t in tasks:
            # 等待子线程执行结束之后再获取子线程的响应结果
            t.join()
            try:
                results.append(t.get_result())
            except Exception as e:
                print(e)
        return results

    def __test_connect_ip(self, ip, port):
        """测试端口连通性,根据ip和port"""
        print("Test ip and port connectivity. %s:%s"%(ip, port))
        try:
            if ip.startswith("["):
                ip = ip.strip("[]")
                sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, int(port)))
            return True
        except socket.error as e:
            return False
        finally:
            sock.close()

    def __test_connect_domain(self, domain, port):
        """根据domain和port测试端口连通性"""
        print("Test domain and port connectivity. %s:%s" % (domain, port))
        # 获取域名对应的ip列表
        ip_list = set()
        try:
            addrs = socket.getaddrinfo(domain, None)
            for item in addrs:
                ip_list.add(item[4][0])
                print("Successfully obtained the ip list, the ip list corresponding to the domain(%s) is %s" % (
                    domain, ip_list))
        except:
            # 无法获取ip时会执行到这里
            print("Unable to get ip of domain(%s)" % domain)
            return False
        # 使用domain对应的第一个ip测试连通性.
        ip = list(ip_list)[0]
        # 获取ip版本
        try:
            version = self.__checkip(address=ip)
        except Exception as e:
            print("Ip is illegal.[error: %s]" % e)
        # 根据ip版本增加对应的
        if version == 6:
            ip = "[" + ip + "]"
            return self.__test_connect_ip(ip, port)

    def __url_with_flag(self, url, flag, index):
        """
        根据index判断将flag拼接在url的位置，0表示拼接在url前面，1表示拼接在url后面。
        :param url:
        :param flag:
        :param index:
        :return: 返回拼接之后的url
        """
        if flag:
            print(index)
            if int(index) == 0:
                url = '/' + str(flag) + url   # index=0,将flag作为路径的一部分拼接
            else:
                url = url + '?' + str(flag)     # index为其他值时，将flag作为参数值拼接。
        return url

    def __get_url(self, protocol, host, path):
        """拼接url路径"""
        if path.startswith('/'):
            url = protocol + "://" + host + path  # 这里在linux上可能出错，需要关注
        else:
            url = protocol + "://" + host + '/' + path
            # print "请求url为", url
        return url

    def __get_payload(self, payload_json_path, payload_type, rule_id):
        """
        从json文件中读取指定类型payload_type和rule_id的文件
        :param payload_json_path:
        :param payload_type:
        :param rule_id:
        :return:
        """
        try:
            with codecs.open(payload_json_path, "r", encoding="utf-8") as f:
                payload_json = json.loads(f.read())
        except IOError:
            print("文件%s不存在" % payload_json_path)
            # 如果payload_type不属于map.json文件中的key，此时就直接报错
        if payload_type not in payload_json.keys():
            raise Exception("payload_type %s is not in %s" % (payload_type, list(payload_json.keys())))
        # 1. rule_id存在于payload_type下面，此时直接获取对应的payload
        # 2. 如果rule_id不存在于payload_type下面，随机映射到该类型下面的某个rule_id上
        # -- 2021-11-23这里还有一些问题，主要问题是rule_id为0或者1的时候映射到payload_json[payload_type]字典中的顺序可能不固定，主要是因为字典的顺序不定
        if str(rule_id) in payload_json[payload_type].keys():
            payload = payload_json[payload_type][str(rule_id)][0]
        else:
            map_rule_id = payload_json[payload_type].keys()[0]
            print("The current rule_id=%s does not exist in the %s type of the payload.json file, and it has been automatically mapped to the payload with rule_id=%s" % (
                str(rule_id), payload_type, map_rule_id))
            payload = payload_json[payload_type][str(map_rule_id)][0]
        return payload

    def __checkip(self, address):
        """
        获取IP的version的版本
        :param address:
        :param version: ipv4 or ipv6
        :return:
        """
        try:
            version = IPy.IP(address).version()
            return version
        except Exception as e:
            raise e

class TThread(Thread):
    """自定义线程类"""
    def __init__(self, func, args, kwargs):
        """函数及该函数对应的参数"""
        super(TThread, self).__init__()
        self.func = func
        self.args = args
        self.kwargs = kwargs
        self.result = None  # 函数执行结果

    def run(self):
        try:
            self.result = self.func(*self.args, **self.kwargs)  # 在线程中执行函数
            self.result = {"result": self.result, "msg": "function %s execute success" % self.func}  # 如果函数func执行正常，就保存相应的执行结果到result中。
        except requests.exceptions.ConnectionError as e:
            e_str = e.__str__()
            self.result = {"result": False, "msg": "function %s execute abnormally. The reason for the error is %s" % (self.func, e_str)}

    def get_result(self):
        """
        存在结果就返回result,否则返回None
        :return:
        """
        try:
            return self.result
        except:
            return None


