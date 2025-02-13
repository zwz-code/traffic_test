# -*- coding:utf-8 -*-
import json
import time
import requests
import os
from jsonpath import jsonpath
from jsonpath_ng import parse
import yaml
from Config.config import conf
from Config.token import token as prev_token, prev_time, ip, config_path
requests.packages.urllib3.disable_warnings()

class BaseMethods:
    def __init__(self):
        self.ip = conf.ip
        self.port = conf.port
        self.psw = conf.psw
        self.db_usr = conf.db_usr
        self.db_psw = conf.db_psw
        self.token_usr = conf.token_usr
        self.token_psw = conf.token_psw
        self.interface_type = conf.interface_type

    def get_token_write_yaml(self, timeout=1800):
        """
        函数目的：获取token值并写入yaml配置文件中
        :param timeout: token存活时间
        :return:
        """
        url = "https://{ip}:{port}/rest/v3/token".format(ip=self.ip, port=self.port)
        data = {
            "accountId": self.token_usr,
            "pwd": self.token_psw
        }
        cur_time = time.time()
        if ip == self.ip and (cur_time - prev_time) < timeout:
            print("token未失效")
            return prev_token
        res = requests.post(url=url, json=data, verify=False)
        if res.status_code == 200:
            token = res.json()["token"]
            yaml_data = {
                "token": token,
                "prev_time": int(time.time()),
                "ip": self.ip
            }
            with open(config_path, "w", encoding="utf-8") as f:
                yaml.dump(data=yaml_data, stream=f, allow_unicode=True)
            return token
        else:
            raise Exception("*** get token failed ***")

    def send_get_request(self, req_path, params=None):
        """
        发送Get请求
        :param req_path: 请求路径
        :param params: 参数
        :return:
        """
        if self.interface_type == "v3":
            token = self.get_token_write_yaml()
            headers = {'Authorization': "Bearer " + token}
            url = "https://{ip}:{port}/rest/v3/{req_path}".format(ip=self.ip, port=self.port, req_path=req_path)
        elif self.interface_type == "v1":
            headers = {'Content-type': 'application/json'}
            url = "https://{ip}:{port}/rest/v1/{req_path}".format(ip=self.ip, port=self.port,
                                                                      req_path=req_path)
        else:
            raise ValueError("RestApi接口类型错误!")
        try:
            response = requests.get(url=url, params=params, headers=headers, verify=False, auth=(self.token_usr, self.token_psw) if self.interface_type == "v1" else None)
            res = response.json()
            return res
        except Exception as e:
            print("get requests send error! details:-->> %s"%e)

    def send_post_request(self, req_path, data, files=None):
        """
        发送POST请求
        :param data: 请求数据
        :param req_path: 请求路径
        :param files:上传文件
        :return:
        """
        if self.interface_type == "v3":
            token = self.get_token_write_yaml()
            headers = {'Authorization': "Bearer " + token}
            headers.update({'Content-Type':'application/json'})
            url = "https://{ip}:{port}/rest/v3/{req_path}".format(ip=self.ip, port=self.port, req_path=req_path)
        elif self.interface_type == "v1":
            headers = {'Content-type': 'application/json'}
            url = "https://{ip}:{port}/rest/v1/{req_path}".format(ip=self.ip, port=self.port,
                                                                      req_path=req_path)
        else:
            raise ValueError("RestApi接口类型错误!")
        try:
            response = requests.post(url=url, json=data, headers=headers, files=files, verify=False, auth=(self.token_usr, self.token_psw) if self.interface_type == "v1" else None)
            res = response.json()
            return res
        except Exception as e:
            print("get requests send error! details:-->> %s"%e)

    def send_put_request(self, req_path, data):
        """
        发送put请求
        :param req_path: 请求路径
        :param data: 请求数据
        :return:
        """
        if self.interface_type == "v3":
            token = self.get_token_write_yaml()
            headers = {'Authorization': "Bearer " + token}
            headers.update({'Content-Type': 'application/json'})
            url = "https://{ip}:{port}/rest/v3/{req_path}".format(ip=self.ip, port=self.port, req_path=req_path)
        elif self.interface_type == "v1":
            headers = {'Content-type': 'application/json'}
            url = "https://{ip}:{port}/rest/v1/{req_path}".format(ip=self.ip, port=self.port,
                                                                      req_path=req_path)
        else:
            raise ValueError("RestApi接口类型错误!")
        try:
            response = requests.put(url=url, json=data, headers=headers, verify=False, auth=(self.token_usr, self.token_psw) if self.interface_type == "v1" else None)
            res = response.json()
            return res
        except Exception as e:
            print("get requests send error! details:-->> %s" % e)

    def send_delete_request(self, req_path, params=None, data=None):
        """
        发送DELETE请求
        :param data: 请求数据
        :param req_path: 请求路径
        :param params:参数
        :return:
        """
        if self.interface_type == "v3":
            token = self.get_token_write_yaml()
            headers = {'Authorization': "Bearer " + token}
            headers.update({'Content-Type':'application/json'})
            url = "https://{ip}:{port}/rest/v3/{req_path}".format(ip=self.ip, port=self.port, req_path=req_path)
        elif self.interface_type == "v1":
            headers = {'Content-type': 'application/json'}
            url = "https://{ip}:{port}/rest/v1/{req_path}".format(ip=self.ip, port=self.port,
                                                                      req_path=req_path)
        else:
            raise ValueError("RestApi接口类型错误!")
        try:
            response = requests.delete(url=url, headers=headers, json=data, params=params, verify=False, auth=(self.token_usr, self.token_psw) if self.interface_type == "v1" else None)
            res = response.json()
            return res
        except Exception as e:
            print("get requests send error! details:-->> %s"%e)

    """一些处理数据的方法"""
    def remove_empty_value(self, json_data, spe_value=[None], min_dict_len=0, min_list_len=0):
        """
        删除Json数据中键值为空的键值对
        :param json_data:
        :param spe_value: 针对非字典和list的取值,如果取值属于spe_value,此时就不保留该键值对.
        :param min_dict_len: 针对dict, 如果dict的长度小于等于min_dict_len,则删除对应的键值对.
        :param min_list_len: 针对list, 如果list的长度小于等于min_list_len,则删除对应的键值对.
        :return:
        """
        if isinstance(json_data, dict):
            info_re = dict()
            for key, value in json_data.items():
                # print value ,type(value)
                if isinstance(value, dict):
                    re = self.remove_empty_value(value, spe_value, min_dict_len, min_list_len)
                    if len(re) > min_dict_len:
                        info_re[key] = re
                elif isinstance(value, list):
                    re = self.remove_empty_value(value, spe_value, min_dict_len, min_list_len)
                    if len(re) > min_list_len:
                        info_re[key] = re
                else:
                    if value not in spe_value:
                        info_re[key] = value
            return info_re
        elif isinstance(json_data, list):
            info_re = list()
            for value in json_data:
                if isinstance(value, dict):
                    re = self.remove_empty_value(value, spe_value, min_dict_len, min_list_len)
                    if len(re) > min_dict_len:
                        info_re.append(re)
                elif isinstance(value, list):
                    re = self.remove_empty_value(value, spe_value, min_dict_len, min_list_len)
                    if len(re) > min_list_len:
                        info_re.append(re)
                else:
                    if value not in spe_value:
                        info_re.append(value)
            return info_re
        else:
            print("json_data需要是字典或者list")

    def exclude_params(self, data, del_key):
        """
        删除字典中给定的键值对
        :param data:
        :param del_key:
        :return:
        """
        if not isinstance(data, dict):
            raise TypeError("data must be dict type")
        if not isinstance(del_key, list):
            raise TypeError("del_key must be list type")
        if not set(del_key).issubset(set(data.keys())):
            raise ValueError("del_key has keys that do not exist in data")
        if len(del_key) == 0:
            return data
        new_data = {}
        for key, value in data.items():
            if key in del_key:
                continue
            new_data[key] = value
        return new_data

    def update_json(self, json_data, update_value, min_dict_len=0, min_list_len=0):
        """
        对Json中的数据进行替换更新,并且剔除空值。
        :param json_data: json数据
        :param update_value: 替换的参数字典
        :param min_dict_len: 针对dict, 如果dict的长度小于等于min_dict_len,则删除对应的键值对.
        :param min_list_len: 针对list, 如果list的长度小于等于min_list_len,则删除对应的键值对.
        :return:
        """
        if not isinstance(update_value, dict):
            raise TypeError("更新的参数必须是字典的形式")
        for key, value in update_value.items():
                condition = '$..' + key
                jsonpath_expr = parse(condition)
                jsonpath_expr.update(json_data, value)
        json_data = self.remove_empty_value(json_data=json_data, min_dict_len=min_dict_len, min_list_len=min_list_len)
        return json_data

    def get_json_value(self, json_path):
        """
        从Json文件中获取Json数据
        :param json_path: Json文件的路径
        :return:
        """
        path = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
        temp_path = '/Operation/Interface_Auto/Json_Data'
        path = path+temp_path
        json_filepath = os.path.join(path, json_path)
        with open(json_filepath, 'r', encoding='utf-8') as f:
            json_data = json.load(f)
        return json_data

    def assert_json_domain(self, domain, path):
        """
        判断domain值是否在login_data中
        :param domain: 需要判断的域名值
        :return:
        """
        with open(path) as json_file:
            data = json.load(json_file)
            domain_list = list(set(jsonpath(data, "$.cookies[*].domain")))
            if domain in domain_list:
                return True
            else:
                return False

    @classmethod
    def write_json(cls, data, path):
        """
        :param data:
        :param path:
        :return:
        """
        if not os.path.exists(path):
            raise FileNotFoundError(f'File not found: {path}')
        with open(path, 'w') as json_file:
            json.dump(data, json_file, indent=4)

if __name__ == '__main__':
    pass