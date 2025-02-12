"""
读取yaml文件内容
"""
#coding = utf8
import yaml
import os
cur_path = os.path.abspath(os.path.dirname(__file__))
config_path = os.path.join(cur_path, 'token.yaml')

#获取token相关属性值
with open(config_path, 'r', encoding='utf-8') as f:
    result = yaml.load(f.read(), Loader=yaml.FullLoader)
token = result["token"]
prev_time = result["prev_time"]
ip = result["waf_ip"]

