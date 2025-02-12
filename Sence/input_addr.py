"""
-*- coding: utf-8 -*-
"""
import os
from Base.base_methods import BaseMethods as bm

def writeaddr():
    input_http = input("请输入http站点的地址（多个站点以逗号隔开,例如：188.2.9.192:80,2009::192:81,  端口递增的站点可以按照如下输入：188.2.9.192:100-150,2009::192:200-300):\t\n")
    input_https = input("请输入https站点的地址（多个站点以逗号隔开,例如：188.2.9.192:80,2009::192:81,  端口递增的站点可以按照如下输入：188.2.9.192:100-150,2009::192:200-300):\t\n")
    http_list = []
    https_list = []
    for value in input_http.split(','):
        parts = value.split(':')
        ip = ':'.join(parts[:-1])
        port = parts[-1]
        if "-" in port:
            start_port = int(port.split("-")[0])
            end_port = int(port.split("-")[1])
            l = [{"server_ip": str(ip), "server_port": str(i), "protocol": "http"} for i in range(start_port, end_port)]
            http_list = https_list + l
        else:
            http_list.append({"server_ip": str(ip), "server_port": str(port), "protocol": "http"})
    for value in input_https.split(','):
        parts = value.split(':')
        ip = ':'.join(parts[:-1])
        port = parts[-1]
        if "-" in port:
            start_port = int(port.split("-")[0])
            end_port = int(port.split("-")[1])
            l = [{"server_ip": str(ip), "server_port": str(i), "protocol": "https"} for i in range(start_port, end_port)]
            https_list.append(l)
        else:
            https_list.append({"server_ip": str(ip), "server_port": str(port), "protocol": "https"})
    data = http_list + https_list
    file_path = os.path.abspath(os.path.join(os.path.abspath(__file__), '..', 'address_info.json'))
    bm.write_json(data=data, path=file_path)

if __name__ == '__main__':
    pass


