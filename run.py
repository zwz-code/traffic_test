"""
-*- coding: utf-8 -*-
"""
import time
from Sence.input_addr import writeaddr

if __name__ == '__main__':
    flag = input("是否发送所有类型的攻击：[Y/N]")
    if flag == 'N':
        t = input("选择需要发送的攻击类型(多个攻击类型用逗号隔开，例如选择 爬虫和sql注入则输入：4,5)：\t\n1:http协议校验\t\n2:web服务器攻击\t\n3:web插件攻击\t\n4:爬虫防护\t\n5:sql注入\t\n6:命令注入攻击\t\n7:LDAP注入攻击\t\n8:web通用防护-SSI指令攻击\t\n9:web通用防护-Xpath攻击\t\n10:web通用防护-Xss攻击\t\n11:web通用防护-路径穿越防护\t\n12:web通用防护-远程文件包含防护\t\n13:web通用防护-WebShell防护\t\n14:非法上传\t\n15:非法下载\t\n16:信息泄露\t\n17:盗链防护\t\n18:扫描防护\t\n19:cookie安全\t\n20:内容过滤\t\n21:敏感信息过滤\t\n22:XML攻击防护\t\n23:语义引擎-PHP代码注入\t\n24:语义引擎-Java代码注入\t\n")
        print(t)
        payload = t.split(',')
        print(payload)
    else:
        payload = "all"
    from Sence.send_traffic import SendTraffic
    SendTraffic().send_traffic_req(payload_type=payload)



