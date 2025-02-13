

# 使用本工具前请阅读此文档

## 目录

- [上手指南](#上手指南)
  - [开发前的配置要求](#开发前的配置要求)
  - [安装步骤](#安装步骤)
  - [文件目录说明](#文件目录说明)
  
- [使用说明](#文件目录说明)

- [更新日志](#更新日志)

  

### 上手指南

###### 开发前的配置要求

1. python3 环境

###### **安装步骤**

安装第三方库

```sh
pip3 install -r requirements.txt
```

###### 文件目录说明   ######

```
Send_Traffic-V1 
│  requirements.txt
│  run.py
├─Base
│  │  base_methods.py
├─Config
│  │  config.ini
│  │  config.py
│  │  token.py
│  │  token.yaml
├─Operation
│  └─Send_Payload
│      │  send_payload_req.py
│      ├─Attack_traffic
│      │  │  attack.py
│      │  │  loop.py
│      ├─Connect_DB
│      │  │  access_pgsql.py
│      │  │  get_waf_log.py
│      ├─Send_Req
│      │  │  payload.json
│      │  │  send_request.py
│      │  ├─Payload_Files
│      │  │      abcd.ashx
│      │  │      abcd.py
├─reports
└─Sence
    │  address_info.json
    │  input_addr.py
    │  send_traffic.py

```



### 使用说明

介绍：该打流工具对目标地址发送常见的攻击流量，并对防护的结果进行测试验证，最终输出测试结果报告。

①：使用工具之前一定要在Sence/address_info中将目标地址进行正确填写；

②：本工具需要获取攻击载荷的特征值，将攻击特征保存在payload.json文件中；

③：本工具会对设备连接数据库进行日志测试，因此需要在config.ini中配置设备正确信息；

④：执行run.py启动程序，启动时会提示攻击流量类型；

⑤：测试结果会保存在reports文件夹下



### 更新日志

- V1版本新增了并发测试与ddt数据驱动测试方法；
- V2版本新增对结果报告中的关键数据进行可视化展示，例如误报率、检查率等重要测试结果参数；







