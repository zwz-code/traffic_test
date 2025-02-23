from configparser import ConfigParser
from configparser import RawConfigParser
import os

class Config:
    def __init__(self):
        """
        初始化配置
        """
        self.conf = RawConfigParser(allow_no_value=True)
        self.conf_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.ini')

        if not os.path.exists(self.conf_path):
            raise IOError("配置文件不存在")
        self.conf.read(self.conf_path, encoding="utf-8")
        self.get_all_config()

    def get_all_config(self):
        """
        读取配置文件信息.
        :return:
        """
        self.ip = self.conf.get("device", "ip")
        self.port = self.conf.get("device", "port")
        self.psw = self.conf.get("device", "password")
        self.db_usr = self.conf.get("device", "db_usr")
        self.db_psw = self.conf.get("device", "db_psw")
        self.token_usr = self.conf.get("token", "token_usr")
        self.token_psw = self.conf.get("token", "token_psw")
        self.interface_type = self.conf.get("token", "type")
        self.ssh_port = self.conf.get("SSH", "ssh_port")
        self.ssh_psw = self.conf.get("SSH", "ssh_psw")

conf = Config()
