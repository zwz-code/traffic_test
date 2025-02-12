# -*- coding:utf-8 -*-
"""
用于对函数进行循环运行的类
"""
import time
import traceback

class LoopFunc():
    timeout = 30
    interval = 2
    def loop_func(self, func, exp_value=True, *args, **kwargs):
        """
        循环执行某个函数，直到达到预期的结果。用于发送payload和查询日志结果逗使用该函数。
        :param func: 要循环执行的函数
        :param exp_value: 函数func的期望返回值，可以接受单个值、list、tuple,目前默认为True即可
        :param timeout: 超时时间
        :param interval: 循环间隔
        :param kwargs: 函数中的参数。
        :return: 如果在超时时间内得到预期结果，就返回True和提示信息；否则就返回False和提示信息。
        """
        print("循环执行函数%s,时间间隔为%s,超时时间为%s" % (func.__name__, self.interval, self.timeout))
        end_time = time.time() + self.timeout
        while time.time() < end_time:
            # 获取函数执行结果
            try:
                result = func(*args, **kwargs)
                print("%s函数执行结果为:%s" % (func.__name__, result))
            except Exception as e:
                traceback.print_exc()
                return False, "%s函数调用错误. %s" % (func.__name__, e)
            # 判断函数结果是否符合预期结果
            # exp_value转换为list
            exp_value = exp_value if isinstance(exp_value, (list, tuple)) else [exp_value]
            if result in exp_value:
                print ("函数执行结果%s存在于期望结果%s中" % (result, exp_value))
                return True, "函数执行结果%s存在于期望结果%s中" % (result, exp_value)
            time.sleep(self.interval)
        return False, "函数执行结果%s不存在于期望结果%s中，且超过了最大超时时间%s" % (result, exp_value, self.timeout)
