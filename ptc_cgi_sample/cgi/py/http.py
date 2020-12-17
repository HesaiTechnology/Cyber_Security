import requests
import json
import socket
import time
import os
from urllib.parse import quote
import base64

default_admin='*****'
default_passwd='*****'

class HttpsApi(object):

    def __init__(self):
        self._product_type = None
        self.cookies = None

    def login(self, username, passwd):
        url = 'http://192.168.1.201/pandar.cgi?action=get&object=login'
        bytes_passwd = passwd.encode("utf-8")
        passwdB64 = base64.b64encode(bytes_passwd)
        passwdB64_utf8 = str(passwdB64, encoding = "utf8")
        data = {'key':username,'value':passwdB64_utf8}
        res = requests.post(url, json=data)
        print(res.content)
        data = json.loads(res.text)
        name = data.get('Body').get('cookie').get('name')
        uuid = data.get('Body').get('cookie').get('value')
        self.cookies = {name: uuid}

    def send_get_request_and_receive_return_info(self,url,timeout=10, *, retry_num=1):
        s = requests.Session()
        a = requests.adapters.HTTPAdapter(max_retries=retry_num)
        s.mount('http://', a)
        res = s.request('GET', url, timeout = timeout, cookies=self.cookies)
        assert res.status_code == 200, 'cannot connect to lidar, error code: %s' %(res.status_code)
        info =  json.loads(res.text)
        info['Connection_Status'] = res.status_code
        return info

    def send_post_request_and_receive_return_info(self, url, timeout=10, *, retry_num=1, data=None, files=None):
        s = requests.Session()
        a = requests.adapters.HTTPAdapter(max_retries=retry_num)
        s.mount('http://', a)
        res = s.request('POST', url, data=data, files=files,timeout=timeout, cookies=self.cookies)
        assert res.status_code == 200, 'cannot connect to lidar, error code: %s' %(res.status_code)
        info =  json.loads(res.text)
        info['Connection_Status'] = res.status_code
        return info

if __name__ == "__main__":
    y = HttpsApi()
    print(y.login(default_admin, default_passwd))
    print(y.send_get_request_and_receive_return_info("http://192.168.1.201/pandar.cgi?action=get&object=workmode"))
