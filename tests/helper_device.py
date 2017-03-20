# -*- coding: utf-8 -*-
import json
import urllib

import requests
from requests.auth import HTTPBasicAuth


class Device(object):
    def __init__(self, **kwargs):
        self.host = kwargs['host']
        self.port = kwargs['port']

        self.headers = {'content-type': 'application/json'}

	self.status = False

	self.base_path = ''

    def get_device_list(self, type=None, city=None, timeout=15):
	"""获取设备信息列表"""
	# 键值字典
        params_dict = {}
        if type is not None:
            params_dict['type'] = type
        if city is not None:
            params_dict['city'] = city
        # 键值字符串
        params_str = urllib.urlencode(params_dict)
        url = 'http://{0}:{1}/{2}device?{3}'.format(
            self.host, self.port, self.base_path, params_str)
        try:
            r = requests.get(url, headers=self.headers, timeout=timeout)
            if r.status_code == 200:
                return json.loads(r.text)
            else:
                self.status = False
                raise Exception(u'url: {url}, status: {code}, {text}'.format(
                    url=url, code=r.status_code, text=r.text))
        except Exception as e:
            self.status = False
            raise

    def get_device_by_ip(self, ip, timeout=15):
        """根据ip获取设备信息"""
        url = 'http://{0}:{1}/{2}device?ip={3}'.format(
            self.host, self.port, self.base_path, ip)
        try:
            r = requests.get(url, headers=self.headers, timeout=timeout)
            if r.status_code == 200 or 404:
                return json.loads(r.text)
            else:
                self.status = False
                raise Exception(u'url: {url}, status: {code}, {text}'.format(
                    url=url, code=r.status_code, text=r.text))
        except Exception as e:
            self.status = False
            raise

    def get_device_by_id(self, id, timeout=15):
        """根据ID获取设备信息"""
        url = 'http://{0}:{1}/{2}device/{3}'.format(
            self.host, self.port, self.base_path, id)
        try:
            r = requests.get(url, headers=self.headers, timeout=timeout)
            if r.status_code == 200 or 404:
                return json.loads(r.text)
            else:
                self.status = False
                raise Exception(u'url: {url}, status: {code}, {text}'.format(
                    url=url, code=r.status_code, text=r.text))
        except Exception as e:
            self.status = False
            raise

    def get_device_check(self, num=10, type=None, city=None, timeout=15):
        """获取设备信息"""
	# 键值字典
        params_dict = {}
        if type is not None:
            params_dict['type'] = type
        if city is not None:
            params_dict['city'] = city
        # 键值字符串
        params_str = urllib.urlencode(params_dict)
        url = 'http://{0}:{1}/{2}device_check/{3}?{4}'.format(
            self.host, self.port, self.base_path, num, params_str)
        try:
            r = requests.get(url, headers=self.headers, timeout=timeout)
            if r.status_code == 200:
                return json.loads(r.text)
            else:
                self.status = False
                raise Exception(u'url: {url}, status: {code}, {text}'.format(
                    url=url, code=r.status_code, text=r.text))
        except Exception as e:
            self.status = False
            raise

    def set_device_by_id(self, id, data, timeout=15):
        """根据ID设置设备状态信息"""
        url = 'http://{0}:{1}/{2}device/{3}'.format(
            self.host, self.port, self.base_path, id)
        try:
            r = requests.post(url, headers=self.headers, data=json.dumps(data))
            if r.status_code == 201 or 404:
                return json.loads(r.text)
            else:
                self.status = False
                raise Exception(u'url: {url}, status: {code}, {text}'.format(
                    url=url, code=r.status_code, text=r.text))
        except Exception as e:
	    self.status = False
            raise

    def set_device(self, data, timeout=15):
        """设置设备状态信息"""
        url = 'http://{0}:{1}/{2}device_multi'.format(
            self.host, self.port, self.base_path)
        try:
            r = requests.post(url, headers=self.headers,
                              data=json.dumps({'info': data}))
            if r.status_code == 201:
                return json.loads(r.text)
            else:
                self.status = False
                raise Exception(u'url: {url}, status: {code}, {text}'.format(
                    url=url, code=r.status_code, text=r.text))
        except Exception as e:
	    self.status = False
            raise

    def get_city_list(self, timeout=15):
	"""获取县区信息列表"""
        url = 'http://{0}:{1}/{2}city'.format(
            self.host, self.port, self.base_path)
        try:
            r = requests.get(url, headers=self.headers, timeout=timeout)
            if r.status_code == 200:
                return json.loads(r.text)
            else:
                self.status = False
                raise Exception(u'url: {url}, status: {code}, {text}'.format(
                    url=url, code=r.status_code, text=r.text))
        except Exception as e:
            self.status = False
            raise

    def get_type_list(self, timeout=15):
	"""获取设备类型列表"""
        url = 'http://{0}:{1}/{2}type'.format(
            self.host, self.port, self.base_path)
        try:
            r = requests.get(url, headers=self.headers, timeout=timeout)
            if r.status_code == 200:
                return json.loads(r.text)
            else:
                self.status = False
                raise Exception(u'url: {url}, status: {code}, {text}'.format(
                    url=url, code=r.status_code, text=r.text))
        except Exception as e:
            self.status = False
            raise

