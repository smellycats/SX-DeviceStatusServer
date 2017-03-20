# -*- coding: utf-8 -*-
import json
import unittest

import arrow

from helper_device import Device


class DeviceRequestTestCase(unittest.TestCase):
    def setUp(self):
        self.ini = {
            'host': '127.0.0.1',
            'port': 5000
        }
        self.dev = Device(**self.ini)
        self.dev.base_path = ''
    
    def tearDown(self):
        pass

    def test_get_device_list(self):
        r = self.dev.get_device_list()
        self.assertGreater(r.get('total_count', None), 10)
        r = self.dev.get_device_list(type=2)
        self.assertGreater(r.get('total_count', None), 10)
        r = self.dev.get_device_list(city=1)
        self.assertGreater(r.get('total_count', None), 20)

    def test_get_device_by_id(self):
        r = self.dev.get_device_by_id(2)
        self.assertEqual(r['type_id'], 2)

    def test_get_device_by_ip(self):
        r = self.dev.get_device_by_ip(ip='192.168.191.250')
        self.assertEqual(r['total_count'], 1)

    def test_get_device_check(self):
        r = self.dev.get_device_check(num=10, type=2, city=1)
        self.assertNotEqual(r.get('total_count', None), None)

    def test_set_device_by_id(self):
        data = {'status': False}
        r = self.dev.set_device_by_id(id=2, data=data)
        self.assertEqual(r['status'], False)

    def test_set_device(self):
        data = [
            {'id': 3, 'ip': '192.168.191.247', 'status': False},
            {'id': 4, 'ip': '192.168.191.245', 'status': True}
        ]
        r = self.dev.set_device(data)
        self.assertNotEqual(r.get('total', None), None)

    def test_get_city(self):
        r = self.dev.get_city_list()
        self.assertEqual(r['items'][0]['name'], u'惠城区')
        self.assertEqual(r['items'][0]['alias'], 'hcq')
        
    def test_get_type(self):
        r = self.dev.get_type_list()
        self.assertEqual(r['items'][1]['name'], u'工控机')
