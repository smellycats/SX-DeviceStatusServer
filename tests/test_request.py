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
        r = self.dev.get_device_list(type=2)
        self.assertNotEqual(r.get('total_count', None), None)

    def test_get_device_by_ip(self):
        r = self.dev.get_device_by_ip(ip='192.168.191.250')
        self.assertEqual(r['type_id'], 2)

    def test_get_device_check(self):
        r = self.dev.get_device_check(num=10, type=2)
        self.assertNotEqual(r.get('total_count', None), None)

    def test_set_device(self):
        data = [
            {'ip': '192.168.191.247', 'status': False},
            {'ip': '192.168.191.245', 'status': True}
        ]
        r = self.dev.set_device(data)
        self.assertNotEqual(r.get('total', None), None)
        
        

