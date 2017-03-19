# -*- coding: utf-8 -*-
import arrow

import unittest

from app import db, app
from app.models import *


class ModelTestCase(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass
    
    def test_get_device_by_ip(self):
        dev = Device.query.filter_by(ip='127.0.0.1').first()
        self.assertEqual(dev.city_id, 1)

    def test_get_device_list(self):
        t = arrow.now('PRC').replace(minutes=-1).datetime.replace(tzinfo=None)
        dev = db.session.query(Device). filter(
            Device.modified<=t, Device.last_access<=t, Device.type_id==2,
            Device.banned==0).order_by(Device.modified).limit(10).all()
        self.assertEqual(dev[0].type_id, 2)
        


if __name__ == '__main__':
    pass
    #test_device_get()
    #test_device_get2()
    #test_device_post()

