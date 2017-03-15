# -*- coding: utf-8 -*-
import datetime

import arrow

from app import db, app
from app.models import *
from app.helper import *


def test_scope_get():
    scope = Scope.query.all()
    for i in scope:
        print i.name

def test_user_get():
    user = Users.query.filter_by(username='admin', banned=0).first()
    print user.scope
    
def test_device_get():
##    dev = db.session.query(Device).filter(
##        Device.modified <= arrow.now().replace(minutes=-1).datetime).order_by(Device.modified).limit(3).all()
##    print dev
    #now = arrow.utcnow().replace(hours=8)
    dev_list = db.session.query(Device).filter(
        Device.modified <= arrow.now('PRC').replace(minutes=-1).datetime.replace(tzinfo=None),
        Device.last_access <= arrow.now('PRC').replace(minutes=-1).datetime.replace(tzinfo=None),
        Device.banned==0).order_by(Device.modified).limit(10).all()
    print dev_list
    #now = arrow.now('PRC').datetime
    #print now
    for i in dev_list:
        i.last_access = arrow.now('PRC').datetime.replace(tzinfo=None)
    db.session.commit()

def test_device_get2():
    dev = db.session.query(Device).filter(
        Device.ip == '192.168.189.147').first()
    print type(dev.last_access)
    print dev.last_access

def test_device_post():
    ip = '192.168.186.186123'
    dev = Device.query.filter_by(ip=ip).first()
    if not dev:
        print '123'
    print dev
    #dev.application = '567'
    #print type(dev.modified)
    #print type(arrow.now().datetime)
    print datetime.datetime.now()
    dev.modified = datetime.datetime.now()#arrow.now().datetime
    db.session.commit()
    #print r.crossing_id



if __name__ == '__main__':
    test_device_get()
    #test_device_get2()
    #test_device_post()

