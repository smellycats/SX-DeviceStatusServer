# -*- coding: utf-8 -*-
import arrow

from . import db


class Users(db.Model):
    """用户"""
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), index=True)
    password = db.Column(db.String(128))
    scope = db.Column(db.String(128), default='')
    date_created = db.Column(db.DateTime, default=arrow.now().datetime)
    date_modified = db.Column(db.DateTime, default=arrow.now().datetime)
    banned = db.Column(db.Integer, default=0)

    def __init__(self, username, password, scope='', banned=0,
                 date_created=None, date_modified=None):
        self.username = username
        self.password = password
        self.scope = scope
        now = arrow.now().datetime
        if not date_created:
            self.date_created = now
        if not date_modified:
            self.date_modified = now
        self.banned = banned

    def __repr__(self):
        return '<Users %r>' % self.id


class Scope(db.Model):
    """权限范围"""
    __tablename__ = 'scope'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), unique=True)

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return '<Scope %r>' % self.id


class Device(db.Model):
    """设备状态表"""
    __tablename__ = 'device'
    #__bind_key__ = 'kakou'
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(64))
    type = db.Column(db.String(128), default='')
    application = db.Column(db.String(128), default='')
    modified = db.Column(db.DateTime)
    last_access = db.Column(db.DateTime)
    status = db.Column(db.Integer, default=1)
    ps = db.Column(db.String(256), default='')
    banned = db.Column(db.Integer, default=0)

    def __init__(self, ip, type, application, modified, last_access,
                 status, ps, banned=0):
        self.ip = ip
        self.type = type
        self.application = application
        self.modified = modified
        self.last_access = last_access
        self.status = status
        self.ps = ps
        self.banned = banned

    def __repr__(self):
        return '<Device %r>' % self.id


