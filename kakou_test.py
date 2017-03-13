# -*- coding: utf-8 -*-
import time
import datetime
import json

import arrow

from app.helper_kakou import Kakou


def get_maxid():
    config = {
	'host': '10.47.223.147',
	'port': 8080,
	'username': 'hcqkakou',
	'password': 'kakoutest'
    }

    kk = Kakou(**config)
    print kk.get_kakou_maxid()

def get_kkdd():
    config = {
	'host': '10.47.223.147',
	'port': 8080,
	'username': 'hcqkakou',
	'password': 'kakoutest'
    }
    kk = Kakou(**config)
    print kk.get_kkdd_all()['items'][0]

def get_kakou():
    config = {
	'host': '10.47.223.147',
	'port': 8080,
	'username': 'hcqkakou',
	'password': 'kakoutest'
    }
    kk = Kakou(**config)
    print kk.get_kakou_info(510181890, 510181892)

if __name__ == '__main__':  # pragma nocover
    get_maxid()
    get_kkdd()
    get_kakou()
