#!/usr/bin/env python
# -*- coding: utf-8 -*-

import datetime
import keyring
import json
import os
import sqlite3

from image_backup import main as do_backup

conn = sqlite3.connect("reg.db")
conn.text_factory = str
crs = conn.cursor()

#ids = ["25241c58-3fc5-45bb-adf3-5d45bb6f8702",
#        "0b8bd4be-0348-4f7a-9ab7-2665e37f4e72",
#        "f84e88e7-d8c9-41c3-87c5-7c420426b9ae"]
#sql = "update users set server_ids = '%s' where username = 'edleafe'" % json.dumps(ids)
#print "SQL"
#print sql
#crs.execute(sql)
#conn.commit()
#exit()

sql = "select username, server_ids, retain from users"
crs.execute(sql)
jobs = crs.fetchall()

for job in jobs:
    username, server_ids, retain = job
    res = do_backup(username=username, api_key=keyring.get_password("pyrax", username),
            server_ids=server_ids, backup_count=retain)
#    print res
