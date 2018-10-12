#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# vim: tabstop=2 shiftwidth=2 softtabstop=2 expandtab

import sys
import csv
import hashlib
import hmac
import base64
import requests
import time
import json
import logging
import traceback
from random import randint

import MySQLdb
import arrow
import dataset

reload(sys)
sys.setdefaultencoding('utf-8')

logging.basicConfig(format='%(asctime)s [%(levelname)s] %(message)s', level=logging.WARNING)
logger = logging.getLogger()

QUERY_FMT = {
        'mysql_insert' : '''INSERT INTO %(database)s.%(table)s (ip, ip_grp, country, admin_code, r1, r2, r3, latitude, longitude, net)
                            VALUES %(val)s'''
            }

def get_geolocation(query_ip):

  timestamp = str(int(time.time() * 1000))
  api_key = "API_KEY" 
  access_key = "ACCESS_KEY"                # access key id (from portal or sub account)
  secret_key = "SECRET_KEY"                # secret key (from portal or sub account)
  secret_key = bytearray(secret_key, 'UTF-8')

  method = "GET"
  url = "https://ncloud.apigw.ntruss.com/geolocation/v1/geoLocation?enc=utf8&ext=t&ip={}&responseFormatType=json".format(query_ip)
  uri = "/geolocation/v1/geoLocation?enc=utf8&ext=t&ip={}&responseFormatType=json".format(query_ip)

  message = method + " " + uri + "\n" + timestamp + "\n" + api_key + "\n" + access_key
  message = bytearray(message, 'UTF-8')
  signature = base64.b64encode(hmac.new(secret_key, message, digestmod=hashlib.sha256).digest())

  headers = { 'x-ncp-apigw-timestamp': timestamp, 
              'x-ncp-apigw-api-key': api_key,
              'x-ncp-iam-access-key': access_key,
              'x-ncp-apigw-signature-v1': signature }
  try: 
    response = requests.get(url, headers=headers)
    return response
  except Exception, e:
    logger.error(e)
    return 0

with open("ip.csv") as csvfile:
  csv_reader = csv.reader(csvfile, delimiter=',')
  
  ip_grps = []

  for row in csv_reader:
    for b in range(int(row[0].split(".")[1]), int(row[2].split(".")[1]) + 1):
      for c in range(int(row[0].split(".")[2]), int(row[2].split(".")[2]) + 1):
        ip_grps.append(row[0].split(".")[0] + "." + str(b) + "." + str(c))

mysql_endpoint = '''mysql://%(user)s:%(password)s@%(db_host)s:%(db_port)s/%(db_name)s?charset=utf8''' % {
  'user': base64.b64decode('encoded_user_id'),
  'password': base64.b64decode('encoded_password'),
  'db_port': {port},
  'db_host': 'db_host_name',
  'db_name': 'db_name'
}

partitioned_ip_grps = (ip_grps[i:i+100] for i in xrange(0, len(ip_grps), 100))

partition = 0

for ip_groups in partitioned_ip_grps:
  ip_geolocation = []
  logger.error("Partition " + str(partition + 1))
  partition += 1
  for ip_grp in ip_groups:
    for i in range(4):
      d = i * 64 + 1
  
      query_ip = ip_grp + "." + str(d)
      response = get_geolocation(query_ip)
      if response == 0:
        continue
      response = json.loads(response.text)
      
      try:
        
        entry = {'ip': query_ip,
                 'ip_grp': ip_grp + "." + str(d - 1),
                 'country': response['geoLocation']['country'],
                 'admin_code': response['geoLocation']['code'] if response['geoLocation']['code'] else -1,
                 'r1': response['geoLocation']['r1'],
                 'r2': response['geoLocation']['r2'],
                 'r3': response['geoLocation']['r3'],
                 'latitude': response['geoLocation']['lat'] if response['geoLocation']['lat'] else -1,
                 'longitude': response['geoLocation']['long'] if response['geoLocation']['long'] else -1,
                 'net': response['geoLocation']['net']
                 }
      except Exception, e:
        logger.error(e)
        logger.error(response)
        continue

      ip_geolocation.append(entry)
  
  mysql_db = dataset.connect(mysql_endpoint, engine_kwargs={'encoding': 'utf-8'})
  
  value_fmt = '''("%(ip)s", "%(ip_grp)s", "%(country)s", %(admin_code)s, "%(r1)s", "%(r2)s", "%(r3)s", %(latitude)s, %(longitude)s, "%(net)s")'''
  
  partitioned_result_list = (ip_geolocation[i:i+100] for i in xrange(0, len(ip_geolocation), 100))
  
  for elems in partitioned_result_list:
    val = ", ".join([value_fmt % e for e in elems])
    query = QUERY_FMT['mysql_insert'] % {'database': 'database_name', 'table': 'table_name', 'val': val}
  
    try:
      mysql_db.query(query)
    except Exception, e:
      logger.error(e)
      traceback.print_exc()
      raise Exception("Error while inserting to MySQL")
