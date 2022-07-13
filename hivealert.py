#!/usr/bin/env python3

import uuid
import json
import time
import logging
import requests
import pprint
from tempfile import NamedTemporaryFile
from base64 import b64decode
from flask import Flask, request, Response
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact, CustomFieldHelper

app = Flask(__name__)

DEBUG_LEVEL = logging.DEBUG  # DEBUG, INFO, ERROR, WARNING
GRAYLOG = 'GRAYLOG_URL'
HIVE = 'HIVE_URL'
HIVE_API_KEY = 'HIVE_API_KEY'
LOG_FORMAT = '%(asctime)-15s %(message)s'
api = TheHiveApi(HIVE, HIVE_API_KEY)
logging.basicConfig(format=LOG_FORMAT, level=DEBUG_LEVEL)


@app.route('/alertsuricata', methods=['POST'])
def create_alert():
    try:
        raw = json.loads(request.data.decode())
        log = raw['check_result']['matching_messages'][0]
        alert = log['fields']
    except Exception as e:
        logging.debug(e)
        if 'Dummy alert' in str(request.data):
            logging.debug('Test alert detected.')
            return Response(status=200)
        else:
            logging.debug('Unable to parse message: ' + request.data.decode())
        return Response(status=503)

    logging.info("New Suricata alert received!")
    logging.debug(alert)

    artifacts = []

    # Attach original alert as artifact
    alert_file = NamedTemporaryFile('w+t', prefix='alert_', suffix='.txt')
    alert_file.write(json.dumps(alert, indent=2))
    alert_file.flush()
    artifacts.append(AlertArtifact(dataType='file', data=alert_file.name))

    # Attach packet as binary file artifact
    if 'packet' in alert:
        packet_file = NamedTemporaryFile('w+b', prefix='packet_',
                                         suffix='.pcap')
        packet_file.write(b64decode(alert['packet']))
        packet_file.flush()
        artifacts.append(AlertArtifact(dataType='file', data=packet_file.name))

    # Build description
    desc = '[{}] signature: {} -- link: \
            {}/messages/{}/{}\n'.format(alert['alert_severity'],
                                        alert['alert_signature'],
                                        GRAYLOG, log['index'], log['id'])

    hivealert = Alert(title=alert['alert_category'],
                      tlp=3,
                      tags=['ids', 'suricata'],
                      description=desc,
                      type='external',
                      source=alert['name'],
                      sourceRef=str(uuid.uuid4())[0:6],
                      artifacts=artifacts)

    response = api.create_alert(hivealert)
    if response.status_code == 201:
        logging.debug(json.dumps(response.json(), indent=4, sort_keys=True))
        id = response.json()['id']
    else:
        logging.debug('ko: {}/{}'.format(response.status_code, response.text))

    # Confirm alert in TheHive
    response = api.get_alert(id)
    if response.status_code == requests.codes.ok:
        logging.debug(json.dumps(response.json(), indent=4, sort_keys=True))
    else:
        logging.debug('ko: {}/{}'.format(response.status_code, response.text))
    alert_file.close()
    packet_file.close()
    return Response(status=201)

# app.run('0.0.0.0')
