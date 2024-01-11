import logging
import os

import requests
# from alerta.exceptions import RejectException
from alerta.plugins import PluginBase

try:
    from alerta.plugins import app  # alerta >= 5.0
except ImportError:
    from alerta.app import app  # alerta < 5.0

LOG = logging.getLogger('alerta.plugins')

ZAMMAD_URL = os.environ.get('ZAMMAD_URL') or app.config['ZAMMAD_URL']
ZAMMAD_API_TOKEN = os.environ.get('ZAMMAD_API_TOKEN') or app.config['ZAMMAD_API_TOKEN']
ZAMMAD_CUSTOMER_MAIL = os.environ.get('ZAMMAD_CUSTOMER_MAIL') or app.config['ZAMMAD_CUSTOMER_MAIL']


class TriggerEvent(PluginBase):

    def pre_receive(self, alert, **kwargs):
        return alert

    @staticmethod
    def _event_type(severity):
        if severity in ['cleared', 'normal', 'ok']:
            return 'close'
        else:
            return 'open'

    def post_receive(self, alert, **kwargs):
        if alert.repeat:
            return

        message = '{} alert for {} - {}'.format(
            alert.severity.capitalize(), ','.join(alert.service), alert.resource)

        payload = {
            'title': message,
            'customer': ZAMMAD_CUSTOMER_MAIL,
            'article': {
                'subject': "Alerta alert!",
                'body': alert.get_body(history=False),
                "type": "note",
                "internal": False
            }
        }
        
        headers={'Authorization': 'Token token={}'.format(ZAMMAD_API_TOKEN)}

        LOG.debug('Zammad Payload: %s', payload)

        try:
            r = requests.post(ZAMMAD_URL+"/api/v1/tickets", json=payload, headers=headers, timeout=2)
        except Exception as e:
            raise RuntimeError('Zammad connection error: %s' % e)
        LOG.debug('Zammad response: {} - {}'.format(r.status_code, r.text))
        return

    def status_change(self, alert, status, text, **kwargs):
        if status not in ['ack', 'assign']:
            return

        message = '{} alert for {} - {}'.format(
            alert.severity.capitalize(), ','.join(alert.service), alert.resource)

        payload = {
            'title': message,
            'customer': ZAMMAD_CUSTOMER_MAIL,
            'article': {
                'subject': "Alerta alert!",
                'body': alert.get_body(history=False),
                "type": "note",
                "internal": False
            }
        }
        
        headers={'Authorization': 'Token token={}'.format(ZAMMAD_API_TOKEN)}

        LOG.debug('Zammad Payload: %s', payload)

        try:
            r = requests.post(ZAMMAD_URL+"/api/v1/tickets", json=payload, headers=headers, timeout=2)
        except Exception as e:
            raise RuntimeError('Zammad connection error: %s' % e)
        LOG.debug('Zammad response: {} - {}'.format(r.status_code, r.text))