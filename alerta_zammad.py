import logging
import os
import json

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
ZAMMAD_ALLOWED_SEVERITIES = os.environ.get('ZAMMAD_ALLOWED_SEVERITIES') or app.config['ZAMMAD_ALLOWED_SEVERITIES'] or 'security,critical,major'

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

        LOG.debug("Alert Severity is: "+ alert.severity + "| Allowed severities is: " + ZAMMAD_ALLOWED_SEVERITIES)
        if alert.severity.casefold() not in ZAMMAD_ALLOWED_SEVERITIES.casefold():
            return

        #dont open new ticket
        if "ticketid" in alert.attributes.keys():
            LOG.debug("Ticketid is already set -> no new ticket!")
            return

        message = '{} alert for {} - {}'.format(
            alert.severity.capitalize(), ','.join(alert.service), alert.resource)

        payload = {
            'title': message,
            'group': 'Users',
            'customer': ZAMMAD_CUSTOMER_MAIL,
            'article': {
                'subject': "Alerta alert!",
                'body': json.dumps(alert.get_body(history=False), indent=4),
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

        if r.status_code == 201:
            jsonResponse = r.json()
            alertAttributes = alert.attributes
            alertAttributes["ticketid"] = jsonResponse["id"]
            alert.update_attributes(alertAttributes)

        return

    def status_change(self, alert, status, text, **kwargs):
        if "ticketid" not in alert.attributes.keys():
            return

        headers={'Authorization': 'Token token={}'.format(ZAMMAD_API_TOKEN)}

        if status == "closed":
            state = "closed"
        elif alert.severity.casefold() not in ZAMMAD_ALLOWED_SEVERITIES.casefold():
            return
        else:
            state = "open"

        message = '{} alert for {} - {}'.format(
            alert.severity.capitalize(), ','.join(alert.service), alert.resource)

        payload = {
            'title': message,
            'group': 'Users',
            "state": state,
            'customer': ZAMMAD_CUSTOMER_MAIL,
            'article': {
                'subject': "Alert Update",
                'body': json.dumps(alert.get_body(history=False).pop("rawData", None), indent=4),
                "type": "note",
                "internal": False
            }
        }

        LOG.debug('Zammad Payload: %s', payload)

        try:
            r = requests.put(ZAMMAD_URL+"/api/v1/tickets/"+ str(alert.attributes["ticketid"]), json=payload, headers=headers, timeout=2)
        except Exception as e:
            raise RuntimeError('Zammad connection error: %s' % e)
        LOG.debug('Zammad response: {} - {}'.format(r.status_code, r.text))