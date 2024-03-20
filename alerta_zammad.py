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
        if TriggerEvent.checkCleardStatus(severity):    
            return 'closed'
        else:
            return 'open'
    
    @staticmethod
    def checkCleardStatus(severity):
        return severity.casefold() in ['cleared', 'normal', 'ok']

    @staticmethod
    def checkAllowedSeverity(severity):
        return severity.casefold() in ZAMMAD_ALLOWED_SEVERITIES.casefold()

    def post_receive(self, alert, **kwargs):
        LOG.debug("Post_Receive for alert.id: " + alert.id)
        if alert.repeat:
            LOG.debug("Post_Receive: Alert was repeated -> exit" )
            return

        LOG.debug("Post_Receive: Alert Severity is: "+ alert.severity + "| Allowed severities is: " + ZAMMAD_ALLOWED_SEVERITIES)
        if not TriggerEvent.checkAllowedSeverity(alert.severity):
            return

        #dont open new ticket
        if "ticketid" in alert.attributes.keys():
            LOG.debug("Post_Receive: Ticketid is already set -> no new ticket!")
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

        LOG.debug('Post_Receive: Zammad Payload: %s', payload)

        try:
            r = requests.post(ZAMMAD_URL+"/api/v1/tickets", json=payload, headers=headers, timeout=2)
        except Exception as e:
            raise RuntimeError('Zammad connection error: %s' % e)

        LOG.debug('Post_Receive: Zammad response: {} - {}'.format(r.status_code, r.text))

        if r.status_code == 201:
            jsonResponse = r.json()
            alertAttributes = alert.attributes
            alertAttributes["ticketid"] = jsonResponse["id"]
            alert.update_attributes(alertAttributes)

        return

    def status_change(self, alert, status, text, **kwargs):
        LOG.debug("Status_Change for alert.id: " + alert.id)
        if "ticketid" not in alert.attributes.keys():
            LOG.debug("Alert has no ticketid -> exiting")
            return

        LOG.debug("Status_Change: Current Alert Severity is: " + alert.severity + " - previous Alert Severity was: " + alert.previous_severity)
        if status == "closed" or self.checkCleardStatus(alert.severity):
            state = "closed"
        elif not TriggerEvent.checkAllowedSeverity(alert.severity) or not TriggerEvent.checkAllowedSeverity(alert.previous_severity):
            return
        else:
            state = "open"
        
        headers={'Authorization': 'Token token={}'.format(ZAMMAD_API_TOKEN)}

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

        LOG.debug('Status_Change: Zammad Payload: %s', payload)

        try:
            r = requests.put(ZAMMAD_URL+"/api/v1/tickets/"+ str(alert.attributes["ticketid"]), json=payload, headers=headers, timeout=2)
        except Exception as e:
            raise RuntimeError('Zammad connection error: %s' % e)
        LOG.debug('Status_Change: Zammad response: {} - {}'.format(r.status_code, r.text))