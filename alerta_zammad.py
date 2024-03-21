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

ZAMMAD_URL = os.environ.get('ZAMMAD_URL') or app.config.get('ZAMMAD_URL') or "http://127.0.0.1:8080"
ZAMMAD_API_TOKEN = os.environ.get('ZAMMAD_API_TOKEN') or app.config.get('ZAMMAD_API_TOKEN') or ""
AUTH_HEADER = {'Authorization': 'Token token={}'.format(ZAMMAD_API_TOKEN)}
ZAMMAD_CUSTOMER_MAIL = os.environ.get('ZAMMAD_CUSTOMER_MAIL') or app.config.get('ZAMMAD_CUSTOMER_MAIL') or "Test@test.com"
ZAMMAD_ALLOWED_SEVERITIES = os.environ.get('ZAMMAD_ALLOWED_SEVERITIES') or app.config.get('ZAMMAD_ALLOWED_SEVERITIES') or "critical"

class TriggerEvent(PluginBase):

    def pre_receive(self, alert, **kwargs):
        return alert
    
    @staticmethod
    def checkCleardStatus(severity) -> bool:
        return severity.casefold() in ['cleared', 'normal', 'ok']

    @staticmethod
    def checkAllowedSeverity(severity) -> bool:
        return severity.casefold() in ZAMMAD_ALLOWED_SEVERITIES.casefold()

    @staticmethod
    def createPayload(alert, state="") -> dict[str, any]:
        message = '{} alert for {} - {}'.format(
           alert.severity.capitalize(), ','.join(alert.service), alert.resource)
        
        body = alert.get_body(history=False)
        body.pop("rawData", None)

        payload = {
            'title': message,
            'group': 'Users',
            'customer': ZAMMAD_CUSTOMER_MAIL,
            'article': {
                'subject': "Alerta alert!",
                'body': json.dumps(body, indent=4),
                "type": "note",
                "internal": False
            }
        }

        if state:
            payload['state'] = state

        return payload
    
    @staticmethod
    def createTicket(payload) -> requests.Response:
        try:
            return requests.post(ZAMMAD_URL+"/api/v1/tickets", json=payload, headers=AUTH_HEADER, timeout=2)
        except Exception as e:
            raise RuntimeError('Zammad connection error: %s' % e)

    @staticmethod
    def updateTicket(alert, payload) -> requests.Response:
        try:
            return requests.put(ZAMMAD_URL+"/api/v1/tickets/"+ str(alert.attributes["ticketid"]), json=payload, headers=AUTH_HEADER, timeout=2)
        except Exception as e:
            raise RuntimeError('Zammad connection error: %s' % e) 

    def post_receive(self, alert, **kwargs):
        LOG.debug("Post_Receive for alert.id: " + alert.id)
        if alert.repeat:
            LOG.debug("Post_Receive: Alert was repeated -> exit" )
            return

        hasTicketId = "ticketid" in alert.attributes.keys()

        overThreshold = TriggerEvent.checkAllowedSeverity(alert.severity)

        deescalation = not overThreshold and TriggerEvent.checkAllowedSeverity(alert.previous_severity)

        if not (overThreshold or deescalation):
            return
        elif deescalation:
            state = "closed"
        elif hasTicketId:
            state = "open"
        else:
            state = ""

        payload = TriggerEvent.createPayload(alert, state)

        LOG.debug('Post_Receive: Zammad Payload: %s', payload)

        if hasTicketId:
            r = TriggerEvent.updateTicket(alert, payload)
        else:
            r = TriggerEvent.createTicket(payload)

        LOG.debug('Post_Receive: Zammad response: {} - {}'.format(r.status_code, r.text))

        if r.status_code == 201 and not hasTicketId:
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
        
        if not TriggerEvent.checkAllowedSeverity(alert.severity):
            LOG.debug("Alert Severity is not over Threshold!")
            return

        if status == "closed":
            state = "closed"
        else:
            state = "open"
        
        r = TriggerEvent.updateTicket(alert, TriggerEvent.createPayload(alert, state) )

        LOG.debug('Status_Change: Zammad response: {} - {}'.format(r.status_code, r.text))