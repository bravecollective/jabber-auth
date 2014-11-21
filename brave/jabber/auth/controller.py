# encoding: utf-8

from __future__ import unicode_literals

from web.auth import authenticate, deauthenticate
from web.core import config, url, session
from web.core.http import HTTPFound

from brave.api.client import API


log = __import__('logging').getLogger(__name__)


class AuthenticationMixIn(object):
    def authorize(self):
        # Perform the initial API call and direct the user.
        
        api = API(config['api.endpoint'], config['api.identity'], config['api.private'], config['api.public'])
        
        success = str(url.complete('/authorized'))
        failure = str(url.complete('/nolove'))
        
        result = api.core.authorize(success=success, failure=failure)
        
        raise HTTPFound(location=result.location)
    
    def ciao(self):
        deauthenticate(True)
        
        raise HTTPFound(location='/')
    
    def authorized(self, token):
        # Capture the returned token and use it to look up the user details.
        # If we don't have this character, create them.
        # Store the token against this user account.
        # Note that our own 'sessions' may not last beyond the UTC date returned as 'expires'.
        # (Though they can be shorter!)
        
        # We request an authenticated session from the server.
        
        # Prevent users from specifying their session IDs (Some user-agents were sending null ids, leading to users
        # authenticated with a session id of null
        session.regenerate_id()

        authenticate(token)
        
        raise HTTPFound(location='/')
    
    def nolove(self, token):
        return 'brave.mumble.template.whynolove', dict()
