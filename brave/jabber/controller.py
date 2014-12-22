# encoding: utf-8

from __future__ import unicode_literals

from web.auth import authenticated, user
from web.core import Controller

from brave.jabber.util import StartupMixIn
from brave.jabber.auth.controller import AuthenticationMixIn

import zxcvbn

log = __import__('logging').getLogger(__name__)


class RootController(Controller, StartupMixIn, AuthenticationMixIn):
    def index(self):
        if authenticated:
            return 'brave.jabber.template.index', dict()

        return 'brave.jabber.template.welcome', dict()

    def combine_pings(self):
        user.combine_pings = not user.combine_pings if user.combine_pings is not None else True
        if user.save():
            return 'json:', dict(success=True)

    def passwd(self, password):
        u = user._current_obj()
        
        #If the password has a score of less than 4, don't permit it (this check also done client-side)
        if(zxcvbn.password_strength(password).get("score") < 3):
            return 'json:', dict(success=False, message="The password supplied was not strong enough.")

        try:
            u.password = password
            u.save()
        except:
            log.exception("Error attempting to assign password.")
            return 'json:', dict(success=False, message="Something terrible happened.")
        
        return 'json:', dict(success=True)
