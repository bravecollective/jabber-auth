#!/home/tyler/brave/bin/python

from __future__ import unicode_literals

import sys
from brave.api.client import API
from web.commands.shell import ShellCommand
from paste.script.command import Command

import re
from datetime import datetime
from random import choice
from string import printable
from mongoengine import BinaryField, connect
from mongoengine.base import BaseField
from scrypt import error as scrypt_error, encrypt as scrypt, decrypt as validate_scrypt

from web.core import config
from mongoengine import Document, EmbeddedDocument, StringField, DateTimeField, IntField, EmbeddedDocumentField, ListField
from logging import StreamHandler, DEBUG

from ecdsa import SigningKey, VerifyingKey, NIST256p
from binascii import unhexlify
from hashlib import sha256


AUTH_FAIL = "0"
AUTH_SUCCESS = "1"

API_ENDPOINT = "http://localhost:8080/api"
API_IDENTITY = "53bf20d99ce4be153ae19ce6"
API_PRIVATE = "95c0a1bf354a58316d5e7e76e34be4df81180d8d1318ab6000f91a64496f035f"
API_PUBLIC = "3c7d8470dd16e5fa39962c87f6dd9446aaabba3cca2170bfee2d3be2ed044ba60649d1c4249bbea28beac3b87441d06f516ffe0503d0c690961d97bd8e34532e"

log = __import__('logging').getLogger(__name__)

def auth(username, host, password):
    log.info('Authenticate "%s"', username)
    
    name = username.split("@")[0]
        
    # Look up the user.
    try:
        user = Ticket.objects.only('tags', 'updated', 'password', 'corporation__id', 'alliance__id', 'alliance__ticker', 'character__id', 'token').get(character__name=name)
    except Ticket.DoesNotExist:
        log.warn('User "%s" not found in the Ticket database.', name)
        return AUTH_FAIL
        
    password = password.encode('utf-8')
       
    if not isinstance(password, basestring):
        log.warn('pass-notString-fail "%s"', name)
        return AUTH_FAIL
    elif password == '':
        log.warn('pass-empty-fail "%s"', name)
        return AUTH_FAIL
    elif user.password == '':
       log.warn('pass-not-set-fail "%s"', name)
       return UNKNOWN_USER_FAIL
    elif not Ticket.password.check(user.password, password):
       log.warn('pass-fail "%s"', name)
       return AUTH_FAIL
        
    # -------
    # Check to make sure that the user is still valid and that their token has not expired yet.
    # -------
            
    # load up the API
    api = API(API_ENDPOINT, API_IDENTITY, API_PRIVATE, API_PUBLIC)
         
   # try:
        # If the token is not valid, deny access
    if not Ticket.authenticate(user.token):
        return AUTH_FAIL
    """ except Exception as e:
        log.warning("Exception {0} occured when attempting to authenticate user {1}.".format(e, name))
        return AUTH_FAIL
                
        # Update the local user object against the newly refreshed DB ticket.
        user = Ticket.objects.only('tags', 'updated', 'password', 'corporation__id', 'alliance__id', 'alliance__ticker', 'character__id', 'token').get(character__name=name)
            
        # Define the registration date if one has not been set.
        Ticket.objects(character__name=name, registered=None).update(set__registered=datetime.utcnow())
        
        for tag in ('member', 'blue', 'guest', 'jabber'):
            if tag in user.tags: break"""
   # else:
    #    log.warn('User "%s" does not have permission to connect to this server.', name)
     #   return AUTH_FAIL
        
    tags = [i.replace('jabber.', '') for i in user.tags]
        
    tags.append('corporation-{0}'.format(user.corporation.id))
    if user.alliance and user.alliance.id:
        tags.append('alliance-{0}'.format(user.alliance.id))
        
    log.debug('success "%s" %s', name, ' '.join(tags))
        
    ticker = user.alliance.ticker if user.alliance.ticker else '----'
    return AUTH_SUCCESS
    
def isuser(username):
    # Look up the user.
    print("isuser")
    try:
        user = Ticket.objects.only('tags', 'updated', 'password', 'corporation__id', 'alliance__id', 'alliance__ticker', 'character__id', 'token').get(character__name=name)
        return AUTH_SUCCESS
    except Ticket.DoesNotExist:
        log.warn('User "%s" not found in the Ticket database.', name)
        return AUTH_FAIL

def respond(ret):
    sys.stdout.write(ret+"\n")
    sys.stdout.flush()
    
def hex2key(hex_key):
    key_bytes = unhexlify(hex_key)
    if len(hex_key) == 64:
        return SigningKey.from_string(key_bytes, curve=NIST256p,
                hashfunc=sha256)
    elif len(hex_key) == 128:
        return VerifyingKey.from_string(key_bytes, curve=NIST256p,
                hashfunc=sha256)
    else:
        raise ValueError("Key in hex form is of the wrong length.")
    

class PasswordField(BinaryField):
    def __init__(self, difficulty=1, **kwargs):
        self.difficulty = difficulty
        
        super(PasswordField, self).__init__(**kwargs)
    
    def to_python(self, value):
        return value
    
    def __set__(self, instance, value):
        if instance._initialised:
            if isinstance(value, unicode):
                value = value.encode('utf-8')
            
            salt = b''.join([choice(printable) for i in range(32)])
            value = str(scrypt(salt, value, maxtime=self.difficulty))
        
        return super(PasswordField, self).__set__(instance, value)
    
    def to_mongo(self, value):
        if value is None:
            return value
        
        return super(PasswordField, self).to_mongo(value)
    
    def check(self, source, value):
        try:
            # It may be a tiny bit more difficult for us to validate than it was to generate.
            # Even a few ms too long will give us bad results.
            validate_scrypt(source, value, self.difficulty * 4)
            
        
        except scrypt_error:
            return False
        except Exception as e:
            log.warn(e)
            return False
        return True


# TODO: Deduplication?  Only store integer ID, turn Entity into its own collection.
# Would require migration map/reduce and scrubbing query.

class Entity(EmbeddedDocument):
    meta = dict(allow_inheritance=False)
    
    id = IntField(db_field='i')
    name = StringField(db_field='n')
    ticker = StringField(db_field='t')


class Ticket(Document):
    meta = dict(
            collection = 'Tickets',
            allow_inheritance = False,
            indexes = [
                    'character.id'
                ],
        )
    
    token = StringField(db_field='t')
    
    character = EmbeddedDocumentField(Entity, db_field='c', default=lambda: Entity())
    corporation = EmbeddedDocumentField(Entity, db_field='o', default=lambda: Entity())
    alliance = EmbeddedDocumentField(Entity, db_field='a', default=lambda: Entity())
    tags = ListField(StringField(), db_field='g', default=list)
    
    password = PasswordField(db_field='pw', difficulty=0.125)
    comment = StringField(db_field='m', default='')
    
    expires = DateTimeField(db_field='e')
    seen = DateTimeField(db_field='s')  # TODO: Update this when the user connects/disconnects.
    updated = DateTimeField(db_field='u')
    registered = DateTimeField(db_field='r')
    
    @property
    def has_password(self):
        return bool(self.password)
    
    def __repr__(self):
        return "<Ticket {0.id} \"{0.character.name}\">".format(self)
    
    @classmethod
    def authenticate(cls, identifier, password=None):
        """Validate the given identifier; password is ignored."""
        
        api = API(API_ENDPOINT, API_IDENTITY, API_PRIVATE, API_PUBLIC)
        result = api.core.info(identifier)
        
        #Invalid token sent. Probably a better way to handle this.
        if not result:
            log.info("Token %s not valid, or connection to Core has been lost.", identifier)
            return None
        
        user = cls.objects(character__id=result.character.id).first()
        
        if not user:
            user = cls(token=identifier, expires=result.expires, seen=datetime.utcnow())
        elif identifier != user.token:
            user.token = identifier
        
        user.character.id = result.character.id
        user.character.name = result.character.name.replace(" ", "_").lower()
        user.corporation.id = result.corporation.id
        user.corporation.name = result.corporation.name
        
        if result.alliance:
            user.alliance.id = result.alliance.id
            user.alliance.name = result.alliance.name
            
            alliance = api.lookup.alliance(result.alliance.id, only='short')
            if alliance and alliance.success:
                user.alliance.ticker = alliance.short
        
        user.tags = [i.replace('jabber.', '') for i in (result.tags if 'tags' in result else [])]
        user.updated = datetime.now()
        user.save()
        
        return user.id, user
    
    @classmethod
    def lookup(cls, identifier):
        """Thaw current user data based on session-stored user ID."""
        
        user = cls.objects(id=identifier).first()
        
        if user:
            user.update(set__seen=datetime.utcnow())
        
        return user

connect('jabber')

API_PRIVATE = hex2key(API_PRIVATE)
API_PUBLIC = hex2key(API_PUBLIC)

hand = StreamHandler()
hand.setLevel(DEBUG)
log.addHandler(hand)

methods = {
    "auth": { "function": auth, "parameters": 3 },
    "isuser": { "function": isuser, "paramaters": 1 }
}

while 1:
    line = sys.stdin.readline().rstrip("\n")
    #respond("error: test %s"%line)
    method, sep, data = line.partition(":")
    if method in methods:
        method_info = methods[method]
        split_data = data.split(":", method_info["parameters"])
        if len(split_data) == method_info["parameters"]:
            respond(method_info["function"](*split_data))
        else:
            respond("error: incorrect number of parameters to method '%s' %s"%(method, len(split_data)))
    else:
        respond("error: method '%s' not implemented"%method)

