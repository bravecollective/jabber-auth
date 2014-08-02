# encoding: utf-8

from __future__ import unicode_literals

import re
from datetime import datetime
from random import choice
from string import printable
from mongoengine import BinaryField
from mongoengine.base import BaseField
from scrypt import error as scrypt_error, encrypt as scrypt, decrypt as validate_scrypt

from hashlib import sha256
from ecdsa import SigningKey, VerifyingKey, NIST256p
from binascii import unhexlify

from web.core import config
from mongoengine import Document, EmbeddedDocument, StringField, DateTimeField, IntField, EmbeddedDocumentField, ListField
from brave.api.client import API


log = __import__('logging').getLogger(__name__)

API_ENDPOINT = "http://localhost:8080/api"
API_IDENTITY = "53bf20d99ce4be153ae19ce6"
API_PRIVATE = "95c0a1bf354a58316d5e7e76e34be4df81180d8d1318ab6000f91a64496f035f"
API_PUBLIC = "3c7d8470dd16e5fa39962c87f6dd9446aaabba3cca2170bfee2d3be2ed044ba60649d1c4249bbea28beac3b87441d06f516ffe0503d0c690961d97bd8e34532e"

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

API_PRIVATE = hex2key(API_PRIVATE)
API_PUBLIC = hex2key(API_PUBLIC)

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
    username = StringField(db_field='d')
    
    password = PasswordField(db_field='pw', difficulty=0.125)
    comment = StringField(db_field='m', default='')
    
    expires = DateTimeField(db_field='e')
    seen = DateTimeField(db_field='s')  # TODO: Update this when the user connects/disconnects.
    updated = DateTimeField(db_field='u')
    registered = DateTimeField(db_field='r')
    
    jid_host = StringField(db_field='j')
    
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
        user.character.name = result.character.name
        user.username = result.character.name.replace(" ", "_").lower()
        user.corporation.id = result.corporation.id
        user.corporation.name = result.corporation.name
        
        if result.alliance:
            user.alliance.id = result.alliance.id
            user.alliance.name = result.alliance.name
            
            alliance = api.lookup.alliance(result.alliance.id, only='short')
            if alliance and alliance.success:
                user.alliance.ticker = alliance.short
        
        user.tags = [i.replace('jabber.', '') for i in (result.perms if 'perms' in result else [])]
        
        # Hardcode the hosts because I'm tired and just want this done with
        hosts = set_has_any_permission(tags, 'host.*')
        if hosts:
            jid_host = hosts[0]
        else:
            jid_host = 'public.bravecollective.com'
        
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
