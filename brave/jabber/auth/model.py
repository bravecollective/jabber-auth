# encoding: utf-8

from __future__ import unicode_literals

import re
from datetime import datetime, timedelta
from random import choice, randint
from string import printable
from mongoengine import BinaryField
from mongoengine.base import BaseField
from scrypt import error as scrypt_error, encrypt as scrypt, decrypt as validate_scrypt

from hashlib import sha256
from ecdsa import SigningKey, VerifyingKey, NIST256p
from binascii import unhexlify

from web.core import config
from mongoengine import Document, EmbeddedDocument, StringField, DateTimeField, IntField, EmbeddedDocumentField, ListField, BooleanField, ReferenceField
from brave.api.client import API, Permission


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
    username = StringField(db_field='d', unique=True)
    
    password = PasswordField(db_field='pw', difficulty=0.125)
    comment = StringField(db_field='m', default='')
    
    expires = DateTimeField(db_field='e')
    seen = DateTimeField(db_field='s')  # TODO: Update this when the user connects/disconnects.
    updated = DateTimeField(db_field='u')
    registered = DateTimeField(db_field='r')
    
    jid_host = StringField(db_field='j')
    bot = BooleanField(db_field='b')
    # Used solely by bots
    display_name = StringField(db_field='bs')
    owner = ReferenceField("Ticket", db_field='ow')

    @property
    def joinable_mucs(self):
        mucs = Permission.set_has_any_permission(self.tags, 'muc.enter.*')
        
        allowed_mucs = []
        
        if not mucs:
            return []
        
        for muc in mucs:
            # Get just the muc name
            muc = muc.replace('muc.enter.', '')
            
            # Check if a user has been outcasted from the room, used to ban specific users from a room
            # they normally could access. (Why did I agree to not allowing negative permissions again?)
            if not Permission.set_grants_permission(self.tags, 'muc.affiliate.outcast.{0}'.format(muc)):
                allowed_mucs.append(muc)
    
        return allowed_mucs
        
    def muc_nickname(self, muc):
        
        # When the room we're joining is not known, show the user's default ranks
        if muc == '*':
            muc = 'default'
        
        if self.alliance and self.alliance.ticker:
            alliance = self.alliance.ticker
        else:
            alliance = "----"
        
        char = self.character.name
        
        if self.bot:
            return self.display_name
    	
        use_corp_ticker = Permission.set_grants_permission(self.tags, 'muc.nick.corp.{0}'.format(muc))

        if use_corp_ticker:
            alliance = self.corporation.ticker

        # Check if the user has a permission granting them access to a rank in this room.
        ranks = Permission.set_has_any_permission(self.tags, 'muc.rank.*.{0}'.format(muc))
        
        # If the user has no ranks for this room specified, check if they have any default ranks
        if not ranks:
            ranks = Permission.set_has_any_permission(self.tags, 'muc.rank.*.{0}'.format('default'))
            muc = "default"
        
        if not ranks:
            return "{0} [{1}]".format(char, alliance)
        
        display = set()
        for r in ranks:
            # Remove the beginning portion of the permission, as well as the room identifier to get just the rank
            display.add(r.replace("muc.rank.", "").replace(".{0}".format(muc), ""))
    
        return "{0} [{1}] ({2})".format(char, alliance, ", ".join(display))
        
    def muc_roles(self, muc):
        # Affiliations
        affs = dict()
        affs['owner'] = u'muc.affiliate.owner.{0}'.format(muc)
        affs['admin'] = u'muc.affiliate.admin.{0}'.format(muc)
        affs['member'] = u'muc.affiliate.member.{0}'.format(muc)
        affs['outcast'] = u'muc.affiliate.outcast.{0}'.format(muc)
    
        # Roles
        roles = dict()
        roles['moderator'] = u'muc.role.moderator.{0}'.format(muc)
        roles['participant'] = u'muc.role.participant.{0}'.format(muc)
        roles['visitor'] = u'muc.role.visitor.{0}'.format(muc)
    
        role = None
        affiliation = None
    
        for a, perm in affs.iteritems():
            if Permission.set_grants_permission(self.tags, perm):
                affiliation = a
                break
    
        for r, perm in roles.iteritems():
            if Permission.set_grants_permission(self.tags, perm):
                role = r
                break
    
        if not role and affiliation == 'owner' or affiliation == 'admin':
            role = 'moderator'
            
        if not muc in self.joinable_mucs:
            return "outcast:visitor"
    
        # Default affiliation is member (user will have already been checked for access)
        return "{0}:{1}".format(affiliation if affiliation else "member", role if role else "participant")
        
    def can_send_ping(self, ping_group):
        if not Permission.set_grants_permission(self.tags, 'ping.send.{0}'.format(ping_group)):
            return "0"
        
        return "1"
        
    def can_receive_ping(self, ping_group):
        if not Permission.set_grants_permission(self.tags, 'ping.ignore.{0}'.format(ping_group)) and Permission.set_grants_permission(self.tags, 'ping.receive.{0}'.format(ping_group)):
            return(str(str(self.username) + str("@") + str(self.jid_host)))
            
        return False
        
    @property
    def vCard(self):
        if self.bot:
            return "{username}:BOT:BOT".format(username=self.display_name)
        org_name = self.alliance.name
        org_unit = self.corporation.name
        full_name = self.character.name
        
        return "{full_name}:{org_name}:{org_unit}".format(full_name=full_name, org_name=org_name, org_unit=org_unit)
    
    @property
    def has_password(self):
        return bool(self.password)
    
    def __repr__(self):
        return "<Ticket {0.id} \"{0.character.name}\">".format(self)
    
    @classmethod
    def authenticate(cls, identifier, password=None):
        """Validate the given identifier; password is ignored."""
        
        user = cls.objects(token=identifier).first()

        if user:
            user.updated = user.updated.replace(tzinfo=None)

        if user and datetime.utcnow() - user.updated < timedelta(minutes=1):
            return user.id, user

        api = API(API_ENDPOINT, API_IDENTITY, API_PRIVATE, API_PUBLIC)
        result = api.core.info(identifier)
        
        # Invalid token sent. Probably a better way to handle this.
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
        # Spaces and ' are invalid for XMPP IDs
        user.username = result.character.name.replace(" ", "_").replace("'", "").lower() if not user.username else user.username
        user.corporation.id = result.corporation.id
        user.corporation.name = result.corporation.name
 
        corporation = api.lookup.corporation(result.corporation.id, only='short')
        if corporation and corporation.success:
            user.corporation.ticker = corporation.short
       
        if result.alliance:
            user.alliance.id = result.alliance.id
            user.alliance.name = result.alliance.name
            
            alliance = api.lookup.alliance(result.alliance.id, only='short')
            if alliance and alliance.success:
                user.alliance.ticker = alliance.short
        
        user.tags = [i.replace('jabber.', '') for i in (result.perms if 'perms' in result else [])]
        
        hosts = Permission.set_has_any_permission(user.tags, 'host.*')
        if hosts and 'host.pokemon.bravecollective.com' in hosts:
            user.jid_host = 'pokemon.bravecollective.com'
        elif hosts:
            user.jid_host = hosts[0][5:]
        else:
            user.jid_host = 'public.bravecollective.com'
        
        user.updated = datetime.utcnow()
        user.save()
        
        return user.id, user
    
    @classmethod
    def lookup(cls, identifier):
        """Thaw current user data based on session-stored user ID."""
        
        user = cls.objects(id=identifier).first()
        
        if user:
            user.update(set__seen=datetime.utcnow())
        
        return user
        
    @staticmethod
    def create_bot(owner, username, password, display_name):
        # Create the Bot based on the bot's owner
        t = Ticket(token=owner.token, character=owner.character, alliance=owner.alliance, tags=owner.tags)
        t.username = username
        t.password = password
        t.display_name = display_name
        t.jid_host = 'bot.bravecollective.com'
        t.bot = True
        t.owner = owner
        t.save()
