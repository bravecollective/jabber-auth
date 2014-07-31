#!/home/tyler/brave/bin/python -u

from __future__ import unicode_literals

import sys
from brave.api.client import API
from web.commands.shell import ShellCommand
from paste.script.command import Command

import re
from datetime import datetime, timedelta
from random import choice
from string import printable
from mongoengine import BinaryField, connect
from mongoengine.base import BaseField
from scrypt import error as scrypt_error, encrypt as scrypt, decrypt as validate_scrypt

from web.core import config
from mongoengine import Document, EmbeddedDocument, StringField, DateTimeField, IntField, EmbeddedDocumentField, ListField
from logging import StreamHandler, DEBUG
from brave.jabber.auth.model import Ticket, API_ENDPOINT, API_IDENTITY, API_PRIVATE, API_PUBLIC

from ecdsa import SigningKey, VerifyingKey, NIST256p
from binascii import unhexlify
from hashlib import sha256

from brave.api.client import Permission

import time
import os

from socket import *

ACCESS_APPROVED = "1"
ACCESS_DENIED = "0"

log = __import__('logging').getLogger(__name__)

api = API(API_ENDPOINT, API_IDENTITY, API_PRIVATE, API_PUBLIC)

def muc_access(username, room):
    server = room.split("@")[1]
    room = room.split("@")[0]
    if '/' in server:
        server = server.split('/')[0]
    
    if server != "conference.localhost" and server != 'braveineve.com':
        respond("error: Invalid host: {0}".format(server), conn)
        return
    
    name = username.split("@")[0].lower()
    
    user = ""
    
    # Look up the user.
    try:
        user = Ticket.objects.only('tags', 'updated', 'password', 'corporation__id', 'alliance__id', 'alliance__ticker', 'character__id', 'token').get(character__name=name)
    except Ticket.DoesNotExist:
        log.warn('User "%s" not found in the Ticket database.', name)
        return ACCESS_DENIED
    
    if not user.updated or (user.updated + timedelta(minutes=5)) < datetime.now():
		print "UPDATING DUE TO TIME!"
		if not Ticket.authenticate(user.token):
			return AUTH_FAIL
		
		user = Ticket.objects.only('tags', 'updated', 'password', 'corporation__id', 'alliance__id', 'alliance__ticker', 'character__id', 'token').get(character__name=name)
    
    tags = [i.replace('jabber.', '') for i in user.tags]
    
    # Check if a user has been outcasted from the room, used to ban specific users from a room
    # they normally could access. (Why did I agree to not allowing negative permissions again?)
    if Permission.set_grants_permission(tags, 'muc.affiliate.outcast.{0}'.format(room)):
		return ACCESS_DENIED
    
    if Permission.set_grants_permission(tags, 'muc.enter.{0}'.format(room)):
        return ACCESS_APPROVED
    return ACCESS_DENIED
    
def muc_roles(username, room):
    name = username
    
    # Look up the user.
    try:
        user = Ticket.objects.only('tags', 'updated', 'password', 'corporation__id', 'alliance__id', 'alliance__ticker', 'character__id', 'token').get(character__name=name)
    except Ticket.DoesNotExist:
        log.warn('User "%s" not found in the Ticket database.', name)
        respond(ACCESS_DENIED, conn)
        return
    
    if not user.updated or (user.updated + timedelta(minutes=5)) < datetime.now():
		print "UPDATING DUE TO TIME!"
		if not Ticket.authenticate(user.token):
			return AUTH_FAIL
		
		user = Ticket.objects.only('tags', 'updated', 'password', 'corporation__id', 'alliance__id', 'alliance__ticker', 'character__id', 'token').get(character__name=name)
    
    tags = [i.replace('jabber.', '') for i in user.tags]
    
    # Affiliations
    affs = dict()
    affs['owner'] = u'muc.affiliate.owner.{0}'.format(room)
    affs['admin'] = u'muc.affiliate.admin.{0}'.format(room)
    affs['member'] = u'muc.affiliate.member.{0}'.format(room)
    affs['outcast'] = u'muc.affiliate.outcast.{0}'.format(room)
    
    
    # Roles
    roles = dict()
    roles['moderator'] = u'muc.role.moderator.{0}'.format(room)
    roles['participant'] = u'muc.role.participant.{0}'.format(room)
    roles['visitor'] = u'muc.role.visitor.{0}'.format(room)
    
    role = None
    affiliation = None
    
    for a, perm in affs.iteritems():
        if Permission.set_grants_permission(tags, perm):
            affiliation = a
            break
    
    for r, perm in roles.iteritems():
        if Permission.set_grants_permission(tags, perm):
            role = r
            break
    if not role and affiliation == 'owner' or affiliation == 'admin':
		role = 'moderator'
    
    # Default affiliation is member (user will have already been checked for access
    return "{0}:{1}".format(affiliation if affiliation else "member", role if role else "participant")

def muc_nick(username, room):
    """ TODO: Allow this to vary based on room."""
    
    name = username
    
    # Look up the user.
    try:
        user = Ticket.objects.only('tags', 'updated', 'password', 'corporation__id', 'alliance__id', 'alliance__ticker', 'character__id', 'token', 'display_name').get(character__name=name)
    except Ticket.DoesNotExist:
        log.warn('User "%s" not found in the Ticket database.', name)
        respond(ACCESS_DENIED, conn)
        return
        
    if not user.updated or (user.updated + timedelta(minutes=5)) < datetime.now():
		print "UPDATING DUE TO TIME!"
		if not Ticket.authenticate(user.token):
			return AUTH_FAIL
		
		user = Ticket.objects.only('tags', 'updated', 'password', 'corporation__id', 'alliance__id', 'alliance__ticker', 'character__id', 'token', 'display_name').get(character__name=name)
    
    tags = [i.replace('jabber.', '') for i in user.tags]
    
    if user.alliance.ticker:
        alliance = user.alliance.ticker
    else:
        alliance = "----"
        
    char = user.display_name
    
    # Check if the user has a permission granting them access to a rank in this room.
    ranks = Permission.set_has_any_permission(tags, 'muc.rank.*.{0}'.format(room))
    
    display = set()
    for r in ranks:
		display.add(r.replace("muc.rank.", "").replace(".{0}".format(room), ""))
    
    if ranks:
        return "{0} [{1}] ({2})".format(char, alliance, ", ".join(display))
    
    return "{0} [{1}]".format(char, alliance)
    
def auth(username, host, password):
    log.info('Authenticate "%s"', username)
    
    name = username.split("@")[0]

    # Look up the user.
    try:
        user = Ticket.objects.only('tags', 'updated', 'password', 'corporation__id', 'alliance__id', 'alliance__ticker', 'character__id', 'token').get(character__name=name)
    except Ticket.DoesNotExist:
        log.warn('User "%s" not found in the Ticket database.', name)
        return ACCESS_DENIED
        
    password = password.encode('utf-8')
       
    if not isinstance(password, basestring):
        log.warn('pass-notString-fail "%s"', name)
        return ACCESS_DENIED
    elif password == '':
        log.warn('pass-empty-fail "%s"', name)
        return ACCESS_DENIED
    elif user.password == '':
       log.warn('pass-not-set-fail "%s"', name)
       return ACCESS_DENIED
    elif not Ticket.password.check(user.password, password):
       log.warn('pass-fail "%s"', name)
       return ACCESS_DENIED
         
   # try:
        # If the token is not valid, deny access
    if not Ticket.authenticate(user.token):
        return ACCESS_DENIED
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
    
    if not Permission.set_grants_permission(tags, 'connect'):
        return ACCESS_DENIED
    
    return ACCESS_APPROVED
    
def isuser(username):
    # Look up the user.
    print("isuser")
    try:
        user = Ticket.objects.only('tags', 'updated', 'password', 'corporation__id', 'alliance__id', 'alliance__ticker', 'character__id', 'token').get(character__name=name)
        return AUTH_SUCCESS
    except Ticket.DoesNotExist:
        log.warn('User "%s" not found in the Ticket database.', name)
        return AUTH_FAIL

def respond(ret, conn):
    print ret
    conn.send(ret+"\n")
    
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

connect('jabber')

hand = StreamHandler()
hand.setLevel(DEBUG)
log.addHandler(hand)

index = 0

sock = socket()
sock.bind(('127.0.0.1', 12345))
sock.listen(5)

print "Listening"

while 1:
	try:
		conn, addr = sock.accept()
		print "Received connection from {0}".format(addr)
		line = conn.recv(2048)
		print "Received: {0}".format(line)
		#conn.send("Hello o/\n")
		method, sep, data = line.partition(":")
		split_data = data.split(":")
		if method == "muc_access" and len(split_data) == 2:
			respond(muc_access(str(split_data[0]), str(split_data[1])), conn)
			continue
		elif method == "auth" and len(split_data) == 3:
			respond(auth(split_data[0], split_data[1], split_data[2]), conn)
			continue
		elif method == "isuser" and len(split_data) == 1:
			respond(isuser(split_data[0]), conn)
			continue
		elif method == "muc_roles" and len(split_data) == 2:
			respond(muc_roles(split_data[0], split_data[1]), conn)
			continue
		elif method == "muc_nick" and len(split_data) == 2:
			respond(muc_nick(split_data[0], split_data[1]), conn)
			continue
		respond("ERROR: FAILED TO COMPREHEND RESPONSE!", conn)
	except Exception as e:
		print "An exception has occurred: {0}".format(e)
		respond("ERROR: AN INTERNAL ERROR HAS OCCURRED", conn)
		raise e
