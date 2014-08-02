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
    
    # TODO: CONFIG THIS
    if server != "conference.bravecollective.com" and server != 'bravecollective.com':
        return ACCESS_DENIED
    
    name = username.split("@")[0].lower()
    
    user = ""
    
    # Look up the user.
    try:
        user = Ticket.objects.only('tags', 'updated', 'password', 'corporation__id', 'alliance__id', 'alliance__ticker', 'character__id', 'token').get(username=name)
    except Ticket.DoesNotExist:
        log.warn('User "%s" not found in the Ticket database.', name)
        return ACCESS_DENIED
    
    if not user.updated or (user.updated + timedelta(minutes=5)) < datetime.now():
        if not Ticket.authenticate(user.token):
            return ACCESS_DENIED
        
        user = Ticket.objects.only('tags', 'updated', 'password', 'corporation__id', 'alliance__id', 'alliance__ticker', 'character__id', 'token').get(username=name)
    
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
        user = Ticket.objects.only('tags', 'updated', 'password', 'corporation__id', 'alliance__id', 'alliance__ticker', 'character__id', 'token').get(username=name)
    except Ticket.DoesNotExist:
        log.warn('User "%s" not found in the Ticket database.', name)
        respond(ACCESS_DENIED, conn)
        return
    
    if not user.updated or (user.updated + timedelta(minutes=5)) < datetime.now():
        if not Ticket.authenticate(user.token):
            return ACCESS_DENIED
        
        user = Ticket.objects.only('tags', 'updated', 'password', 'corporation__id', 'alliance__id', 'alliance__ticker', 'character__id', 'token').get(username=name)
    
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
    
    name = username
    
    # Look up the user.
    try:
        user = Ticket.objects.only('tags', 'updated', 'password', 'corporation__id', 'alliance__id', 'alliance__ticker', 'character__id', 'token', 'character__name').get(username=name)
    except Ticket.DoesNotExist:
        log.warn('User "%s" not found in the Ticket database.', name)
        respond(ACCESS_DENIED, conn)
        return
        
    if not user.updated or (user.updated + timedelta(minutes=5)) < datetime.now():
        print "UPDATING DUE TO TIME!"
        if not Ticket.authenticate(user.token):
            return ACCESS_DENIED
        
        user = Ticket.objects.only('tags', 'updated', 'password', 'corporation__id', 'alliance__id', 'alliance__ticker', 'character__id', 'token', 'character__name').get(username=name)
    
    tags = [i.replace('jabber.', '') for i in user.tags]
    
    if user.alliance.ticker:
        alliance = user.alliance.ticker
    else:
        alliance = "----"
        
    char = user.character.name
    
    # Check if the user has a permission granting them access to a rank in this room.
    ranks = Permission.set_has_any_permission(tags, 'muc.rank.*.{0}'.format(room))
    
    display = set()
    for r in ranks:
        display.add(r.replace("muc.rank.", "").replace(".{0}".format(room), ""))
    
    if ranks:
        return "{0} [{1}] ({2})".format(char, alliance, ", ".join(display))
    
    return "{0} [{1}]".format(char, alliance)
    
def auth(host, username, password):
    log.info('Authenticate "%s"', username)
    
    name = username.split("@")[0]

    # Look up the user.
    try:
        user = Ticket.objects.only('tags', 'updated', 'password', 'corporation__id', 'alliance__id', 'alliance__ticker', 'character__id', 'token', 'jid_host').get(username=name)
    except Ticket.DoesNotExist:
        log.warn('User "%s" not found in the Ticket database.', name)
        return ACCESS_DENIED
        
    password = password.encode('utf-8')
    
    if user.jid_host != host:
        log.warn("User attempted to join on incorrect host {0}; actual host is {1}".format(host, user.jid_host))
        return ACCESS_DENIED
    
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
         
    # If the token is not valid, deny access
    if not Ticket.authenticate(user.token):
        return ACCESS_DENIED
        
    tags = [i.replace('jabber.', '') for i in user.tags]
        
    tags.append('corporation-{0}'.format(user.corporation.id))
    if user.alliance and user.alliance.id:
        tags.append('alliance-{0}'.format(user.alliance.id))
        
    log.debug('success "%s" %s', name, ' '.join(tags))
    
    ticker = user.alliance.ticker if user.alliance.ticker else '----'
    
    if not Permission.set_grants_permission(tags, 'connect'):
        return ACCESS_DENIED
    
    return ACCESS_APPROVED
    
def send_ping(username, group):
    
    name = username
    
    # Look up the user.
    try:
        user = Ticket.objects.only('tags', 'updated', 'password', 'corporation__id', 'alliance__id', 'alliance__ticker', 'character__id', 'token').get(username=name)
    except Ticket.DoesNotExist:
        log.warn('User "%s" not found in the Ticket database.', name)
        return ACCESS_DENIED
        
    tags = [i.replace('jabber.', '') for i in user.tags]
    
    if not Permission.set_grants_permission(tags, 'ping.send.{0}'.format(group)):
        return ACCESS_DENIED
        
    return ACCESS_APPROVED
    
def receive_ping(group):
    
    # users = Ticket.objects.only('username').get(tags__in='ping.receive.{0}'.format(group))
    
    users = Ticket.objects.only('username', 'tags')
    
    perm = 'ping.receive.{0}'.format(group)
    
    members = []
    
    for u in users:
        if Permission.set_grants_permission(u.tags, perm):
            members.append(str(u.username))
    
    return str(members)
    
def isuser(username):
    # Look up the user.
    print("isuser")
    name = username
    try:
        user = Ticket.objects.only('tags', 'updated', 'password', 'corporation__id', 'alliance__id', 'alliance__ticker', 'character__id', 'token').get(username=name)
        return ACCESS_APPROVED
    except Ticket.DoesNotExist:
        log.warn('User "%s" not found in the Ticket database.', name)
        return ACCESS_DENIED

def respond(ret, conn):
    print ret
    conn.send(ret+"\n")

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
        if not method == 'receive_ping' and not split_data[0] in ['bravecollective.com', 'allies.bravecollective.com', 'conference.bravecollective.com']:
            respond("ERROR: Non-Authorized host", conn)
            continue
        if not method == 'receive_ping' and not Ticket.objects.only('username').get(username=split_data[1]).get(jid_host=split_data[0]):
            respond("ERROR: User does not exist on this host.", conn)
            continue
        if method == "muc_access" and len(split_data) == 3:
            respond(muc_access(split_data[1], split_data[2]), conn)
            continue
        elif method == "auth" and len(split_data) == 3:
            respond(auth(split_data[0], split_data[1], split_data[2]), conn)
            continue
        elif method == "isuser" and len(split_data) == 2:
            respond(isuser(split_data[0], split_data[1]), conn)
            continue
        elif method == "muc_roles" and len(split_data) == 3:
            respond(muc_roles(split_data[1], split_data[2]), conn)
            continue
        elif method == "muc_nick" and len(split_data) == 3:
            respond(muc_nick(split_data[1], split_data[2]), conn)
            continue
        elif method == "send_ping" and len(split_data) == 3:
            respond(send_ping(split_data[1], split_data[2]), conn)
            continue
        elif method == "receive_ping" and len(split_data) == 1:
            respond(receive_ping(split_data[0]), conn)
            continue
        respond("ERROR: FAILED TO COMPREHEND RESPONSE!", conn)
    except AssertionError as e:
        print "An exception has occurred: {0}".format(e)
        respond("ERROR: AN INTERNAL ERROR HAS OCCURRED", conn)
        raise e
