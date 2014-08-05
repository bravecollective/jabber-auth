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
from ecdsa.keys import BadSignatureError
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
        return ACCESS_APPROVED
    
    name = username
    
    user = ""
    
    # Look up the user.
    try:
        user = Ticket.objects.only('tags', 'updated', 'password', 'corporation__id', 'alliance__id', 'alliance__ticker', 'character__id', 'token').get(username=name)
    except Ticket.DoesNotExist:
        log.warn('User "%s" not found in the Ticket database.', name)
        return ACCESS_DENIED
    
    return ACCESS_APPROVED if (room in user.joinable_mucs) else ACCESS_DENIED
    
def muc_roles(username, room):
    name = username
    
    # Look up the user.
    try:
        user = Ticket.objects.only('tags', 'updated', 'password', 'corporation__id', 'alliance__id', 'alliance__ticker', 'character__id', 'token').get(username=name)
    except Ticket.DoesNotExist:
        log.warn('User "%s" not found in the Ticket database.', name)
        respond(ACCESS_DENIED, conn)
        return
    
    return user.muc_roles(room)

def muc_nick(username, room):
    
    name = username
    
    # Look up the user.
    try:
        user = Ticket.objects.get(username=name)
    except Ticket.DoesNotExist:
        log.warn('User "%s" not found in the Ticket database.', name)
        respond(ACCESS_DENIED, conn)
        return
        
    return user.muc_nickname(room)
    
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
        
    return user.can_send_ping(group)
    
def receive_ping(group):
    
    # users = Ticket.objects.only('username').get(tags__in='ping.receive.{0}'.format(group))
    
    users = Ticket.objects.only('username', 'tags', 'jid_host')
    
    members = []
    
    for u in users:
        name = u.can_receive_ping(group)
        if name:
            members.append(name)
    
    return str(members)
    
def vCard(username):
    name = username
    
    # Look up the user.
    try:
        user = Ticket.objects.get(username=name)
    except Ticket.DoesNotExist:
        log.warn('User "%s" not found in the Ticket database.', name)
        return ""
        
    return user.vCard
    
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
        if not method == 'receive_ping':
            t = Ticket.objects(username=split_data[1]).only('jid_host').first()
            if not t:
                respond("ERROR: User {0} does not exist".format(split_data[1]), conn)
                continue
            if not t.jid_host or t.jid_host.lower() != split_data[0].lower(): 
                respond("ERROR: User {0} does not exist on this host {1}, expected {2}".format(t.username, split_data[0], t.jid_host), conn)
                continue
        if method == "muc_access" and len(split_data) == 3:
            respond(muc_access(split_data[1], split_data[2]), conn)
            continue
        elif method == "auth" and len(split_data) == 3:
            respond(auth(split_data[0], split_data[1], split_data[2]), conn)
            continue
        elif method == "isuser" and len(split_data) == 2:
            respond(isuser(split_data[1]), conn)
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
        elif method == "vCard" and len(split_data) == 2:
            respond(vCard(split_data[1]), conn)
            continue
        respond("ERROR: FAILED TO COMPREHEND RESPONSE!", conn)
    except BadSignatureError as e:
        print "BadSignatureError"
        respond("ERROR: AN INTERNAL ERROR HAS OCCURRED", conn)
        raise e
