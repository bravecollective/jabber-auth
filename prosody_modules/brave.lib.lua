-- Prosody IM
-- Copyright (C) 2008-2010 Matthew Wild
-- Copyright (C) 2008-2010 Waqas Hussain
-- Copyright (C) 2014 Tyler O'Meara
--
-- This project is MIT/X11 licensed. Please see the
-- COPYING file in the source package for more information.

-- BEGIN MUC VARIABLES --

local jid_split = require "util.jid".split;
local jid_bare = require "util.jid".bare;
local st = require "util.stanza";
local uuid_gen = require "util.uuid".generate;
local um_is_admin = require "core.usermanager".is_admin;
local hosts = prosody.hosts;

-- END MUC VARIABLES --

local _M = {};

local index = 0
local host = module.host;
_M.socket = require("socket")

_M.serverName = module:get_option_string("brave_server");
_M.serverPort = module:get_option_string("brave_port");

assert(not host:find(":"), "Invalid hostname");

function _M.query(text)
    client = socket.tcp()
    client:connect(_M.serverName, _M.serverPort);
    client:send(text)
    local resp, status, partial = client:receive()
    if resp ~= "1" then
        return false;
    end
    return true;
end

function _M.str_query(text)
    client = socket.tcp()
    client:connect(_M.serverName, _M.serverPort);
    client:send(text)
    local resp, status, partial = client:receive()
    return resp;
end

return _M;

