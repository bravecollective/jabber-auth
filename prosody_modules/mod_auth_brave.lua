--
-- Prosody IM
-- Copyright (C) 2010 Waqas Hussain
-- Copyright (C) 2010 Jeff Mitchell
-- Copyright (C) 2013 Mikael Nordfeldth
-- Copyright (C) 2013 Matthew Wild, finally came to fix it all
-- Copyright (C) 2014 Tyler O'Meara
--
-- This project is MIT/X11 licensed. Please see the
-- COPYING file in the source package for more information.
--

local usermanager = require "core.usermanager";
local new_sasl = require "util.sasl".new;
local server = require "net.server";
local have_async, async = pcall(require, "util.async");

local st = require "util.stanza";

local host = module.host;

assert(not host:find(":"), "Invalid hostname");

local bravelib = module:require "brave";
local query = bravelib.query;
local str_query = bravelib.str_query;

local new_sasl = require "util.sasl".new;

local auth = {};

function auth.test_password(username, password)
    return query("auth:"..host..":"..username..":"..password)
end

function auth.set_password(username, password)
    return nil, "Account creation/modification not available.";
end

function auth.user_exists(username)
    return query("isuser:"..host..":"..username)
end

function auth.create_user(username, password)
    return nil, "Account creation/modification not available.";
end

function auth.get_sasl_handler()
    local testpass_authentication_profile = {
        plain_test = function(sasl, username, password)
            log("warn", tostring(auth.test_password(username, password)))
            return auth.test_password(username, password), true;
        end,
    };
    return new_sasl(module.host, testpass_authentication_profile);
end

module:provides("auth", auth)

