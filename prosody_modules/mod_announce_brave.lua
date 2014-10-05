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

local host = module.host;

assert(not host:find(":"), "Invalid hostname");

local bravelib = module:require "brave";
local query = bravelib.query;
local str_query = bravelib.str_query;

local st, jid = require "util.stanza", require "util.jid";

local hosts = prosody.hosts;
local is_admin = require "core.usermanager".is_admin;

function send_to_online(message, host, group)
	local sessions;
	if host then
		sessions = { [host] = hosts[host] };
	else
		sessions = hosts;
	end
        
        sessions = hosts;
       
	local c = 0;
	message.attr.from = group.."."..host;
	if group == 'DEFCON' or group == 'defcon' then
	    message.attr.type = "headline";
	end
	local resp = str_query('receive_ping:'..group)
	resp = resp:gsub("'", "")	
        	
	for hostname, host_session in pairs(sessions) do
	    if host_session.sessions then
		for user in resp:gmatch("[a-zA-Z0-9_]+@"..hostname) do
	            c = c + 1;
		    message.attr.to = user;
		    module:send(message);
	        end
	    end
	end

	return c;
end


-- Old <message>-based jabberd-style announcement sending
function handle_announcement(event)
	local origin, stanza = event.origin, event.stanza;
	local node, host, resource = jid.split(stanza.attr.to);
	local frnode, frhost, frresource = jid.split(stanza.attr.from);
	
	if not (resource:len() >= 10) then
	    module:log("info", "Message to host less than 10 chars.")
	    return;
	end
	
	if resource:sub(0,9) ~= "announce/" then
	    module:log("warn", "Message to host did not have resource of announce/*")
		return; -- Not an announcement
	end
	
	local group = resource:sub(10)
	
	if not query('send_ping:'..frhost..":"..frnode..':'..group) then
	    module:log("warn", "Non-admin '%s' tried to send server announcement", stanza.attr.from);
	    return; -- User does  not have permission
	end
	
	module:log("info", "Sending server announcement to all online members of \""..group.."\"");
	local message = st.clone(stanza);
	message.attr.type = "chat";
	
	local c = send_to_online(message, host, group);
	module:log("info", "Announcement sent to %d online users", c);
	return true;
end
module:hook("message/host", handle_announcement);

function announce_handler(self, data, state)
	if state then
		if data.action == "cancel" then
			return { status = "canceled" };
		end

		module:log("info", "Sending server announcement to all online users");
		local message = st.message({type = "headline"}, fields.announcement):up()
			:tag("subject"):text(fields.subject or "Announcement");
		
		local count = send_to_online(message, data.to);
		
		module:log("info", "Announcement sent to %d online users", count);
		return { status = "completed", info = ("Announcement sent to %d online users"):format(count) };
	else
		return { status = "executing", actions = {"next", "complete", default = "complete"}, form = announce_layout }, "executing";
	end

	return true;
end

local adhoc_new = module:require "adhoc".new;
local announce_desc = adhoc_new("Send Announcement to Online Users", "http://jabber.org/protocol/admin#announce", announce_handler, "admin");
module:provides("adhoc", announce_desc);

