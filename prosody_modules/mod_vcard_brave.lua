-- Prosody IM
-- Copyright (C) 2008-2010 Matthew Wild
-- Copyright (C) 2008-2010 Waqas Hussain
-- Copyright (C) 2014 Tyler O'Meara
--
-- This project is MIT/X11 licensed. Please see the
-- COPYING file in the source package for more information.
--

local jid_split = require "util.jid".split;
local st = require "util.stanza";

local bravelib = module:require "brave";
local query = bravelib.query;
local str_query = bravelib.str_query;

local vcards = module:open_store();

local host = module.host;

module:add_feature("vcard-temp");

local function handle_vcard(event)
	local session, stanza = event.origin, event.stanza;
	local to = stanza.attr.to;
	if stanza.attr.type == "get" then
		local vCard;
		if to then
			local node, host = jid_split(to);
			vCard = str_query("vCard:"..host..":"..node); -- load vCard for user or server
		else
			vCard = str_query("vCard:"..host..":"..session.username);-- load user's own vCard
		end
                vc = st.stanza("vCard")
                index = 0
                for tag in vCard:gmatch("[^:]+") do
                    if index == 0 then
                        fn = vc:tag('FN'):text(tag):up()
                    end
                    if index == 1 then
                        org = vc:tag('ORG')
                        org:tag('ORGNAME'):text(tag):up()
                    end
                    if index == 2 then
                        org:tag('ORGUNIT'):text(tag):up()
                    end
                    index = index + 1
                end
		if vc then
			session.send(st.reply(stanza):add_child(vc)); -- send vCard!
		else
			session.send(st.error_reply(stanza, "cancel", "item-not-found"));
		end
	else
		if not to then
			if vcards:set(session.username, st.preserialize(stanza.tags[1])) then
				session.send(st.reply(stanza));
			else
				-- TODO unable to write file, file may be locked, etc, what's the correct error?
				session.send(st.error_reply(stanza, "wait", "internal-server-error"));
			end
		else
			session.send(st.error_reply(stanza, "auth", "forbidden"));
		end
	end
	return true;
end

module:hook("iq/bare/vcard-temp:vCard", handle_vcard);
module:hook("iq/host/vcard-temp:vCard", handle_vcard);

-- COMPAT w/0.8
if module:get_option("vcard_compatibility") ~= nil then
	module:log("error", "The vcard_compatibility option has been removed, see"..
		"mod_compat_vcard in prosody-modules if you still need this.");
end

