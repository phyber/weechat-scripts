local io = require "io"
local tonumber = tonumber
local weechat = weechat

local SCRIPT_NAME	= "loadavg"
local SCRIPT_AUTHOR	= "phyber"
local SCRIPT_VERSION	= "1.0"
local SCRIPT_LICENSE	= "GPL3"
local SCRIPT_DESC	= "Display loadavg on a bar."

local SCRIPT_CONF = {
	proc_loadavg	= {
		"/proc/loadavg",
		"Path to /proc/loadavg",
	},
	refresh_rate	= {
		"5",
		"Refresh rate.",
	},
}

local function print(msg)
	weechat.print(weechat.current_buffer(), msg)
end

function loadavg_config_cb(data, option, value)
	weechat.unhook('loadavg_timer_cb')
	weechat.hook_timer(tonumber(weechat.config_get_plugin('refresh_rate')) * 1000, 0, 0, 'loadavg_timer_cb', nil)
	return weechat.WEECHAT_RC_OK
end

function loadavg_timer_cb()
	weechat.bar_item_update('loadavg')
	return weechat.WEECHAT_RC_OK
end

function loadavg_item_cb()
	local f = io.open(weechat.config_get_plugin('proc_loadavg'))
	if f then
		local loadavg = f:read()
		f:close()
		loadavg = loadavg:gsub("^([%w.]+) ([%w.]+) ([%w.]+).*", "%1 %2 %3")
		return loadavg
	else
		return ""
	end
end

weechat.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION, SCRIPT_LICENSE, SCRIPT_DESC, nil, nil)

for k, v in pairs(SCRIPT_CONF) do
	if weechat.config_is_set_plugin(k) == 0 then
		weechat.config_set_plugin(k, v[1])
	end
	if tonumber(weechat.info_get('version_number', '')) >= 0x00030500 then
		weechat.config_set_desc_plugin(k, v[2])
	end
end

weechat.bar_item_new('loadavg', 'loadavg_item_cb', nil)
weechat.hook_timer(tonumber(weechat.config_get_plugin('refresh_rate')) * 1000, 0, 0, 'loadavg_timer_cb', nil)
weechat.hook_config("plugins.var.lua." .. SCRIPT_NAME .. ".*", "loadavg_config_cb", nil)
