SCRIPT_NAME	= "whitelist"
SCRIPT_AUTHOR	= "phyber"
SCRIPT_VERSION	= "1.0"
SCRIPT_LICENSE	= "GPL3"
SCRIPT_DESC	= "Block private messages from people not on your whitelist."
SCRIPT_COMMAND	= SCRIPT_NAME

try:
	import weechat
except:
	import sys
	print("This script must be run under WeeChat")
	sys.exit(1)

def parse_message(server, signal_data):
	details = {}
	if int(version) >= 0x00030400:
		details = weechat.info_get_hashtable("irc_message_parse", {
			"message":	signal_data,
			"server":	server
		})
	else:
		(source, command, channel, message) = signal_data.split(" ", 3)
		details['arguments'] = "{} {}".format(channel, message)
		details['channel'] = channel
		details['command'] = command
		details['host'] = source.lstrip(":")
		details['nick'] = weechat.info_get("irc_nick_from_host", signal_data)
	
	details['message'] = details['arguments'].split(" :", 1)[1]

	return details

def whitelist_config_get_value(section_name, option_name):
	section = weechat.config_search_section(config_file, section_name)
	value = weechat.config_search_option(config_file, section, option_name)

	return value

def whitelist_config_init():
	config_file = weechat.config_new("whitelist", "whitelist_config_reload_cb", "")
	if not config_file:
		return
	config_section = {}

	for s in ('channels', 'hosts', 'networks', 'nicks'):
		config_section[s] = weechat.config_new_section(config_file, s, 0, 0, "", "", "", "", "", "", "", "", "", "")
		if not config_section[s]:
			weechat.config_free(config_file)
			return

	return config_file

def whitelist_config_read(config_file):
	return weechat.config_read(config_file)

def whitelist_config_write(config_file):
	return weechat.config_write(config_file)

def whitelist_config_reload_cb(userdata, config_file):
	return weechat.WEECHAT_CONFIG_READ_OK

def whitelist_check(server, nick, host):
	return False


def whitelist_privmsg_modifier_cb(userdata, modifier, server, raw_irc_msg):
	details = parse_message(server, raw_irc_msg)

	# Only operate on private messages.
	if details['channel'].startswith('#'):
		weechat.prnt("", "Returning raw channel message.")
		return raw_irc_msg
	else:
		weechat.prnt("", "Processing private message")
		block = whitelist_check(server, details['nick'], details['host'])
		if block:
			return ""
		return raw_irc_msg

def whitelist_list():
	pass

def whitelist_add(type, arg):
	pass

def whitelist_del(type, arg):
	pass

def whitelist_cmd(userdata, buffer, args):
	weechat.prnt("", "UD: '{}' / BUF: '{}' / ARGS: '{}'".format(userdata, weechat.buffer_get_string(buffer, "name"), args))
	return weechat.WEECHAT_RC_OK

if __name__ == '__main__':
	if weechat.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION, SCRIPT_LICENSE, SCRIPT_DESC, "", ""):
		config_file = whitelist_config_init()
		version = weechat.info_get("version_number", "") or 0
		weechat.hook_modifier("irc_in_privmsg", "whitelist_privmsg_modifier_cb", "")
		weechat.hook_command(SCRIPT_COMMAND, "Manage the whitelist", "ARGS", "ARGS DESC", "", "whitelist_cmd", "")
