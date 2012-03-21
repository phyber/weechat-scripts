SCRIPT_NAME	= "whitelist"
SCRIPT_AUTHOR	= "phyber"
SCRIPT_VERSION	= "1.0"
SCRIPT_LICENSE	= "GPL3"
SCRIPT_DESC	= "Block private messages from people not on your whitelist."
SCRIPT_COMMAND	= SCRIPT_NAME

SCRIPT_CONFIG = {
	"general": {
		'notification': {
			"type":			"boolean",
			"desc":			"Receive a notification when a message is blocked",
			"min":			0,
			"max":			0,
			"string_values":	"",
			"default":		"on",
			"value":		"on",
			"check_cb":		"",
			"change_cb":		"",
			"delete_cb":		"",
		},
		'logging': {
			"type":			"boolean",
			"desc":			"Log blocked private messages",
			"min":			0,
			"max":			0,
			"string_values":	"",
			"default":		"on",
			"value":		"on",
			"check_cb":		"",
			"change_cb":		"",
			"delete_cb":		"",
		},
		'network_channel_only': {
			"type":			"boolean",
			"desc":			"Only allow messages from a person if they're in a channel with you on the whitelisted network",
			"min":			0,
			"max":			0,
			"string_values":	"",
			"default":		"on",
			"value":		"on",
			"check_cb":		"",
			"change_cb":		"",
			"delete_cb":		"",
		},
	},
	"whitelists": {
		'channels': {
			"type":			"string",
			"desc":			"Whitelisted channels",
			"min":			0,
			"max":			0,
			"string_values":	"",
			"default":		"",
			"value":		"",
			"check_cb":		"",
			"change_cb":		"",
			"delete_cb":		"",
		},
		'hosts': {
			"type":			"string",
			"desc":			"Whitelisted hosts",
			"min":			0,
			"max":			0,
			"string_values":	"",
			"default":		"",
			"value":		"",
			"check_cb":		"",
			"change_cb":		"",
			"delete_cb":		"",
		},
		'networks': {
			"type":			"string",
			"desc":			"Whitelisted networks",
			"min":			0,
			"max":			0,
			"string_values":	"",
			"default":		"",
			"value":		"",
			"check_cb":		"",
			"change_cb":		"",
			"delete_cb":		"",
		},
		'nicks': {
			"type":			"string",
			"desc":			"Whitelisted nicks",
			"min":			0,
			"max":			0,
			"string_values":	"",
			"default":		"",
			"value":		"",
			"check_cb":		"",
			"change_cb":		"",
			"delete_cb":		"",
		},
	},
}

try:
	import weechat
except:
	import sys
	print("This script must be run under WeeChat")
	sys.exit(1)
import re
import time

# Host to RegEx mappings
HTR = {}
for i in range(256):
	ch = chr(i)
	HTR[ch] = "{}".format(ch)
HTR['?'] = '.'
HTR['*'] = '.*'


def htr_replace(match):
	return HTR[match.group(0)]

def host_to_lower(host):
	(ident, hostname) = host.split("@", 1)
	return "{}@{}".format(ident, hostname.lower())

def host_to_regex(host):
	host = host_to_lower(host)
	return re.sub('(.)', htr_replace, host)

def parse_message(server, signal_data):
	details = {}
	if int(weechat_version) >= 0x00030400:
		# Newer (>=0.3.4) versions of WeeChat can prepare a hash with most of
		# what we want.
		details = weechat.info_get_hashtable("irc_message_parse", {
			"message":	signal_data,
			"server":	server
		})
	else:
		# WeeChat <0.3.4 we have to construct it ourselves.
		(source, command, channel, message) = signal_data.split(" ", 3)
		details['arguments'] = "{} {}".format(channel, message)
		details['channel'] = channel
		details['command'] = command
		details['host'] = source.lstrip(":")
		details['nick'] = weechat.info_get("irc_nick_from_host", signal_data)

	# WeeChat leaves this important part to us. Get the actual message.
	details['message'] = details['arguments'].split(" :", 1)[1]

	# If the message starts and ends with \001, it's a CTCP
	if details['message'].startswith('\001') and details['message'].endswith('\001'):
		details['ctcp'] = True
	else:
		details['ctcp'] = False

	return details

def whitelist_config_init():
	config_file = weechat.config_new("whitelist", "whitelist_config_reload_cb", "")
	if not config_file:
		return None

	for section in SCRIPT_CONFIG:
		config_section = weechat.config_new_section(
			config_file,
			section,
			0, 0, "", "", "", "", "", "", "", "", "", ""
		)
		if not config_section:
			weechat.config_free(config_file)
			return None
		for option_name, props in SCRIPT_CONFIG[section].items():
			weechat.config_new_option(
				config_file,
				config_section,
				option_name,
				props['type'],
				props['desc'],
				props['string_values'],
				props['min'],
				props['max'],
				props['default'],
				props['default'],
				0,
				props['check_cb'], "",
				props['change_cb'], "",
				props['delete_cb'], ""
			)

	return config_file

def whitelist_config_read(config_file):
	return weechat.config_read(config_file)

def whitelist_config_write(config_file):
	return weechat.config_write(config_file)

def whitelist_config_reload_cb(userdata, config_file):
	return weechat.WEECHAT_CONFIG_READ_OK

def whitelist_config_change_cb(userdata, option):
	option = list(set(filter(None, option.split(" "))))
	return option

def whitelist_config_get_value(section_name, option_name):
	# This is a lot of work to just get the value of an option.
	section = weechat.config_search_section(config_file, section_name)
	option = weechat.config_search_option(config_file, section, option_name)

	# Automatically choose the correct weechat.config_* function and call it.
	value = getattr(weechat, "config_"+SCRIPT_CONFIG[section_name][option_name]['type'])(option)

	return value

def whitelist_infolist_get_value(infolist_name, server, element, type):
	infolist = weechat.infolist_get(infolist_name, "", server)
	weechat.infolist_next(infolist)
	value = getattr(weechat, "infolist_"+type)(infolist, element)
	weechat.infolist_free(infolist)

	return value

def whitelist_get_channels(server):
	infolist = weechat.infolist_get("irc_channel", "", server)
	channels = []
	while weechat.infolist_next(infolist):
		channel = weechat.infolist_string(infolist, "name")
		channels.append(channel)
	
	weechat.infolist_free(infolist)

	return channels

def whitelist_get_channel_nicks(server, channel):
	infolist = weechat.infolist_get("irc_nick", "", "{},{}".format(server, channel))
	nicks = []
	while weechat.infolist_next(infolist):
		nick = weechat.infolist_string(infolist, "name")
		nicks.append(nick)
	
	weechat.infolist_free(infolist)

	return nicks

def whitelist_completion_sections(userdata, completion_item, buffer, completion):
	for section in SCRIPT_CONFIG['whitelists']:
		weechat.hook_completion_list_add(completion, section, 0, weechat.WEECHAT_LIST_POS_SORT)
	return weechat.WEECHAT_RC_OK

def whitelist_check(server, details):
	nick = details['nick']
	host = details['host']

	current_addr = whitelist_infolist_get_value("irc_server", server, "current_address", "string")
	whitelist_networks = filter(None, whitelist_config_get_value('whitelists', 'networks').split(" "))
	#whitelist_networks.append(current_addr)

	# FIRST: Check if we have whitelisted things on this network.
	if server in whitelist_networks:
		# If we're only accepting messages from people in our channels...
		if whitelist_config_get_value('general', 'network_channel_only'):
			# Get a list of channels
			for channel in whitelist_get_channels(server):
				# And check if they're in it.
				if nick in whitelist_get_channel_nicks(server, channel):
					# Accept it if they are.
					return False
		else:
			# Otherwise just accept the message.
			return False

	# SECOND: Check the nicks.
	for whitenick_entry in filter(None, whitelist_config_get_value('whitelists', 'nicks').split(" ")):
		# 1. Simple check, is the nick itself whitelisted.
		if whitenick_entry == nick:
			return False
		# 2. Is the nick localised to the current server
		if whitenick_entry == "{}@{}".format(nick, server):
			return False
		# 3. Last try, is it localised to the current server addr?
		if whitenick_entry == "{}@{}".format(nick, current_addr):
			return False

	# THIRD: Check the hosts.
	# Split up the hosts and filter them for empty strings.
	for whitelisted_host in filter(None, whitelist_config_get_value('whitelists', 'hosts').split(" ")):
		# 1. Check if the whitelisted host matches.
		if re.match(host_to_regex(whitelisted_host), host):
			return False

	# FOURTH: Check the channels.
	# Check each whitelisted channel to see if the nick is in one of those channels
	for whitelisted_channel in filter(None, whitelist_config_get_value('whitelists', 'channels').split(" ")):
		channel_nicks = whitelist_get_channel_nicks(server, whitelisted_channel)
		# 1. Check if the nick is in the channel.
		if nick in channel_nicks:
			return False

	# Place a notification in the status window
	if whitelist_config_get_value('general', 'notification'):
		weechat.prnt("", "[{}] {} [{}] attempted to send you a private message.".format(server, nick, host))

	# Log the message
	if whitelist_config_get_value('general', 'logging'):
		with open(weechat_dir+"/whitelist.log", 'a') as f:
			f.write("{}: [{}] {} [{}]: {}\n".format(time.asctime(), server, nick, host, details['message']))

	# Block it
	return True

def whitelist_privmsg_modifier_cb(userdata, modifier, server, raw_irc_msg):
	details = parse_message(server, raw_irc_msg)

	# Only operate on private messages.
	if not details['ctcp']:
		if not details['channel'].startswith('#'):
			block = whitelist_check(server, details)
			if block:
				return ""

	# Return the unmodified raw message if we're not blocking
	# or it's not a private message.
	return raw_irc_msg

def whitelist_list():
	for section in SCRIPT_CONFIG['whitelists']:
		value = whitelist_config_get_value('whitelists', section)
		weechat.prnt("", "{}: {}".format(section, value))

def whitelist_add(type, arg):
	pass

def whitelist_del(type, arg):
	pass

def whitelist_cmd(userdata, buffer, arg):
	if arg in ('', 'list'):
		whitelist_list()
	
	#weechat.prnt("", "UD: '{}' / BUF: '{}' / ARGS: '{}'".format(userdata, weechat.buffer_get_string(buffer, "name"), arg))
	return weechat.WEECHAT_RC_OK

if __name__ == '__main__':
	if weechat.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION, SCRIPT_LICENSE, SCRIPT_DESC, "", ""):
		config_file = whitelist_config_init()
		whitelist_config_read(config_file)
		weechat_version = weechat.info_get("version_number", "") or 0
		weechat_dir = weechat.info_get("weechat_dir", "")
		weechat.hook_modifier("irc_in_privmsg", "whitelist_privmsg_modifier_cb", "")
		weechat.hook_command(SCRIPT_COMMAND, "Manage the whitelist",
			# OPTION ARGUMENTS
			"list"
			" || add <type> <arg>"
			" || del <type> <arg>",
			# ARGUMENT DESCRIPTIONS
			"      list: lists whitelists and their contents\n"
			"       add: add an entry to a given whitelist\n"
			"       del: delete an entry from a given whitelist\n"
			"\n"
			"Examples:\n"
			"  Add entries to whitelist:\n"
			"    /whitelist add network Freenode\n"
			"    /whitelist add host *!buddy@*.isp.com\n"
			"  Delete entries from whitelist:\n"
			"    /whitelist del nick Someguy\n"
			"    /whitelist del channel #weechat\n",
			# COMPLETIONS
			"list %(whitelist_args)"
			" || add %(whitelist_args)"
			" || del %(whitelist_args)",
			# COMMAND TO CALL + USERDATA
			"whitelist_cmd", ""
		)
		weechat.hook_completion("whitelist_args", "list of whitelist arguments", "whitelist_completion_sections", "")
