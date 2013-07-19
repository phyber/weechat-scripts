try:
	import weechat
except ImportError:
	import sys
	print("This script must be run under WeeChat")
	sys.exit(1)
import re
import time

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
			"change_data":		"",
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
			"change_data":		"",
			"delete_cb":		"",
		},
		'network_channel_only': {
			"type":			"boolean",
			"desc":			"Only allow messages from a person if they're "
							"in a channel with you on the whitelisted network",
			"min":			0,
			"max":			0,
			"string_values":	"",
			"default":		"on",
			"value":		"on",
			"check_cb":		"",
			"change_cb":		"",
			"change_data":		"",
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
			"change_cb":		"whitelist_config_option_change_cb",
			"change_data":		"channels",
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
			"change_cb":		"whitelist_config_option_change_cb",
			"change_data":		"hosts",
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
			"change_cb":		"whitelist_config_option_change_cb",
			"change_data":		"networks",
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
			"change_cb":		"whitelist_config_option_change_cb",
			"change_data":		"nicks",
			"delete_cb":		"",
		},
	},
}

WHITELIST_TYPE_ALIAS = {
		'chan': "channels",
		'channel': "channels",
		'host': "hosts",
		'net': "networks",
		'network': "networks",
		'nick': "nicks",
		}

FIELD_TYPE_FUNC = {
		# Not available to API
		#'b': weechat.infolist_buffer,
		'i': weechat.infolist_integer,
		'p': weechat.infolist_pointer,
		's': weechat.infolist_string,
		't': weechat.infolist_time,
		}

CTCP_MARKER = '\001'

# Host to RegEx mappings
HTR = {x:x for x in (chr(x) for x in xrange(256))}
HTR['?'] = '.'
HTR['*'] = '.*'

def host_to_lower(host):
	"""Convert the hostname portion of an address string to lowercase."""
	(ident, hostname) = host.split("@", 1)
	return "{ident}@{hostname}".format(
			ident=ident,
			hostname=hostname.lower())

def host_to_regex(host):
	"""Convert host to a regex."""
	host = host_to_lower(host)
	return re.sub('(.)', lambda match: HTR[match.group(0)], host)

class InfolistGenerator(object):
	"""Infolist context manager/generator for easy use of infolists.

	Accepts the same arguments as weechat's infolist_get function.

	>>> with InfolistGenerator("irc_channel", "", "server_name") as infolist:
	>>>     channels = [row['name']
	>>>         for row in infolist
	>>>         if row['name'].startswith('#')]
	"""

	def __init__(self, infolist_name, pointer, infolist_args):
		self.infolist_name = infolist_name
		self.pointer = pointer
		self.infolist_args = infolist_args
		self._infolist = None

	def __enter__(self):
		self._infolist = weechat.infolist_get(
				self.infolist_name,
				self.pointer,
				self.infolist_args
				)
		return self

	def __exit__(self, *exc_info):
		weechat.infolist_free(self._infolist)
		self._infolist = None

	def __iter__(self):
		return self

	def get_fields(self):
		"""Return a dict of the fields in the current infolist position."""
		fields = {}
		for field in weechat.infolist_fields(self._infolist).split(","):
			(field_type, field_name) = field.split(":")
			try:
				field_value = FIELD_TYPE_FUNC[field_type](
						self._infolist,
						field_name
						)
			except KeyError:
				continue
			fields[field_name] = field_value
		return fields

	def next(self):
		"""Return the next set of fields"""
		if weechat.infolist_next(self._infolist):
			fields = self.get_fields()
			return fields
		else:
			raise StopIteration

class Message(object):
	"""Parse raw signal_data from WeeChat into something more managable."""
	def __init__(self, server, signal_data):
		self._server = server
		self._signal_data = signal_data
		self.details = None
		self._parse_message()

	def __str__(self):
		return self.signal_data()

	def _parse_message(self):
		"""Parse the signal_data"""
		if int(WEECHAT_VERSION) >= 0x00030400:
			# Newer (>=0.3.4) versions of WeeChat can prepare a hash with most of
			# what we want.
			self.details = weechat.info_get_hashtable("irc_message_parse", {
				"message":	self.signal_data(),
				"server":	self.server()
			})
		else:
			# WeeChat <0.3.4 we have to construct it ourselves.
			(source, command, channel, message) = self._signal_data.split(" ", 3)
			self.details = {}
			self.details['arguments'] = "{channel} {message}".format(
					channel=channel,
					message=message)
			self.details['channel'] = channel
			self.details['command'] = command
			self.details['host'] = source.lstrip(":")
			self.details['nick'] = weechat.info_get(
					"irc_nick_from_host",
					self.signal_data())

		# WeeChat leaves this important part to us. Get the actual message.
		self.details['message'] = self.arguments().split(" :", 1)[1]

	def arguments(self):
		"""Return the command arguments"""
		return self.details['arguments']

	def channel(self):
		"""Return channel portion of message.

		This might be better named "target", since it could be the
		nick of a user being queried.
		"""
		return self.details['channel']

	def command(self):
		"""Returns the IRC protocol command, eg. PRIVMSG."""
		return self.details['command']

	def host(self):
		"""Return the host for the sender of the message"""
		return self.details['host']

	def hostname(self):
		"""Return the hostname for the sender of the message"""
		return self.host().split('@')[1]

	def ident(self):
		"""Return the ident"""
		return self.host().split('!')[1]

	def message(self):
		"""Return the message"""
		return self.details['message']

	def nick(self):
		"""Return the message sender nick"""
		return self.details['nick']

	def server(self):
		"""Return the server"""
		return self._server

	def signal_data(self):
		"""Return the raw signal data"""
		return self._signal_data

	def is_channel(self):
		"""Return True if the message is from an IRC channel"""
		return self.channel().startswith('#')

	def is_ctcp(self):
		"""Return True if the message is a CTCP"""
		message = self.message()
		if message.startswith(CTCP_MARKER) and message.endswith(CTCP_MARKER):
			return True
		return False

	def is_query(self):
		"""Return True if the message is from a query"""
		return not self.is_channel()

def whitelist_config_init():
	"""Initialize the whitelist configuration."""
	config_file = weechat.config_new("whitelist",
			"whitelist_config_reload_cb",
			""
			)
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
				props['check_cb'],
				"",
				props['change_cb'],
				props['change_data'],
				props['delete_cb'],
				""
			)

	return config_file

def whitelist_config_read(config_file):
	"""
	Read the whitelist config file.
	"""
	return weechat.config_read(config_file)

def whitelist_config_write(config_file):
	"""
	Write the whitelist config file.
	"""
	return weechat.config_write(config_file)

def whitelist_config_reload_cb(userdata, config_file):
	"""
	Callback after the config file has been reloaded.
	"""
	return weechat.WEECHAT_CONFIG_READ_OK

def whitelist_config_option_change_cb(userdata, option):
	"""Callback when a config option was changed."""
	weechat.prnt("", "Whitelisted {type} now: {values}".format(
		type=userdata,
		values=whitelist_config_get_value('whitelists', userdata))
		)
	return weechat.WEECHAT_RC_OK

def whitelist_config_get_value(section_name, option_name):
	"""Return a value from the whitelist configuration."""
	# This is a lot of work to just get the value of an option.
	section = weechat.config_search_section(CONFIG_FILE, section_name)
	option = weechat.config_search_option(CONFIG_FILE, section, option_name)

	# Automatically choose the correct weechat.config_* function and call it.
	config_function = "config_{type}".format(
			type=SCRIPT_CONFIG[section_name][option_name]['type']
			)
	value = getattr(weechat, config_function)(option)

	return value

def whitelist_config_set_value(section_name, option_name, value):
	"""Set a configuration option."""
	section = weechat.config_search_section(CONFIG_FILE, section_name)
	option = weechat.config_search_option(CONFIG_FILE, section, option_name)

	ret = weechat.config_option_set(option, value, 1)
	return ret

def whitelist_infolist_get_value(infolist_name, server, element):
	"""Return the first instance of element from the infolist"""
	with InfolistGenerator(infolist_name, "", server) as infolist:
		for row in infolist:
			return row.get(element)

def whitelist_get_channels(server):
	"""Get a list of channels on the given server."""
	with InfolistGenerator("irc_channel", "", server) as infolist:
		for row in infolist:
			if row['name'].startswith('#'):
				yield row['name']

def whitelist_get_channel_nicks(server, channel):
	"""Get a list of nicks in the given channel on the given server"""
	with InfolistGenerator("irc_nick", "", "{server},{channel}".format(
		server=server,
		channel=channel)) as infolist:
		for row in infolist:
			yield row['name']

def whitelist_completion_sections(userdata, completion_item, buf, completion):
	"""Add hooks for whitelist completion."""
	for section in SCRIPT_CONFIG['whitelists']:
		weechat.hook_completion_list_add(completion,
				section,
				0,
				weechat.WEECHAT_LIST_POS_SORT
				)
	return weechat.WEECHAT_RC_OK

def whitelist_check(message):
	"""Return a boolean indicating if the given details are whitelisted or not."""
	nick = message.nick()
	host = message.host()
	server = message.server()

	current_addr = whitelist_infolist_get_value(
			"irc_server", server, "current_address"
			)
	whitelist_networks = filter(None,
			whitelist_config_get_value('whitelists', 'networks').split(" ")
			)

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
	for whitelisted_nick in filter(None,
			whitelist_config_get_value('whitelists', 'nicks').split(" ")):
		# 1. Simple check, is the nick itself whitelisted.
		if whitelisted_nick == nick:
			return False
		# 2. Is the nick localised to the current server
		if whitelisted_nick == "{nick}@{server}".format(nick=nick, server=server):
			return False
		# 3. Last try, is it localised to the current server addr?
		if whitelisted_nick == "{nick}@{addr}".format(nick=nick, addr=current_addr):
			return False

	# THIRD: Check the hosts.
	# Split up the hosts and filter them for empty strings.
	for whitelisted_host in filter(None,
			whitelist_config_get_value('whitelists', 'hosts').split(" ")):
		# Check for localised host
		# @ will always exist in hosts, so try to split and just pass
		# on ValueError, which means there was no @server portion.
		try:
			(white_name, white_host, whitelisted_server) = whitelisted_host.split('@', 2)
			# Skip if this host is for another server
			if server != whitelisted_server:
				continue
			# Fixup the whitelisted_host
			whitelisted_host = "{name}@{host}".format(
					name=white_name,
					host=white_host)
		except ValueError:
			pass
		# Check if the whitelisted host matches.
		if re.match(host_to_regex(whitelisted_host), host):
			return False

	# FOURTH: Check the channels.
	# Check each whitelisted channel to see if the nick is in one of those channels
	for whitelisted_channel in filter(None,
			whitelist_config_get_value('whitelists', 'channels').split(" ")):
		# Check for localised channel
		if '@' in whitelisted_channel:
			(whitelisted_channel, whitelisted_server) = whitelisted_channel.split('@', 1)
			# Skip if channel is for another server
			if server != whitelisted_server:
				continue
		channel_nicks = whitelist_get_channel_nicks(server, whitelisted_channel)
		# 1. Check if the nick is in the channel.
		if nick in channel_nicks:
			return False

	# Place a notification in the status window
	if whitelist_config_get_value('general', 'notification'):
		weechat.prnt("",
				"[{server}] {nick} [{host}] "
				"attempted to send you a private message.".format(
			server=server,
			nick=nick,
			host=host)
			)

	# Log the message
	if whitelist_config_get_value('general', 'logging'):
		whitelist_log_file = "{weechat_dir}/whitelist.log".format(
				weechat_dir=WEECHAT_DIR)
		with open(whitelist_log_file, 'a') as logfile:
			logfile.write("{time}: [{server}] {nick} [{host}]: {message}\n".format(
				time=time.asctime(),
				server=server,
				nick=nick,
				host=host,
				message=message.message())
				)

	# Block it
	return True

def whitelist_privmsg_modifier_cb(userdata, modifier, server, raw_irc_msg):
	"""Modifies the raw_irc_msg depending on whitelisted status."""
	message = Message(server, raw_irc_msg)

	if message.is_query():
		block = whitelist_check(message)
		if block:
			return ""

	# Return the unmodified raw message if we're not blocking
	# or it's not a private message.
	return raw_irc_msg

def whitelist_list():
	"""Lists all whitelist details."""
	for section in SCRIPT_CONFIG['whitelists']:
		value = whitelist_config_get_value('whitelists', section)
		weechat.prnt("", "{section}: {value}".format(
			section=section,
			value=value)
			)

def whitelist_add(listtype, arg):
	"""Add entry to the given whitelist type."""
	# Create a list from the current setting
	values = whitelist_config_get_value('whitelists', listtype).split()
	# Add the new value to the list.
	values.append(arg)
	# Set the new option value. We use a set here to ensure uniqueness and
	# we sort it just so that output is nicer.
	whitelist_config_set_value('whitelists',
			listtype,
			" ".join(sorted(set(values)))
			)

def whitelist_del(listtype, arg):
	"""Remove entry from the given whitelist type."""
	values = whitelist_config_get_value('whitelists', listtype).split()
	try:
		values.remove(arg)
		whitelist_config_set_value('whitelists', listtype, " ".join(values))
	except ValueError:
		weechat.prnt("", "Whitelist error. '{arg}' not found in '{type}'.".format(
			arg=arg,
			type=listtype)
			)

def whitelist_cmd_split(count, args, default=None):
	"""Split the whitelist command line"""
	# Hilarious.
	args = args.split()
	while len(args) < count:
		args.append(default)
	# Just return the first three args.
	return args[:3]

def whitelist_cmd(userdata, buf, args):
	"""Parse whitelist commands and take action."""
	(cmd, listtype, arg) = whitelist_cmd_split(3, args)

	if cmd in (None, '', 'list'):
		whitelist_list()
		return weechat.WEECHAT_RC_OK

	if listtype in VALID_OPTION_TYPES:
		try:
			listtype = WHITELIST_TYPE_ALIAS[listtype]
		except KeyError:
			pass
		if arg is not None:
			if cmd == 'add':
				whitelist_add(listtype, arg)

			if cmd == 'del':
				whitelist_del(listtype, arg)
		else:
			weechat.prnt("", "Error. Must supply an argument to '{type}'.".format(
				type=listtype)
				)
	else:
		weechat.prnt("", "Error. Valid whitelist types are: {types}.".format(
			types=", ".join(VALID_OPTION_TYPES))
			)

	return weechat.WEECHAT_RC_OK

if __name__ == '__main__':
	if weechat.register(SCRIPT_NAME, SCRIPT_AUTHOR,
			SCRIPT_VERSION, SCRIPT_LICENSE, SCRIPT_DESC, "", ""):
		CONFIG_FILE = whitelist_config_init()
		if CONFIG_FILE:
			whitelist_config_read(CONFIG_FILE)
		VALID_OPTION_TYPES = ([
				k for k
				in SCRIPT_CONFIG['whitelists'].keys()] +
				[k for k
				in WHITELIST_TYPE_ALIAS.keys()])
		WEECHAT_VERSION = weechat.info_get("version_number", "") or 0
		WEECHAT_DIR = weechat.info_get("weechat_dir", "")
		weechat.hook_modifier("irc_in_privmsg",
				"whitelist_privmsg_modifier_cb",
				""
				)
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
			"    /whitelist add net[work] Freenode\n"
			"    /whitelist add host *!buddy@*.isp.com\n"
			"  Delete entries from whitelist:\n"
			"    /whitelist del nick Someguy\n"
			"    /whitelist del chan[nel] #weechat\n",
			# COMPLETIONS
			"list %(whitelist_args)"
			" || add %(whitelist_args)"
			" || del %(whitelist_args)",
			# COMMAND TO CALL + USERDATA
			"whitelist_cmd", ""
		)
		weechat.hook_completion("whitelist_args",
				"list of whitelist arguments",
				"whitelist_completion_sections",
				""
				)
