try:
	import weechat
except:
	import sys
	print("You must run this inside weechat")
	sys.exit(1)

def parse_message(server, signal_data):
	"""
	Parses an IRC PRIVMSG into a hash.
	Provides support for WeeChat < 3.4
	Returns: {
		"arguments": arguments, (includes channel)
		"channel": channel,
		"command": command,
		"host": host,
		"message": message,
		"nick": nick,
	}
	"""
	version = weechat.info_get("version_number", "") or 0
	details = {}
	if int(version) >= 0x00030400:
		# WeeChat >= 3.4, use the built-in irc_message_parse
		details = weechat.info_get_hashtable("irc_message_parse", {
			"message":	signal_data,
			"server":	server
		})
	else:
		# This should build an identical hash for WeeChat < 3.4
		(source, command, channel, message) = signal_data.split(" ", 3)
		details['arguments'] = "{} {}".format(channel, message)
		details['channel'] = channel
		details['command'] = command
		details['host'] = source.lstrip(":")
		details['nick'] = weechat.info_get("irc_nick_from_host", signal_data)

	# WeeChat leaves this step up to us for some reason, ugh.
	# Split out the actual PRIVMSG. You know, the part we actually care about.
	details['message'] = details['arguments'].split(" :", 1)[1]

	return details

def privmsg_cb(userdata, signal, signal_data):
	(server, signal) = signal.split(",")

	details = parse_message(server, signal_data)

	weechat.prnt("", "<{}/{}> -> {}".format(details['nick'], details['channel'], details['message']))

	return weechat.WEECHAT_RC_OK

if __name__ == '__main__':
	if weechat.register("MessageParse", "phyber", "0.1", "GPL3", "Shows details about incoming private message.", "", ""):
		weechat.hook_signal("*,irc_in_privmsg", "privmsg_cb", "")
