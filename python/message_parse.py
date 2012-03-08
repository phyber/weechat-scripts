try:
	import weechat
except:
	import sys
	print("You must run this inside weechat")
	sys.exit(1)

def privmsg_cb(data, signal, signal_data):
	(server, signal) = signal.split(",")

	details = weechat.info_get_hashtable("irc_message_parse", {
		"message": signal_data,
		"server": server
	})
	message = details['arguments'].split(" :", 1)[1]

	weechat.prnt("", "DATA: '{}'".format(data))
	weechat.prnt("", "<{}/{}> -> {}".format(details['nick'], details['channel'], message))
	return weechat.WEECHAT_RC_OK

if __name__ == '__main__':
	weechat.register("MessageParse", "phyber", "0.1", "GPL3", "Shows details about incoming private message.", "", "")
	weechat.hook_signal("*,irc_in_privmsg", "privmsg_cb", "")
