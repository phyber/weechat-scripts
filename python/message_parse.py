try:
    import weechat
except ImportError:
    import sys
    print("You must run this inside weechat")
    sys.exit(1)

SCRIPT_NAME = "message_parse"
SCRIPT_AUTHOR = "phyber"
SCRIPT_VERSION = "0.1"
SCRIPT_LICENSE = "GPL3"
SCRIPT_DESC = "Shows details about incoming private message."


def parse_message(server, signal_data):
    """
    Parses an IRC PRIVMSG into a hash.
    Provides support for WeeChat < 0.3.4
    Returns: {
        "arguments": arguments, (includes channel)
        "channel": channel,
        "command": command,
        "host": host,
        "text": text,
        "nick": nick,
    }
    """
    details = {}
    if int(version) >= 0x00030400:
        # WeeChat >= 0.3.4, use the built-in irc_message_parse
        details = weechat.info_get_hashtable("irc_message_parse", {
            "message":	signal_data,
            "server":	server
        })
    else:
        # This should build an identical hash for WeeChat < 0.3.4
        (source, command, channel, message) = signal_data.split(" ", 3)
        details['arguments'] = "{} {}".format(channel, message)
        details['channel'] = channel
        details['command'] = command
        details['host'] = source.lstrip(":")
        details['nick'] = weechat.info_get("irc_nick_from_host", signal_data)

    # WeeChat leaves this step up to us for some reason, ugh.
    # Split out the actual PRIVMSG. You know, the part we actually care about.
    details['text'] = details['arguments'].split(" :", 1)[1]

    return details


def privmsg_cb(userdata, signal, signal_data):
    (server, signal) = signal.split(",")

    details = parse_message(server, signal_data)

    weechat.prnt("", "[{}] <{}/{}> -> {}".format(
        server,
        details['nick'],
        details['channel'],
        details['text'])
        )

    return weechat.WEECHAT_RC_OK


def privmsg_modifier_cb(userdata, modifier, servername, raw_irc_msg):
    weechat.prnt("", "{}".format(userdata))
    weechat.prnt("", "{}".format(modifier))
    weechat.prnt("", "{}".format(servername))
    weechat.prnt("", "{}".format(raw_irc_msg))

    return "{} {}".format(raw_irc_msg, servername)


if __name__ == '__main__':
    if weechat.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION,
                        SCRIPT_LICENSE, SCRIPT_DESC, "", ""):
        version = weechat.info_get("version_number", "") or 0
        weechat.hook_signal("*,irc_in_privmsg", "privmsg_cb", "")
        weechat.hook_modifier("irc_in_privmsg", "privmsg_modifier_cb", "")
