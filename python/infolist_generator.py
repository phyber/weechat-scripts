FIELD_TYPES = {
		# Not available to API
		#'b': "infolist_buffer",
		'i': "infolist_integer",
		'p': "infolist_pointer",
		's': "infolist_string",
		't': "infolist_time",
		}

class infolist_generator(object):
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
		fields = {}
		try:
			for field in weechat.infolist_fields(self._infolist).split(","):
				(field_type, field_name) = field.split(":")
				infolist_function = FIELD_TYPES.get(field_type, None)

				# Skip infolist types that we can't handle.
				if infolist_function is None:
					continue

				field_value = getattr(weechat, infolist_function)(
						self._infolist, field_name
						)
				fields[field_name] = field_value
			return fields
		except TypeError as e:
			weechat.prnt("", "Exception: {}".format(e))

	def next(self):
		# Advance the infolist
		if weechat.infolist_next(self._infolist):
			fields = self.get_fields()
			return fields
		else:
			raise StopIteration

# Examples of using the generator to get a channel list
# and a list of nicks in a specific channel.

#def get_channels(server):
#	channels = []
#
#	with infolist_generator("irc_channel", "", server) as infolist:
#		channels = [row['name'] for row in infolist if row['name'].startswith('#')]
#
#	return channels

#def get_channel_nicks(server, channel):
#	nicks = []
#
#	with infolist_generator("irc_nick", "", "{server},{channel}".format(
#		server=server,
#		channel=channel)) as infolist:
#		nicks = [row['name'] for row in infolist]
#
#	return nicks
