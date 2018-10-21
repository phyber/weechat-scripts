# -*- coding: utf-8 -*-

# Copyright (c) 2009 by Bazerka <bazerka@quakenet.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

#
# Redirects "whois" and "whowas" responses to active buffer.
# Optionally redirects response to query windows (for use with whois_on_query.py)
# (this script requires WeeChat 0.3.0 (or newer) and python 2.5)
#
# History:
#
# 2009-12-22, Bazerka <bazerka@quakenet.org>:
#     version 0.3: fix silly typo bug in idle time calculations.
# 2009-12-22, Bazerka <bazerka@quakenet.org>:
#     version 0.2: replace use of <string>.format for Python 2.5 compat.
# 2009-12-22, Bazerka <bazerka@quakenet.org>:
#     version 0.1: initial release version.
#

SCRIPT_NAME    = "whois_in_active_buffer"
SCRIPT_AUTHOR  = "Bazerka <bazerka@quakenet.org>"
SCRIPT_VERSION = "0.3"
SCRIPT_LICENSE = "GPL3"
SCRIPT_DESC    = "Display whois in active buffer"

try:
    import weechat
    WEECHAT_RC_OK = weechat.WEECHAT_RC_OK
    import_ok = True
except ImportError:
    print("This script must be run under WeeChat.")
    print("Get WeeChat now at: http://www.weechat.org/")
    import_ok = False

try:
    import time, datetime
except ImportError as message:
    print("Missing package(s) for %s: %s" % (SCRIPT_NAME, message))
    import_ok = False


settings = {
  "redirect_pv_whois": "on",
  "keep_server_buffer_output": "off",
}


def numeric_handler(numeric, data, buffer):
    print_data = ""
    print_format = ""
    if numeric in [307,310,313,318,319,320,378,379,401,406,671]:
        nick, message = data[3:5]
        print_data = {
          "nick": nick,
          "message": message,
        }
        print_format = '%(C)s%(message)s'
    elif numeric == 301:
        nick, away_message = data[3:5]
        print_data = {
          "nick": nick,
          "away_message": away_message,
        }
        print_format = '%(C)sis away: %(away_message)s'
    elif numeric == 311:
        nick, username, host = data[3:6]
        realname = data[7]
        print_data = {
          "nick": nick,
          "username": username,
          "host": host,
          "realname": realname,
        }
        print_format = '%(CD)s(%(CH)s%(username)s@%(host)s%(CD)s)%(C)s: %(realname)s'
    elif numeric == 312:
        nick, server, server_desc = data[3:6]
        print_data = {
          "nick": nick,
          "server": server,
          "server_desc": server_desc,
        }
        print_format = '%(C)s%(server)s %(CD)s(%(C)s%(server_desc)s%(CD)s)'
    elif numeric == 317:
        nick, idle, signon, message = data[3:7]
        m , s = divmod(int(idle), 60)
        h , m = divmod(m, 60)
        d , h = divmod(h, 24)
        if d > 0:
            idletime = "%%(C)s%%(B)s%d %%(C)sdays, %%(B)s%02d %%(C)shours %%(B)s%02d %%(C)sminutes %%(B)s%02d %%(C)sseconds" % (d, h, m, s)
        else:
            idletime = "%%(C)s%%(B)s%02d %%(C)shours %%(B)s%02d %%(C)sminutes %%(B)s%02d %%(C)sseconds" % (h, m, s)
        signontime = time.ctime(int(signon))
        print_data = {
          "nick": nick,
          "signon": signontime,
        }
        print_format = '%%(C)sidle: %s, signon at: %%(B)s%%(signon)s' % idletime
    elif numeric == 330:
        nick, away_message = data[3:5]
        print_data = {
          "nick": nick,
          "away_message": away_message,
        }
        print_format = '%(C)sis away: %(away_message)s'
    elif numeric == 338:
        nick, actual_ip, message = data[3:6]
        print_data = {
          "nick": nick,
          #"actual_userhost": actual_userhost,
          "actual_ip": actual_ip,
          "message": message,
        }
        #print_format = '%(C)s%(message)s: %(CH)s%(actual_userhost)s %(CD)s(%(C)s%(actual_ip)s%(CD)s)'
        print_format = '%(C)s%(message)s: %(CD)s(%(C)s%(actual_ip)s%(CD)s)'
    else:
        debug('Unknown numeric: %s' % numeric)
    if print_format and print_data and buffer:
        print_output(print_format, print_data, buffer)
                                                    
def debug(s, prefix='debug', buffer=''):
    weechat.prnt(buffer, '%s: %s' %(prefix, s))

def print_output(stringformat, values, buffer):
    formats = {
      'CD': weechat.color('chat_delimiters'),
      'CN': weechat.color('chat_nick'),
      'CH': weechat.color('chat_host'),
      'C': weechat.color('chat'),
      'B': weechat.color('bold'),
      'P': weechat.prefix('network'),
    }
    if values:
        formats.update(values)
    if stringformat:
        stringformat = '%s%s' % ('%(CD)s[%(CN)s%(nick)s%(CD)s] ',stringformat)
        output = formats['P'] + stringformat % formats
        weechat.prnt(buffer, output)                    

def split_signal_data(sig_data):
    data = []
    if sig_data[0] == ':':
        server, sig_data = sig_data[1:].split(' ', 1)
        data.append(server)
    if sig_data.find(' :') != -1:
        sig_data, last = sig_data.split(' :',1)
        middle = sig_data.split()
        data = data + middle
        data.append(last)
    else:
        data = data + sig_data.split()
    return data

def find_query_buffer(nick, server):
    buffer = weechat.info_get('irc_buffer', '%s,%s' % (server, nick))
    server_buffer = weechat.info_get('irc_buffer', server)
    if buffer == server_buffer:
        buffer = weechat.current_buffer()
    return buffer
    
def is_server_buffer(buffer):
    buff_name = weechat.buffer_get_string(buffer, 'name')
    if buff_name[0:7] == 'server.':
        return True
    return False

def whois_modifier_cb(data, modifier, modifier_data, string):
    buffer = ""
    signal_data = split_signal_data(string)
    if weechat.config_get_plugin('redirect_pv_whois') == 'on':
        buffer = find_query_buffer(signal_data[3], modifier_data)
    else:
        buffer = weechat.current_buffer()
    numeric_handler(int(modifier.split('_')[2]), signal_data, buffer)
    if weechat.config_get_plugin('keep_server_buffer_output') == 'on' and not is_server_buffer(buffer):
        return string
    else:
        return ""


if __name__ == '__main__' and import_ok:
    if weechat.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION, SCRIPT_LICENSE, SCRIPT_DESC, "", ""): 
        for option, default_value in settings.items():
            if not weechat.config_is_set_plugin(option):
                weechat.config_set_plugin(option, default_value)
        for numeric in [301,307,310,311,312,313,314,317,318,319,320,338,330,369,378,379,401,406,671]: 
            weechat.hook_modifier('irc_in_%d' % numeric, 'whois_modifier_cb', '')


# vim:set shiftwidth=2 softtabstop=2 expandtab textwidth=100:
