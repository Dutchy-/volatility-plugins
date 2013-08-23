# Volatility
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

"""
@author:       Edwin Smulders
@license:      GNU General Public License 2.0 or later
@contact:      mail@edwinsmulders.eu
"""

import volatility.plugins.linux.process_info as linux_process_info
import volatility.plugins.linux.common as linux_common
import volatility.obj as obj
import socket
import itertools



net_vtypes_32 = {
    'hostent': [ 0x14, {
        'h_name': [0x0, ['pointer', ['String', dict(length=128)]]],
        'h_aliases': [0x4, ['pointer', ['address', ['String', dict(length=128)]]]],
        'h_addrtype': [0x8, ['unsigned int']],
        'h_length': [0xc, ['unsigned int']],
        'h_addr_list': [0x10, ['pointer', ['address', ['String', dict(length=128)]]]],
    }],
    'addrinfo': [ 0x20, {
        'ai_flags': [0x0, ['unsigned int']],
        'ai_family': [0x4, ['unsigned int']],
        'ai_socktype': [0x8, ['unsigned int']],
        'ai_protocol': [0xc, ['unsigned int']],
        'ai_addrlen': [0x10, ['unsigned int']],
        'ai_addr': [0x14, ['pointer', ['sockaddr_in']]],
        'ai_canonname': [0x18, ['pointer', ['String', dict(length=128)]]],
        'ai_next': [0x1c, ['pointer', ['void']]]
    }],
    'sockaddr_in': [ 0x10, {
        'sin_family': [0x0, ['unsigned short']],
        'sin_port': [0x2, ['network unsigned short']],
        'sin_addr': [0x4, ['IpAddress']],
        'sin_zero': [0x8, ['String', dict(length=8)]]
    }],
}

net_vtypes_64 = {
    'hostent': [ 0x20, {
        'h_name': [0x0, ['pointer', ['String', dict(length=128)]]],
        'h_aliases': [0x8, ['pointer', ['pointer', ['String', dict(length=128)]]]],
        'h_addrtype': [0x10, ['unsigned int']],
        'h_length': [0x14, ['unsigned int']],
        'h_addr_list': [0x18, ['pointer', ['pointer', ['String', dict(length=128)]]]],
        }],
    'addrinfo': [ 0x28, {
        'ai_flags': [0x0, ['unsigned int']],
        'ai_family': [0x4, ['unsigned int']],
        'ai_socktype': [0x8, ['unsigned int']],
        'ai_protocol': [0xc, ['unsigned int']],
        'ai_addrlen': [0x10, ['unsigned int']],
        'ai_addr': [0x14, ['pointer', ['sockaddr_in']]],
        'ai_canonname': [0x1c, ['pointer', ['String', dict(length=128)]]],
        'ai_next': [0x24, ['pointer', ['void']]]
    }],
    'sockaddr_in' : net_vtypes_32['sockaddr_in'],
}

vtypes = net_vtypes_64

class NetTypes(obj.ProfileModification):
    """
    Adds vtypes for some network type structs
    """
    conditions = {"os" : lambda x: x in ["linux"]}

    def modification(self, profile):
        if profile.metadata.get('memory_model', '32bit') == '32bit':
            profile.vtypes.update(net_vtypes_32)
        else:
            profile.vtypes.update(net_vtypes_64)
        profile.native_types['network unsigned short'] = [2, '!h']
        profile.native_types['network unsigned long'] = [4, '!I']
        profile.native_types['network unsigned int'] = [4, '!I']

        # add dict of string -> class
        #profile.object_classes.update({"_hist_entry":_hist_entry})


class linux_process_rules(linux_process_info.linux_process_info):
    def __init__(self, config, *args, **kwargs):
        linux_process_info.linux_process_info.__init__(self, config, *args, **kwargs)

    def calculate(self):
        for p in linux_process_info.linux_process_info.calculate(self):
            #for i in p.get_data_pointers_from_threads():
            #    print(i)
            #exit(0)
            rules = [sockaddr_rule, hostent_rule, addrinfo_rule]
            #rules = [sockaddr_rule]
            for r in rules:
                for match in r(self.profile, p).execute():
                    print(match.d())
                    #try: print(match.ai_addr.dereference().d())
                    #except Exception,e: print(e)
        return

    def render_text(self, outfd, data):
        # FIXME: move output to here
        pass


class rule(object):
    """
    A basic rule class which is mostly abstract
    """
    def __init__(self, profile, process, **kwargs):
        self.profile = profile
        self.process = process
        self.proc_as = process.proc_as
        self.matches = []
        self.struct_format = None
        self.struct_format_list = False

    def execute(self):
        pass

    def match(self, address):
        pass


class boolean_rule(rule):
    """
    A boolean rule class which matches on the condition() function.
    """
    def __init__(self, *args, **kwargs):
        rule.__init__(self, *args, **kwargs)
        if 'condition' in kwargs:
            self.condition = kwargs['condition']

    def match(self, value):
        return self.condition(value)

    def condition(self, value):
        return True


class sa_family_rule(boolean_rule):
    """
    A boolean rule with the condition that the value must be a an address family.
    """
    def condition(self, value):
        return value in [socket.AF_INET, socket.AF_UNIX, socket.AF_INET6]
            # or address == socket.AF_IMPLINK # FIXME: These don't exist in python?

# several other rules
class is_pointer_rule(boolean_rule):
    def condition(self, value):
        return self.process.is_data_pointer(value)

class socktype(boolean_rule):
    def condition(self, value):
        return value in [socket.SOCK_STREAM, socket.SOCK_DGRAM]

class protocol(boolean_rule):
    def condition(self, value):
        return value in [socket.SOL_TCP, socket.SOL_UDP, socket.SOL_IP, socket.SOL_SOCKET]


class net_addr_len(boolean_rule):
    def condition(self, value):
        # ipv4 vs ipv6
        return value == 4 or value == 16


class pointer_scan_rule(rule):
    """
    A abstract rule class to scan pointers. Subclasses defines subrules to match on.
    """
    obj = None
    subrules = None
    def execute(self):
        #it =  self.process.get_unique_data_pointers()
        it = self.process.get_unique_pointers( itertools.chain(
            self.process.get_data_pointers(),
            self.process.get_data_pointers_from_heap(),
            self.process.get_pointers(cond=self.process.is_data_pointer,
                                      space=self.process.reg),
            self.process.get_data_pointers_from_threads()
        ))
        i = 0
        for address, value in it:
            i+=1
            m = self.match(value)
            if m:
                self.matches.append(m)
        print("{} pointers scanned.".format(i))
        return self.matches

    def match(self, address):
        res = True
        m = obj.Object(self.obj, address, self.proc_as)

        for attr, subrule in self.subrules:
            value = m.__getattr__(attr)
            prevres = res
            res &= subrule.match(value)
            if (res or prevres) and attr[:4] == 'ai_p':
                print(address, attr, value, res)
        if res:
            return m
        return None

class sockaddr_rule(pointer_scan_rule):
    def __init__(self, profile, process):
        pointer_scan_rule.__init__(self, profile, process)

        self.obj = "sockaddr_in"
        self.subrules = \
            [
                ('sin_family', sa_family_rule(self.profile,process)),
                ('sin_port',boolean_rule(self.profile,process)), #always True
                ('sin_addr', boolean_rule(self.profile,process)), # always True
                ('sin_zero', boolean_rule(self.profile,process, condition=lambda x: x == '\0'*8))
            ]


class hostent_rule(pointer_scan_rule):
    def __init__(self, profile, process):
        pointer_scan_rule.__init__(self, profile, process)
        self.obj = "hostent"
        self.subrules = \
            [
                ('h_name', is_pointer_rule(self.profile,process)),
                ('h_aliases',is_pointer_rule(self.profile,process)),
                ('h_addrtype',sa_family_rule(self.profile,process)),
                ('h_length',net_addr_len(self.profile,process)),
                ('h_addr_list',is_pointer_rule(self.profile,process))
            ]

class addrinfo_rule(pointer_scan_rule):
    def __init__(self, profile, process):
        pointer_scan_rule.__init__(self, profile, process)
        self.obj = "addrinfo"
        self.subrules = \
            [
                ('ai_flags', boolean_rule(self.profile,process)),
                ('ai_family', sa_family_rule(self.profile,process)),
                ('ai_socktype',socktype(self.profile,process)),
                ('ai_protocol', protocol(self.profile,process)),
                ('ai_addrlen', net_addr_len(self.profile,process)),
                ('ai_addr', is_pointer_rule(self.profile,process)),
                ('ai_canonname', boolean_rule(self.profile,process)),
                ('ai_next', boolean_rule(self.profile,process))
            ]

    def match(self, address):
        m = pointer_scan_rule.match(self,address)
        return m