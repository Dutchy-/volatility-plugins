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

import volatility.plugins.linux.common as linux_common
import volatility.obj as obj
import struct
import volatility.debug as debug

# https://github.com/torvalds/linux/blob/master/include/linux/swap.h

swap_vtypes = { # unfinished
    'swap_info_struct': [ 0x80, {
        'flags': [0x0, ['unsigned long']], # SWP_USED etc: see above
        'prio': [0x8, ['short']], # swap priority of this type
        'type': [0xa, ['char']], # strange name for an index
        'next': [0xb, ['char']], # next type on the swap list
        'max': [0xc, ['unsigned int']], # extent of the swap_map
        'swap_map': [0x10, ['pointer', ['unsigned char']]], # vmalloc'ed array of usage counts
        'lowest_bit': [0x18, ['unsigned int']], # index of first free in swap_map
        'highest_bit': [0x1c, ['unsigned int']], # index of last free in swap_map
        'pages': [0x20, ['unsigned int']], # total of usable pages of swap
        'inuse_pages': [0x24, ['unsigned int']], # number of those currently in use
        'cluster_next': [0x28, ['unsigned int']], # likely index for next allocation
        'cluster_nr': [0x2c, ['unsigned int']], # countdown to next cluster search
        'lowest_alloc': [0x30, ['unsigned int']], # while preparing discard cluster
        'highest_alloc': [0x34, ['unsigned int']], # while preparing discard cluster
        'curr_swap_extent': [0x38, ['pointer', ['address', ['swap_extent']]]], #
        'first_swap_extent': [0x40, ['swap_extent']], #
        'bdev': [0x68, ['pointer', ['address', ['block_device']]]], # swap device or bdev of swap file
        'swap_file': [0x70, ['pointer', ['address', ['file']]]], # seldom referenced
        'old_block_size': [0x78, ['unsigned int']], # seldom referenced
        'lock': [0x7c, ['spinlock_t']], #
        #'frontswap_map': [0x5f, ['pointer', 'unsigned long']],
        #'frontswap_pages': [0x67, 'atomic_t'],
        #'lock': [0x6b, 'spinlock_t'],
        }],
    'swap_extent': [ 0x28, {
        'list': [0x0, ['list_head']],
        'start_page': [0x10, ['pgoff_t']],
        'nr_pages': [0x18, ['pgoff_t']],
        'start_block': [0x20, ['sector_t']]
    }]
}

native_types = {
    'spinlock_t' : [4, '<I'],
    'pgoff_t'    : [4, '<I'],
    'sector_t'   : [4, '<I']
}

class SwapTypes(obj.ProfileModification):
    conditions = {"os" : lambda x: x in ["linux"]}

    def modification(self, profile):
        if profile.metadata.get('memory_model', '32bit') == '32bit':
            profile.vtypes.update(swap_vtypes)
        else:
            profile.vtypes.update(swap_vtypes)


        profile.native_types.update(native_types)
        #for key in profile.vtypes:
            #if 'swap' in key:
                #print(key, profile.vtypes[key])

        # add dict of string -> class
        #profile.object_classes.update({"_hist_entry":_hist_entry})

class linux_swap(linux_common.AbstractLinuxCommand):
    def __init__(self, config, *args, **kwargs):
        linux_common.AbstractLinuxCommand.__init__(self, config, *args, **kwargs)
        linux_common.set_plugin_members(self)


    def calculate(self):
        swap_info_offset = self.addr_space.profile.get_symbol("swap_info")
        swap_info_struct_offset = struct.unpack("<Q", self.addr_space.read(swap_info_offset, 8))[0]

        #print(swap_info)
        swap_info_struct = obj.Object("swap_info_struct", vm = self.addr_space, offset = swap_info_struct_offset)
        print(swap_info_struct.d())
        self.validate_swap(swap_info_struct)

        b = self.addr_space.read(swap_info_struct_offset, 200)
        print(swap_info_struct.first_swap_extent.d())

        for i in struct.unpack("<"+ "I"*(200/4), b):
            print("{:08x}".format(i))

    def render_text(self, outfd, data):
        pass

    def validate_swap(self, swap_info_struct):
        #print("max: {:016x}".format(swap_info_struct.max))
        debug.info("inuse_pages <= pages: {}".format(swap_info_struct.inuse_pages <= swap_info_struct.pages))
        debug.info("lowest_bit <= highest_bit: {}".format(swap_info_struct.lowest_bit <= swap_info_struct.highest_bit))
        debug.info("lowest_alloc <= highest_alloc: {}".format(swap_info_struct.lowest_alloc <= swap_info_struct.highest_alloc))
        debug.info("is_valid_address(swap_map): {}".format(self.addr_space.is_valid_address(swap_info_struct.swap_map)))
        debug.info("is_valid_address(curr_swap_extent): {}".format(self.addr_space.is_valid_address(swap_info_struct.curr_swap_extent)))
        #debug.info("is_valid_address(first_swap_extent): {}".format(self.addr_space.is_valid_address(swap_info_struct.first_swap_extent)))
        debug.info("is_valid_address(bdev): {}".format(self.addr_space.is_valid_address(swap_info_struct.bdev)))
        #print("{:016x}".format(swap_info_struct.curr_swap_extent))

