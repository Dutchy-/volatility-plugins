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
@contact:      edwin.smulders@gmail.com
"""

import volatility.plugins.linux.pslist as linux_pslist

class linux_environment(linux_pslist.linux_pslist):
    """ Display the process environment """
    
    def calculate(self):
        data = linux_pslist.linux_pslist.calculate(self)
        for task in data:
            if task.mm:
                env = self.read_addr_range(task, task.mm.env_start, task.mm.env_end)
                size = task.mm.env_end - task.mm.env_start
                yield (task, self.env_list(env, size))
    
    def env_list(self, env, size):
        res = []
        for page in env:
	    if size > 4096:
                size -= 4096
	    else:
                page = page[:size]
            for s in page.split('\0'):
                if s != "":
                    res.append(s)
	return res
        
    def read_addr_range(self, task, start, end):
        pagesize = 4096 

        # set the as with our new dtb so we can read from userland
        proc_as = task.get_process_address_space()

        # xrange doesn't support longs :(
        while start < end:
            page = proc_as.zread(start, pagesize)
            yield page
            start = start + pagesize

    def render_text(self, outfd, data):
        for task, env_list in data:
            outfd.write("\nTask pid: {0}\n\n".format(task.pid))
            for envline in env_list:
                outfd.write(envline + '\n')
