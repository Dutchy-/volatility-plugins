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
@author: Edwin Smulders
@license: GNU General Public License 2.0 or later
@contact: mail@edwinsmulders.eu
"""

import volatility.plugins.linux.common as linux_common
import volatility.plugins.linux.info_regs as linux_info_regs
import volatility.plugins.linux.check_syscall as linux_check_syscall
import struct

stats = {}
stats['syscall'] = {}
stats['syscall']['total'] = 0

class linux_process_syscall(linux_info_regs.linux_info_regs):
    def __init__(self, config, *args, **kwargs):
        linux_info_regs.linux_info_regs.__init__(self, config, *args, **kwargs)
        linux_common.set_plugin_members(self)

        syscalls = linux_check_syscall.linux_check_syscall(self._config).calculate()
        self.syscalls64 = {}
        self.syscalls32 = {}
        for table_name, syscall, address, hooked  in syscalls:
            if table_name == '64bit':
                table = self.syscalls64
            else:
                table = self.syscalls32
            symbol = "HOOKED" if hooked != 0 else self.profile.get_symbol_by_address('kernel', address)
            table[syscall] = address, symbol #

            #print(list(self.syscalls))


    def calculate(self):
        for task, name, registers in linux_info_regs.linux_info_regs(self._config).calculate():
            proc_as = task.get_process_address_space()
            for threadname, reg in registers:
                if reg != None:
                    syscall = self.analyze_registers(proc_as, reg)
                    yield threadname, syscall


    def render_text(self, outfd, data):
        for threadname, syscall in data:
            outfd.write("Thread name: {}\n".format(threadname))
            if syscall:
                outfd.write("Syscall: {}\n".format(syscall['name']))
                outfd.write("Address: {:016x}\n".format(syscall['address']))
                outfd.write("Parameters:\n")
                for i in syscall['parameters']:
                    outfd.write("\t{:016x}\n".format(i))
            else:
                outfd.write("Current instruction was not a syscall\n")

    def analyze_registers(self, proc_as, reg):
        """
        Analyze the registers for currently executing system calls.
        @param proc_as: process address space
        @param thread_number: the thread registers from linux_info_regs
        @return: syscall dict
        """

        if self.is_syscall(proc_as, reg['rip']):
            syscall = {}
            syscall['address'] = self.syscalls64[reg['rax']][0]
            syscall['name'] = self.syscalls64[reg['rax']][1]
            syscall['parameters'] = (reg['rdi'], reg['rsi'], reg['rdx'], reg['r10'], reg['r8'], reg['r9'])

            stats['syscall']['total'] += 1
            if not syscall['name'] in stats['syscall']:
                stats['syscall'][syscall['name']] = 1
            else:
                stats['syscall'][syscall['name']] += 1

            return syscall
        return None

    def is_syscall(self, proc_as, rip):
        """
        Determine if the current instruction is a system call.
        @param proc_as: the process address space
        @param rip: the current instruction pointer
        @return: True or False
        """
        size = 2
        syscall = '\x0f\x05'
        return proc_as.read(rip - size, size) == syscall