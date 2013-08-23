Volatility Plugins
==================

Plugins in this repository:

 - linux_environment
 - linux_threads
 - linux_info_regs
 - linux_process_info
 - linux_process_stack
 - linux_process_rules
 - linux_process_syscall
 - linux_swap

linux_environment
-----------------

Displays the environment of a linux process. I made this as practice with volatility.

Depends: linux_pslist

Parameters:
 - -p <PID>: select a specific process, by its PID.

linux_threads
-------------

Displays the threads for a process.

Depends: linux_pslist

Parameters:
 - -p <PID>: select a specific process, by its PID.


linux_info_regs
---------------

Displays the CPU registers as saved on the kernel stack, per thread.
Does not display registers for kernel threads, because this has not been tested.

Written in collaboration with emd3l.

Depends: linux_threads

Parameters:
 - -p <PID>: select a specific process, by its PID.


linux_process_info
------------------

Collects basic information about a process. I've disabled all output
for now, it merely provides helper objects/functions for some of my
other plugins. If I'd had to do this again, I'd modify task_struct
instead of doing it this way. Has lots of old, somewhat useless code.
Should depend on linux_info_regs, but not yet.

Depends: linux_threads, linux_pslist

Parameters:
 - -p <PID>: select a specific process, by its PID.


linux_process_stack
-------------------

The main part of my research, it does analysis of the stack. Main features:
 - Find return addresses on the stack.
 - Calculate function addresses from return addresses.
 - Match function addresses to (dynamic) symbols.

Depends: linux_process_info

Only works on x86_64 (due to disassembling code). Normal output is fairly basic. This plugin is the most important
part of my research, but has limited practical use. Still depends on my old register code, not on my earlier released
linux_info_regs.

Parameters:
 - -p <PID>: the process to analyze, recommended to use, because analysis of the full system might take a while.
 - -s dir/to/symbols: Optional, directory containing symbol files ('nm' output). Helper scripts included.
 - -o file: Optional, a file to write an annotated stack to. Useful for manual inspection of the resulting stack frames.


linux_process_rules
-------------------

A plugin I created at the start of my research, it uses scan rules
to scan pointers for networking structs. It works fairly well, but is
prone to false positives. I discontinued any research done with it.
Mainly tested on x86_64, but should also work on 32bits.

Depends: linux_process_info

Parameters: 
 - -p <PID>


linux_process_syscall
---------------------

Detects any currently executing syscall based on register contents. 

Depends: linux_info_regs

Parameters: 
 - -p <PID>


linux_swap
----------

Experiments on finding relevant linux swap structs in kernel space. Only finds these structs, does nothing else (yet).
