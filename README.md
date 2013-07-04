Volatility Plugins
==================

Plugins in this repository:

 - linux_threads
 - linux_info_regs

linux_threads
-------------

Displays the threads for a process.

Depends: linux_pslist

Parameters:
 - -p <PID>: select a specific process, by its PID.


linux_info_regs
---------------

Displays the CPU registers as saved on the kernel stack, per thread.
Written in collaboration with emd3l.

Depends: linux_threads

Parameters:
 - -p <PID>: select a specific process, by its PID.
