# intro
A tool called sysfinder can be used to locate a syscall in a specific Glibc version starting from a given symbol.
It gathers data using Radare 2 and displays a list of the syscalls along with sample routes to reach them.
# usage
```
Syscall finder
	-s	specifies the symbol where the search starts
	-f	specifies library path
	-p	print profiler data
	-t	print terse data
	-h	this help

usage: ./sysfinder -f libc.so.6 -s sym.malloc
```
A simple usage requires specifying both the Glibc binary file (currently ARM and x86 are supported) and a symbol for starting the search.
To use the tool, the symbol must be stated using the Radare format, which is the 'nm' symbol followed by the word'sym.'
The option `-t` for terse output allows printing only the syscall list and omitting the path samples list.
The option `-p` is for profiling, not meant to be used in any context different from developing.
