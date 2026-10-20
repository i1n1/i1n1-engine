# TLSF 3.1

Original source: Matthew Conte, https://github.com/mattconte/tlsf,
commit `deff9ab509341f264addbd3c8ada533678591905`.

The complete BSD three-clause copyright, redistribution conditions and
disclaimer are retained in `tlsf.h`. Include that notice in source and binary
redistribution materials. Neither the copyright holder nor contributors endorse
this project.

`tlsf.c` and `tlsf.h` are byte-for-byte upstream files, including their original
line endings; see `provenance.json`. Private freestanding headers and the
this project port supply actual byte copying and terminal diagnostics. No
operating-system allocation, Boot Services allocation or successful stub is used.

The native wrapper validates retained spans, size arithmetic, alignment and live
allocation descriptors. It does not expose the unchecked upstream convenience
create/realloc or debug-walker interfaces to the backend API. It is not a sandbox
against corrupted native allocator metadata or out-of-bounds native writes.
