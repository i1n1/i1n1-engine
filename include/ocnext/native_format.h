#ifndef OCNEXT_PRIVATE_NATIVE_FORMAT_H
#define OCNEXT_PRIVATE_NATIVE_FORMAT_H
#include <stddef.h>
#include <stdarg.h>
#define OCNEXT_NATIVE_FORMAT_PROFILE 1u
#define OCNEXT_NATIVE_FORMAT_MAX_FORMAT 4096u
#define OCNEXT_NATIVE_FORMAT_MAX_OUTPUT 1048576u
/* Native ASCII integer profile1, no wire/CPU/EFI capability ABI. Exact C
 * promoted argument types, char* ASCII strings, %% and c/d/i/u/o/x/X/p.
 * Integer hh/h/l/ll/j/z/t; literal width/precision<=4096, <=128 conversions.
 * LP64 %p is16 lowercase hex digits, no0x (implementation-defined choice).
 * No stars, FP,
 * writeback, wide/locale, positional or vendor conversion. Whole-format
 * refusal returns-1 before args/output; ordinary truncation returns full
 * would-have-written length and NUL-terminates nonempty output capacity.
 * Caller provides stable readable format/argument strings (<=1MiB each),
 * correct argument types, writable output and disjoint live input/output.
 * Not an arbitrary-pointer or malicious native-C sandbox. Copied va_lists
 * leave caller's cursor usable. Max complete output1MiB excluding NUL;
 * capacity may be at most1048577 including NUL. Refusal is-1.
 */
int ocnext_native_vformat_v1(char *,size_t,const char *,va_list);
#endif
