#include <stddef.h>
#include <stdint.h>
#include "tlsf_include/assert.h"
#include "tlsf_include/stdio.h"
#include "tlsf_include/string.h"

/* A bounded volatile postmortem record survives until the actual trap. It is
 * diagnostic data, not a callback, logger, allocator or recovery authority.
 * Literal vendor printf formats are recorded without pretending to implement
 * formatting. This path never returns successful printf/fence/OS status.
 */
static volatile struct {
    uint64_t marker;
    unsigned kind,line;
    char message[160],file[96];
} fatal_record;

static void diagnostic_text(volatile char *out,size_t bytes,const char *text)
{
    size_t i=0;
    if(text) for(;i+1<bytes && text[i];++i) out[i]=text[i];
    for(;i<bytes;++i)out[i]=0;
}

static _Noreturn void terminal_trap(void)
{
#if defined(__clang__) || defined(__GNUC__)
    __builtin_trap();
#else
    for(;;) { /* A terminal stop is never a successful fallback. */ }
#endif
}

_Noreturn void ocnext_backend_tlsf_assert_fail(const char *expression,const char *file,unsigned line)
{
    fatal_record.kind=1;fatal_record.line=line;
    diagnostic_text(fatal_record.message,sizeof(fatal_record.message),expression);
    diagnostic_text(fatal_record.file,sizeof(fatal_record.file),file);
    fatal_record.marker=UINT64_C(0x4f4e485046415441);
    terminal_trap();
}

_Noreturn int ocnext_backend_tlsf_diagnostic(const char *format,...)
{
    fatal_record.kind=2;fatal_record.line=0;
    diagnostic_text(fatal_record.message,sizeof(fatal_record.message),format);
    diagnostic_text(fatal_record.file,sizeof(fatal_record.file),"TLSF diagnostic");
    fatal_record.marker=UINT64_C(0x4f4e485046415441);
    terminal_trap();
}

void *ocnext_backend_tlsf_memcpy(void *destination,const void *source,size_t bytes)
{
    uintptr_t d=(uintptr_t)destination,s=(uintptr_t)source;
    if(bytes) {
        if(!d || !s || bytes>UINTPTR_MAX-d || bytes>UINTPTR_MAX-s)
            ocnext_backend_tlsf_assert_fail("copy span",__FILE__,__LINE__);
        if(destination==source)return destination;
        if(d<s+bytes && s<d+bytes)
            ocnext_backend_tlsf_assert_fail("overlapping memcpy",__FILE__,__LINE__);
        volatile unsigned char *out=(volatile unsigned char *)destination;
        const volatile unsigned char *in=(const volatile unsigned char *)source;
        for(size_t i=0;i<bytes;++i)out[i]=in[i];
    }
    return destination;
}
