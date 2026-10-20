#include "native_format.h"
#include <stdint.h>
#include <limits.h>

#define NANOPRINTF_VISIBILITY_STATIC
#define NANOPRINTF_USE_FIELD_WIDTH_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_PRECISION_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_LARGE_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_SMALL_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_ALT_FORM_FLAG 1
#define NANOPRINTF_USE_FLOAT_FORMAT_SPECIFIERS 0
#define NANOPRINTF_USE_FLOAT_HEX_FORMAT_SPECIFIER 0
#define NANOPRINTF_USE_FLOAT_SCI_FORMAT_SPECIFIER 0
#define NANOPRINTF_USE_FLOAT_SHORTEST_FORMAT_SPECIFIER 0
#define NANOPRINTF_USE_FLOAT_SINGLE_PRECISION 0
#define NANOPRINTF_USE_BINARY_FORMAT_SPECIFIERS 0
#define NANOPRINTF_USE_WRITEBACK_FORMAT_SPECIFIERS 0
#define NANOPRINTF_USE_FIXED_WIDTH_FORMAT_SPECIFIERS 0
#define NANOPRINTF_IMPLEMENTATION
#include "nanoprintf.h"

/* Reuse this pinned parser in the implementation's own TU. It is not a
 * stable exported upstream API. Never accept its verbatim-unknown fallback
 * or ignored incompatible flags/lengths as successful C formatting.
 */
static int accepted(const char *format)
{
    size_t n=0,tokens=0;
    if(!format || (uintptr_t)format>UINTPTR_MAX-OCNEXT_NATIVE_FORMAT_MAX_FORMAT)return 0;
    while(n<=OCNEXT_NATIVE_FORMAT_MAX_FORMAT && format[n])++n;
    if(n>OCNEXT_NATIVE_FORMAT_MAX_FORMAT)return 0;
    const char *p=format,*limit=format+n;
    while(p<limit){
        if(*p!='%'){++p;continue;}
        npf_format_spec_t spec;
        const char *end=npf_parse_format_spec_end(p,&spec);
        if(!end || end>limit || end<=p || ++tokens>128)return 0;
        char conversion=end[-1];
        if(spec.field_width_opt==NPF_FMT_SPEC_OPT_STAR || spec.prec_opt==NPF_FMT_SPEC_OPT_STAR ||
           spec.field_width<0 || spec.field_width>(int)OCNEXT_NATIVE_FORMAT_MAX_FORMAT ||
           spec.prec<0 || spec.prec>(int)OCNEXT_NATIVE_FORMAT_MAX_FORMAT)return 0;
        /* NPF also accepts negative literal precision, duplicate/invalid
         * modifiers and uppercase aliases. Reject those before any va_arg. */
        for(const char *q=p+1;q<end-1;++q)
            if(*q=='.' && q+1<end-1 && q[1]=='-')return 0;
        if(conversion=='%'){
            if(end-p!=2)return 0;
        }else if(conversion=='s' || conversion=='c' || conversion=='p'){
            if(spec.length_modifier!=NPF_FMT_SPEC_LEN_MOD_NONE || spec.prepend ||
               spec.alt_form || spec.leading_zero_pad)return 0;
            if((conversion=='c' || conversion=='p') && spec.prec_opt!=NPF_FMT_SPEC_OPT_NONE)return 0;
        }else if(conversion=='d'||conversion=='i'||conversion=='u'||
                 conversion=='o'||conversion=='x'||conversion=='X'){
            if(spec.length_modifier>NPF_FMT_SPEC_LEN_MOD_LARGE_PTRDIFFT)return 0;
            if(spec.alt_form && (conversion=='d'||conversion=='i'||conversion=='u'))return 0;
            if(spec.prepend && (conversion=='u'||conversion=='o'||conversion=='x'||conversion=='X'))return 0;
        }else return 0;
        p=end;
    }
    return 1;
}
int ocnext_native_vformat_v1(char *output,size_t capacity,const char *format,va_list args)
{
    va_list count_args,render_args;int count,written;
    if(capacity>OCNEXT_NATIVE_FORMAT_MAX_OUTPUT+1u || (capacity && !output) ||
       (capacity && (uintptr_t)output>UINTPTR_MAX-(capacity-1u)) || !accepted(format))return -1;
    va_copy(count_args,args);
    count=npf_vsnprintf(NULL,0,format,count_args);
    va_end(count_args);
    if(count<0 || (unsigned)count>OCNEXT_NATIVE_FORMAT_MAX_OUTPUT)return -1;
    if(!capacity)return count;
    va_copy(render_args,args);
    written=npf_vsnprintf(output,capacity,format,render_args);
    va_end(render_args);
    /* Stable valid inputs make both passes deterministic. A mismatch is a
     * contract/library fault; do not fabricate a successful length. */
    return written==count?count:-1;
}
