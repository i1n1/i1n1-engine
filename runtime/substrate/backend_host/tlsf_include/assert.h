#ifndef OCNEXT_TLSF_PRIVATE_ASSERT_H
#define OCNEXT_TLSF_PRIVATE_ASSERT_H
/* This include directory belongs only to the imported TLSF translation unit.
 * Assertions remain fail-closed even in NDEBUG builds. No OS assertion path.
 */
_Noreturn void ocnext_backend_tlsf_assert_fail(const char *,const char *,unsigned);
#define assert(expression) ((expression) ? (void)0 : \
    ocnext_backend_tlsf_assert_fail(#expression,__FILE__,(unsigned)__LINE__))
#endif
