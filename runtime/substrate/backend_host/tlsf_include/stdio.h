#ifndef OCNEXT_TLSF_PRIVATE_STDIO_H
#define OCNEXT_TLSF_PRIVATE_STDIO_H
/* Vendor diagnostic branches are unexpected after wrapper preflight. Record
 * their literal message and trap; this is deliberately not a success stub or
 * a public printf implementation. Default pool walking is not exposed.
 */
_Noreturn int ocnext_backend_tlsf_diagnostic(const char *,...);
#define printf ocnext_backend_tlsf_diagnostic
#endif
