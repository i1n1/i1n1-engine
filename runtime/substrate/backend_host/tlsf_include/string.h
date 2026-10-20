#ifndef OCNEXT_TLSF_PRIVATE_STRING_H
#define OCNEXT_TLSF_PRIVATE_STRING_H
#include <stddef.h>
void *ocnext_backend_tlsf_memcpy(void *,const void *,size_t);
#define memcpy ocnext_backend_tlsf_memcpy
#endif
