#include "ocnext/boot_args.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

static int integer(const char *text,uint64_t *out)
{
    char *end;unsigned long long value;
    if(!text || !*text || *text=='-' || *text=='+')return -1;
    errno=0;value=strtoull(text,&end,0);
    if(errno || *end)return -1;
    *out=(uint64_t)value;return 0;
}
int main(int argc,char **argv)
{
    struct ocnext_bootargs_study p={0};uint64_t n[8];uint8_t bytes[1152];unsigned i;
    if(argc!=9) {fprintf(stderr,"Usage: %s VIRT_BASE PHYS_BASE RAM_BYTES KERNEL_SPAN BOOT_ARGS_PA TOP_PA DT_PA DT_BYTES\nHeadless rv3 study only; never a qualified macOS boot contract.\n",argv[0]);return 2;}
    for(i=0;i<8;++i)if(integer(argv[i+1],&n[i]))return 2;
    if(n[7]>UINT32_MAX)return 2;
    p.revision=3;p.version=2;p.virt_base=n[0];p.phys_base=p.kernel_pa=n[1];
    p.mem_size=p.mem_size_actual=n[2];p.kernel_bytes=n[3];p.boot_args_pa=n[4];
    p.top_of_kernel_data=n[5];p.device_tree_pa=n[6];p.device_tree_bytes=(uint32_t)n[7];
    if(ocnext_bootargs_v3_encode(&p,bytes,sizeof(bytes))!=OCNEXT_BOOTARGS_OK)return 2;
    return fwrite(bytes,1,sizeof(bytes),stdout)==sizeof(bytes) && fflush(stdout)==0 ? 0 : 3;
}
