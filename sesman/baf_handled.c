#if defined(HAVE_CONFIG_H)
#include <config_ac.h>
#endif
#include "baf_handle_service.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static int positive(const char *s,long *v){char *e;errno=0;*v=strtol(s,&e,10);return !errno&&e!=s&&!*e&&*v>0;}
int main(int argc,char **argv){const char *p=BAF_HANDLE_DEFAULT_SOCKET;long c=BAF_HANDLE_DEFAULT_CAPACITY,t=BAF_HANDLE_DEFAULT_MAX_TTL;int i;for(i=1;i<argc;i++){if(i+1>=argc)return 1;if(!strcmp(argv[i],"-s"))p=argv[++i];else if(!strcmp(argv[i],"-c")&&positive(argv[i+1],&c))++i;else if(!strcmp(argv[i],"-t")&&positive(argv[i+1],&t))++i;else{fprintf(stderr,"Usage: %s [-s socket] [-c capacity] [-t max-ttl]\n",argv[0]);return 1;}}return baf_handle_service_run(p,c,t);}
