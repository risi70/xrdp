#if defined(HAVE_CONFIG_H)
#include <config_ac.h>
#endif
#include "baf_handle_service.h"
#include <errno.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
#define MAGIC 0x42414648u
#define HANDLE_VERSION 1
#define OP_STORE 1
#define OP_RESOLVE 2
#define OP_CLEANUP 3
#define OP_PING 4
struct message { uint32_t magic; uint16_t version, op; uint32_t status, assertion_length; int64_t expires_at; uint32_t count; char handle[65]; char target[256]; unsigned char assertion[BAF_HANDLE_MAX_ASSERTION]; };
struct entry { struct entry *next; char handle[65], target[256]; unsigned char *assertion; size_t length; int64_t expires_at; };
static void clear(void *v, size_t n) { volatile unsigned char *p=v; while (n--) *p++=0; }
void baf_handle_assertion_free(unsigned char *p,size_t n) { if(p){clear(p,n);free(p);} }
static int valid_handle(const char *h) { size_t i; if(!h||strlen(h)!=64)return 0; for(i=0;i<64;i++)if(!((h[i]>='0'&&h[i]<='9')||(h[i]>='a'&&h[i]<='f')))return 0; return 1; }
static int address(const char *p,struct sockaddr_un *a) { size_t n; if(!p||!*p||(n=strlen(p))>=sizeof(a->sun_path))return -1; memset(a,0,sizeof(*a));a->sun_family=AF_UNIX;memcpy(a->sun_path,p,n+1);return 0; }
static int connect_to(const char *p,int ms) { struct sockaddr_un a;struct timeval t;int fd;if(ms<=0||address(p,&a)||(fd=socket(AF_UNIX,SOCK_SEQPACKET,0))<0)return -1;t.tv_sec=ms/1000;t.tv_usec=(ms%1000)*1000;if(setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&t,sizeof(t))||setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&t,sizeof(t))||connect(fd,(struct sockaddr *)&a,sizeof(a))){close(fd);return -1;}return fd; }
static enum baf_handle_status request(const char *p,int ms,struct message *m) { struct message r;int fd=connect_to(p,ms);ssize_t n=-1;if(fd<0)return BAF_HANDLE_UNAVAILABLE;if(send(fd,m,sizeof(*m),MSG_NOSIGNAL)==sizeof(*m))n=recv(fd,&r,sizeof(r),MSG_TRUNC);close(fd);clear(m->assertion,sizeof(m->assertion));if(n!=sizeof(r)||r.magic!=MAGIC||r.version!=HANDLE_VERSION||r.op!=m->op||r.status>BAF_HANDLE_ERROR||r.assertion_length>BAF_HANDLE_MAX_ASSERTION){clear(&r,sizeof(r));return BAF_HANDLE_UNAVAILABLE;}memcpy(m,&r,sizeof(r));clear(&r,sizeof(r));return m->status; }
enum baf_handle_status baf_handle_store(const char *p,int ms,const unsigned char *a,size_t n,int64_t exp,const char *target,char h[65]) { struct message m;enum baf_handle_status s;if(!a||!n||n>BAF_HANDLE_MAX_ASSERTION||!target||strlen(target)>255||!h)return BAF_HANDLE_BAD_REQUEST;memset(&m,0,sizeof(m));m.magic=MAGIC;m.version=HANDLE_VERSION;m.op=OP_STORE;m.assertion_length=n;m.expires_at=exp;strcpy(m.target,target);memcpy(m.assertion,a,n);s=request(p,ms,&m);if(s==BAF_HANDLE_OK&&valid_handle(m.handle))strcpy(h,m.handle);else if(s==BAF_HANDLE_OK)s=BAF_HANDLE_UNAVAILABLE;clear(&m,sizeof(m));return s; }
enum baf_handle_status baf_handle_resolve_and_consume(const char *p,int ms,const char *h,const char *target,unsigned char **a,size_t *n) { struct message m;enum baf_handle_status s;unsigned char *copy;if(!valid_handle(h)||!target||strlen(target)>255||!a||!n)return BAF_HANDLE_BAD_REQUEST;*a=NULL;*n=0;memset(&m,0,sizeof(m));m.magic=MAGIC;m.version=HANDLE_VERSION;m.op=OP_RESOLVE;strcpy(m.handle,h);strcpy(m.target,target);s=request(p,ms,&m);if(s==BAF_HANDLE_OK){copy=m.assertion_length?malloc(m.assertion_length):NULL;if(!copy)s=BAF_HANDLE_ERROR;else{memcpy(copy,m.assertion,m.assertion_length);*a=copy;*n=m.assertion_length;}}clear(&m,sizeof(m));return s; }
static enum baf_handle_status simple(const char *p,int ms,uint16_t op,uint32_t *count){struct message m;enum baf_handle_status s;memset(&m,0,sizeof(m));m.magic=MAGIC;m.version=HANDLE_VERSION;m.op=op;s=request(p,ms,&m);if(s==BAF_HANDLE_OK&&count)*count=m.count;clear(&m,sizeof(m));return s;}
enum baf_handle_status baf_handle_ping(const char*p,int ms){return simple(p,ms,OP_PING,NULL);} enum baf_handle_status baf_handle_cleanup_expired(const char*p,int ms,uint32_t*c){return simple(p,ms,OP_CLEANUP,c);}
static void free_entry(struct entry *e){if(e){baf_handle_assertion_free(e->assertion,e->length);clear(e,sizeof(*e));free(e);}}
static uint32_t cleanup(struct entry **head,int64_t now,size_t *used){struct entry **l=head;uint32_t n=0;while(*l){struct entry *e=*l;if(e->expires_at<=now){*l=e->next;free_entry(e);--*used;++n;}else l=&e->next;}return n;}
static int generate(char h[65]){static const char x[]="0123456789abcdef";unsigned char b[32];size_t i;if(RAND_bytes(b,32)!=1)return 0;for(i=0;i<32;i++){h[2*i]=x[b[i]>>4];h[2*i+1]=x[b[i]&15];}h[64]=0;clear(b,32);return 1;}
static void process(struct entry **head,size_t *used,size_t cap,int64_t max_ttl,struct message *m){int64_t now=time(NULL);struct entry **l;m->status=BAF_HANDLE_BAD_REQUEST;if(m->magic!=MAGIC||m->version!=HANDLE_VERSION)return;if(m->op==OP_PING){m->status=BAF_HANDLE_OK;return;}if(m->op==OP_CLEANUP){m->count=cleanup(head,now,used);m->status=BAF_HANDLE_OK;return;}if(m->op==OP_STORE){struct entry *e;if(!m->assertion_length||m->assertion_length>BAF_HANDLE_MAX_ASSERTION||m->target[255]||m->expires_at<=now||m->expires_at-now>max_ttl)return;cleanup(head,now,used);if(*used>=cap){m->status=BAF_HANDLE_CAPACITY;return;}e=calloc(1,sizeof(*e));if(!e||(e->assertion=malloc(m->assertion_length))==NULL||!generate(e->handle)){free_entry(e);m->status=BAF_HANDLE_ERROR;return;}memcpy(e->assertion,m->assertion,m->assertion_length);e->length=m->assertion_length;e->expires_at=m->expires_at;strcpy(e->target,m->target);e->next=*head;*head=e;++*used;strcpy(m->handle,e->handle);m->assertion_length=0;clear(m->assertion,sizeof(m->assertion));m->status=BAF_HANDLE_OK;return;}if(m->op!=OP_RESOLVE||!valid_handle(m->handle)||m->target[255])return;for(l=head;*l;l=&(*l)->next){struct entry *e=*l;if(!strcmp(e->handle,m->handle)){if(e->expires_at<=now){*l=e->next;free_entry(e);--*used;m->status=BAF_HANDLE_EXPIRED;}else if(strcmp(e->target,m->target)){*l=e->next;free_entry(e);--*used;m->assertion_length=0;clear(m->assertion,sizeof(m->assertion));m->status=BAF_HANDLE_TARGET_MISMATCH;}else{m->assertion_length=e->length;memcpy(m->assertion,e->assertion,e->length);*l=e->next;free_entry(e);--*used;m->status=BAF_HANDLE_OK;}return;}}m->status=BAF_HANDLE_NOT_FOUND;}
int baf_handle_service_run(const char *p,size_t cap,int64_t max_ttl){struct sockaddr_un a;struct entry *head=NULL;size_t used=0;int lfd=-1,result=1;if(!cap||max_ttl<=0||address(p,&a)||(lfd=socket(AF_UNIX,SOCK_SEQPACKET,0))<0)return 1;unlink(p);if(bind(lfd,(struct sockaddr*)&a,sizeof(a))||chmod(p,0660)||listen(lfd,64))goto done;result=0;for(;;){struct message m;int fd=accept(lfd,NULL,NULL);ssize_t n;if(fd<0){if(errno==EINTR)continue;result=1;break;}memset(&m,0,sizeof(m));n=recv(fd,&m,sizeof(m),MSG_TRUNC);if(n==sizeof(m))process(&head,&used,cap,max_ttl,&m);else{m.magic=MAGIC;m.version=HANDLE_VERSION;m.status=BAF_HANDLE_BAD_REQUEST;}(void)send(fd,&m,sizeof(m),MSG_NOSIGNAL);clear(&m,sizeof(m));close(fd);}done:while(head){struct entry*n=head->next;free_entry(head);head=n;}if(lfd>=0)close(lfd);unlink(p);return result;}
