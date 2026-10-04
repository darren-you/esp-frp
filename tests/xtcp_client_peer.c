// SPDX-License-Identifier: Apache-2.0
#define _POSIX_C_SOURCE 200809L
#include "esp_frp.h"
#include "esp_frp_xtcp_visitor.h"
#include "client_port.h"
#include "dns_fixture.h"
#include "flash_store_fixture.h"
#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
typedef struct { efrp_client_t *client; atomic_bool trusted; atomic_uint events; pthread_t worker; bool has_worker; } events_t;
static bool trusted(void *context) { return atomic_load(&((events_t *)context)->trusted); }
static void event(void *context,const efrp_status_t *status)
{
    events_t *e=context;if(!e->has_worker){e->worker=pthread_self();e->has_worker=true;}assert(pthread_equal(e->worker,pthread_self()));
    efrp_status_t copy;assert(efrp_get_status(e->client,&copy)==EFRP_OK&&copy.phase==status->phase);
    assert(efrp_start(e->client)==EFRP_INVALID_STATE);atomic_fetch_add(&e->events,1);
 if(status->error!=EFRP_OK||status->xtcp.error!=EFRP_OK)fprintf(stderr,"C event phase=%d error=%d xtcp=%d/%d attempt=%"PRIu64" established=%"PRIu64"\n",status->phase,status->error,status->xtcp.phase,status->xtcp.error,status->xtcp.attempts,status->xtcp.established);
}
static unsigned fds(void) { unsigned count=0;for(int fd=0;fd<1024;++fd)if(fcntl(fd,F_GETFD)>=0)++count;return count; }
static efrp_status_t wait_phase(events_t *e,efrp_phase_t phase,uint64_t ready_count)
{
    uint64_t deadline=efrp_port_now_ms()+15000;for(;;){
        efrp_status_t s;assert(efrp_get_status(e->client,&s)==EFRP_OK);
        if(s.phase==phase&&s.ready_sessions>=ready_count)return s;
        if(efrp_port_now_ms()>=deadline){fprintf(stderr,"XTCP wait phase=%d actual=%d error=%d xtcp=%d/%d attempts=%"PRIu64"\n",phase,s.phase,s.error,s.xtcp.phase,s.xtcp.error,s.attempts);abort();}
        poll(NULL,0,1);
    }
}
static void stop(events_t *e)
{
    assert(efrp_stop(e->client,5000)==EFRP_OK);efrp_status_t s;assert(efrp_get_status(e->client,&s)==EFRP_OK);
    assert(s.phase==EFRP_PHASE_STOPPED&&!s.work.active&&!s.work.waiting&&!s.work.cleaning&&!fixture_dns_active());
    unsigned before=atomic_load(&e->events);poll(NULL,0,5);assert(atomic_load(&e->events)==before);
}
int main(int argc,char **argv)
{
    assert(argc==12);bool visitor=!strcmp(argv[1],"visitor");assert(visitor||!strcmp(argv[1],"provider"));
    unsigned server_port=(unsigned)strtoul(argv[2],NULL,10),local_port=(unsigned)strtoul(argv[4],NULL,10);
    unsigned stun1=(unsigned)strtoul(argv[5],NULL,10),stun2=(unsigned)strtoul(argv[6],NULL,10);
    assert(server_port&&server_port<=65535&&local_port&&local_port<=65535&&stun1&&stun1<=65535&&stun2&&stun2<=65535);
    FILE *file=fopen(argv[3],"rb");assert(file);uint8_t ca[EFRP_TLS_MAX_CA_BYTES];size_t ca_length=fread(ca,1,sizeof ca,file);assert(ca_length&&ca_length<sizeof ca&&!ferror(file)&&!fclose(file));
    unsigned baseline=fds();static efrp_test_flash_t flash;efrp_aead_flash_store_t store=efrp_test_flash_store(&flash);assert(efrp_aead_flash_store_recover(&store)==EFRP_OK);
    events_t events={.trusted=true};char host[254]="frp.fixture.invalid",token[]="public-full-flow-token",secret[129],user[129],target[129],id[65];
    assert(strlen(argv[7])<sizeof secret&&strlen(argv[8])<sizeof user&&strlen(argv[9])<sizeof target);strcpy(secret,argv[7]);strcpy(user,argv[8]);strcpy(target,argv[9]);
    assert(snprintf(id,sizeof id,"fixture-xtcp-%s-%ld",argv[1],(long)getpid())>0);
    if(!strcmp(argv[10],"wrong-token"))token[0]='x';else if(!strcmp(argv[10],"wrong-host"))strcpy(host,"wrong.fixture.invalid");else if(!strcmp(argv[10],"untrusted"))atomic_store(&events.trusted,false);else assert(!strcmp(argv[10],"normal"));
    efrp_result_t expected=(efrp_result_t)strtol(argv[11],NULL,10);fixture_dns_mode(FIXTURE_DNS_READY);
    efrp_xtcp_options_t options={.peer_profile=EFRP_QUIC_PROFILE_P256_AES128_X25519,.stun_servers={{{127,0,0,1},(uint16_t)stun1},{{127,0,0,1},(uint16_t)stun2}},.stun_server_count=2,.udp_bind_ipv4={127,0,0,1}};
    if(visitor){
        efrp_xtcp_visitor_config_t c={.server_hostname=host,.server_port=(uint16_t)server_port,.ca_pem=ca,.ca_length=ca_length,.token=(const uint8_t*)token,.token_length=strlen(token),.hostname="fixture-xtcp-board",.user=user,.client_id=id,.server_proxy_name=target,.secret_key=secret,.bind_ipv4={127,0,0,1},.bind_port=(uint16_t)local_port,.options=options,.time_is_trusted=trusted,.flash_store=&store,.on_event=event,.context=&events};
        assert(efrp_xtcp_visitor_create(&c,&events.client)==EFRP_OK&&events.client);assert(efrp_xtcp_visitor_create(&c,&events.client)==EFRP_INVALID_STATE);memset(&c,0,sizeof c);
    }else{
        efrp_proxy_options_t proxy={.secret_key=secret};
        efrp_config_t c={.server_hostname=host,.server_port=(uint16_t)server_port,.ca_pem=ca,.ca_length=ca_length,.token=(const uint8_t*)token,.token_length=strlen(token),.hostname="fixture-xtcp-board",.user=user,.client_id=id,.proxy_name=target,.proxy_type=EFRP_PROXY_XTCP,.proxy_options=&proxy,.xtcp_options=&options,.local_ipv4={127,0,0,1},.local_port=(uint16_t)local_port,.time_is_trusted=trusted,.flash_store=&store,.on_event=event,.context=&events};
        assert(efrp_create(&c,&events.client)==EFRP_OK&&events.client);assert(efrp_create(&c,&events.client)==EFRP_INVALID_STATE);memset(&c,0,sizeof c);memset(&proxy,0,sizeof proxy);
    }
    memset(ca,0,sizeof ca);memset(host,0,sizeof host);memset(token,0,sizeof token);memset(secret,0,sizeof secret);memset(user,0,sizeof user);memset(target,0,sizeof target);memset(id,0,sizeof id);memset(&options,0,sizeof options);
    assert(efrp_start(events.client)==EFRP_OK);efrp_status_t status=wait_phase(&events,expected==EFRP_OK?EFRP_PHASE_READY:EFRP_PHASE_FAILED,expected==EFRP_OK?1:0);
    if(expected!=EFRP_OK){assert(status.error==expected);printf("FAILED %d\n",status.error);}else{assert(status.pongs&&status.run_id[0]&&!status.tls_verify_flags);printf("READY %u %s\n",local_port,status.run_id);}fflush(stdout);
    assert(fcntl(STDIN_FILENO,F_SETFL,fcntl(STDIN_FILENO,F_GETFL)|O_NONBLOCK)==0);
    uint64_t limit=efrp_port_now_ms()+120000;
    for(;;){assert(efrp_port_now_ms()<limit);assert(efrp_get_status(events.client,&status)==EFRP_OK);assert(status.work.active<=2&&status.work.active+status.work.cleaning<=2&&status.work.waiting<=1&&status.work.pending<=1);
        char command;ssize_t got=read(STDIN_FILENO,&command,1);if(got==0)break;if(got<0){poll(NULL,0,1);continue;}
        if(command=='q')break;
        if(command=='s'){printf("STATE %d %d %"PRIu64" %"PRIu64" %u %u %u %"PRIu64" %"PRIu64" %d\n",status.xtcp.phase,status.xtcp.error,status.xtcp.established,status.xtcp.rejected,status.work.active,status.work.waiting,status.work.cleaning,status.work.completed,status.work.failed,status.work.last_error);
            fprintf(stderr,"C requested STATE global=%d/%d failure_phase=%d xtcp=%d/%d attempts=%"PRIu64" failed=%"PRIu64"\n",status.phase,status.error,status.failure_phase,status.xtcp.phase,status.xtcp.error,status.xtcp.attempts,status.xtcp.failed);fflush(stdout);}
        else if(command=='z'){stop(&events);assert(fds()==baseline);puts("STOPPED");fflush(stdout);}
        else if(command=='r'){assert(efrp_start(events.client)==EFRP_OK);status=wait_phase(&events,EFRP_PHASE_READY,status.ready_sessions+1);printf("RESTARTED %u %s\n",local_port,status.run_id);fflush(stdout);}
        else if(command=='u'){atomic_store(&events.trusted,false);status=wait_phase(&events,EFRP_PHASE_FAILED,0);assert(status.error==EFRP_TIME_UNTRUSTED);puts("UNTRUSTED");fflush(stdout);}
    }
    stop(&events);assert(efrp_destroy(&events.client,5000)==EFRP_OK&&!events.client);assert(fds()==baseline);puts("CLEAN");return 0;
}
